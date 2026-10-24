//! Private-key / session-secret loading and Krypt04Mcg packet decryption.
//!
//! The cryptographic layout mirrors Krypt04Mcg's `CryptoService` and
//! `PacketCodec` for the algorithms this tool can implement:
//!
//! * KEM: bare ML-KEM-512/768/1024, the Bouncy Castle native composite
//!   `MLKEM768-X25519-SHA3-256` / `MLKEM1024-X448-SHA3-256`, and the
//!   project's custom `K04-HYBRID-V1` ML-KEM+X25519/X448 hybrids.
//! * AEAD: AES-256-GCM and ChaCha20-Poly1305.
//! * KDF: HKDF-SHA256 with the project's domain labels.
//!
//! Private keys, session secrets and public signature keys are loaded here.
//! Signature verification itself lives in [`crate::signature`]; it is
//! independent of decryption. A successful decryption authenticates the
//! ciphertext under the loaded key but does not by itself prove the claimed
//! sender identity.

use std::fs;
use std::path::{Path, PathBuf};

use aes_gcm::Aes256Gcm;
use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};
use base64::Engine as _;
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use ml_kem::{Decapsulate, MlKem512, MlKem768, MlKem1024};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use sha3::Sha3_256;
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

use crate::model::{
    DecryptionAttempt, DecryptionOutcome, DecryptionStatus, FragmentGroup, LoadedLogs,
    MessageStatus, ParsedPacket, SignatureOutcome,
};
use crate::packet::{FLAG_COMPRESSED, FLAG_SESSION_RESPONSE, FLAG_SIGNED, hex};
use crate::signature::SignatureKeyRegistry;

const HYBRID_MAGIC: u32 = 0x4b30_3401;
const HYBRID_MAX_COMPONENT: usize = 2 * 1024 * 1024;
const MAX_PLAINTEXT_BYTES: usize = 16 * 1024 * 1024;
const MAX_KEY_FILE_BYTES: u64 = 16 * 1024 * 1024;
const SENSITIVE_FILE_MAGIC: &[u8; 8] = b"KMCGSEC1";
const MASTER_KEY_MAGIC: &[u8; 8] = b"KMCGKEY1";

const OID_ML_KEM_512: &str = "2.16.840.1.101.3.4.4.1";
const OID_ML_KEM_768: &str = "2.16.840.1.101.3.4.4.2";
const OID_ML_KEM_1024: &str = "2.16.840.1.101.3.4.4.3";
const OID_MLKEM768_X25519: &str = "1.3.6.1.5.5.7.6.58";
const OID_MLKEM1024_X448: &str = "1.3.6.1.5.5.7.6.65";
/// Domain separator from draft-ietf-lamps-pq-composite-kem for
/// MLKEM768-X25519-SHA3-256 (`\.//^\`).
const COMPOSITE_768_X25519_LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];
const COMPOSITE_1024_X448_LABEL: &[u8] = b"MLKEM1024-X448";

// ---------------------------------------------------------------------------
// Public key store
// ---------------------------------------------------------------------------

/// All private keys and session secrets the user has loaded. Sensitive key
/// material is kept in memory only and is never serialized.
#[derive(Default)]
pub struct KeyStore {
    pub private_keys: Vec<PrivateKeyEntry>,
    pub sessions: Vec<SessionEntry>,
    /// Public signature keys used to verify signed packet envelopes.
    pub signatures: SignatureKeyRegistry,
    pub sources: Vec<String>,
    pub warnings: Vec<String>,
}

/// One loadable KEM private key from a Krypt04Mcg `LocalKeyMaterial`.
pub struct PrivateKeyEntry {
    pub owner: String,
    pub uuid: String,
    /// KEM identifier without the `/private` role suffix.
    pub algorithm: String,
    pub signature_algorithm: String,
    pub fingerprint: String,
    pub source: String,
    dedup_id: String,
    kem: KemPrivateKey,
}

/// One session epoch secret loaded from a `sessions/*.json` ledger.
#[derive(Clone)]
pub struct SessionEntry {
    pub peer: String,
    pub session_id: String,
    pub source: String,
    secret: [u8; 32],
}

#[derive(Clone, Debug, Default)]
pub struct KeyLoadSummary {
    pub files_scanned: usize,
    pub keys_added: usize,
    pub sessions_added: usize,
    pub public_keys_added: usize,
    pub duplicate_keys: usize,
    pub duplicate_sessions: usize,
    pub warnings: Vec<String>,
}

impl KeyLoadSummary {
    pub fn message(&self) -> String {
        let mut text = format!(
            "扫描 {} 个文件，新增 {} 个私钥、{} 个会话密钥、{} 个签名公钥",
            self.files_scanned, self.keys_added, self.sessions_added, self.public_keys_added
        );
        if self.duplicate_keys > 0 || self.duplicate_sessions > 0 {
            text.push_str(&format!(
                "（跳过重复私钥 {}、重复会话 {}）",
                self.duplicate_keys, self.duplicate_sessions
            ));
        }
        if !self.warnings.is_empty() {
            text.push_str(&format!("；{} 条提示", self.warnings.len()));
        }
        text
    }
}

/// Which direction key a captured raw-channel record needs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamKeyDirection {
    /// The captured client sent the record (`data/.../<local>/<peer>`).
    Send,
    /// The captured client received the record (`data/.../<peer>/<local>`).
    Receive,
}

/// One direction of one `krypt04mcg_stream:data/N` record stream.
///
/// Krypt04Mcg derives a fresh XChaCha20-Poly1305 key for every stream,
/// direction and business channel. The nonce is the stream UUID followed by an
/// implicit record counter, and the AAD binds the session, stream, slot and
/// business channel. Records carry no explicit counter, so records must be
/// decrypted in capture order.
pub struct StreamRecordCipher {
    key: [u8; 32],
    aad: Vec<u8>,
    stream_id: Uuid,
    counter: u64,
}

impl StreamRecordCipher {
    /// Number of successfully authenticated records so far.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// Authenticates and decrypts the next record. The counter advances only
    /// after successful authentication, matching Krypt04Mcg's `ChannelCrypto`.
    pub fn decrypt_next(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
        if ciphertext.len() < 16 {
            return Err("流记录短于 16 字节认证标签".to_owned());
        }
        if self.counter >= i64::MAX as u64 {
            return Err("流记录计数器耗尽".to_owned());
        }
        let mut nonce = [0u8; 24];
        nonce[..16].copy_from_slice(self.stream_id.as_bytes());
        nonce[16..].copy_from_slice(&self.counter.to_be_bytes());
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key)
            .map_err(|_| "无法初始化 XChaCha20-Poly1305".to_owned())?;
        let nonce = XNonce::try_from(&nonce[..])
            .map_err(|_| "XChaCha20-Poly1305 nonce 长度无效".to_owned())?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &self.aad,
                },
            )
            .map_err(|_| {
                format!(
                    "XChaCha20-Poly1305 认证失败（第 {} 条记录；密钥、AAD 或记录顺序不匹配）",
                    self.counter
                )
            })?;
        self.counter += 1;
        Ok(plaintext)
    }
}

impl Drop for StreamRecordCipher {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

impl KeyStore {
    /// Derives the per-stream, per-direction record cipher from a loaded
    /// `stream-api` session secret.
    #[allow(clippy::too_many_arguments)]
    pub fn stream_cipher(
        &self,
        session_id: &str,
        stream_id: Uuid,
        slot: i32,
        channel: &str,
        local: &str,
        peer: &str,
        direction: StreamKeyDirection,
    ) -> Result<StreamRecordCipher, String> {
        if local.eq_ignore_ascii_case(peer) {
            return Err("流两端身份相同，无法派生方向密钥".to_owned());
        }
        let session = self
            .sessions
            .iter()
            .find(|session| session.session_id == session_id)
            .ok_or_else(|| {
                format!(
                    "没有 sessionId 为 {session_id} 的会话密钥。请加载 Krypt04Mcg 账户目录中的 stream-api/sessions/ 或聊天 sessions/。"
                )
            })?;
        let salt = decode_base64url(session_id)?;
        let context = format!("{session_id}/{stream_id}/{slot}/{channel}");
        let (source, target) = match direction {
            StreamKeyDirection::Send => (local, peer),
            StreamKeyDirection::Receive => (peer, local),
        };
        let info = format!(
            "krypt04mcg_stream/v1/data/{context}/{}/{}",
            source.to_ascii_lowercase(),
            target.to_ascii_lowercase()
        );
        let key = hkdf_sha256(&session.secret, Some(&salt), info.as_bytes())?;
        let aad = format!("krypt04mcg_stream/v1/{context}").into_bytes();
        Ok(StreamRecordCipher {
            key,
            aad,
            stream_id,
            counter: 0,
        })
    }

    /// Verifies a control-channel HMAC produced by `ChannelCrypto.authenticate`.
    /// `kind` must be the wire enum name (`OPEN`, `READY`, ...); `slot_for_mac`
    /// is `-1` for `OPEN` and the assigned slot for every other kind.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_stream_control(
        &self,
        session_id: &str,
        source: &str,
        target: &str,
        kind: &str,
        stream_id: Uuid,
        slot_for_mac: i32,
        channel: &str,
        sequence: i64,
        body: &[u8],
    ) -> Result<bool, String> {
        let session = self
            .sessions
            .iter()
            .find(|session| session.session_id == session_id)
            .ok_or_else(|| format!("没有 sessionId 为 {session_id} 的会话密钥"))?;
        let salt = decode_base64url(session_id)?;
        let info = format!(
            "krypt04mcg_stream/v1/control/{}/{}",
            source.to_ascii_lowercase(),
            target.to_ascii_lowercase()
        );
        let key = hkdf_sha256(&session.secret, Some(&salt), info.as_bytes())?;
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&key)
            .map_err(|_| "无法初始化 HMAC-SHA256".to_owned())?;
        let text = format!("{kind}/{stream_id}/{slot_for_mac}/{channel}/{session_id}/{sequence}");
        mac.update(text.as_bytes());
        Ok(mac.verify_slice(body).is_ok())
    }

    /// Decrypts a legacy `krypt04mcg:tunnel` envelope. The envelope carries a
    /// stream UUID and lease followed by a `SESSION_MESSAGE` packet whose
    /// session key is derived from the chat session secret with the tunnel
    /// domain separator.
    pub fn decrypt_legacy_tunnel(
        &self,
        binary: &[u8],
        stream_id: Uuid,
        lease: i64,
    ) -> DecryptionOutcome {
        let packet = crate::packet::parse_packet(binary);
        let mut outcome = DecryptionOutcome::default();
        if packet.error.is_some() || packet.packet_type != Some(4) {
            outcome.status = DecryptionStatus::Unsupported;
            outcome.error = Some("隧道内层不是可解析的 SESSION_MESSAGE".to_owned());
            return outcome;
        }
        if lease < 0 {
            outcome.status = DecryptionStatus::Failed;
            outcome.error = Some("隧道 lease 为负数".to_owned());
            return outcome;
        }
        let Some(session_id) = packet.session_id.as_deref() else {
            outcome.status = DecryptionStatus::Unsupported;
            outcome.error = Some("隧道内层缺少 sessionId".to_owned());
            return outcome;
        };
        outcome.session_id = Some(session_id.to_owned());
        let Some(session) = self
            .sessions
            .iter()
            .find(|session| session.session_id == session_id)
        else {
            outcome.status = DecryptionStatus::NoKey;
            outcome.error = Some(format!("没有 sessionId 为 {session_id} 的会话密钥"));
            return outcome;
        };
        let result = (|| -> Result<Vec<u8>, String> {
            let salt = decode_base64url(session_id)?;
            let info = format!(
                "krypt04mcg tunnel v1\n{stream_id}\n{lease}\n{}\n{}",
                packet.sender.to_ascii_lowercase(),
                packet.receiver.to_ascii_lowercase()
            );
            let tunnel_key = hkdf_sha256(&session.secret, Some(&salt), info.as_bytes())?;
            let message_id = decode_hex(&packet.message_id_hex)?;
            if message_id.len() != 16 {
                return Err("messageId 长度不是 16 字节".to_owned());
            }
            let derived = hkdf_sha256(&tunnel_key, Some(&message_id), b"krypt04mcg session")?;
            let nonce = slice_field(binary, packet.nonce_data_offset, packet.nonce_len)?;
            let ciphertext =
                slice_field(binary, packet.ciphertext_data_offset, packet.ciphertext_len)?;
            let aad = build_aad(&packet)?;
            let plaintext =
                aead_decrypt(&packet.algorithms.aead, &derived, nonce, &aad, ciphertext)?;
            maybe_inflate(plaintext, packet.flags.unwrap_or(0) & FLAG_COMPRESSED != 0)
        })();
        match result {
            Ok(plaintext) => {
                outcome.status = DecryptionStatus::Decrypted;
                outcome.key_owner = Some(session.peer.clone());
                outcome.key_source = Some(session.source.clone());
                outcome.key_algorithm = Some(packet.algorithms.aead.clone());
                outcome.key_kind = Some("session_secret".to_owned());
                outcome.attempts.push(DecryptionAttempt {
                    key_owner: session.peer.clone(),
                    key_source: session.source.clone(),
                    key_kind: "session_secret".to_owned(),
                    algorithm: packet.algorithms.aead.clone(),
                    success: true,
                    error: None,
                });
                let compressed = packet.flags.unwrap_or(0) & FLAG_COMPRESSED != 0;
                finish_plaintext(&mut outcome, plaintext, compressed);
            }
            Err(error) => {
                outcome.status = DecryptionStatus::Failed;
                outcome.error = Some(error);
            }
        }
        outcome
    }

    /// Parses, decrypts and verifies a complete Krypt04Mcg packet envelope
    /// carried inside a stream control message.
    pub fn analyze_packet(
        &self,
        binary: &[u8],
    ) -> (ParsedPacket, DecryptionOutcome, SignatureOutcome) {
        let packet = crate::packet::parse_packet(binary);
        let status = if packet.error.is_none() {
            MessageStatus::Parsed
        } else {
            MessageStatus::Invalid
        };
        let group = FragmentGroup {
            message_id: packet.message_id_hex.clone(),
            transport_sender: packet.sender.clone(),
            total: 1,
            slots: Default::default(),
            first_seen: Default::default(),
            last_seen: Default::default(),
            first_order: 0,
            duplicate_count: 0,
            conflicts: 0,
            warnings: Vec::new(),
            binary: Some(binary.to_vec()),
            packet: Some(packet.clone()),
            status,
            decryption: None,
            signature: None,
        };
        let outcome = self.decrypt_message(&group);
        let signature = self.signatures.verify_packet(&packet, binary);
        (packet, outcome, signature)
    }

    pub fn is_empty(&self) -> bool {
        self.private_keys.is_empty() && self.sessions.is_empty() && self.signatures.is_empty()
    }

    pub fn clear(&mut self) {
        self.private_keys.clear();
        self.sessions.clear();
        self.signatures.clear();
        self.sources.clear();
        self.warnings.clear();
    }

    /// Loads one or more key files, session ledgers, account directories, or a
    /// parent directory containing several accounts.
    pub fn load_paths(&mut self, paths: &[PathBuf]) -> KeyLoadSummary {
        let mut summary = KeyLoadSummary::default();
        for path in paths {
            self.load_path(path, &mut summary);
        }
        summary
    }

    fn load_path(&mut self, path: &Path, summary: &mut KeyLoadSummary) {
        if path.is_dir() {
            // An account root contains keys/private/local.json and sessions/.
            let local = path.join("keys").join("private").join("local.json");
            if local.is_file() {
                self.note_source(path);
                self.load_file(&local, summary);
                self.load_public_dir(&path.join("keys").join("public"), summary);
                self.load_self_public_export(path, summary);
                self.load_sessions_dir(path, summary);
                self.load_stream_api_dir(path, summary);
                return;
            }
            // Also accept the `keys` directory itself.
            let nested_local = path.join("private").join("local.json");
            if nested_local.is_file() {
                self.note_source(path);
                self.load_file(&nested_local, summary);
                if let Some(account_root) = path.parent() {
                    self.load_public_dir(&path.join("public"), summary);
                    self.load_self_public_export(account_root, summary);
                    self.load_sessions_dir(account_root, summary);
                    self.load_stream_api_dir(account_root, summary);
                }
                return;
            }

            // A `stream-api` root has its own secrets/master.key and sessions/.
            if path.join("secrets").join("master.key").is_file() && path.join("sessions").is_dir() {
                self.note_source(path);
                self.load_sessions_in(&path.join("sessions"), summary);
                return;
            }

            // A standalone `keys/public` directory (or a `keys` directory
            // without private material).
            if path.join("public").is_dir() {
                self.note_source(path);
                self.load_public_dir(&path.join("public"), summary);
                if path.join("private").join("local.json").is_file() {
                    self.load_file(&path.join("private").join("local.json"), summary);
                }
                return;
            }

            let roots = find_account_roots(path);
            if !roots.is_empty() {
                for root in roots {
                    self.note_source(&root);
                    let local = root.join("keys").join("private").join("local.json");
                    if local.is_file() {
                        self.load_file(&local, summary);
                    }
                    self.load_public_dir(&root.join("keys").join("public"), summary);
                    self.load_self_public_export(&root, summary);
                    self.load_sessions_dir(&root, summary);
                    self.load_stream_api_dir(&root, summary);
                }
                return;
            }

            // Otherwise treat direct JSON files in the selected directory as
            // individually exported key/session files.
            match fs::read_dir(path) {
                Ok(entries) => {
                    let mut files: Vec<PathBuf> = entries
                        .flatten()
                        .map(|entry| entry.path())
                        .filter(|candidate| {
                            candidate.is_file()
                                && candidate
                                    .extension()
                                    .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
                        })
                        .collect();
                    files.sort();
                    for file in files {
                        self.load_file(&file, summary);
                    }
                }
                Err(error) => {
                    self.warn(summary, format!("无法读取目录 {}：{error}", path.display()))
                }
            }
        } else if path.is_file() {
            self.note_source(path);
            self.load_file(path, summary);
        } else {
            self.warn(summary, format!("路径不存在或不可读取：{}", path.display()));
        }
    }

    fn load_sessions_dir(&mut self, account_root: &Path, summary: &mut KeyLoadSummary) {
        self.load_sessions_in(&account_root.join("sessions"), summary);
    }

    /// Loads `keys/public/*.json`, the public identities exchanged over the
    /// `krypt04mcg:public_key` channel.
    fn load_public_dir(&mut self, dir: &Path, summary: &mut KeyLoadSummary) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|candidate| {
                candidate.is_file()
                    && candidate
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
            })
            .collect();
        files.sort();
        for file in files {
            self.load_file(&file, summary);
        }
    }

    fn load_self_public_export(&mut self, account_root: &Path, summary: &mut KeyLoadSummary) {
        let path = account_root.join("export").join("self-public.json");
        if path.is_file() {
            self.load_file(&path, summary);
        }
    }

    /// Loads the separate `stream-api/sessions/` ledger used by the raw
    /// encrypted channel transport. It has its own `secrets/master.key`, so the
    /// files are decrypted independently of the chat session directory.
    fn load_stream_api_dir(&mut self, account_root: &Path, summary: &mut KeyLoadSummary) {
        self.load_sessions_in(&account_root.join("stream-api").join("sessions"), summary);
    }

    fn load_sessions_in(&mut self, dir: &Path, summary: &mut KeyLoadSummary) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        let mut files: Vec<PathBuf> = entries
            .flatten()
            .map(|entry| entry.path())
            .filter(|candidate| {
                candidate.is_file()
                    && candidate
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("json"))
            })
            .collect();
        files.sort();
        for file in files {
            self.load_file(&file, summary);
        }
    }

    fn load_file(&mut self, path: &Path, summary: &mut KeyLoadSummary) {
        summary.files_scanned += 1;
        if let Ok(metadata) = fs::metadata(path)
            && metadata.len() > MAX_KEY_FILE_BYTES
        {
            self.warn(
                summary,
                format!(
                    "跳过过大的密钥文件 {}（{} 字节）",
                    path.display(),
                    metadata.len()
                ),
            );
            return;
        }
        let text = match read_sensitive_text(path) {
            Ok(text) => text,
            Err(error) => {
                self.warn(summary, format!("{}：{error}", path.display()));
                return;
            }
        };
        let value: serde_json::Value = match serde_json::from_str(&text) {
            Ok(value) => value,
            Err(error) => {
                self.warn(
                    summary,
                    format!("{} 不是有效 JSON：{error}", path.display()),
                );
                return;
            }
        };
        self.ingest_value(&value, path, summary);
    }

    fn ingest_value(
        &mut self,
        value: &serde_json::Value,
        path: &Path,
        summary: &mut KeyLoadSummary,
    ) {
        match value {
            serde_json::Value::Array(items) => {
                for item in items {
                    self.ingest_value(item, path, summary);
                }
            }
            serde_json::Value::Object(object) => {
                if object.contains_key("kemPrivateKey") {
                    self.ingest_local_material(value, path, summary);
                } else if object.contains_key("signaturePublicKey") {
                    self.ingest_public_identity(value, path, summary);
                } else if object.contains_key("stateVersion") || object.contains_key("session") {
                    self.ingest_session_state(value, path, summary);
                } else if object.contains_key("keyData") {
                    let algorithm = object
                        .get("algorithm")
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    if algorithm.to_ascii_lowercase().ends_with("/public") {
                        if self
                            .signatures
                            .ingest_record_value(value, &path.display().to_string())
                        {
                            summary.public_keys_added += 1;
                        }
                    } else if let Ok(record) =
                        serde_json::from_value::<KeyRecordJson>(value.clone())
                    {
                        self.add_key_record(&record, None, path, summary);
                    }
                } else if object.contains_key("secret") && object.contains_key("sessionId") {
                    self.ingest_session_value(value, path, summary, false);
                } else {
                    self.warn(
                        summary,
                        format!(
                            "{} 不包含可识别的私钥或会话字段（需要 LocalKeyMaterial 或 sessions 记录）",
                            path.display()
                        ),
                    );
                }
            }
            _ => self.warn(summary, format!("{} 不是 JSON 对象或数组", path.display())),
        }
    }

    fn ingest_public_identity(
        &mut self,
        value: &serde_json::Value,
        path: &Path,
        summary: &mut KeyLoadSummary,
    ) {
        if self
            .signatures
            .ingest_identity_value(value, &path.display().to_string())
        {
            summary.public_keys_added += 1;
        }
    }

    fn ingest_local_material(
        &mut self,
        value: &serde_json::Value,
        path: &Path,
        summary: &mut KeyLoadSummary,
    ) {
        if self
            .signatures
            .ingest_identity_value(value, &path.display().to_string())
        {
            summary.public_keys_added += 1;
        }
        let Some(kem_private) = value.get("kemPrivateKey") else {
            self.warn(summary, format!("{} 缺少 kemPrivateKey", path.display()));
            return;
        };
        let record = match serde_json::from_value::<KeyRecordJson>(kem_private.clone()) {
            Ok(record) => record,
            Err(error) => {
                self.warn(
                    summary,
                    format!("{} 的 kemPrivateKey 无法解析：{error}", path.display()),
                );
                return;
            }
        };
        let signature_algorithm = value
            .get("signaturePrivateKey")
            .and_then(|record| record.get("algorithm"))
            .and_then(serde_json::Value::as_str)
            .map(strip_role)
            .unwrap_or_default()
            .to_owned();
        self.add_key_record(&record, Some(signature_algorithm), path, summary);
    }

    fn ingest_session_state(
        &mut self,
        value: &serde_json::Value,
        path: &Path,
        summary: &mut KeyLoadSummary,
    ) {
        let mut found = false;
        if let Some(session) = value.get("session") {
            found |= self.ingest_session_value(session, path, summary, false);
        }
        if let Some(prepared) = value.get("prepared")
            && let Some(session) = prepared.get("session")
        {
            found |= self.ingest_session_value(session, path, summary, true);
        }
        if !found {
            self.warn(summary, format!("{} 中没有可用的会话密钥", path.display()));
        }
    }

    fn ingest_session_value(
        &mut self,
        value: &serde_json::Value,
        path: &Path,
        summary: &mut KeyLoadSummary,
        prepared: bool,
    ) -> bool {
        let Ok(record) = serde_json::from_value::<SessionRecordJson>(value.clone()) else {
            return false;
        };
        let (Some(session_id), Some(secret_text)) = (record.session_id, record.secret) else {
            return false;
        };
        let secret_bytes = match decode_base64url(&secret_text) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.warn(
                    summary,
                    format!("{} 的会话密钥不是合法 Base64URL：{error}", path.display()),
                );
                return false;
            }
        };
        let Ok(secret) = <[u8; 32]>::try_from(secret_bytes.as_slice()) else {
            self.warn(
                summary,
                format!(
                    "{} 的会话密钥长度为 {} 字节，预期 32 字节",
                    path.display(),
                    secret_bytes.len()
                ),
            );
            return false;
        };
        if self
            .sessions
            .iter()
            .any(|session| session.session_id == session_id)
        {
            summary.duplicate_sessions += 1;
            return true;
        }
        let mut source = path.display().to_string();
        if prepared {
            source.push_str("（待提交会话）");
        }
        self.sessions.push(SessionEntry {
            peer: record.peer.unwrap_or_else(|| "(未知)".to_owned()),
            session_id,
            source,
            secret,
        });
        summary.sessions_added += 1;
        true
    }

    fn add_key_record(
        &mut self,
        record: &KeyRecordJson,
        signature_algorithm: Option<String>,
        path: &Path,
        summary: &mut KeyLoadSummary,
    ) {
        let algorithm = strip_role(&record.algorithm).to_owned();
        if record.algorithm.to_ascii_lowercase().ends_with("/public") {
            self.warn(
                summary,
                format!(
                    "{} 中的 {} 是公钥记录，无法用于解密",
                    path.display(),
                    record.algorithm
                ),
            );
            return;
        }
        if !looks_like_kem_algorithm(&algorithm) {
            // Signature private keys are useful to Krypt04Mcg but not to packet
            // decryption; ignore them without cluttering the warning list.
            return;
        }
        let key_data = match decode_base64url(&record.key_data) {
            Ok(bytes) => bytes,
            Err(error) => {
                self.warn(
                    summary,
                    format!(
                        "{} 中 {} 的 keyData 不是合法 Base64URL：{error}",
                        path.display(),
                        algorithm
                    ),
                );
                return;
            }
        };
        let kem = match parse_kem_private(&algorithm, &key_data) {
            Ok(kem) => kem,
            Err(error) => {
                self.warn(
                    summary,
                    format!(
                        "{} 中的 {} 私钥暂不支持：{error}",
                        path.display(),
                        algorithm
                    ),
                );
                return;
            }
        };
        let digest = Sha256::digest(&key_data);
        let dedup_id = hex(&digest);
        if self
            .private_keys
            .iter()
            .any(|entry| entry.dedup_id == dedup_id)
        {
            summary.duplicate_keys += 1;
            return;
        }
        let fingerprint = if record.fingerprint.trim().is_empty() {
            // Never expose a hash of private key bytes as a display
            // fingerprint; derive a stable non-secret identifier instead.
            hex(&Sha256::digest(
                format!("{}|{}|{}", record.owner, record.uuid, algorithm).as_bytes(),
            ))
        } else {
            record.fingerprint.clone()
        };
        self.private_keys.push(PrivateKeyEntry {
            owner: if record.owner.trim().is_empty() {
                "(未知)".to_owned()
            } else {
                record.owner.clone()
            },
            uuid: record.uuid.clone(),
            algorithm,
            signature_algorithm: signature_algorithm.unwrap_or_default(),
            fingerprint,
            source: path.display().to_string(),
            kem,
            dedup_id,
        });
        summary.keys_added += 1;
    }

    fn note_source(&mut self, path: &Path) {
        let text = path.display().to_string();
        if !self.sources.contains(&text) {
            self.sources.push(text);
        }
    }

    fn warn(&mut self, summary: &mut KeyLoadSummary, warning: String) {
        summary.warnings.push(warning.clone());
        if !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }

    // -----------------------------------------------------------------------
    // Decryption
    // -----------------------------------------------------------------------

    /// Recomputes decryption and signature verification for every reassembled
    /// message.
    pub fn decrypt_loaded(&self, loaded: &mut LoadedLogs) {
        for message in &mut loaded.messages {
            message.decryption = Some(self.decrypt_message(message));
            message.signature = Some(self.verify_message(message));
        }
    }

    /// Verifies one reassembled packet signature against the loaded public
    /// keys. Independent of payload decryption.
    pub fn verify_message(&self, message: &FragmentGroup) -> SignatureOutcome {
        match (&message.packet, message.binary.as_deref()) {
            (Some(packet), Some(binary)) => self.signatures.verify_packet(packet, binary),
            _ => SignatureOutcome {
                status: crate::model::SignatureStatus::NotAttempted,
                error: Some("消息不完整或缺少二进制，无法验证签名".to_owned()),
                ..SignatureOutcome::default()
            },
        }
    }

    /// Decrypts a single reassembled packet. Never panics and never exposes
    /// unauthenticated plaintext: only AEAD-verified output is returned.
    pub fn decrypt_message(&self, message: &FragmentGroup) -> DecryptionOutcome {
        let mut outcome = DecryptionOutcome::default();
        let Some(packet) = &message.packet else {
            outcome.status = DecryptionStatus::NotAttempted;
            return outcome;
        };
        let Some(binary) = message.binary.as_deref() else {
            outcome.status = DecryptionStatus::NotAttempted;
            return outcome;
        };
        if message.status != MessageStatus::Parsed || packet.error.is_some() {
            outcome.status = DecryptionStatus::NotAttempted;
            return outcome;
        }
        let (Some(packet_type), Some(flags)) = (packet.packet_type, packet.flags) else {
            outcome.status = DecryptionStatus::NotAttempted;
            return outcome;
        };

        if !packet.algorithms.hkdf.eq_ignore_ascii_case("HKDF-SHA256") {
            outcome.status = DecryptionStatus::Unsupported;
            outcome.error = Some(format!(
                "包使用 HKDF {}，本工具只实现 HKDF-SHA256",
                packet.algorithms.hkdf
            ));
            return outcome;
        }
        if !matches!(
            packet.algorithms.aead.trim().to_ascii_uppercase().as_str(),
            "AES-256-GCM" | "AES256-GCM" | "CHACHA20-POLY1305" | "CHACHA20POLY1305"
        ) {
            outcome.status = DecryptionStatus::Unsupported;
            outcome.error = Some(format!(
                "包使用 AEAD 算法 {}，本工具只实现 AES-256-GCM 与 ChaCha20-Poly1305",
                packet.algorithms.aead
            ));
            return outcome;
        }

        let aad = match build_aad(packet) {
            Ok(aad) => aad,
            Err(error) => {
                outcome.status = DecryptionStatus::Failed;
                outcome.error = Some(format!("无法重建 AEAD AAD：{error}"));
                return outcome;
            }
        };
        let nonce = match slice_field(binary, packet.nonce_data_offset, packet.nonce_len) {
            Ok(bytes) => bytes,
            Err(error) => {
                outcome.status = DecryptionStatus::Failed;
                outcome.error = Some(error);
                return outcome;
            }
        };
        let ciphertext =
            match slice_field(binary, packet.ciphertext_data_offset, packet.ciphertext_len) {
                Ok(bytes) => bytes,
                Err(error) => {
                    outcome.status = DecryptionStatus::Failed;
                    outcome.error = Some(error);
                    return outcome;
                }
            };
        let compressed = flags & FLAG_COMPRESSED != 0;

        if packet_type == 4 {
            let Some(session_id) = &packet.session_id else {
                outcome.status = DecryptionStatus::Unsupported;
                outcome.error = Some("会话消息缺少 sessionId".to_owned());
                return outcome;
            };
            outcome.session_id = Some(session_id.clone());
            let matching: Vec<&SessionEntry> = self
                .sessions
                .iter()
                .filter(|session| session.session_id == *session_id)
                .collect();
            if matching.is_empty() {
                outcome.status = DecryptionStatus::NoKey;
                outcome.error = Some(format!(
                    "没有 sessionId 为 {session_id} 的会话密钥。请加载 Krypt04Mcg 账户目录中的 sessions/，或先在游戏中完成会话交换。"
                ));
                return outcome;
            }
            for session in matching {
                let attempt = match decrypt_with_session(
                    session, packet, nonce, &aad, ciphertext, compressed,
                ) {
                    Ok(plaintext) => {
                        outcome.status = DecryptionStatus::Decrypted;
                        outcome.key_owner = Some(session.peer.clone());
                        outcome.key_source = Some(session.source.clone());
                        outcome.key_algorithm = Some(packet.algorithms.aead.clone());
                        outcome.key_kind = Some("session_secret".to_owned());
                        outcome.attempts.push(DecryptionAttempt {
                            key_owner: session.peer.clone(),
                            key_source: session.source.clone(),
                            key_kind: "session_secret".to_owned(),
                            algorithm: packet.algorithms.aead.clone(),
                            success: true,
                            error: None,
                        });
                        finish_plaintext(&mut outcome, plaintext, compressed);
                        return outcome;
                    }
                    Err(error) => DecryptionAttempt {
                        key_owner: session.peer.clone(),
                        key_source: session.source.clone(),
                        key_kind: "session_secret".to_owned(),
                        algorithm: packet.algorithms.aead.clone(),
                        success: false,
                        error: Some(error),
                    },
                };
                outcome.attempts.push(attempt);
            }
            outcome.status = DecryptionStatus::Failed;
            outcome.error = Some("所有匹配的会话密钥都无法通过 AEAD 认证".to_owned());
            return outcome;
        }

        // A SESSION_EXCHANGE response is encapsulated to a one-time KEM key
        // that the initiator keeps only in memory, so logs normally cannot
        // contain enough information to decrypt it.
        if packet_type == 3 && flags & FLAG_SESSION_RESPONSE != 0 {
            outcome.status = DecryptionStatus::Unsupported;
            outcome.error = Some(
                "会话交换响应加密到一次性临时 KEM 公钥；私钥只存在于发起方内存中，通常无法从日志解密。"
                    .to_owned(),
            );
            return outcome;
        }

        if !is_supported_kem_label(&packet.algorithms.kem) {
            outcome.status = DecryptionStatus::Unsupported;
            outcome.error = Some(format!(
                "包使用 KEM 算法 {}，本工具暂不支持该算法（支持 ML-KEM-512/768/1024、ML-KEM-768+X25519、ML-KEM-1024+X448 与 K04-HYBRID-V1 ML-KEM+X25519/X448）",
                packet.algorithms.kem
            ));
            return outcome;
        }

        let candidates: Vec<&PrivateKeyEntry> = self
            .private_keys
            .iter()
            .filter(|key| key.owner.eq_ignore_ascii_case(&packet.receiver))
            .collect();
        if candidates.is_empty() {
            outcome.status = DecryptionStatus::NoKey;
            outcome.error = Some(format!(
                "没有 owner 为 {} 的私钥（包算法 {}，接收者 {}）",
                packet.receiver, packet.algorithms.kem, packet.receiver
            ));
            return outcome;
        }

        // Prefer keys whose algorithm matches the packet, but still try the
        // remaining owner-matched keys so a stale label cannot hide a usable
        // key. The AEAD tag remains the final authority.
        let mut ordered = candidates;
        ordered.sort_by_key(|key| !key.algorithm.eq_ignore_ascii_case(&packet.algorithms.kem));

        let kem_ciphertext = match slice_field(
            binary,
            packet.kem_ciphertext_data_offset,
            packet.kem_ciphertext_len,
        ) {
            Ok(bytes) => bytes,
            Err(error) => {
                outcome.status = DecryptionStatus::Failed;
                outcome.error = Some(error);
                return outcome;
            }
        };

        for key in ordered {
            let attempt = match decrypt_with_key(
                key,
                packet,
                nonce,
                &aad,
                kem_ciphertext,
                ciphertext,
                compressed,
            ) {
                Ok(plaintext) => {
                    outcome.status = DecryptionStatus::Decrypted;
                    outcome.key_owner = Some(key.owner.clone());
                    outcome.key_source = Some(key.source.clone());
                    outcome.key_algorithm = Some(key.algorithm.clone());
                    outcome.key_kind = Some("private_key".to_owned());
                    outcome.attempts.push(DecryptionAttempt {
                        key_owner: key.owner.clone(),
                        key_source: key.source.clone(),
                        key_kind: "private_key".to_owned(),
                        algorithm: key.algorithm.clone(),
                        success: true,
                        error: None,
                    });
                    finish_plaintext(&mut outcome, plaintext, compressed);
                    return outcome;
                }
                Err(error) => DecryptionAttempt {
                    key_owner: key.owner.clone(),
                    key_source: key.source.clone(),
                    key_kind: "private_key".to_owned(),
                    algorithm: key.algorithm.clone(),
                    success: false,
                    error: Some(error),
                },
            };
            outcome.attempts.push(attempt);
        }

        let unsupported = outcome.attempts.iter().all(|attempt| {
            attempt
                .error
                .as_deref()
                .is_some_and(|error| error.contains("暂不支持") || error.contains("不支持的 KEM"))
        });
        outcome.status = if unsupported {
            DecryptionStatus::Unsupported
        } else {
            DecryptionStatus::Failed
        };
        outcome.error = Some(if unsupported {
            format!(
                "包使用 {}，当前没有可解封装该算法的私钥实现",
                packet.algorithms.kem
            )
        } else {
            "已用全部匹配私钥尝试，KEM 解封装或 AEAD 认证失败".to_owned()
        });
        outcome
    }
}

fn decrypt_with_key(
    key: &PrivateKeyEntry,
    packet: &ParsedPacket,
    nonce: &[u8],
    aad: &[u8],
    kem_ciphertext: &[u8],
    ciphertext: &[u8],
    compressed: bool,
) -> Result<Vec<u8>, String> {
    let shared = key.kem.decapsulate(kem_ciphertext)?;
    let message_id = decode_hex(&packet.message_id_hex)?;
    if message_id.len() != 16 {
        return Err(format!(
            "messageId 长度为 {}，预期 16 字节",
            message_id.len()
        ));
    }
    let derived = hkdf_sha256(&shared, Some(&message_id), b"krypt04mcg message aead")?;
    let plaintext = aead_decrypt(&packet.algorithms.aead, &derived, nonce, aad, ciphertext)?;
    maybe_inflate(plaintext, compressed)
}

fn decrypt_with_session(
    session: &SessionEntry,
    packet: &ParsedPacket,
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    compressed: bool,
) -> Result<Vec<u8>, String> {
    let message_id = decode_hex(&packet.message_id_hex)?;
    if message_id.len() != 16 {
        return Err(format!(
            "messageId 长度为 {}，预期 16 字节",
            message_id.len()
        ));
    }
    let derived = hkdf_sha256(&session.secret, Some(&message_id), b"krypt04mcg session")?;
    let plaintext = aead_decrypt(&packet.algorithms.aead, &derived, nonce, aad, ciphertext)?;
    maybe_inflate(plaintext, compressed)
}

fn finish_plaintext(outcome: &mut DecryptionOutcome, bytes: Vec<u8>, compressed: bool) {
    outcome.compressed = compressed;
    outcome.plaintext_length = bytes.len();
    outcome.plaintext_hex = Some(hex(&bytes));
    outcome.plaintext_base64url =
        Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes));
    if let Ok(text) = std::str::from_utf8(&bytes) {
        let text = text.to_owned();
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&text)
            && (json.is_object() || json.is_array())
        {
            outcome.json = Some(json);
        }
        outcome.plaintext = Some(text);
    }
    outcome.plaintext_bytes = bytes;
}

fn slice_field(binary: &[u8], offset: usize, length: usize) -> Result<&[u8], String> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| "字段偏移溢出".to_owned())?;
    binary
        .get(offset..end)
        .ok_or_else(|| format!("字段范围 {offset}..{end} 超出二进制长度 {}", binary.len()))
}

// ---------------------------------------------------------------------------
// AAD reconstruction (PacketCodec.aadFor)
// ---------------------------------------------------------------------------

pub(crate) fn build_aad(packet: &ParsedPacket) -> Result<Vec<u8>, String> {
    let version = packet
        .protocol_version
        .ok_or_else(|| "缺少协议版本".to_owned())?;
    let packet_type = packet.packet_type.ok_or_else(|| "缺少包类型".to_owned())?;
    let flags = packet.flags.ok_or_else(|| "缺少标志位".to_owned())?;
    let timestamp = packet
        .timestamp_millis
        .ok_or_else(|| "缺少时间戳".to_owned())?;

    let mut out = Vec::new();
    out.push(version);
    out.push(packet_type);
    out.push(flags);
    push_string(&mut out, &packet.sender);
    push_string(&mut out, &packet.receiver);
    if version >= 3 {
        out.extend_from_slice(&timestamp.to_be_bytes());
    }
    let message_id = decode_hex(&packet.message_id_hex)?;
    if message_id.len() != 16 {
        return Err(format!(
            "messageId 长度为 {}，预期 16 字节",
            message_id.len()
        ));
    }
    out.extend_from_slice(&message_id);

    let session_v4 = version >= 4 && packet_type == 4;
    if session_v4 {
        let session_id = packet
            .session_id
            .as_deref()
            .ok_or_else(|| "会话消息缺少 sessionId".to_owned())?;
        push_string(&mut out, session_id);
        let sequence = packet
            .sequence
            .ok_or_else(|| "会话消息缺少 sequence".to_owned())?;
        out.extend_from_slice(&sequence.to_be_bytes());
    }
    if version < 3 {
        let index = packet
            .aad_fragment_index
            .ok_or_else(|| "旧版包缺少 AAD 分片索引".to_owned())?;
        let total = packet
            .aad_fragment_total
            .ok_or_else(|| "旧版包缺少 AAD 分片总数".to_owned())?;
        out.extend_from_slice(&index.to_be_bytes());
        out.extend_from_slice(&total.to_be_bytes());
    }
    if version < 3 || packet_type != 4 {
        push_string(&mut out, &packet.algorithms.kem);
    }
    if version < 3 || flags & FLAG_SIGNED != 0 {
        push_string(&mut out, &packet.algorithms.signature);
    }
    push_string(&mut out, &packet.algorithms.aead);
    if version >= 2 {
        push_string(&mut out, &packet.algorithms.hkdf);
    }
    Ok(out)
}

fn push_string(out: &mut Vec<u8>, value: &str) {
    let bytes = value.as_bytes();
    let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn decode_hex(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("十六进制字符串长度为奇数".to_owned());
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    let bytes = text.as_bytes();
    for pair in bytes.as_chunks::<2>().0 {
        let high = hex_digit(pair[0]).ok_or_else(|| "十六进制字符无效".to_owned())?;
        let low = hex_digit(pair[1]).ok_or_else(|| "十六进制字符无效".to_owned())?;
        out.push(high << 4 | low);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// AEAD / HKDF / compression
// ---------------------------------------------------------------------------

fn hkdf_sha256(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> Result<[u8; 32], String> {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut output = [0u8; 32];
    hkdf.expand(info, &mut output)
        .map_err(|_| "HKDF-SHA256 扩展失败".to_owned())?;
    Ok(output)
}

fn aead_decrypt(
    algorithm: &str,
    key: &[u8],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, String> {
    let normalized = algorithm.trim().to_ascii_uppercase();
    if key.len() != 32 {
        return Err(format!("AEAD 密钥长度为 {}，预期 32 字节", key.len()));
    }
    match normalized.as_str() {
        "AES-256-GCM" | "AES256-GCM" => {
            if nonce.len() != 12 {
                return Err(format!("AES-256-GCM nonce 长度为 {}，预期 12", nonce.len()));
            }
            let cipher =
                Aes256Gcm::new_from_slice(key).map_err(|_| "无法初始化 AES-256-GCM".to_owned())?;
            let nonce = Nonce::<Aes256Gcm>::try_from(nonce)
                .map_err(|_| "AES-256-GCM nonce 长度无效".to_owned())?;
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| "AES-256-GCM 认证失败（密钥不匹配、AAD 不同或密文被篡改）".to_owned())
        }
        "CHACHA20-POLY1305" | "CHACHA20POLY1305" => {
            if nonce.len() != 12 {
                return Err(format!(
                    "ChaCha20-Poly1305 nonce 长度为 {}，预期 12",
                    nonce.len()
                ));
            }
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| "无法初始化 ChaCha20-Poly1305".to_owned())?;
            let nonce = Nonce::<ChaCha20Poly1305>::try_from(nonce)
                .map_err(|_| "ChaCha20-Poly1305 nonce 长度无效".to_owned())?;
            cipher
                .decrypt(
                    &nonce,
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| {
                    "ChaCha20-Poly1305 认证失败（密钥不匹配、AAD 不同或密文被篡改）".to_owned()
                })
        }
        other => Err(format!("暂不支持 AEAD 算法：{other}")),
    }
}

fn maybe_inflate(plaintext: Vec<u8>, compressed: bool) -> Result<Vec<u8>, String> {
    if !compressed {
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err("明文超过大小上限".to_owned());
        }
        return Ok(plaintext);
    }
    // Raw DEFLATE (Java `new Inflater(true)`), with bounded output and the
    // same trailing-byte rejection as Krypt04Mcg's inflate().
    let mut decompressor = flate2::Decompress::new(false);
    let mut output = Vec::new();
    let mut buffer = [0u8; 8192];
    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let status = decompressor
            .decompress(
                &plaintext[before_in as usize..],
                &mut buffer,
                flate2::FlushDecompress::Finish,
            )
            .map_err(|error| format!("DEFLATE 解压失败：{error}"))?;
        let produced = (decompressor.total_out() - before_out) as usize;
        if produced > 0 {
            if output.len() + produced > MAX_PLAINTEXT_BYTES {
                return Err(format!("解压后的明文超过 {} 字节上限", MAX_PLAINTEXT_BYTES));
            }
            output.extend_from_slice(&buffer[..produced]);
        }
        match status {
            flate2::Status::StreamEnd => break,
            flate2::Status::Ok | flate2::Status::BufError => {
                if decompressor.total_in() == before_in && produced == 0 {
                    return Err("压缩数据被截断或不完整".to_owned());
                }
            }
        }
    }
    if decompressor.total_in() != plaintext.len() as u64 {
        return Err(format!(
            "压缩数据有 {} 个尾随字节",
            plaintext.len() as u64 - decompressor.total_in()
        ));
    }
    Ok(output)
}

// ---------------------------------------------------------------------------
// KEM private key parsing and decapsulation
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MlKemLevel {
    K512,
    K768,
    K1024,
}

impl MlKemLevel {
    fn from_oid(oid: &str) -> Option<Self> {
        match oid {
            OID_ML_KEM_512 => Some(Self::K512),
            OID_ML_KEM_768 => Some(Self::K768),
            OID_ML_KEM_1024 => Some(Self::K1024),
            _ => None,
        }
    }

    fn identifier(self) -> &'static str {
        match self {
            Self::K512 => "ML-KEM-512",
            Self::K768 => "ML-KEM-768",
            Self::K1024 => "ML-KEM-1024",
        }
    }

    fn ciphertext_len(self) -> usize {
        match self {
            Self::K512 => 768,
            Self::K768 => 1088,
            Self::K1024 => 1568,
        }
    }

    fn decapsulate(self, seed: &[u8; 64], ciphertext: &[u8]) -> Result<[u8; 32], String> {
        if ciphertext.len() != self.ciphertext_len() {
            return Err(format!(
                "{} 密文长度为 {}，预期 {}",
                self.identifier(),
                ciphertext.len(),
                self.ciphertext_len()
            ));
        }
        match self {
            Self::K512 => {
                let key = ml_kem::DecapsulationKey::<MlKem512>::from_seed(seed_array(seed)?);
                let shared = key
                    .decapsulate_slice(ciphertext)
                    .map_err(|error| format!("ML-KEM-512 解封装失败：{error}"))?;
                to_shared_key(shared.as_slice())
            }
            Self::K768 => {
                let key = ml_kem::DecapsulationKey::<MlKem768>::from_seed(seed_array(seed)?);
                let shared = key
                    .decapsulate_slice(ciphertext)
                    .map_err(|error| format!("ML-KEM-768 解封装失败：{error}"))?;
                to_shared_key(shared.as_slice())
            }
            Self::K1024 => {
                let key = ml_kem::DecapsulationKey::<MlKem1024>::from_seed(seed_array(seed)?);
                let shared = key
                    .decapsulate_slice(ciphertext)
                    .map_err(|error| format!("ML-KEM-1024 解封装失败：{error}"))?;
                to_shared_key(shared.as_slice())
            }
        }
    }
}

fn seed_array(seed: &[u8; 64]) -> Result<ml_kem::Seed, String> {
    ml_kem::Seed::try_from(seed.as_slice()).map_err(|_| "ML-KEM 种子长度无效".to_owned())
}

fn to_shared_key(bytes: &[u8]) -> Result<[u8; 32], String> {
    <[u8; 32]>::try_from(bytes).map_err(|_| "KEM 共享密钥长度不是 32 字节".to_owned())
}

#[derive(Clone, Debug)]
enum ClassicalPrivate {
    X25519([u8; 32]),
    X448([u8; 56]),
}

impl ClassicalPrivate {
    fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        match bytes.len() {
            32 => Ok(Self::X25519(
                bytes.try_into().expect("checked 32-byte length"),
            )),
            56 => Ok(Self::X448(
                bytes.try_into().expect("checked 56-byte length"),
            )),
            other => Err(format!(
                "经典 KEM 私钥长度为 {other}，当前只支持 X25519 (32) / X448 (56)"
            )),
        }
    }

    fn algorithm(&self) -> &'static str {
        match self {
            Self::X25519(_) => "X25519",
            Self::X448(_) => "X448",
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::X25519(_) => 32,
            Self::X448(_) => 56,
        }
    }

    /// Returns `(shared_secret, recipient_public_key)`.
    fn agree(&self, peer_public: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
        match self {
            Self::X25519(secret) => {
                let peer: [u8; 32] = peer_public
                    .try_into()
                    .map_err(|_| "X25519 公钥长度不是 32 字节".to_owned())?;
                let secret = X25519StaticSecret::from(*secret);
                let public = X25519PublicKey::from(&secret);
                let shared = secret.diffie_hellman(&X25519PublicKey::from(peer));
                if !shared.was_contributory() {
                    return Err("X25519 协商结果为全零（低阶公钥）".to_owned());
                }
                Ok((shared.as_bytes().to_vec(), public.to_bytes().to_vec()))
            }
            Self::X448(secret) => {
                let secret = x448::Secret::from_bytes(secret)
                    .ok_or_else(|| "X448 私钥长度无效".to_owned())?;
                let public = x448::PublicKey::from(&secret);
                let peer = x448::PublicKey::from_bytes(peer_public)
                    .ok_or_else(|| "X448 公钥无效或为低阶点".to_owned())?;
                let shared = secret
                    .as_diffie_hellman(&peer)
                    .ok_or_else(|| "X448 协商失败（低阶公钥）".to_owned())?;
                Ok((shared.as_bytes().to_vec(), public.as_bytes().to_vec()))
            }
        }
    }
}

enum KemPrivateKey {
    Bare {
        level: MlKemLevel,
        seed: [u8; 64],
    },
    /// Bouncy Castle native composite KEM (SHA3-256 combiner):
    /// ML-KEM-768+X25519 or ML-KEM-1024+X448.
    NativeComposite {
        name: String,
        level: MlKemLevel,
        seed: [u8; 64],
        classical: ClassicalPrivate,
        label: Vec<u8>,
    },
    /// Krypt04Mcg's own `K04-HYBRID-V1` frame with ML-KEM + X25519/X448.
    CustomHybrid {
        name: String,
        label: String,
        pq: Box<KemPrivateKey>,
        classical: ClassicalPrivate,
        pq_public_spki: Vec<u8>,
    },
}

impl KemPrivateKey {
    fn decapsulate(&self, ciphertext: &[u8]) -> Result<[u8; 32], String> {
        match self {
            Self::Bare { level, seed } => level.decapsulate(seed, ciphertext),
            Self::NativeComposite {
                name,
                level,
                seed,
                classical,
                label,
            } => {
                let ml_len = level.ciphertext_len();
                let classical_len = classical.len();
                if ciphertext.len() != ml_len + classical_len {
                    return Err(format!(
                        "{name} 密文长度为 {}，预期 {}",
                        ciphertext.len(),
                        ml_len + classical_len
                    ));
                }
                let mlkem_ciphertext = &ciphertext[..ml_len];
                let classical_ciphertext = &ciphertext[ml_len..];
                let mlkem_shared = level.decapsulate(seed, mlkem_ciphertext)?;
                let (classical_shared, classical_public) = classical.agree(classical_ciphertext)?;
                let mut digest = Sha3_256::new();
                digest.update(mlkem_shared);
                digest.update(&classical_shared);
                digest.update(classical_ciphertext);
                digest.update(&classical_public);
                digest.update(label);
                to_shared_key(digest.finalize().as_slice())
            }
            Self::CustomHybrid {
                name,
                label,
                pq,
                classical,
                pq_public_spki,
            } => {
                let parts = split_frame(ciphertext, 2)?;
                let (pq_ciphertext, classical_ciphertext) = (parts[0], parts[1]);
                if classical_ciphertext.len() != classical.len() {
                    return Err(format!(
                        "{name} 经典密文长度为 {}，预期 {}",
                        classical_ciphertext.len(),
                        classical.len()
                    ));
                }
                let mlkem_shared = pq.decapsulate(pq_ciphertext)?;
                let (classical_shared, classical_public) = classical.agree(classical_ciphertext)?;
                let recipient_public =
                    frame(&[pq_public_spki.as_slice(), classical_public.as_slice()]);
                let context = frame(&[label.as_bytes(), ciphertext, recipient_public.as_slice()]);
                let mut ikm = Vec::with_capacity(mlkem_shared.len() + classical_shared.len());
                ikm.extend_from_slice(&mlkem_shared);
                ikm.extend_from_slice(&classical_shared);
                hkdf_sha256(&ikm, None, &context)
            }
        }
    }
}

fn parse_kem_private(algorithm: &str, key_data: &[u8]) -> Result<KemPrivateKey, String> {
    if key_data.starts_with(&HYBRID_MAGIC.to_be_bytes()) {
        return parse_custom_hybrid(algorithm, key_data);
    }

    let (oid, body) = pkcs8_extract(key_data)?;
    if let Some(level) = MlKemLevel::from_oid(&oid) {
        let expected = level.identifier();
        if !algorithm.eq_ignore_ascii_case(expected) {
            return Err(format!("密钥编码是 {expected}，但记录声明为 {algorithm}"));
        }
        let seed = bare_mlkem_seed(body)?;
        return Ok(KemPrivateKey::Bare { level, seed });
    }
    if oid == OID_MLKEM768_X25519 {
        return parse_native_composite(
            algorithm,
            body,
            "ML-KEM-768+X25519",
            MlKemLevel::K768,
            &COMPOSITE_768_X25519_LABEL,
        );
    }
    if oid == OID_MLKEM1024_X448 {
        return parse_native_composite(
            algorithm,
            body,
            "ML-KEM-1024+X448",
            MlKemLevel::K1024,
            COMPOSITE_1024_X448_LABEL,
        );
    }
    Err(format!(
        "OID {oid} 不是本工具支持的 ML-KEM 私钥（支持 ML-KEM-512/768/1024、ML-KEM-768+X25519、ML-KEM-1024+X448 与 K04-HYBRID-V1 混合密钥）"
    ))
}

fn parse_native_composite(
    algorithm: &str,
    body: &[u8],
    name: &str,
    level: MlKemLevel,
    label: &[u8],
) -> Result<KemPrivateKey, String> {
    if !algorithm.eq_ignore_ascii_case(name) {
        return Err(format!("密钥编码是 {name}，但记录声明为 {algorithm}"));
    }
    if body.len() <= 64 {
        return Err(format!(
            "{name} 私钥正文长度为 {}，至少需要 64 字节 ML-KEM 种子",
            body.len()
        ));
    }
    let mut seed = [0u8; 64];
    seed.copy_from_slice(&body[..64]);
    let classical = ClassicalPrivate::from_bytes(&body[64..])?;
    let expected_classical = if name.ends_with("X25519") {
        "X25519"
    } else {
        "X448"
    };
    if classical.algorithm() != expected_classical {
        return Err(format!(
            "{name} 的经典私钥长度为 {}，预期 {expected_classical}",
            body.len() - 64
        ));
    }
    Ok(KemPrivateKey::NativeComposite {
        name: name.to_owned(),
        level,
        seed,
        classical,
        label: label.to_vec(),
    })
}

fn parse_custom_hybrid(algorithm: &str, key_data: &[u8]) -> Result<KemPrivateKey, String> {
    let parts = split_frame(key_data, 3)?;
    let (pq_private, classical_private, pq_public) = (parts[0], parts[1], parts[2]);
    let (oid, body) = pkcs8_extract(pq_private)?;
    let Some(level) = MlKemLevel::from_oid(&oid) else {
        return Err(format!("混合密钥的 PQ 组件 OID {oid} 不受支持"));
    };
    let seed = bare_mlkem_seed(body)?;
    let classical = ClassicalPrivate::from_bytes(classical_private)?;
    let expected = format!("{}+{}", level.identifier(), classical.algorithm());
    if !algorithm.eq_ignore_ascii_case(&expected) {
        return Err(format!(
            "混合密钥编码是 {expected}，但记录声明为 {algorithm}"
        ));
    }
    Ok(KemPrivateKey::CustomHybrid {
        name: algorithm.to_owned(),
        label: format!("krypt04mcg hybrid kem v1 {algorithm}"),
        pq: Box::new(KemPrivateKey::Bare { level, seed }),
        classical,
        pq_public_spki: pq_public.to_vec(),
    })
}

fn bare_mlkem_seed(body: &[u8]) -> Result<[u8; 64], String> {
    // The PKCS#8 privateKey OCTET STRING for bare ML-KEM wraps a DER SEQUENCE
    // whose first OCTET STRING is the 64-byte FIPS 203 seed. Accept a directly
    // encoded 64-byte seed as well for exported raw material.
    let seed_bytes = if body.len() == 64 {
        body
    } else {
        let mut reader = DerReader::new(body);
        let (tag, sequence) = reader.read_tlv()?;
        if tag != 0x30 {
            return Err(format!(
                "ML-KEM 私钥正文首标签为 0x{tag:02x}，预期 SEQUENCE"
            ));
        }
        let mut sequence = DerReader::new(sequence);
        let (tag, seed) = sequence.read_tlv()?;
        if tag != 0x04 {
            return Err(format!(
                "ML-KEM 私钥种子标签为 0x{tag:02x}，预期 OCTET STRING"
            ));
        }
        seed
    };
    <[u8; 64]>::try_from(seed_bytes)
        .map_err(|_| format!("ML-KEM 私钥种子长度为 {}，预期 64 字节", seed_bytes.len()))
}

fn split_frame(data: &[u8], count: usize) -> Result<Vec<&[u8]>, String> {
    if data.len() < 4 + count * 4 {
        return Err("K04-HYBRID-V1 帧过短".to_owned());
    }
    let magic = u32::from_be_bytes(data[0..4].try_into().expect("4 bytes"));
    if magic != HYBRID_MAGIC {
        return Err(format!("K04-HYBRID-V1 magic 无效：0x{magic:08x}"));
    }
    let mut offset = 4;
    let mut parts = Vec::with_capacity(count);
    for _ in 0..count {
        let length_bytes = data
            .get(offset..offset + 4)
            .ok_or_else(|| "K04-HYBRID-V1 长度字段被截断".to_owned())?;
        offset += 4;
        let length = u32::from_be_bytes(length_bytes.try_into().expect("4 bytes")) as usize;
        if length == 0 || length > HYBRID_MAX_COMPONENT {
            return Err(format!("K04-HYBRID-V1 组件长度无效：{length}"));
        }
        let end = offset
            .checked_add(length)
            .ok_or_else(|| "K04-HYBRID-V1 组件长度溢出".to_owned())?;
        let part = data
            .get(offset..end)
            .ok_or_else(|| "K04-HYBRID-V1 组件被截断".to_owned())?;
        parts.push(part);
        offset = end;
    }
    if offset != data.len() {
        return Err(format!(
            "K04-HYBRID-V1 帧有 {} 个尾随字节",
            data.len() - offset
        ));
    }
    Ok(parts)
}

fn frame(components: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&HYBRID_MAGIC.to_be_bytes());
    for component in components {
        out.extend_from_slice(&(component.len() as u32).to_be_bytes());
        out.extend_from_slice(component);
    }
    out
}

// ---------------------------------------------------------------------------
// Minimal DER parsing (PKCS#8)
// ---------------------------------------------------------------------------

fn pkcs8_extract(der: &[u8]) -> Result<(String, &[u8]), String> {
    let mut outer = DerReader::new(der);
    let (tag, sequence) = outer.read_tlv()?;
    if tag != 0x30 {
        return Err(format!("PKCS#8 首标签为 0x{tag:02x}，预期 SEQUENCE"));
    }
    let mut sequence = DerReader::new(sequence);
    let (tag, _version) = sequence.read_tlv()?;
    if tag != 0x02 {
        return Err(format!("PKCS#8 版本标签为 0x{tag:02x}，预期 INTEGER"));
    }
    let (tag, algorithm) = sequence.read_tlv()?;
    if tag != 0x30 {
        return Err(format!("PKCS#8 算法标签为 0x{tag:02x}，预期 SEQUENCE"));
    }
    let (tag, private_key) = sequence.read_tlv()?;
    if tag != 0x04 {
        return Err(format!("PKCS#8 私钥标签为 0x{tag:02x}，预期 OCTET STRING"));
    }
    let mut algorithm = DerReader::new(algorithm);
    let (tag, oid) = algorithm.read_tlv()?;
    if tag != 0x06 {
        return Err(format!(
            "算法 OID 标签为 0x{tag:02x}，预期 OBJECT IDENTIFIER"
        ));
    }
    Ok((oid_to_string(oid), private_key))
}

struct DerReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_tlv(&mut self) -> Result<(u8, &'a [u8]), String> {
        let tag = *self
            .data
            .get(self.pos)
            .ok_or_else(|| "DER 数据被截断（缺少标签）".to_owned())?;
        self.pos += 1;
        let first = *self
            .data
            .get(self.pos)
            .ok_or_else(|| "DER 数据被截断（缺少长度）".to_owned())?;
        self.pos += 1;
        let length = if first & 0x80 == 0 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 || count > 8 {
                return Err(format!("DER 长度编码无效（{count} 字节）"));
            }
            let length_bytes = self
                .data
                .get(self.pos..self.pos + count)
                .ok_or_else(|| "DER 长度字段被截断".to_owned())?;
            self.pos += count;
            let mut length = 0usize;
            for byte in length_bytes {
                length = length
                    .checked_mul(256)
                    .and_then(|value| value.checked_add(*byte as usize))
                    .ok_or_else(|| "DER 长度溢出".to_owned())?;
            }
            length
        };
        let end = self
            .pos
            .checked_add(length)
            .ok_or_else(|| "DER 长度溢出".to_owned())?;
        let value = self
            .data
            .get(self.pos..end)
            .ok_or_else(|| "DER 数据被截断（长度超出输入）".to_owned())?;
        self.pos = end;
        Ok((tag, value))
    }
}

fn oid_to_string(oid: &[u8]) -> String {
    let Some(first) = oid.first() else {
        return String::new();
    };
    let mut parts = vec![(u64::from(*first)) / 40, (u64::from(*first)) % 40];
    let mut value: u64 = 0;
    for byte in &oid[1..] {
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            parts.push(value);
            value = 0;
        }
    }
    parts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(".")
}

// ---------------------------------------------------------------------------
// Key file helpers
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
struct KeyRecordJson {
    #[serde(default)]
    algorithm: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    uuid: String,
    #[serde(default)]
    fingerprint: String,
    #[serde(default, rename = "createdAt")]
    _created_at: Option<serde_json::Value>,
    #[serde(default, rename = "keyData")]
    key_data: String,
}

#[derive(Clone, Debug, Deserialize)]
struct SessionRecordJson {
    #[serde(default)]
    peer: Option<String>,
    #[serde(default, rename = "sessionId")]
    session_id: Option<String>,
    #[serde(default)]
    secret: Option<String>,
}

fn strip_role(algorithm: &str) -> &str {
    let trimmed = algorithm.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.ends_with("/private") {
        &trimmed[..trimmed.len() - "/private".len()]
    } else if lower.ends_with("/public") {
        &trimmed[..trimmed.len() - "/public".len()]
    } else {
        trimmed
    }
}

fn looks_like_kem_algorithm(algorithm: &str) -> bool {
    let upper = algorithm.to_ascii_uppercase();
    upper.starts_with("ML-KEM")
        || upper.starts_with("CMCE/")
        || upper.starts_with("HQC/")
        || upper.starts_with("NTRULPRIME/")
        || upper.starts_with("SNTRUPRIME/")
}

/// Algorithms this build can decapsulate. Keep in sync with
/// `parse_kem_private`.
fn is_supported_kem_label(algorithm: &str) -> bool {
    matches!(
        algorithm.trim().to_ascii_uppercase().as_str(),
        "ML-KEM-512"
            | "ML-KEM-768"
            | "ML-KEM-1024"
            | "ML-KEM-512+X25519"
            | "ML-KEM-768+X25519"
            | "ML-KEM-1024+X25519"
            | "ML-KEM-512+X448"
            | "ML-KEM-768+X448"
            | "ML-KEM-1024+X448"
    )
}

fn decode_base64url(text: &str) -> Result<Vec<u8>, String> {
    let trimmed = text.trim();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .map_err(|error| error.to_string())
}

fn read_sensitive_text(path: &Path) -> Result<String, String> {
    let bytes = fs::read(path).map_err(|error| format!("无法读取：{error}"))?;
    if bytes.starts_with(SENSITIVE_FILE_MAGIC) {
        let plaintext = decrypt_sensitive_file(path, &bytes)?;
        return String::from_utf8(plaintext).map_err(|_| "解密后的文件不是 UTF-8".to_owned());
    }
    String::from_utf8(bytes).map_err(|_| "文件不是 UTF-8 文本或 KMCGSEC1 加密格式".to_owned())
}

fn decrypt_sensitive_file(path: &Path, data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < SENSITIVE_FILE_MAGIC.len() + 12 + 16 {
        return Err("KMCGSEC1 加密文件被截断".to_owned());
    }
    let nonce = &data[SENSITIVE_FILE_MAGIC.len()..SENSITIVE_FILE_MAGIC.len() + 12];
    let ciphertext = &data[SENSITIVE_FILE_MAGIC.len() + 12..];
    let roots = account_roots(path);
    if roots.is_empty() {
        return Err(
            "文件已用 KMCGSEC1 加密，但找不到包含 secrets/master.key 的账户目录".to_owned(),
        );
    }
    let mut last_error = String::new();
    for root in roots {
        let master_key = match read_master_key(&root.join("secrets").join("master.key")) {
            Ok(key) => key,
            Err(error) => {
                last_error = error;
                continue;
            }
        };
        let Ok(relative) = path.strip_prefix(&root) else {
            continue;
        };
        let aad = relative.to_string_lossy().replace('\\', "/");
        let cipher = match Aes256Gcm::new_from_slice(&master_key) {
            Ok(cipher) => cipher,
            Err(_) => continue,
        };
        let nonce = match Nonce::<Aes256Gcm>::try_from(nonce) {
            Ok(nonce) => nonce,
            Err(_) => continue,
        };
        match cipher.decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: aad.as_bytes(),
            },
        ) {
            Ok(plaintext) => return Ok(plaintext),
            Err(_) => {
                last_error = format!(
                    "无法用 {} 的 master.key 认证该文件（AAD 路径为 {aad}）",
                    root.display()
                );
            }
        }
    }
    Err(if last_error.is_empty() {
        "KMCGSEC1 解密失败".to_owned()
    } else {
        last_error
    })
}

fn read_master_key(path: &Path) -> Result<[u8; 32], String> {
    let data = fs::read(path).map_err(|error| format!("无法读取 {}：{error}", path.display()))?;
    if data.len() < MASTER_KEY_MAGIC.len() + 2 || !data.starts_with(MASTER_KEY_MAGIC) {
        return Err(format!("{} 不是有效的 master.key", path.display()));
    }
    let mode = data[MASTER_KEY_MAGIC.len()];
    match mode {
        2 => {
            let key_bytes = &data[MASTER_KEY_MAGIC.len() + 1..];
            <[u8; 32]>::try_from(key_bytes).map_err(|_| {
                format!(
                    "{} 的主密钥长度为 {}，预期 32 字节",
                    path.display(),
                    key_bytes.len()
                )
            })
        }
        1 => {
            let protected = &data[MASTER_KEY_MAGIC.len() + 1..];
            dpapi_unprotect(protected).map_err(|error| format!("{}：{error}", path.display()))
        }
        other => Err(format!("不支持的 master.key 保护模式：{other}")),
    }
}

#[cfg(windows)]
const DPAPI_ENTROPY: &[u8] = b"Krypt04Mcg local storage v1";

/// Unwraps the per-user DPAPI blob stored in a mode-1 `master.key`.
/// The blob is bound to the Windows user profile that created it (the
/// reference implementation does not use `CRYPTPROTECT_LOCAL_MACHINE`).
#[cfg(windows)]
fn dpapi_unprotect(protected: &[u8]) -> Result<[u8; 32], String> {
    use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
    use windows_sys::Win32::Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptUnprotectData,
    };

    let input = CRYPT_INTEGER_BLOB {
        cbData: protected.len() as u32,
        pbData: protected.as_ptr() as *mut u8,
    };
    let entropy = CRYPT_INTEGER_BLOB {
        cbData: DPAPI_ENTROPY.len() as u32,
        pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB::default();

    let ok = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            std::ptr::null(),
            std::ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if ok == 0 {
        let code = unsafe { GetLastError() };
        return Err(format!(
            "DPAPI 解包失败（GetLastError=0x{code:08X}）；请确认以创建该 master.key 的 Windows 用户运行"
        ));
    }
    if output.pbData.is_null() {
        return Err("DPAPI 返回了空数据".to_owned());
    }
    let bytes =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(output.pbData as _);
    }
    <[u8; 32]>::try_from(bytes.as_slice())
        .map_err(|_| format!("DPAPI 解包后的主密钥长度为 {}，预期 32 字节", bytes.len()))
}

#[cfg(not(windows))]
fn dpapi_unprotect(_protected: &[u8]) -> Result<[u8; 32], String> {
    Err(
        "master.key 使用 Windows DPAPI 保护，只能在创建它的 Windows 用户下解密；在 Linux/macOS 上请导出明文 LocalKeyMaterial 或使用 owner-only（模式 2）主密钥"
            .to_owned(),
    )
}

/// Returns ancestor directories that look like Krypt04Mcg account roots,
/// nearest first.
fn account_roots(path: &Path) -> Vec<PathBuf> {
    let start = if path.is_dir() {
        path.to_path_buf()
    } else {
        match path.parent() {
            Some(parent) => parent.to_path_buf(),
            None => return Vec::new(),
        }
    };
    start
        .ancestors()
        .filter(|ancestor| ancestor.join("secrets").join("master.key").is_file())
        .map(Path::to_path_buf)
        .collect()
}

fn find_account_roots(root: &Path) -> Vec<PathBuf> {
    fn walk(directory: &Path, depth: usize, out: &mut Vec<PathBuf>) {
        if depth > 6 || out.len() >= 64 {
            return;
        }
        if directory
            .join("keys")
            .join("private")
            .join("local.json")
            .is_file()
            || (directory.join("secrets").join("master.key").is_file()
                && directory.join("sessions").is_dir())
        {
            out.push(directory.to_path_buf());
            return;
        }
        let Ok(entries) = fs::read_dir(directory) else {
            return;
        };
        let mut children: Vec<PathBuf> = entries
            .flatten()
            .filter_map(|entry| {
                let file_type = entry.file_type().ok()?;
                if !file_type.is_dir() {
                    return None;
                }
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.starts_with('.')
                    || matches!(
                        name.as_ref(),
                        "logs"
                            | "target"
                            | "build"
                            | "node_modules"
                            | ".gradle"
                            | "mods"
                            | "saves"
                            | "libraries"
                            | "versions"
                            | "assets"
                            | "crash-reports"
                            | "screenshots"
                    )
                {
                    return None;
                }
                Some(entry.path())
            })
            .collect();
        children.sort();
        for child in children {
            walk(&child, depth + 1, out);
        }
    }

    let mut roots = Vec::new();
    walk(root, 0, &mut roots);
    roots
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_oid_strings() {
        assert_eq!(
            oid_to_string(&[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02]),
            OID_ML_KEM_768
        );
        assert_eq!(
            oid_to_string(&[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x06, 0x3a]),
            OID_MLKEM768_X25519
        );
    }

    #[test]
    fn hybrid_frame_round_trip() {
        let encoded = frame(&[b"abc", b"defgh"]);
        let parts = split_frame(&encoded, 2).unwrap();
        assert_eq!(parts, vec![&b"abc"[..], &b"defgh"[..]]);
    }

    #[test]
    fn aad_strings_use_u16_lengths() {
        let mut out = Vec::new();
        push_string(&mut out, "tester");
        assert_eq!(out, b"\x00\x06tester");
    }

    #[test]
    fn inflates_raw_deflate_and_rejects_trailing_bytes() {
        use std::io::Write as _;

        let mut encoder =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(b"raw deflate payload").unwrap();
        let compressed = encoder.finish().unwrap();
        assert_eq!(
            maybe_inflate(compressed.clone(), true).unwrap(),
            b"raw deflate payload"
        );

        let mut with_trailing = compressed;
        with_trailing.push(0);
        assert!(maybe_inflate(with_trailing, true).is_err());

        assert!(maybe_inflate(b"hello".to_vec(), true).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_protected_master_key_and_kmcg_round_trip() {
        use aes_gcm::Aes256Gcm;
        use aes_gcm::aead::{Aead, KeyInit, Nonce, Payload};

        let key = [0x5Au8; 32];
        let protected = dpapi_protect_for_test(&key).unwrap();

        let root =
            std::env::temp_dir().join(format!("k04m-log-parser-dpapi-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("secrets")).unwrap();
        fs::create_dir_all(root.join("keys").join("private")).unwrap();

        let mut master_bytes = Vec::new();
        master_bytes.extend_from_slice(MASTER_KEY_MAGIC);
        master_bytes.push(1);
        master_bytes.extend_from_slice(&protected);
        let master_path = root.join("secrets").join("master.key");
        fs::write(&master_path, master_bytes).unwrap();
        assert_eq!(read_master_key(&master_path).unwrap(), key);

        // Verify that a KMCGSEC1 file encrypted under the recovered master key
        // also unprotects with the account-relative path as AAD.
        let plaintext = r#"{"test":"dpapi"}"#;
        let nonce_bytes = [0x42u8; 12];
        let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
        let nonce = Nonce::<Aes256Gcm>::try_from(&nonce_bytes[..]).unwrap();
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext.as_bytes(),
                    aad: b"keys/private/local.json",
                },
            )
            .unwrap();
        let mut envelope = Vec::new();
        envelope.extend_from_slice(SENSITIVE_FILE_MAGIC);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);
        let local_path = root.join("keys").join("private").join("local.json");
        fs::write(&local_path, envelope).unwrap();
        assert_eq!(read_sensitive_text(&local_path).unwrap(), plaintext);

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(windows)]
    fn dpapi_protect_for_test(data: &[u8]) -> Result<Vec<u8>, String> {
        use windows_sys::Win32::Foundation::{GetLastError, LocalFree};
        use windows_sys::Win32::Security::Cryptography::{
            CRYPT_INTEGER_BLOB, CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData,
        };

        let input = CRYPT_INTEGER_BLOB {
            cbData: data.len() as u32,
            pbData: data.as_ptr() as *mut u8,
        };
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: DPAPI_ENTROPY.len() as u32,
            pbData: DPAPI_ENTROPY.as_ptr() as *mut u8,
        };
        let mut output = CRYPT_INTEGER_BLOB::default();
        let ok = unsafe {
            CryptProtectData(
                &input,
                std::ptr::null(),
                &entropy,
                std::ptr::null(),
                std::ptr::null(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        };
        if ok == 0 {
            let code = unsafe { GetLastError() };
            return Err(format!("DPAPI 保护失败（GetLastError=0x{code:08X}）"));
        }
        if output.pbData.is_null() {
            return Err("DPAPI 返回了空数据".to_owned());
        }
        let bytes =
            unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
        unsafe {
            let _ = LocalFree(output.pbData as _);
        }
        Ok(bytes)
    }

    fn store_with_session(session_id: &str, secret: &str, name: &str) -> KeyStore {
        let root = std::env::temp_dir().join(format!(
            "k04m-log-parser-session-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let record = serde_json::json!({
            "peer": "Bob",
            "sessionId": session_id,
            "secret": secret,
        });
        fs::write(
            root.join("session.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        let mut store = KeyStore::default();
        let summary = store.load_paths(std::slice::from_ref(&root));
        assert_eq!(summary.sessions_added, 1, "{:?}", summary.warnings);
        let _ = fs::remove_dir_all(&root);
        store
    }

    #[test]
    fn stream_cipher_matches_bouncy_castle_vector() {
        // Generated with Krypt04Mcg's ChannelCrypto derivation and Bouncy
        // Castle's XChaCha20-Poly1305. The secret is a test-only value.
        let session_id = "oKGio6SlpqeoqaqrrK2urw";
        let secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let stream_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let ciphertext = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode("LJvAk3oPJN8aAEs3wVuyu8v5OsI7vkGKL2BwEEYhK3RmzHWCGYJi")
            .unwrap();
        let store = store_with_session(session_id, secret, "stream-vector");

        let mut cipher = store
            .stream_cipher(
                session_id,
                stream_id,
                0,
                "example:test",
                "alice",
                "Bob",
                StreamKeyDirection::Send,
            )
            .unwrap();
        let plaintext = cipher.decrypt_next(&ciphertext).unwrap();
        assert_eq!(plaintext, b"hello krypt04mcg stream");
        assert_eq!(cipher.counter(), 1);

        // The receiver derives the same key with the endpoint order reversed.
        let mut mirror = store
            .stream_cipher(
                session_id,
                stream_id,
                0,
                "example:test",
                "bob",
                "alice",
                StreamKeyDirection::Receive,
            )
            .unwrap();
        assert_eq!(
            mirror.decrypt_next(&ciphertext).unwrap(),
            b"hello krypt04mcg stream"
        );
    }

    #[test]
    fn stream_control_hmac_matches_bouncy_castle_vector() {
        let session_id = "oKGio6SlpqeoqaqrrK2urw";
        let secret = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let stream_id = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let tag = hex_decode("041c5af5d648f06aef9a9acd9c495dd4d46cd9639f3ff075448272d4f632e1ff");
        let store = store_with_session(session_id, secret, "control-vector");
        assert!(
            store
                .verify_stream_control(
                    session_id,
                    "alice",
                    "Bob",
                    "OPEN",
                    stream_id,
                    -1,
                    "example:test",
                    5,
                    &tag,
                )
                .unwrap()
        );
        assert!(
            !store
                .verify_stream_control(
                    session_id,
                    "alice",
                    "Bob",
                    "OPEN",
                    stream_id,
                    0,
                    "example:test",
                    5,
                    &tag,
                )
                .unwrap()
        );
    }

    fn hex_decode(text: &str) -> Vec<u8> {
        text.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                let high = hex_digit(pair[0]).unwrap();
                let low = hex_digit(pair[1]).unwrap();
                (high << 4) | low
            })
            .collect()
    }

    #[test]
    fn loads_stream_api_session_directory() {
        let root = std::env::temp_dir().join(format!(
            "k04m-log-parser-stream-api-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        let stream_api = root.join("stream-api");
        fs::create_dir_all(stream_api.join("secrets")).unwrap();
        fs::create_dir_all(stream_api.join("sessions")).unwrap();
        let mut master = Vec::new();
        master.extend_from_slice(MASTER_KEY_MAGIC);
        master.push(2);
        master.extend_from_slice(&[7u8; 32]);
        fs::write(stream_api.join("secrets").join("master.key"), master).unwrap();
        let record = serde_json::json!({
            "stateVersion": 1,
            "session": {
                "peer": "alice",
                "sessionId": "oKGio6SlpqeoqaqrrK2urw",
                "secret": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8",
            }
        });
        fs::write(
            stream_api.join("sessions").join("alice.json"),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();

        let mut store = KeyStore::default();
        let summary = store.load_paths(std::slice::from_ref(&stream_api));
        assert_eq!(summary.sessions_added, 1, "{:?}", summary.warnings);
        assert_eq!(store.sessions[0].session_id, "oKGio6SlpqeoqaqrrK2urw");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn aad_matches_bouncy_castle_vectors() {
        let document: serde_json::Value =
            serde_json::from_str(include_str!("../tests/data/decryption-vectors.json")).unwrap();
        for case in document["cases"].as_array().unwrap() {
            let encoded = case["packet_base64url"].as_str().unwrap();
            let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(encoded)
                .unwrap();
            let packet = crate::packet::parse_packet(&bytes);
            assert!(
                packet.error.is_none(),
                "{}: {:?}",
                case["name"],
                packet.error
            );
            let aad = build_aad(&packet).unwrap();
            assert_eq!(
                hex(&aad),
                case["aad_hex"].as_str().unwrap(),
                "AAD mismatch for {}",
                case["name"]
            );
        }
    }
}
