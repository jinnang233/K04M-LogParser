//! Public-key signature verification for Krypt04Mcg.
//!
//! Krypt04Mcg distributes signature public keys either in a
//! `LocalKeyMaterial.signaturePublicKey` record or in the
//! `krypt04mcg:public_key` channel as a `PublicIdentity` JSON object. This
//! module collects those keys and verifies the canonical signature field of
//! every signed packet envelope.
//!
//! Supported suites are the FIPS 204 ML-DSA parameter sets, the FIPS 205
//! SLH-DSA parameter sets, the project's custom `K04-HYBRID-SIGNATURE-V1`
//! frames whose post-quantum component is one of those two families, and the
//! Bouncy Castle native composite suites
//! `MLDSA44-Ed25519-SHA512`, `MLDSA65-Ed25519-SHA512` and
//! `MLDSA87-Ed448-SHAKE256`. Other signature suites are reported as
//! unsupported rather than silently treated as valid.

use base64::Engine as _;
use ed448_goldilocks_plus::{Signature as Ed448Signature, VerifyingKey as Ed448Key};
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey as Ed25519Key};
use ml_dsa::{MlDsa44, MlDsa65, MlDsa87, Signature as MlDsaSignature, VerifyingKey as MlDsaKey};
use serde::Serialize;
use sha2::{Digest, Sha256, Sha512};
use sha3_11::digest::{ExtendableOutput, Update as _, XofReader};
use sha3_11::{Shake256, Shake256Reader};
use slh_dsa::{
    Sha2_128f, Sha2_128s, Sha2_192f, Sha2_192s, Sha2_256f, Sha2_256s, Shake128f, Shake128s,
    Shake192f, Shake192s, Shake256f, Shake256s, Signature as SlhDsaSignature,
    VerifyingKey as SlhDsaKey,
};
use spki::SubjectPublicKeyInfoRef;

use crate::model::{ParsedPacket, SignatureAttempt, SignatureOutcome, SignatureStatus};

const HYBRID_SIGNATURE_MAGIC: u32 = 0x4b34_5301;
const HYBRID_SIGNATURE_DOMAIN: &[u8] = b"krypt04mcg hybrid signature v1";
const COMPOSITE_PREFIX: &[u8] = b"CompositeAlgorithmSignatures2025";

const COMPOSITE_MLDSA44_ED25519: &str = "MLDSA44-Ed25519-SHA512";
const COMPOSITE_MLDSA65_ED25519: &str = "MLDSA65-Ed25519-SHA512";
const COMPOSITE_MLDSA87_ED448: &str = "MLDSA87-Ed448-SHAKE256";

const OID_COMPOSITE_MLDSA44_ED25519: &str = "1.3.6.1.5.5.7.6.39";
const OID_COMPOSITE_MLDSA65_ED25519: &str = "1.3.6.1.5.5.7.6.48";
const OID_COMPOSITE_MLDSA87_ED448: &str = "1.3.6.1.5.5.7.6.51";
const OID_ED25519: &str = "1.3.101.112";
const OID_ED448: &str = "1.3.101.113";

/// One signature public key loaded from key material or a captured public-key
/// share. Key bytes are public and are never serialized as secrets.
#[derive(Clone, Debug, Serialize)]
pub struct SignatureKeyEntry {
    pub owner: String,
    pub uuid: String,
    /// Algorithm identifier without the `/public` role suffix.
    pub algorithm: String,
    pub fingerprint: String,
    pub source: String,
    #[serde(skip)]
    key_data: Vec<u8>,
}

/// Registry of signature public keys, matched to packet senders by owner.
#[derive(Clone, Debug, Default)]
pub struct SignatureKeyRegistry {
    entries: Vec<SignatureKeyEntry>,
    warnings: Vec<String>,
}

impl SignatureKeyRegistry {
    pub fn entries(&self) -> &[SignatureKeyEntry] {
        &self.entries
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
        self.warnings.clear();
    }

    pub fn remove(&mut self, index: usize) -> Option<SignatureKeyEntry> {
        (index < self.entries.len()).then(|| self.entries.remove(index))
    }

    pub fn merge(&mut self, other: &SignatureKeyRegistry) {
        for entry in &other.entries {
            let _ = self.insert(entry.clone());
        }
        for warning in &other.warnings {
            self.push_warning(warning.clone());
        }
    }

    /// Adds a bare `KeyRecord` JSON object (`algorithm`, `owner`, `keyData`).
    /// Returns true when a new signature key was stored.
    pub fn ingest_record_value(
        &mut self,
        value: &serde_json::Value,
        fallback_source: &str,
    ) -> bool {
        let Some(record) = parse_key_record(value, fallback_source) else {
            return false;
        };
        if is_kem_algorithm(&record.algorithm) {
            return false;
        }
        self.insert(record)
    }

    /// Adds the `signaturePublicKey` record from a `PublicIdentity` or
    /// `LocalKeyMaterial` JSON object. Returns true when a key was stored.
    pub fn ingest_identity_value(
        &mut self,
        value: &serde_json::Value,
        fallback_source: &str,
    ) -> bool {
        let Some(public_key) = value.get("signaturePublicKey") else {
            return false;
        };
        let mut record = match parse_key_record(public_key, fallback_source) {
            Some(record) => record,
            None => return false,
        };
        let top_owner = json_text(value, "owner");
        let top_uuid = json_text(value, "uuid");
        let record_owner = record.owner.trim().to_owned();
        let record_owner_known = !record_owner.is_empty() && record_owner != "(未知)";
        if let (Some(owner), true) = (&top_owner, record_owner_known)
            && !record_owner.eq_ignore_ascii_case(owner)
        {
            self.push_warning(format!(
                "{} 的签名公钥 owner {record_owner} 与身份 owner {owner} 不一致，已忽略",
                fallback_source
            ));
            return false;
        }
        if let (Some(uuid), false) = (&top_uuid, record.uuid.trim().is_empty())
            && !uuid.eq_ignore_ascii_case(&record.uuid)
        {
            self.push_warning(format!(
                "{} 的签名公钥 uuid {} 与身份 uuid {uuid} 不一致，已忽略",
                fallback_source, record.uuid
            ));
            return false;
        }
        let owner = match (top_owner, record_owner_known) {
            (Some(owner), _) => owner,
            (None, true) => record_owner,
            (None, false) => {
                self.push_warning(format!("{fallback_source} 的签名公钥缺少 owner，已忽略"));
                return false;
            }
        };
        record.owner = owner;
        if let Some(uuid) = top_uuid {
            record.uuid = uuid;
        }
        self.insert(record)
    }

    /// Verifies the canonical signature field of one parsed packet.
    pub fn verify_packet(&self, packet: &ParsedPacket, binary: &[u8]) -> SignatureOutcome {
        let Some(packet_type) = packet.packet_type else {
            return not_attempted("包结构不完整，无法验证签名");
        };
        if packet.error.is_some() {
            return not_attempted("包结构解析失败，无法验证签名");
        }
        if packet_type == 4 || packet.signature_len == 0 {
            return SignatureOutcome {
                status: SignatureStatus::NotPresent,
                signer: Some(packet.sender.clone()),
                ..SignatureOutcome::default()
            };
        }

        let algorithm = packet.algorithms.signature.trim().to_owned();
        let mut outcome = SignatureOutcome {
            signer: Some(packet.sender.clone()),
            algorithm: Some(algorithm.clone()),
            ..SignatureOutcome::default()
        };
        if algorithm.is_empty() || algorithm.eq_ignore_ascii_case("NONE") {
            outcome.status = SignatureStatus::NotPresent;
            outcome.error = Some("SIGNED 标志存在，但签名字段缺失".to_owned());
            return outcome;
        }
        if !algorithm_supported(&algorithm) {
            outcome.status = SignatureStatus::Unsupported;
            outcome.error = Some(format!("本工具不支持验证签名算法 {algorithm}"));
            return outcome;
        }

        let signature =
            match bytes_range(binary, packet.signature_data_offset, packet.signature_len) {
                Ok(signature) => signature,
                Err(error) => {
                    outcome.status = SignatureStatus::Failed;
                    outcome.error = Some(error);
                    return outcome;
                }
            };
        let input = match signature_input(packet, binary) {
            Ok(input) => input,
            Err(error) => {
                outcome.status = SignatureStatus::Failed;
                outcome.error = Some(error);
                return outcome;
            }
        };

        let candidates: Vec<&SignatureKeyEntry> = self
            .entries
            .iter()
            .filter(|entry| entry.owner.eq_ignore_ascii_case(&packet.sender))
            .collect();
        if candidates.is_empty() {
            outcome.status = SignatureStatus::NoKey;
            outcome.error = Some(format!(
                "没有 owner 为 {} 的签名公钥。请加载该账户的 keys/public、local.json 或包含公钥共享的抓包。",
                packet.sender
            ));
            return outcome;
        }

        let mut saw_mismatched_algorithm = false;
        let mut saw_unsupported = false;
        let mut saw_failure = false;
        for key in candidates {
            if !key.algorithm.eq_ignore_ascii_case(&algorithm) {
                saw_mismatched_algorithm = true;
                outcome.attempts.push(SignatureAttempt {
                    key_owner: key.owner.clone(),
                    key_source: key.source.clone(),
                    algorithm: key.algorithm.clone(),
                    success: false,
                    error: Some(format!(
                        "身份签名算法 {} 与包算法 {algorithm} 不一致",
                        key.algorithm
                    )),
                });
                continue;
            }
            match verify_signature(&algorithm, &key.key_data, &input, signature) {
                Ok(true) => {
                    outcome.status = SignatureStatus::Verified;
                    outcome.key_owner = Some(key.owner.clone());
                    outcome.key_source = Some(key.source.clone());
                    outcome.attempts.push(SignatureAttempt {
                        key_owner: key.owner.clone(),
                        key_source: key.source.clone(),
                        algorithm: key.algorithm.clone(),
                        success: true,
                        error: None,
                    });
                    return outcome;
                }
                Ok(false) => {
                    saw_failure = true;
                    outcome.attempts.push(SignatureAttempt {
                        key_owner: key.owner.clone(),
                        key_source: key.source.clone(),
                        algorithm: key.algorithm.clone(),
                        success: false,
                        error: Some("签名与公钥不匹配".to_owned()),
                    });
                }
                Err(VerifyError::Unsupported(message)) => {
                    saw_unsupported = true;
                    outcome.attempts.push(SignatureAttempt {
                        key_owner: key.owner.clone(),
                        key_source: key.source.clone(),
                        algorithm: key.algorithm.clone(),
                        success: false,
                        error: Some(message),
                    });
                }
                Err(VerifyError::Invalid(message)) => {
                    saw_failure = true;
                    outcome.attempts.push(SignatureAttempt {
                        key_owner: key.owner.clone(),
                        key_source: key.source.clone(),
                        algorithm: key.algorithm.clone(),
                        success: false,
                        error: Some(message),
                    });
                }
            }
        }

        if saw_unsupported && !saw_failure && !saw_mismatched_algorithm {
            outcome.status = SignatureStatus::Unsupported;
            outcome.error = Some(format!("签名算法 {algorithm} 的公钥格式暂不支持"));
        } else {
            outcome.status = SignatureStatus::Failed;
            outcome.error = Some(if saw_mismatched_algorithm && !saw_failure {
                format!("找到 {} 的签名公钥，但声明的签名算法不匹配", packet.sender)
            } else {
                format!("已用全部匹配公钥验证 {} 的签名，均不通过", packet.sender)
            });
        }
        outcome
    }

    fn insert(&mut self, entry: SignatureKeyEntry) -> bool {
        if self.entries.iter().any(|existing| {
            existing.owner.eq_ignore_ascii_case(&entry.owner)
                && existing.algorithm.eq_ignore_ascii_case(&entry.algorithm)
                && existing.key_data == entry.key_data
        }) {
            return false;
        }
        self.entries.push(entry);
        true
    }

    fn push_warning(&mut self, warning: String) {
        if self.warnings.len() < 80 && !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }
}

fn not_attempted(error: &str) -> SignatureOutcome {
    SignatureOutcome {
        status: SignatureStatus::NotAttempted,
        error: Some(error.to_owned()),
        ..SignatureOutcome::default()
    }
}

fn parse_key_record(value: &serde_json::Value, fallback_source: &str) -> Option<SignatureKeyEntry> {
    let algorithm_text = json_text(value, "algorithm")?;
    let algorithm = strip_role(&algorithm_text);
    if algorithm.is_empty() {
        return None;
    }
    let key_text = json_text(value, "keyData")?;
    let key_data = decode_base64url(&key_text).ok()?;
    if key_data.is_empty() {
        return None;
    }
    let owner = json_text(value, "owner").unwrap_or_else(|| "(未知)".to_owned());
    let uuid = json_text(value, "uuid").unwrap_or_default();
    let fingerprint = json_text(value, "fingerprint").unwrap_or_else(|| {
        crate::packet::hex(&Sha256::digest(format!("{owner}|{uuid}|{algorithm}")))
    });
    Some(SignatureKeyEntry {
        owner,
        uuid,
        algorithm: algorithm.to_owned(),
        fingerprint,
        source: fallback_source.to_owned(),
        key_data,
    })
}

fn json_text(value: &serde_json::Value, key: &str) -> Option<String> {
    value.get(key)?.as_str().map(str::to_owned)
}

fn strip_role(algorithm: &str) -> &str {
    let trimmed = algorithm.trim();
    let lower = trimmed.to_ascii_lowercase();
    if lower.ends_with("/public") {
        &trimmed[..trimmed.len() - "/public".len()]
    } else if lower.ends_with("/private") {
        &trimmed[..trimmed.len() - "/private".len()]
    } else {
        trimmed
    }
}

fn is_kem_algorithm(algorithm: &str) -> bool {
    let upper = algorithm.to_ascii_uppercase();
    upper.starts_with("ML-KEM")
        || upper.starts_with("CMCE/")
        || upper.starts_with("HQC/")
        || upper.starts_with("NTRULPRIME/")
        || upper.starts_with("SNTRUPRIME/")
}

fn decode_base64url(text: &str) -> Result<Vec<u8>, String> {
    let trimmed = text.trim();
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(trimmed))
        .map_err(|error| error.to_string())
}

// ---------------------------------------------------------------------------
// Canonical signature input (PacketCodec.signatureInput)
// ---------------------------------------------------------------------------

fn signature_input(packet: &ParsedPacket, binary: &[u8]) -> Result<Vec<u8>, String> {
    let version = packet
        .protocol_version
        .ok_or_else(|| "缺少协议版本".to_owned())?;
    let mut out = crate::decrypt::build_aad(packet)?;
    if version < 3 {
        let timestamp = packet
            .timestamp_millis
            .ok_or_else(|| "缺少时间戳".to_owned())?;
        out.extend_from_slice(&timestamp.to_be_bytes());
    }
    let nonce = bytes_range(binary, packet.nonce_data_offset, packet.nonce_len)?;
    push_bytes16(&mut out, nonce);
    let kem = bytes_range(
        binary,
        packet.kem_ciphertext_data_offset,
        packet.kem_ciphertext_len,
    )?;
    push_bytes32(&mut out, kem);
    let ciphertext = bytes_range(binary, packet.ciphertext_data_offset, packet.ciphertext_len)?;
    push_bytes32(&mut out, ciphertext);
    Ok(out)
}

fn bytes_range(binary: &[u8], offset: usize, length: usize) -> Result<&[u8], String> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| "字段偏移溢出".to_owned())?;
    binary
        .get(offset..end)
        .ok_or_else(|| format!("字段范围 {offset}..{end} 超出二进制长度 {}", binary.len()))
}

fn push_bytes16(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_bytes32(out: &mut Vec<u8>, bytes: &[u8]) {
    let length = i32::try_from(bytes.len()).unwrap_or(i32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
}

// ---------------------------------------------------------------------------
// Signature suites
// ---------------------------------------------------------------------------

#[derive(Debug)]
enum VerifyError {
    Unsupported(String),
    Invalid(String),
}

fn algorithm_supported(algorithm: &str) -> bool {
    let algorithm = strip_role(algorithm);
    if matches!(algorithm, "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87") {
        return true;
    }
    if slh_dsa_type(algorithm).is_some() {
        return true;
    }
    if composite_suite(algorithm).is_some() {
        return true;
    }
    if let Some((pq, classical)) = algorithm.split_once('+') {
        return !classical.is_empty()
            && (matches!(pq, "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87")
                || slh_dsa_type(pq).is_some())
            && matches!(classical, "Ed25519" | "Ed448");
    }
    false
}

macro_rules! verify_ml_dsa_spki {
    ($type:ty, $key_data:expr, $input:expr, $context:expr, $signature:expr) => {{
        let spki = SubjectPublicKeyInfoRef::try_from($key_data)
            .map_err(|error| VerifyError::Invalid(format!("ML-DSA 公钥不是有效 SPKI：{error}")))?;
        let key = MlDsaKey::<$type>::try_from(spki)
            .map_err(|error| VerifyError::Invalid(format!("ML-DSA 公钥解析失败：{error}")))?;
        let signature = MlDsaSignature::<$type>::try_from($signature)
            .map_err(|_| VerifyError::Invalid("ML-DSA 签名长度或编码无效".to_owned()))?;
        Ok::<bool, VerifyError>(key.verify_with_context($input, $context, &signature))
    }};
}

macro_rules! verify_ml_dsa_raw {
    ($type:ty, $raw_key:expr, $input:expr, $context:expr, $signature:expr) => {{
        let key_bytes = ml_dsa::EncodedVerifyingKey::<$type>::try_from($raw_key)
            .map_err(|_| VerifyError::Invalid("ML-DSA 公钥长度无效".to_owned()))?;
        let key = <MlDsaKey<$type> as ml_dsa::KeyInit>::new(&key_bytes);
        let signature = MlDsaSignature::<$type>::try_from($signature)
            .map_err(|_| VerifyError::Invalid("ML-DSA 签名长度或编码无效".to_owned()))?;
        Ok::<bool, VerifyError>(key.verify_with_context($input, $context, &signature))
    }};
}

fn verify_signature(
    algorithm: &str,
    key_data: &[u8],
    input: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let algorithm = strip_role(algorithm);
    if let Some(suite) = composite_suite(algorithm) {
        return verify_composite(suite, key_data, input, signature);
    }
    if let Some((pq, classical)) = algorithm.split_once('+') {
        return verify_custom_hybrid(pq, classical, algorithm, key_data, input, signature);
    }
    if let Some(slh) = slh_dsa_type(algorithm) {
        return verify_slh_dsa(slh, key_data, input, signature);
    }
    match algorithm {
        "ML-DSA-44" => verify_ml_dsa_spki!(MlDsa44, key_data, input, &[], signature),
        "ML-DSA-65" => verify_ml_dsa_spki!(MlDsa65, key_data, input, &[], signature),
        "ML-DSA-87" => verify_ml_dsa_spki!(MlDsa87, key_data, input, &[], signature),
        other => Err(VerifyError::Unsupported(format!(
            "本工具不支持签名算法 {other}"
        ))),
    }
}

fn slh_dsa_type(algorithm: &str) -> Option<&'static str> {
    Some(match algorithm {
        "SLH-DSA-SHA2-128F" => "Sha2_128f",
        "SLH-DSA-SHA2-128S" => "Sha2_128s",
        "SLH-DSA-SHA2-192F" => "Sha2_192f",
        "SLH-DSA-SHA2-192S" => "Sha2_192s",
        "SLH-DSA-SHA2-256F" => "Sha2_256f",
        "SLH-DSA-SHA2-256S" => "Sha2_256s",
        "SLH-DSA-SHAKE-128F" => "Shake128f",
        "SLH-DSA-SHAKE-128S" => "Shake128s",
        "SLH-DSA-SHAKE-192F" => "Shake192f",
        "SLH-DSA-SHAKE-192S" => "Shake192s",
        "SLH-DSA-SHAKE-256F" => "Shake256f",
        "SLH-DSA-SHAKE-256S" => "Shake256s",
        _ => return None,
    })
}

macro_rules! verify_slh_dsa {
    ($type:ty, $key_data:expr, $input:expr, $signature:expr) => {{
        let spki = SubjectPublicKeyInfoRef::try_from($key_data)
            .map_err(|error| VerifyError::Invalid(format!("SLH-DSA 公钥不是有效 SPKI：{error}")))?;
        let key = SlhDsaKey::<$type>::try_from(spki)
            .map_err(|error| VerifyError::Invalid(format!("SLH-DSA 公钥解析失败：{error}")))?;
        let signature = SlhDsaSignature::<$type>::try_from($signature)
            .map_err(|_| VerifyError::Invalid("SLH-DSA 签名长度或编码无效".to_owned()))?;
        slh_dsa::signature::Verifier::verify(&key, $input, &signature)
            .map_err(|_| VerifyError::Invalid("SLH-DSA 签名验证失败".to_owned()))?;
        Ok::<bool, VerifyError>(true)
    }};
}

fn verify_slh_dsa(
    kind: &str,
    key_data: &[u8],
    input: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    match kind {
        "Sha2_128f" => verify_slh_dsa!(Sha2_128f, key_data, input, signature),
        "Sha2_128s" => verify_slh_dsa!(Sha2_128s, key_data, input, signature),
        "Sha2_192f" => verify_slh_dsa!(Sha2_192f, key_data, input, signature),
        "Sha2_192s" => verify_slh_dsa!(Sha2_192s, key_data, input, signature),
        "Sha2_256f" => verify_slh_dsa!(Sha2_256f, key_data, input, signature),
        "Sha2_256s" => verify_slh_dsa!(Sha2_256s, key_data, input, signature),
        "Shake128f" => verify_slh_dsa!(Shake128f, key_data, input, signature),
        "Shake128s" => verify_slh_dsa!(Shake128s, key_data, input, signature),
        "Shake192f" => verify_slh_dsa!(Shake192f, key_data, input, signature),
        "Shake192s" => verify_slh_dsa!(Shake192s, key_data, input, signature),
        "Shake256f" => verify_slh_dsa!(Shake256f, key_data, input, signature),
        "Shake256s" => verify_slh_dsa!(Shake256s, key_data, input, signature),
        other => Err(VerifyError::Unsupported(format!(
            "本工具不支持签名算法 {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Custom K04-HYBRID-SIGNATURE-V1 frames
// ---------------------------------------------------------------------------

fn verify_custom_hybrid(
    pq_algorithm: &str,
    classical_algorithm: &str,
    algorithm: &str,
    key_data: &[u8],
    input: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let classical_size = match classical_algorithm {
        "Ed25519" => 64,
        "Ed448" => 114,
        other => {
            return Err(VerifyError::Unsupported(format!(
                "本工具不支持混合签名的经典分量 {other}"
            )));
        }
    };
    let key_parts = split_hybrid_frame(key_data, 2, "签名公钥")?;
    let signature_parts = split_hybrid_frame(signature, 2, "签名")?;
    if signature_parts[1].len() != classical_size {
        return Err(VerifyError::Invalid(format!(
            "混合签名经典分量长度为 {}，预期 {classical_size}",
            signature_parts[1].len()
        )));
    }
    if !classical_algorithm_supported(key_parts[1], classical_algorithm) {
        return Err(VerifyError::Invalid(format!(
            "混合签名公钥的经典分量不是 {classical_algorithm}"
        )));
    }

    let public_frame = hybrid_frame(&[key_parts[0], key_parts[1]]);
    let context = hybrid_frame(&[
        HYBRID_SIGNATURE_DOMAIN,
        algorithm.as_bytes(),
        &Sha512::digest(&public_frame),
        &Sha512::digest(input),
    ]);

    let pq_valid = if matches!(pq_algorithm, "ML-DSA-44" | "ML-DSA-65" | "ML-DSA-87") {
        match pq_algorithm {
            "ML-DSA-44" => {
                verify_ml_dsa_spki!(MlDsa44, key_parts[0], &context, &[], signature_parts[0])?
            }
            "ML-DSA-65" => {
                verify_ml_dsa_spki!(MlDsa65, key_parts[0], &context, &[], signature_parts[0])?
            }
            _ => verify_ml_dsa_spki!(MlDsa87, key_parts[0], &context, &[], signature_parts[0])?,
        }
    } else if let Some(kind) = slh_dsa_type(pq_algorithm) {
        verify_slh_dsa(kind, key_parts[0], &context, signature_parts[0])?
    } else {
        return Err(VerifyError::Unsupported(format!(
            "本工具不支持混合签名的 PQ 分量 {pq_algorithm}"
        )));
    };
    let classical_valid = verify_classical(
        classical_algorithm,
        key_parts[1],
        &context,
        signature_parts[1],
    )?;
    Ok(pq_valid && classical_valid)
}

fn split_hybrid_frame<'a>(
    encoded: &'a [u8],
    count: usize,
    label: &str,
) -> Result<Vec<&'a [u8]>, VerifyError> {
    if encoded.len() < 4 + count * 4 {
        return Err(VerifyError::Invalid(format!("{label}帧过短")));
    }
    let magic = u32::from_be_bytes(encoded[..4].try_into().expect("4 bytes"));
    if magic != HYBRID_SIGNATURE_MAGIC {
        return Err(VerifyError::Invalid(format!("{label}帧 magic 无效")));
    }
    let mut parts = Vec::with_capacity(count);
    let mut cursor = 4usize;
    for _ in 0..count {
        if encoded.len() - cursor < 4 {
            return Err(VerifyError::Invalid(format!("{label}帧长度字段被截断")));
        }
        let length =
            u32::from_be_bytes(encoded[cursor..cursor + 4].try_into().expect("4 bytes")) as usize;
        cursor += 4;
        if length == 0 || length > encoded.len() - cursor {
            return Err(VerifyError::Invalid(format!("{label}帧分量长度无效")));
        }
        parts.push(&encoded[cursor..cursor + length]);
        cursor += length;
    }
    if cursor != encoded.len() {
        return Err(VerifyError::Invalid(format!("{label}帧包含尾随字节")));
    }
    Ok(parts)
}

fn hybrid_frame(components: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4 + components
            .iter()
            .map(|component| 4 + component.len())
            .sum::<usize>(),
    );
    out.extend_from_slice(&HYBRID_SIGNATURE_MAGIC.to_be_bytes());
    for component in components {
        out.extend_from_slice(&(component.len() as u32).to_be_bytes());
        out.extend_from_slice(component);
    }
    out
}

fn classical_algorithm_supported(key_data: &[u8], algorithm: &str) -> bool {
    let Ok(spki) = SubjectPublicKeyInfoRef::try_from(key_data) else {
        return false;
    };
    match algorithm {
        "Ed25519" => spki.algorithm.oid.to_string() == OID_ED25519,
        "Ed448" => spki.algorithm.oid.to_string() == OID_ED448,
        _ => false,
    }
}

fn verify_classical(
    algorithm: &str,
    key_data: &[u8],
    input: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    let spki = SubjectPublicKeyInfoRef::try_from(key_data)
        .map_err(|error| VerifyError::Invalid(format!("经典签名公钥不是有效 SPKI：{error}")))?;
    let raw = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| VerifyError::Invalid("经典签名公钥位串无效".to_owned()))?;
    match algorithm {
        "Ed25519" => {
            let key_bytes: [u8; 32] = raw
                .try_into()
                .map_err(|_| VerifyError::Invalid("Ed25519 公钥长度不是 32 字节".to_owned()))?;
            let key = Ed25519Key::from_bytes(&key_bytes)
                .map_err(|error| VerifyError::Invalid(format!("Ed25519 公钥无效：{error}")))?;
            let signature = Ed25519Signature::from_slice(signature)
                .map_err(|error| VerifyError::Invalid(format!("Ed25519 签名无效：{error}")))?;
            Ok(key.verify_strict(input, &signature).is_ok())
        }
        "Ed448" => {
            let key_bytes: [u8; 57] = raw
                .try_into()
                .map_err(|_| VerifyError::Invalid("Ed448 公钥长度不是 57 字节".to_owned()))?;
            let key = Ed448Key::from_bytes(&key_bytes)
                .map_err(|error| VerifyError::Invalid(format!("Ed448 公钥无效：{error}")))?;
            let signature = Ed448Signature::try_from(signature)
                .map_err(|error| VerifyError::Invalid(format!("Ed448 签名无效：{error}")))?;
            Ok(key.verify_raw(&signature, input).is_ok())
        }
        other => Err(VerifyError::Unsupported(format!(
            "本工具不支持经典签名算法 {other}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Native Bouncy Castle composite signatures
// ---------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum CompositeSuite {
    Mldsa44Ed25519,
    Mldsa65Ed25519,
    Mldsa87Ed448,
}

fn composite_suite(algorithm: &str) -> Option<CompositeSuite> {
    Some(match algorithm {
        COMPOSITE_MLDSA44_ED25519 => CompositeSuite::Mldsa44Ed25519,
        COMPOSITE_MLDSA65_ED25519 => CompositeSuite::Mldsa65Ed25519,
        COMPOSITE_MLDSA87_ED448 => CompositeSuite::Mldsa87Ed448,
        _ => return None,
    })
}

fn verify_composite(
    suite: CompositeSuite,
    key_data: &[u8],
    input: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    // The public key splits at the fixed ML-DSA public-key size, while the
    // signature splits at the fixed ML-DSA signature size.
    let (
        expected_oid,
        label,
        pq_key_size,
        pq_sig_size,
        classical_key_size,
        classical_sig_size,
        classical,
    ) = match suite {
        CompositeSuite::Mldsa44Ed25519 => (
            OID_COMPOSITE_MLDSA44_ED25519,
            "COMPSIG-MLDSA44-Ed25519-SHA512",
            1312,
            2420,
            32,
            64,
            "Ed25519",
        ),
        CompositeSuite::Mldsa65Ed25519 => (
            OID_COMPOSITE_MLDSA65_ED25519,
            "COMPSIG-MLDSA65-Ed25519-SHA512",
            1952,
            3309,
            32,
            64,
            "Ed25519",
        ),
        CompositeSuite::Mldsa87Ed448 => (
            OID_COMPOSITE_MLDSA87_ED448,
            "COMPSIG-MLDSA87-Ed448-SHAKE256",
            2592,
            4627,
            57,
            114,
            "Ed448",
        ),
    };
    let spki = SubjectPublicKeyInfoRef::try_from(key_data)
        .map_err(|error| VerifyError::Invalid(format!("复合签名公钥不是有效 SPKI：{error}")))?;
    let oid = spki.algorithm.oid.to_string();
    if oid != expected_oid {
        return Err(VerifyError::Invalid(format!(
            "复合签名公钥 OID {oid} 与声明算法不匹配"
        )));
    }
    let raw = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| VerifyError::Invalid("复合签名公钥位串无效".to_owned()))?;
    if raw.len() != pq_key_size + classical_key_size {
        return Err(VerifyError::Invalid(format!(
            "复合签名公钥长度为 {}，预期 {}",
            raw.len(),
            pq_key_size + classical_key_size
        )));
    }
    if signature.len() != pq_sig_size + classical_sig_size {
        return Err(VerifyError::Invalid(format!(
            "复合签名长度为 {}，预期 {}",
            signature.len(),
            pq_sig_size + classical_sig_size
        )));
    }
    let (pq_key, classical_key) = raw.split_at(pq_key_size);
    let (pq_signature, classical_signature) = signature.split_at(pq_sig_size);

    // SignatureSpi builds M' = Prefix || Label || len(ctx) || ctx || PH(M)
    // with an empty context; both components sign the same M'.
    // Both SHA-512 and SHAKE-256 produce a 64-byte message representative.
    let mut message = Vec::with_capacity(COMPOSITE_PREFIX.len() + label.len() + 1 + 64);
    message.extend_from_slice(COMPOSITE_PREFIX);
    message.extend_from_slice(label.as_bytes());
    message.push(0);
    match suite {
        CompositeSuite::Mldsa87Ed448 => message.extend_from_slice(&shake256_64(input)),
        _ => message.extend_from_slice(&Sha512::digest(input)),
    }

    // The ML-DSA component receives the label as its FIPS 204 context.
    let context = label.as_bytes();
    let pq_valid = match suite {
        CompositeSuite::Mldsa44Ed25519 => {
            verify_ml_dsa_raw!(MlDsa44, pq_key, &message, context, pq_signature)?
        }
        CompositeSuite::Mldsa65Ed25519 => {
            verify_ml_dsa_raw!(MlDsa65, pq_key, &message, context, pq_signature)?
        }
        CompositeSuite::Mldsa87Ed448 => {
            verify_ml_dsa_raw!(MlDsa87, pq_key, &message, context, pq_signature)?
        }
    };
    let classical_valid =
        verify_classical_raw(classical, classical_key, &message, classical_signature)?;
    Ok(pq_valid && classical_valid)
}

fn verify_classical_raw(
    algorithm: &str,
    raw_key: &[u8],
    input: &[u8],
    signature: &[u8],
) -> Result<bool, VerifyError> {
    match algorithm {
        "Ed25519" => {
            let key_bytes: [u8; 32] = raw_key
                .try_into()
                .map_err(|_| VerifyError::Invalid("Ed25519 公钥长度不是 32 字节".to_owned()))?;
            let key = Ed25519Key::from_bytes(&key_bytes)
                .map_err(|error| VerifyError::Invalid(format!("Ed25519 公钥无效：{error}")))?;
            let signature = Ed25519Signature::from_slice(signature)
                .map_err(|error| VerifyError::Invalid(format!("Ed25519 签名无效：{error}")))?;
            Ok(key.verify_strict(input, &signature).is_ok())
        }
        "Ed448" => {
            let key_bytes: [u8; 57] = raw_key
                .try_into()
                .map_err(|_| VerifyError::Invalid("Ed448 公钥长度不是 57 字节".to_owned()))?;
            let key = Ed448Key::from_bytes(&key_bytes)
                .map_err(|error| VerifyError::Invalid(format!("Ed448 公钥无效：{error}")))?;
            let signature = Ed448Signature::try_from(signature)
                .map_err(|error| VerifyError::Invalid(format!("Ed448 签名无效：{error}")))?;
            Ok(key.verify_raw(&signature, input).is_ok())
        }
        other => Err(VerifyError::Unsupported(format!(
            "本工具不支持经典签名算法 {other}"
        ))),
    }
}

fn shake256_64(input: &[u8]) -> [u8; 64] {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader: Shake256Reader = hasher.finalize_xof();
    let mut output = [0u8; 64];
    reader.read(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_algorithms() {
        assert!(!algorithm_supported("Falcon-512"));
        assert!(!algorithm_supported("RSA-2048"));
        assert!(algorithm_supported("ML-DSA-65"));
        assert!(algorithm_supported("SLH-DSA-SHA2-128F"));
        assert!(algorithm_supported("MLDSA65-Ed25519-SHA512"));
        assert!(algorithm_supported("ML-DSA-65+Ed25519"));
    }

    #[test]
    fn hybrid_frame_round_trips_components() {
        let frame = hybrid_frame(&[b"pq", b"classical"]);
        let parts = split_hybrid_frame(&frame, 2, "test").unwrap();
        assert_eq!(parts, vec![b"pq".as_slice(), b"classical".as_slice()]);
    }

    #[test]
    fn local_key_material_registers_signature_key_without_top_level_owner() {
        // A LocalKeyMaterial has no top-level owner; the nested key record is
        // the authoritative owner.
        let material = serde_json::json!({
            "signaturePublicKey": {
                "algorithm": "ML-DSA-65/public",
                "owner": "alice",
                "uuid": "uuid-alice",
                "fingerprint": "aa",
                "keyData": "AA"
            }
        });
        let mut registry = SignatureKeyRegistry::default();
        assert!(registry.ingest_identity_value(&material, "local.json"));
        assert_eq!(registry.entries().len(), 1);
        assert_eq!(registry.entries()[0].owner, "alice");
        assert_eq!(registry.entries()[0].algorithm, "ML-DSA-65");
    }

    #[test]
    fn rejects_identity_with_mismatched_key_owner() {
        let identity = serde_json::json!({
            "owner": "alice",
            "uuid": "uuid-alice",
            "signaturePublicKey": {
                "algorithm": "ML-DSA-65/public",
                "owner": "mallory",
                "uuid": "uuid-mallory",
                "keyData": "AA"
            }
        });
        let mut registry = SignatureKeyRegistry::default();
        assert!(!registry.ingest_identity_value(&identity, "identity.json"));
        assert!(registry.is_empty());
        assert_eq!(registry.warnings().len(), 1);
    }
}
