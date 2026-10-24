//! PCAP/PCAPNG capture analysis for Krypt04Mcg traffic.
//!
//! The transport is reassembled from the capture with `tcpstreams`, Minecraft
//! framing is decoded with `mc_protocol`, packet identifiers come from
//! `minecraft_data` (Minecraft 26.3 / protocol 777), and the Krypt04Mcg
//! channels are interpreted here.
//!
//! Supported Krypt04Mcg channels:
//!
//! * `krypt04mcg:chat_fragment` — encrypted-chat fragments.
//! * `krypt04mcg:public_key` — public-identity key-share chunks.
//! * `krypt04mcg:tunnel` — legacy ordered tunnel envelope.
//! * `krypt04mcg_stream:control` — stream allocation and session exchange.
//! * `krypt04mcg_stream:data/0` … `data/255` — XChaCha20-Poly1305 records.
//!
//! Raw stream records are authenticated and decrypted when the matching
//! `stream-api` session secret is loaded. The business channel is an opaque
//! byte stream chosen by the application; built-in file streams use
//! `krypt04mcg_file:stream` with Krypt04Mcg's name/length framing.

mod krypt;
mod mc;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local, Utc};
use serde::Serialize;

use crate::decrypt::KeyStore;
use crate::model::{
    DecryptionOutcome, FragmentOccurrence, MessageStatus, ParsedPacket, SignatureOutcome,
};

pub use krypt::CaptureAnalysis;

/// Limits and retention options for capture analysis.
#[derive(Clone, Debug, Default)]
pub struct CaptureOptions {
    /// Keep the complete decrypted application bytes of every stream direction
    /// in memory. Off by default so multi-megabyte streams only retain a hash
    /// and a preview. Enable this for extraction or programmatic access.
    pub retain_stream_data: bool,
}

/// One endpoint direction in a captured TCP conversation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Side {
    ClientToServer,
    ServerToClient,
}

impl Side {
    pub fn label(self) -> &'static str {
        match self {
            Self::ClientToServer => "C2S",
            Self::ServerToClient => "S2C",
        }
    }
}

/// Capture timestamp with human-readable UTC/local renderings.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct CaptureTime {
    pub epoch_millis: i64,
    pub utc: String,
    pub local: String,
    #[serde(skip)]
    pub(crate) secs: i64,
    #[serde(skip)]
    pub(crate) nanos: u32,
}

impl CaptureTime {
    pub(crate) fn from_timestamp(timestamp: tcpstreams::Timestamp) -> Self {
        let Some(utc) = DateTime::<Utc>::from_timestamp(timestamp.secs, timestamp.nanos) else {
            return Self {
                epoch_millis: 0,
                utc: "无效时间戳".to_owned(),
                local: "无效时间戳".to_owned(),
                secs: timestamp.secs,
                nanos: timestamp.nanos,
            };
        };
        Self {
            epoch_millis: timestamp.secs.saturating_mul(1000)
                + i64::from(timestamp.nanos / 1_000_000),
            utc: utc.format("%Y-%m-%d %H:%M:%S%.9f UTC").to_string(),
            local: utc
                .with_timezone(&Local)
                .format("%Y-%m-%d %H:%M:%S%.9f %:z")
                .to_string(),
            secs: timestamp.secs,
            nanos: timestamp.nanos,
        }
    }

    pub(crate) fn sort_key(&self) -> (i64, u32) {
        (self.secs, self.nanos)
    }

    pub(crate) fn log_timestamp(&self) -> crate::model::LogTimestamp {
        let Some(utc) = DateTime::<Utc>::from_timestamp(self.secs, self.nanos) else {
            return crate::model::LogTimestamp::default();
        };
        let local = utc.with_timezone(&Local);
        crate::model::LogTimestamp {
            text: local.format("%Y-%m-%d %H:%M:%S%.3f").to_string(),
            date: Some(local.format("%Y-%m-%d").to_string()),
            time: local.format("%H:%M:%S%.3f").to_string(),
        }
    }
}

/// One capture file and the conversations found in it.
#[derive(Clone, Debug, Serialize)]
pub struct CaptureSource {
    pub path: String,
    pub name: String,
    pub conversations: usize,
    pub minecraft_connections: usize,
    pub packets: u64,
    pub payload_bytes: u64,
    pub bytes: u64,
}

/// One Minecraft TCP connection extracted from the capture.
#[derive(Clone, Debug, Serialize)]
pub struct McConnection {
    pub index: usize,
    pub source: String,
    pub client: String,
    pub server: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub player: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub player_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<i32>,
    pub protocol_supported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_brand: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression_threshold: Option<u32>,
    pub registered_channels: Vec<String>,
    pub start: CaptureTime,
    pub end: CaptureTime,
    pub chat_fragment_messages: usize,
    pub public_key_messages: usize,
    pub control_messages: usize,
    pub tunnel_messages: usize,
    pub data_records: usize,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

/// One Krypt04Mcg channel message. Data records are aggregated per stream
/// direction instead of producing one event per 16 KiB record.
#[derive(Clone, Debug, Serialize)]
pub struct ChannelEvent {
    pub index: usize,
    pub time: CaptureTime,
    pub connection: usize,
    pub side: Side,
    pub channel: String,
    pub frame_offset: u64,
    #[serde(flatten)]
    pub payload: ChannelPayload,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ChannelPayload {
    ChatFragment {
        peer: String,
        version: i32,
        fragment: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        message_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fragment_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fragment_total: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fragment_payload_length: Option<usize>,
    },
    PublicKey {
        peer: String,
        version: i32,
        fragment: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        transfer_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        chunk_index: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        chunk_total: Option<usize>,
        #[serde(skip_serializing_if = "Option::is_none")]
        chunk_length: Option<usize>,
    },
    Control {
        kind: String,
        peer: String,
        stream_id: String,
        slot: i32,
        business_channel: String,
        session_id: String,
        sequence: i64,
        body_length: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        hmac: Option<ControlHmac>,
        #[serde(skip_serializing_if = "Option::is_none")]
        exchange: Option<Box<ControlExchange>>,
    },
    Tunnel {
        peer: String,
        stream_id: String,
        lease: i64,
        envelope_length: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        packet: Option<Box<ParsedPacket>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        decryption: Option<Box<DecryptionOutcome>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<Box<SignatureOutcome>>,
        /// Inner packet bytes retained for post-assembly signature checks.
        #[serde(skip)]
        packet_binary: Vec<u8>,
    },
    Unknown {
        payload_length: usize,
        raw_hex_preview: String,
    },
}

#[derive(Clone, Debug, Serialize)]
pub struct ControlHmac {
    pub verified: bool,
    pub source: String,
    pub target: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ControlExchange {
    pub packet: ParsedPacket,
    pub decryption: DecryptionOutcome,
    pub signature: SignatureOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_exchange: Option<SessionExchangeSummary>,
    /// Inner packet bytes, retained so signature verification can run after
    /// all public-key shares have been assembled. Never serialized.
    #[serde(skip)]
    pub binary: Vec<u8>,
}

/// Sanitized view of `SessionExchangePayload`. Key material and the session
/// secret are deliberately omitted.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SessionExchangeSummary {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder_uuid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_kem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub initiator_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub responder_fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at_millis: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_epoch: Option<i64>,
    pub has_session_secret: bool,
    pub ephemeral_public_key_length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Reassembled encrypted-chat message from `krypt04mcg:chat_fragment`.
#[derive(Clone, Debug, Serialize)]
pub struct ChatTransfer {
    pub message_id: String,
    pub sender: String,
    pub status: MessageStatus,
    pub fragment_total: usize,
    pub unique_fragments: usize,
    pub occurrence_count: usize,
    pub duplicate_count: usize,
    pub conflicts: usize,
    pub missing_indices: Vec<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_base64url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet: Option<ParsedPacket>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decryption: Option<DecryptionOutcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureOutcome>,
    /// Reassembled packet bytes for the GUI hex viewer. Never serialized.
    #[serde(skip)]
    pub binary: Option<Vec<u8>>,
    pub fragments: Vec<FragmentOccurrence>,
}

/// Reassembled public identity from `krypt04mcg:public_key` chunks.
#[derive(Clone, Debug, Serialize)]
pub struct PublicKeyShare {
    pub transfer_id: String,
    pub sender: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub receiver: Option<String>,
    pub version: i32,
    pub total_chunks: usize,
    pub received_chunks: usize,
    pub complete: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<PublicIdentitySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
    pub observations: Vec<ChannelObservation>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChannelObservation {
    pub connection: usize,
    pub side: Side,
    pub time: CaptureTime,
    pub chunk_index: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PublicIdentitySummary {
    pub owner: String,
    pub uuid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kem_public_key: Option<PublicKeyRecordSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature_public_key: Option<PublicKeyRecordSummary>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct PublicKeyRecordSummary {
    pub algorithm: String,
    pub uuid: String,
    pub fingerprint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
}

/// One API stream opened over `krypt04mcg_stream:control`.
#[derive(Clone, Debug, Serialize)]
pub struct ApiStream {
    pub stream_id: String,
    pub channel: String,
    pub session_id: String,
    pub initiator: String,
    pub responder: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_seen: Option<CaptureTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<CaptureTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end_reason: Option<String>,
    pub directions: Vec<ApiStreamDirection>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ApiStreamDirection {
    pub sender: String,
    pub receiver: String,
    pub record_count: usize,
    pub ciphertext_bytes: u64,
    pub decrypted_records: usize,
    pub failed_records: usize,
    pub decryption: String,
    pub content: StreamContent,
    pub records: Vec<StreamRecordInfo>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
    /// Complete authenticated application bytes. Only populated when
    /// [`CaptureOptions::retain_stream_data`] is enabled.
    #[serde(skip)]
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct StreamRecordInfo {
    pub index: u64,
    pub connection: usize,
    pub side: Side,
    pub time: CaptureTime,
    pub ciphertext_length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_length: Option<usize>,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub observations: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview_hex: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct StreamContent {
    pub kind: String,
    pub length: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    pub valid_utf8_prefix: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub declared_file_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text_preview: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base64url: Option<String>,
    pub preview_truncated: bool,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct CaptureSummary {
    pub capture_files: usize,
    pub conversations: usize,
    pub minecraft_connections: usize,
    pub krypt_connections: usize,
    pub channel_messages: usize,
    pub chat_fragments: usize,
    pub chat_transfers: usize,
    pub chat_transfers_decrypted: usize,
    pub public_key_shares: usize,
    pub api_streams: usize,
    pub api_data_records: usize,
    pub api_data_record_observations: usize,
    pub api_data_records_decrypted: usize,
    pub signature_packets: usize,
    pub signatures_verified: usize,
    pub signatures_no_key: usize,
    pub signatures_unsupported: usize,
    pub signatures_failed: usize,
    pub total_plaintext_bytes: u64,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub channels: BTreeMap<String, usize>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

/// Writes capture analysis to a JSON document.
pub fn export_capture_json(path: &Path, analysis: &CaptureAnalysis) -> Result<(), String> {
    let file =
        File::create(path).map_err(|error| format!("无法创建 {}：{error}", path.display()))?;
    let mut writer = BufWriter::new(file);
    serde_json::to_writer_pretty(&mut writer, analysis)
        .map_err(|error| format!("序列化抓包 JSON 失败：{error}"))?;
    writer
        .write_all(b"\n")
        .map_err(|error| format!("写入 {} 失败：{error}", path.display()))?;
    writer
        .flush()
        .map_err(|error| format!("刷新 {} 失败：{error}", path.display()))?;
    Ok(())
}

/// Extracts every retained decrypted stream direction to `directory`.
pub fn extract_stream_data(directory: &Path, analysis: &CaptureAnalysis) -> Result<usize, String> {
    std::fs::create_dir_all(directory)
        .map_err(|error| format!("无法创建 {}：{error}", directory.display()))?;
    let mut written = 0usize;
    for stream in &analysis.api_streams {
        for direction in &stream.directions {
            if direction.data.is_empty() {
                continue;
            }
            let name = format!(
                "{}-{}-to-{}.bin",
                sanitize_file_component(&stream.stream_id),
                sanitize_file_component(&direction.sender),
                sanitize_file_component(&direction.receiver)
            );
            let path = directory.join(name);
            std::fs::write(&path, &direction.data)
                .map_err(|error| format!("写入 {} 失败：{error}", path.display()))?;
            written += 1;
        }
    }
    Ok(written)
}

fn sanitize_file_component(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for ch in text.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "(unknown)".to_owned()
    } else {
        out
    }
}

pub(crate) use krypt::analyze_paths;
pub use mc::is_capture_extension;

#[cfg(test)]
mod tests;

/// Convenience wrapper used by the CLI and tests.
pub fn analyze_captures(
    paths: &[PathBuf],
    key_store: &KeyStore,
    options: &CaptureOptions,
) -> Result<CaptureAnalysis, String> {
    analyze_paths(paths, key_store, options)
}
