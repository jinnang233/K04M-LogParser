//! JSON export for every reassembled message, including incomplete groups.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use base64::Engine as _;
use chrono::{Local, Utc};
use serde::Serialize;

use crate::model::{
    DecryptionOutcome, DecryptionStatus, FragmentGroup, FragmentOccurrence, LoadedLogs,
    LogTimestamp, MessageStatus, ParsedPacket, SignatureOutcome, SignatureStatus, SourceInfo,
};
use crate::packet::hex;

#[derive(Serialize)]
struct ExportDocument<'a> {
    tool: &'static str,
    version: &'static str,
    format_version: u32,
    exported_at_utc: String,
    exported_at_local: String,
    /// True when at least one packet signature was verified with a loaded
    /// sender public key.
    cryptographic_verification: bool,
    /// True when at least one packet was authenticated and decrypted.
    payload_decrypted: bool,
    decryption_summary: DecryptionSummary,
    signature_summary: SignatureSummary,
    summary: ExportSummary,
    sources: Vec<&'a SourceInfo>,
    messages: Vec<ExportMessage<'a>>,
}

#[derive(Serialize)]
struct DecryptionSummary {
    decrypted_messages: usize,
    no_matching_key: usize,
    unsupported_messages: usize,
    failed_messages: usize,
    not_attempted: usize,
}

#[derive(Serialize)]
struct SignatureSummary {
    signed_packets: usize,
    verified: usize,
    no_public_key: usize,
    unsupported: usize,
    failed: usize,
    not_present_or_not_attempted: usize,
}

#[derive(Serialize)]
struct ExportSummary {
    source_files: usize,
    fragment_lines: usize,
    malformed_lines: usize,
    total_messages: usize,
    parsed_messages: usize,
    incomplete_messages: usize,
    invalid_messages: usize,
}

#[derive(Serialize)]
struct ExportMessage<'a> {
    message_id: String,
    transport_sender: String,
    status: MessageStatus,
    first_seen: &'a LogTimestamp,
    last_seen: &'a LogTimestamp,
    fragment_total: usize,
    unique_fragments: usize,
    occurrence_count: usize,
    duplicate_count: usize,
    conflicts: usize,
    missing_indices: Vec<usize>,
    warnings: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    binary_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binary_base64url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binary_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    packet: Option<&'a ParsedPacket>,
    /// Authenticated plaintext and key provenance, when decryption was attempted.
    #[serde(skip_serializing_if = "Option::is_none")]
    decryption: Option<&'a DecryptionOutcome>,
    /// Signature verification against a loaded sender public key.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a SignatureOutcome>,
    fragments: Vec<&'a FragmentOccurrence>,
}

/// Serializes all loaded messages to a pretty-printed JSON document.
pub fn to_json_string(loaded: &LoadedLogs) -> Result<String, String> {
    let document = build_document(loaded);
    let mut json = serde_json::to_string_pretty(&document)
        .map_err(|error| format!("序列化 JSON 失败：{error}"))?;
    json.push('\n');
    Ok(json)
}

/// Writes the complete JSON export to `path`.
pub fn export_json(path: &Path, loaded: &LoadedLogs) -> Result<(), String> {
    let json = to_json_string(loaded)?;
    let file =
        File::create(path).map_err(|error| format!("无法创建 {}：{error}", path.display()))?;
    let mut writer = BufWriter::new(file);
    writer
        .write_all(json.as_bytes())
        .map_err(|error| format!("写入 {} 失败：{error}", path.display()))?;
    writer
        .flush()
        .map_err(|error| format!("刷新 {} 失败：{error}", path.display()))?;
    Ok(())
}

fn build_document(loaded: &LoadedLogs) -> ExportDocument<'_> {
    let now_utc = Utc::now();
    let messages = loaded
        .messages
        .iter()
        .map(build_message)
        .collect::<Vec<_>>();
    let decryption_summary = DecryptionSummary {
        decrypted_messages: count_status(loaded, DecryptionStatus::Decrypted),
        no_matching_key: count_status(loaded, DecryptionStatus::NoKey),
        unsupported_messages: count_status(loaded, DecryptionStatus::Unsupported),
        failed_messages: count_status(loaded, DecryptionStatus::Failed),
        not_attempted: loaded
            .messages
            .iter()
            .filter(|message| message.decryption.is_none())
            .count()
            + count_status(loaded, DecryptionStatus::NotAttempted),
    };
    let signature_summary = SignatureSummary {
        signed_packets: loaded.signed_packet_count(),
        verified: loaded.signature_count(SignatureStatus::Verified),
        no_public_key: loaded.signature_count(SignatureStatus::NoKey),
        unsupported: loaded.signature_count(SignatureStatus::Unsupported),
        failed: loaded.signature_count(SignatureStatus::Failed),
        not_present_or_not_attempted: loaded.signature_count(SignatureStatus::NotPresent)
            + loaded.signature_count(SignatureStatus::NotAttempted),
    };
    ExportDocument {
        tool: "K04M 日志解析器",
        version: env!("CARGO_PKG_VERSION"),
        format_version: 3,
        exported_at_utc: now_utc.to_rfc3339(),
        exported_at_local: now_utc.with_timezone(&Local).to_rfc3339(),
        cryptographic_verification: signature_summary.verified > 0,
        payload_decrypted: decryption_summary.decrypted_messages > 0,
        decryption_summary,
        signature_summary,
        summary: ExportSummary {
            source_files: loaded.sources.len(),
            fragment_lines: loaded.fragment_lines,
            malformed_lines: loaded.malformed_lines,
            total_messages: loaded.messages.len(),
            parsed_messages: loaded.parsed_count(),
            incomplete_messages: loaded.incomplete_count(),
            invalid_messages: loaded.invalid_count(),
        },
        sources: loaded.sources.iter().collect(),
        messages,
    }
}

fn build_message<'a>(message: &'a FragmentGroup) -> ExportMessage<'a> {
    let binary = message.binary.as_deref();
    ExportMessage {
        message_id: message.message_id.clone(),
        transport_sender: message.transport_sender.clone(),
        status: message.status,
        first_seen: &message.first_seen,
        last_seen: &message.last_seen,
        fragment_total: message.total,
        unique_fragments: message.unique_fragments(),
        occurrence_count: message.occurrences(),
        duplicate_count: message.duplicate_count,
        conflicts: message.conflicts,
        missing_indices: message.missing_indices(),
        warnings: &message.warnings,
        binary_length: binary.map(<[u8]>::len),
        binary_base64url: binary
            .map(|bytes| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)),
        binary_hex: binary.map(hex),
        packet: message.packet.as_ref(),
        decryption: message.decryption.as_ref(),
        signature: message.signature.as_ref(),
        fragments: message.all_occurrences_sorted(),
    }
}

fn count_status(loaded: &LoadedLogs, status: DecryptionStatus) -> usize {
    loaded
        .messages
        .iter()
        .filter(|message| {
            message
                .decryption
                .as_ref()
                .is_some_and(|outcome| outcome.status == status)
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_reader::load_paths;
    use std::fs;

    #[test]
    fn export_contains_summary_and_fragments() {
        let dir = std::env::temp_dir().join(format!(
            "k04m-log-parser-export-test-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join("2026-10-21-1.log");
        fs::write(
            &log,
            "[23:18:08] [Server thread/INFO]: <tester> [KRYPT04MCG] 0123456789abcdef0123456789abcdef 0 1 AA\n",
        )
        .unwrap();
        let loaded = load_paths([dir.clone()]).unwrap();
        let json = to_json_string(&loaded).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["summary"]["total_messages"], 1);
        assert_eq!(value["messages"][0]["fragment_total"], 1);
        assert_eq!(value["messages"][0]["unique_fragments"], 1);
        assert!(
            value["sources"][0]["path"]
                .as_str()
                .unwrap()
                .ends_with("2026-10-21-1.log")
        );
        let _ = fs::remove_dir_all(dir);
    }
}
