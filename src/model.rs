//! Data model shared by the log scanner, packet parser, UI and JSON exporter.

use std::collections::BTreeMap;
use std::ops::Range;

use eframe::egui::Color32;
use serde::Serialize;

/// A timestamp copied from a Minecraft log line, optionally combined with a
/// date inferred from the log file name.
#[derive(Clone, Debug, Default, Serialize)]
pub struct LogTimestamp {
    /// Combined, human-readable value, e.g. `2026-10-21 23:18:08`.
    pub text: String,
    /// Date inferred from the file name, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    /// Time exactly as found between the leading brackets.
    pub time: String,
}

impl LogTimestamp {
    pub fn is_empty(&self) -> bool {
        self.text.is_empty() && self.time.is_empty()
    }
}

/// One physical fragment occurrence in one log file.
#[derive(Clone, Debug, Serialize)]
pub struct FragmentOccurrence {
    pub source_path: String,
    pub source_name: String,
    pub line: usize,
    pub timestamp: LogTimestamp,
    pub index: usize,
    pub total: usize,
    pub payload: String,
    pub payload_length: usize,
}

/// The canonical slot for one fragment index. Duplicate occurrences are kept
/// so the UI and JSON export can show where every line came from.
#[derive(Clone, Debug, Default, Serialize)]
pub struct FragmentSlot {
    pub payload: String,
    pub occurrences: Vec<FragmentOccurrence>,
}

/// Outcome of trying to decrypt one reassembled packet with the loaded key
/// material. Decryption never verifies signatures or establishes sender trust;
/// a successful AEAD tag check only proves that the ciphertext was produced by
/// a holder of the matched key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DecryptionStatus {
    /// No decryption was attempted (incomplete or structurally invalid packet).
    #[default]
    NotAttempted,
    /// AEAD authentication and plaintext decoding succeeded.
    Decrypted,
    /// The packet is structurally readable, but no matching private key or
    /// session secret was loaded.
    NoKey,
    /// The algorithm or packet layout cannot be decrypted by this tool.
    Unsupported,
    /// A matching key was found, but KEM/AEAD/decompression failed.
    Failed,
}

impl DecryptionStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotAttempted => "未尝试",
            Self::Decrypted => "已解密",
            Self::NoKey => "缺少密钥",
            Self::Unsupported => "不支持",
            Self::Failed => "解密失败",
        }
    }

    pub fn color(self) -> Color32 {
        match self {
            Self::Decrypted => Color32::from_rgb(88, 201, 135),
            Self::NoKey => Color32::from_rgb(238, 181, 74),
            Self::Unsupported => Color32::from_rgb(200, 160, 255),
            Self::Failed => Color32::from_rgb(235, 104, 104),
            Self::NotAttempted => Color32::from_rgb(140, 150, 165),
        }
    }

    pub fn is_decrypted(self) -> bool {
        self == Self::Decrypted
    }
}

/// Outcome of verifying the `signature` field of a packet envelope against a
/// loaded signature public key.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureStatus {
    /// The packet is incomplete, structurally invalid, or verification was not
    /// attempted.
    #[default]
    NotAttempted,
    /// The packet carries no signature (for example every `SESSION_MESSAGE`).
    NotPresent,
    /// The signature is valid under the matched sender key.
    Verified,
    /// No signature public key for the claimed sender is loaded.
    NoKey,
    /// The signature algorithm is not implemented by this build.
    Unsupported,
    /// A key was found but the signature (or key encoding) is invalid.
    Failed,
}

impl SignatureStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::NotAttempted => "未验证",
            Self::NotPresent => "无签名",
            Self::Verified => "签名有效",
            Self::NoKey => "缺少公钥",
            Self::Unsupported => "不支持",
            Self::Failed => "签名无效",
        }
    }

    pub fn color(self) -> Color32 {
        match self {
            Self::Verified => Color32::from_rgb(88, 201, 135),
            Self::NoKey => Color32::from_rgb(238, 181, 74),
            Self::Unsupported => Color32::from_rgb(200, 160, 255),
            Self::Failed => Color32::from_rgb(235, 104, 104),
            Self::NotAttempted | Self::NotPresent => Color32::from_rgb(140, 150, 165),
        }
    }

    pub fn is_verified(self) -> bool {
        self == Self::Verified
    }
}

/// One public key tried while verifying a packet signature.
#[derive(Clone, Debug, Serialize)]
pub struct SignatureAttempt {
    pub key_owner: String,
    pub key_source: String,
    pub algorithm: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Signature verification result plus provenance for the key that matched.
#[derive(Clone, Debug, Default, Serialize)]
pub struct SignatureOutcome {
    pub status: SignatureStatus,
    /// Sender claimed by the packet envelope.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub attempts: Vec<SignatureAttempt>,
}

impl SignatureOutcome {
    pub fn is_verified(&self) -> bool {
        self.status == SignatureStatus::Verified
    }
}

/// One key or session-secret candidate that was tried for a packet.
#[derive(Clone, Debug, Serialize)]
pub struct DecryptionAttempt {
    pub key_owner: String,
    pub key_source: String,
    /// `private_key` or `session_secret`.
    pub key_kind: String,
    pub algorithm: String,
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Decrypted packet contents plus provenance for the key that opened it.
#[derive(Clone, Debug, Default, Serialize)]
pub struct DecryptionOutcome {
    pub status: DecryptionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_owner: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_source: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_algorithm: Option<String>,
    /// `private_key` for KEM packets, `session_secret` for session messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// Whether the authenticated plaintext was raw-DEFLATE compressed.
    pub compressed: bool,
    pub plaintext_length: usize,
    /// Strictly decoded UTF-8 text, when the plaintext is valid UTF-8.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext: Option<String>,
    /// Pretty-printed JSON interpretation when the plaintext is a JSON object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plaintext_base64url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub attempts: Vec<DecryptionAttempt>,
    /// Raw authenticated plaintext bytes, kept for rendering/copying but never
    /// serialized as an array of numbers.
    #[serde(skip)]
    pub plaintext_bytes: Vec<u8>,
}

impl DecryptionOutcome {
    pub fn is_decrypted(&self) -> bool {
        self.status == DecryptionStatus::Decrypted
    }

    pub fn display_text(&self) -> Option<&str> {
        self.plaintext.as_deref()
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageStatus {
    /// All fragment indices arrived and the packet envelope parsed.
    Parsed,
    /// One or more fragment indices are missing.
    Incomplete,
    /// Reassembly or binary packet parsing failed.
    #[default]
    Invalid,
}

impl MessageStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Parsed => "已解析",
            Self::Incomplete => "不完整",
            Self::Invalid => "错误",
        }
    }

    pub fn color(self) -> Color32 {
        match self {
            Self::Parsed => Color32::from_rgb(88, 201, 135),
            Self::Incomplete => Color32::from_rgb(238, 181, 74),
            Self::Invalid => Color32::from_rgb(235, 104, 104),
        }
    }
}

/// A reassembled Krypt04Mcg message, including incomplete groups.
#[derive(Clone, Debug)]
pub struct FragmentGroup {
    pub message_id: String,
    pub transport_sender: String,
    pub total: usize,
    pub slots: BTreeMap<usize, FragmentSlot>,
    pub first_seen: LogTimestamp,
    pub last_seen: LogTimestamp,
    /// Global arrival order, used for a stable list ordering.
    pub first_order: usize,
    pub duplicate_count: usize,
    pub conflicts: usize,
    pub warnings: Vec<String>,
    /// Complete Base64URL-decoded binary packet, if reassembly succeeded.
    pub binary: Option<Vec<u8>>,
    /// Structural envelope parse result, available even when some warnings
    /// exist. A parse error is reflected in `ParsedPacket::error`.
    pub packet: Option<ParsedPacket>,
    pub status: MessageStatus,
    /// Populated after key material is loaded; `None` means decryption has not
    /// been attempted for this group yet.
    pub decryption: Option<DecryptionOutcome>,
    /// Populated after public keys are loaded; `None` means signature
    /// verification has not been attempted for this group yet.
    pub signature: Option<SignatureOutcome>,
}

impl FragmentGroup {
    pub fn unique_fragments(&self) -> usize {
        self.slots.len()
    }

    pub fn occurrences(&self) -> usize {
        self.slots.values().map(|slot| slot.occurrences.len()).sum()
    }

    pub fn missing_indices(&self) -> Vec<usize> {
        (0..self.total)
            .filter(|index| !self.slots.contains_key(index))
            .collect()
    }

    pub fn all_occurrences_sorted(&self) -> Vec<&FragmentOccurrence> {
        let mut occurrences: Vec<_> = self
            .slots
            .values()
            .flat_map(|slot| slot.occurrences.iter())
            .collect();
        occurrences.sort_by_key(|occurrence| {
            (
                occurrence.index,
                occurrence.source_path.as_str(),
                occurrence.line,
            )
        });
        occurrences
    }

    pub fn binary_len(&self) -> usize {
        self.binary.as_ref().map_or(0, Vec::len)
    }

    pub fn display_sender(&self) -> &str {
        if self.transport_sender.is_empty() {
            "(未知)"
        } else {
            &self.transport_sender
        }
    }
}

/// Source log metadata included in exports.
#[derive(Clone, Debug, Serialize)]
pub struct SourceInfo {
    pub path: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub date: Option<String>,
    pub bytes: u64,
    pub lines: usize,
    pub fragments: usize,
}

/// The complete result of loading one or more log files.
#[derive(Clone, Debug, Default)]
pub struct LoadedLogs {
    pub sources: Vec<SourceInfo>,
    pub messages: Vec<FragmentGroup>,
    pub fragment_lines: usize,
    pub malformed_lines: usize,
    pub warnings: Vec<String>,
}

impl LoadedLogs {
    pub fn parsed_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|message| message.status == MessageStatus::Parsed)
            .count()
    }

    pub fn incomplete_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|message| message.status == MessageStatus::Incomplete)
            .count()
    }

    pub fn invalid_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|message| message.status == MessageStatus::Invalid)
            .count()
    }

    pub fn signature_count(&self, status: SignatureStatus) -> usize {
        self.messages
            .iter()
            .filter(|message| {
                message
                    .signature
                    .as_ref()
                    .is_some_and(|outcome| outcome.status == status)
            })
            .count()
    }

    /// Number of packets that carried a signature field and were checked.
    pub fn signed_packet_count(&self) -> usize {
        self.messages
            .iter()
            .filter(|message| {
                message.signature.as_ref().is_some_and(|outcome| {
                    !matches!(
                        outcome.status,
                        SignatureStatus::NotAttempted | SignatureStatus::NotPresent
                    )
                })
            })
            .count()
    }
}

/// One value in the parsed binary field tree. `offset` and `length` always
/// refer to the reassembled binary packet, allowing the UI to map a selected
/// field back to exact bytes.
#[derive(Clone, Debug, Serialize)]
pub struct DataField {
    /// Machine-friendly name used by the exporter and tooling.
    pub name: String,
    /// Chinese display label used by the GUI.
    pub label: String,
    pub offset: usize,
    pub length: usize,
    /// Concise value shown in the GUI and exported with the field.
    pub value: String,
    /// Full hexadecimal representation for fields whose value is raw bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Palette category, shared by a top-level field and its descendants.
    pub category: u8,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub children: Vec<DataField>,
}

impl DataField {
    pub fn byte_range(&self) -> Range<usize> {
        self.offset..self.offset.saturating_add(self.length)
    }

    pub fn end(&self) -> usize {
        self.offset.saturating_add(self.length)
    }
}

/// Algorithm identifiers carried in the packet envelope.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Algorithms {
    pub kem: String,
    pub signature: String,
    pub aead: String,
    pub hkdf: String,
}

/// Structural packet information. Parsing does not verify signatures,
/// authenticate ciphertext, or decrypt the payload.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ParsedPacket {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packet_type: Option<u8>,
    pub packet_type_name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<u8>,
    pub flag_names: Vec<String>,
    pub sender: String,
    pub receiver: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_millis: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timestamp_local: Option<String>,
    pub message_id_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<i64>,
    /// Legacy v1/v2 AAD fragment metadata, needed to rebuild the AEAD AAD.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad_fragment_index: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aad_fragment_total: Option<u16>,
    pub algorithms: Algorithms,
    pub nonce_len: usize,
    pub kem_ciphertext_len: usize,
    pub ciphertext_len: usize,
    pub signature_len: usize,
    /// Offsets of the variable-length payload bytes inside the reassembled
    /// packet, used to feed KEM/AEAD without re-parsing the field tree.
    pub nonce_data_offset: usize,
    pub kem_ciphertext_data_offset: usize,
    pub ciphertext_data_offset: usize,
    pub signature_data_offset: usize,
    /// Byte offset where parsing stopped.
    pub consumed: usize,
    /// Number of bytes after the parsed envelope.
    pub trailing: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_offset: Option<usize>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
    pub fields: Vec<DataField>,
}

impl ParsedPacket {
    pub fn is_structurally_valid(&self) -> bool {
        self.error.is_none()
    }

    pub fn type_label(&self) -> String {
        match self.packet_type {
            Some(packet_type) => format!("{packet_type} · {}", self.packet_type_name),
            None => "未知".to_owned(),
        }
    }
}
