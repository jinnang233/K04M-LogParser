//! Krypt04Mcg chat-fragment recognition and reassembly.

use std::collections::HashMap;

use base64::Engine as _;

use crate::model::{FragmentGroup, FragmentOccurrence, FragmentSlot, LogTimestamp, MessageStatus};
use crate::packet::{MAX_PACKET_BYTES, parse_packet};

pub const PREFIX: &str = "[KRYPT04MCG]";
const MAX_FRAGMENTS: usize = 2048;
const MAX_ENCODED_PACKET_CHARS: usize = (MAX_PACKET_BYTES * 4).div_ceil(3);

#[derive(Clone, Debug)]
pub struct WireFragment {
    pub line_time: String,
    pub transport_sender: String,
    pub message_id: String,
    pub index: usize,
    pub total: usize,
    pub payload: String,
}

/// Examines a raw log line. `None` means it has no KRYPT04MCG prefix and is
/// unrelated. `Some(Err(_))` means it looks like a fragment but is malformed.
pub fn parse_fragment_line(line: &str) -> Option<Result<WireFragment, String>> {
    let prefix_start = line.find(PREFIX)?;
    let after_prefix = &line[prefix_start + PREFIX.len()..];
    let body = after_prefix.strip_prefix(' ').unwrap_or(after_prefix);

    let mut parts = body.split_ascii_whitespace();
    let Some(message_id) = parts.next() else {
        return Some(Err("前缀后缺少消息 ID".to_owned()));
    };
    let Some(index) = parts.next() else {
        return Some(Err("分片缺少索引".to_owned()));
    };
    let Some(total) = parts.next() else {
        return Some(Err("分片缺少总数".to_owned()));
    };
    let Some(payload) = parts.next() else {
        return Some(Err("分片缺少 Base64URL 载荷".to_owned()));
    };
    if parts.next().is_some() {
        return Some(Err("分片载荷后存在多余字段".to_owned()));
    }

    if message_id.len() != 32 || !message_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Some(Err(format!("消息 ID 必须是 32 位十六进制：{message_id:?}")));
    }
    let Ok(index) = index.parse::<usize>() else {
        return Some(Err(format!("分片索引不是十进制整数：{index:?}")));
    };
    let Ok(total) = total.parse::<usize>() else {
        return Some(Err(format!("分片总数不是十进制整数：{total:?}")));
    };
    if total == 0 || total > MAX_FRAGMENTS {
        return Some(Err(format!(
            "分片总数必须在 1..={MAX_FRAGMENTS} 之间，实际为 {total}"
        )));
    }
    if index >= total {
        return Some(Err(format!("分片索引越界：{index}/{total}")));
    }
    if !payload
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Some(Err("分片载荷包含非 Base64URL 字符".to_owned()));
    }
    if payload.len() > MAX_ENCODED_PACKET_CHARS {
        return Some(Err("分片载荷超过协议编码上限".to_owned()));
    }

    let line_time = line
        .strip_prefix('[')
        .and_then(|rest| rest.split_once(']'))
        .map(|(time, _)| time.trim().to_owned())
        .unwrap_or_default();

    Some(Ok(WireFragment {
        line_time,
        transport_sender: sender_before(line, prefix_start),
        message_id: message_id.to_ascii_lowercase(),
        index,
        total,
        payload: payload.to_owned(),
    }))
}

fn sender_before(line: &str, prefix_start: usize) -> String {
    let before = &line[..prefix_start];
    let Some(close) = before.rfind('>') else {
        return "(未绑定)".to_owned();
    };
    let Some(open) = before[..close].rfind('<') else {
        return "(未绑定)".to_owned();
    };
    let name = before[open + 1..close].trim();
    if name.is_empty() || name.contains('<') || name.contains('>') {
        "(未绑定)".to_owned()
    } else {
        name.to_owned()
    }
}

/// Incrementally groups fragments by transport sender + message ID and
/// reassembles complete groups. Duplicate and conflicting lines are retained
/// for display and export rather than silently discarded.
#[derive(Default)]
pub struct GroupAccumulator {
    builders: Vec<GroupBuilder>,
    by_key: HashMap<(String, String), usize>,
    order: usize,
}

impl GroupAccumulator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_occurrence(
        &mut self,
        transport_sender: &str,
        message_id: &str,
        occurrence: FragmentOccurrence,
    ) {
        let key = (
            transport_sender.to_ascii_lowercase(),
            message_id.to_ascii_lowercase(),
        );
        let builder_index = if let Some(index) = self.by_key.get(&key) {
            *index
        } else {
            let index = self.builders.len();
            self.by_key.insert(key, index);
            self.builders.push(GroupBuilder::new(
                transport_sender.to_owned(),
                message_id.to_ascii_lowercase(),
                occurrence.total,
                occurrence.timestamp.clone(),
                self.order,
            ));
            index
        };
        self.order += 1;
        self.builders[builder_index].add_occurrence(occurrence);
    }

    pub fn finish(self) -> Vec<FragmentGroup> {
        self.builders
            .into_iter()
            .map(GroupBuilder::finish)
            .collect()
    }
}

struct GroupBuilder {
    message_id: String,
    transport_sender: String,
    total: usize,
    slots: std::collections::BTreeMap<usize, FragmentSlot>,
    first_seen: LogTimestamp,
    last_seen: LogTimestamp,
    first_order: usize,
    duplicate_count: usize,
    conflicts: usize,
    total_conflict: bool,
    warnings: Vec<String>,
}

impl GroupBuilder {
    fn new(
        transport_sender: String,
        message_id: String,
        total: usize,
        first_seen: LogTimestamp,
        first_order: usize,
    ) -> Self {
        Self {
            message_id,
            transport_sender,
            total,
            slots: Default::default(),
            last_seen: first_seen.clone(),
            first_seen,
            first_order,
            duplicate_count: 0,
            conflicts: 0,
            total_conflict: false,
            warnings: Vec::new(),
        }
    }

    pub fn add_occurrence(&mut self, occurrence: FragmentOccurrence) {
        if occurrence.timestamp.text > self.last_seen.text {
            self.last_seen = occurrence.timestamp.clone();
        }
        if occurrence.total != self.total {
            self.total_conflict = true;
            self.conflicts += 1;
            self.warnings.push(format!(
                "同一消息 ID 出现不同的分片总数：先见 {}，本行 {}",
                self.total, occurrence.total
            ));
        }
        if occurrence.index >= self.total {
            self.total_conflict = true;
            self.conflicts += 1;
            self.warnings.push(format!(
                "分片索引 {} 超出首个分片声明的总数 {}",
                occurrence.index, self.total
            ));
        }
        if let Some(existing) = self.slots.get_mut(&occurrence.index) {
            if existing.payload == occurrence.payload {
                self.duplicate_count += 1;
            } else {
                self.conflicts += 1;
                self.warnings.push(format!(
                    "同一分片索引 {} 出现不同载荷（保留首次出现的载荷）",
                    occurrence.index
                ));
            }
            existing.occurrences.push(occurrence);
        } else {
            self.slots.insert(
                occurrence.index,
                FragmentSlot {
                    payload: occurrence.payload.clone(),
                    occurrences: vec![occurrence],
                },
            );
        }
    }

    fn finish(self) -> FragmentGroup {
        let complete = !self.total_conflict
            && self.slots.len() == self.total
            && (0..self.total).all(|index| self.slots.contains_key(&index));

        let mut group = FragmentGroup {
            message_id: self.message_id,
            transport_sender: self.transport_sender,
            total: self.total,
            slots: self.slots,
            first_seen: self.first_seen,
            last_seen: self.last_seen,
            first_order: self.first_order,
            duplicate_count: self.duplicate_count,
            conflicts: self.conflicts,
            warnings: self.warnings,
            binary: None,
            packet: None,
            status: MessageStatus::Incomplete,
            decryption: None,
        };

        if self.total_conflict {
            group.status = MessageStatus::Invalid;
            group
                .warnings
                .push("分片总数冲突，无法安全重组二进制包".to_owned());
            return group;
        }
        if !complete {
            group.status = MessageStatus::Incomplete;
            return group;
        }

        let encoded: String = (0..group.total)
            .filter_map(|index| group.slots.get(&index))
            .map(|slot| slot.payload.as_str())
            .collect();
        if encoded.len() > MAX_ENCODED_PACKET_CHARS {
            group.status = MessageStatus::Invalid;
            group
                .warnings
                .push("完整 Base64URL 载荷超过 349,526 字符上限".to_owned());
            return group;
        }

        let binary = match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&encoded) {
            Ok(binary) => binary,
            Err(error) => {
                group.status = MessageStatus::Invalid;
                group.warnings.push(format!("Base64URL 解码失败：{error}"));
                return group;
            }
        };
        if binary.len() > MAX_PACKET_BYTES {
            group.status = MessageStatus::Invalid;
            group.warnings.push(format!(
                "重组后的二进制包为 {} 字节，超过 {} 字节上限",
                binary.len(),
                MAX_PACKET_BYTES
            ));
            return group;
        }

        let packet = parse_packet(&binary);
        if let Some(error) = &packet.error {
            group.status = MessageStatus::Invalid;
            group
                .warnings
                .push(format!("二进制包结构解析失败：{error}"));
        } else {
            group.status = MessageStatus::Parsed;
        }

        if group.conflicts > 0 {
            group.status = MessageStatus::Invalid;
        }
        if !packet.message_id_hex.is_empty()
            && !packet
                .message_id_hex
                .eq_ignore_ascii_case(&group.message_id)
        {
            group.warnings.push(format!(
                "分片 ID {} 与包内 messageId {} 不一致",
                group.message_id, packet.message_id_hex
            ));
        }
        if !group.transport_sender.starts_with('(')
            && !packet.sender.eq_ignore_ascii_case(&group.transport_sender)
        {
            group.warnings.push(format!(
                "日志传输发送者 {} 与包内 sender {} 不一致",
                group.transport_sender, packet.sender
            ));
        }
        for warning in &packet.warnings {
            group.warnings.push(format!("包结构警告：{warning}"));
        }

        group.binary = Some(binary);
        group.packet = Some(packet);
        group
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::FragmentOccurrence;

    fn occurrence(index: usize, total: usize, payload: &str) -> FragmentOccurrence {
        FragmentOccurrence {
            source_path: "/tmp/latest.log".to_owned(),
            source_name: "latest.log".to_owned(),
            line: index + 1,
            timestamp: LogTimestamp {
                text: format!("2026-10-21 23:18:{index:02}"),
                date: Some("2026-10-21".to_owned()),
                time: format!("23:18:{index:02}"),
            },
            index,
            total,
            payload: payload.to_owned(),
            payload_length: payload.len(),
        }
    }

    #[test]
    fn parses_standard_fragment_line() {
        let line = "[23:18:08] [Server thread/INFO]: [Not Secure] <tester> [KRYPT04MCG] 9F0EE31E296A77EB87FD73A3E8CCEDEB 0 10 BAECAAZmb2VyZGk";
        let parsed = parse_fragment_line(line).unwrap().unwrap();
        assert_eq!(parsed.transport_sender, "tester");
        assert_eq!(parsed.message_id, "9f0ee31e296a77eb87fd73a3e8ccedeb");
        assert_eq!(parsed.index, 0);
        assert_eq!(parsed.total, 10);
        assert_eq!(parsed.line_time, "23:18:08");
    }

    #[test]
    fn rejects_bad_fragments() {
        for line in [
            "[KRYPT04MCG] zzz 0 10 abc",
            "[KRYPT04MCG] 0123456789abcdef0123456789abcdef 10 10 abc",
            "[KRYPT04MCG] 0123456789abcdef0123456789abcdef 0 0 abc",
            "[KRYPT04MCG] 0123456789abcdef0123456789abcdef 0 10 a+b",
            "[KRYPT04MCG] 0123456789abcdef0123456789abcdef 0 10 abc extra",
        ] {
            assert!(parse_fragment_line(line).unwrap().is_err(), "{line}");
        }
    }

    #[test]
    fn ignores_unrelated_lines() {
        assert!(parse_fragment_line("[INFO] hello").is_none());
    }

    #[test]
    fn accumulates_duplicates_and_missing_fragments() {
        // "AA" and "AQ" decode to 0x00 and 0x01, but this deliberately is not
        // a valid packet; we only verify grouping status.
        let mut accumulator = GroupAccumulator::new();
        for occurrence in [
            occurrence(0, 2, "AA"),
            occurrence(1, 2, "AQ"),
            occurrence(1, 2, "AQ"),
        ] {
            accumulator.add_occurrence("tester", "0123456789abcdef0123456789abcdef", occurrence);
        }
        let groups = accumulator.finish();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].unique_fragments(), 2);
        assert_eq!(groups[0].duplicate_count, 1);
        assert_eq!(groups[0].status, MessageStatus::Invalid); // 2-byte packet
        assert!(groups[0].binary.is_some());
    }
}
