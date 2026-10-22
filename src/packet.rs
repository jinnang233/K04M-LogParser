//! Structural parser for the Krypt04Mcg encrypted-packet wire format.
//!
//! This module reproduces the byte layout from Krypt04Mcg's `PacketCodec`.
//! It deliberately does not verify signatures or decrypt payloads: those
//! operations require private key material that is not present in chat logs.

use chrono::{DateTime, Local, Utc};

use crate::model::{Algorithms, DataField, ParsedPacket};

pub const MAX_PACKET_BYTES: usize = 256 * 1024;
const MAX_STRING_BYTES: usize = 4096;
const MAX_FIELD_BYTES: usize = 1024 * 1024;
const FLAG_SIGNED: u8 = 0x01;
const FLAG_COMPRESSED: u8 = 0x02;
const FLAG_SESSION_RESPONSE: u8 = 0x04;
const KNOWN_FLAGS: u8 = FLAG_SIGNED | FLAG_COMPRESSED | FLAG_SESSION_RESPONSE;

// Palette categories shared with the hex view.
pub const CAT_HEADER: u8 = 0;
pub const CAT_SENDER: u8 = 1;
pub const CAT_RECEIVER: u8 = 2;
pub const CAT_TIMESTAMP: u8 = 3;
pub const CAT_MESSAGE_ID: u8 = 4;
pub const CAT_SESSION: u8 = 5;
pub const CAT_ALGORITHMS: u8 = 6;
pub const CAT_NONCE: u8 = 7;
pub const CAT_KEM_CIPHERTEXT: u8 = 8;
pub const CAT_CIPHERTEXT: u8 = 9;
pub const CAT_SIGNATURE: u8 = 10;
pub const CAT_RAW: u8 = 11;

#[derive(Debug)]
struct ParseError {
    pos: usize,
    message: String,
}

impl ParseError {
    fn new(pos: usize, message: impl Into<String>) -> Self {
        Self {
            pos,
            message: message.into(),
        }
    }
}

type ParseResult<T> = Result<T, ParseError>;

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn take(&mut self, count: usize) -> ParseResult<&'a [u8]> {
        let end = self
            .pos
            .checked_add(count)
            .ok_or_else(|| ParseError::new(self.pos, "字段长度溢出"))?;
        if end > self.data.len() {
            return Err(ParseError::new(
                self.pos,
                format!(
                    "数据被截断：需要 {count} 字节，只剩 {} 字节",
                    self.remaining()
                ),
            ));
        }
        let bytes = &self.data[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> ParseResult<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> ParseResult<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn i64(&mut self) -> ParseResult<i64> {
        let bytes = self.take(8)?;
        Ok(i64::from_be_bytes(bytes.try_into().expect("8-byte slice")))
    }

    fn i32(&mut self) -> ParseResult<i32> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes(bytes.try_into().expect("4-byte slice")))
    }

    fn string16(&mut self) -> ParseResult<(String, usize, usize)> {
        let start = self.pos;
        let length = self.u16()? as usize;
        if length > MAX_STRING_BYTES {
            return Err(ParseError::new(
                start,
                format!("字符串字段过长：{length} 字节（上限 {MAX_STRING_BYTES}）"),
            ));
        }
        let bytes = self.take(length)?;
        let text = std::str::from_utf8(bytes)
            .map_err(|_| ParseError::new(start + 2, "字符串字段不是合法 UTF-8"))?
            .to_owned();
        Ok((text, start, self.pos - start))
    }

    fn bytes16(&mut self) -> ParseResult<(usize, usize, usize, usize)> {
        let start = self.pos;
        let length = self.u16()? as usize;
        let data_start = self.pos;
        self.take(length)?;
        Ok((start, self.pos - start, data_start, length))
    }

    /// Reads a Java `DataOutputStream.writeInt` length followed by that many
    /// bytes. Returns `(length_prefix_start, total_length, data_start, data_len)`.
    fn bytes32(&mut self) -> ParseResult<(usize, usize, usize, usize)> {
        let start = self.pos;
        let length = self.i32()?;
        if length < 0 {
            return Err(ParseError::new(start, "字节字段长度为负数"));
        }
        let length = length as usize;
        if length > MAX_FIELD_BYTES {
            return Err(ParseError::new(
                start,
                format!("字节字段过长：{length} 字节（上限 {MAX_FIELD_BYTES}）"),
            ));
        }
        let data_start = self.pos;
        self.take(length)?;
        Ok((start, self.pos - start, data_start, length))
    }
}

/// Parses a complete reassembled packet. On failure the returned value still
/// contains every field decoded before the error plus an `unparsed` field, so
/// the GUI and JSON export can inspect partial data.
pub fn parse_packet(data: &[u8]) -> ParsedPacket {
    let mut packet = ParsedPacket::default();
    if data.len() > MAX_PACKET_BYTES {
        packet.error = Some(format!(
            "数据包为 {} 字节，超过协议上限 {} 字节",
            data.len(),
            MAX_PACKET_BYTES
        ));
        packet.error_offset = Some(0);
        packet.fields.push(raw_field(
            "oversized_packet",
            "超限数据包",
            0,
            data,
            "整包超过协议上限",
            CAT_RAW,
        ));
        return packet;
    }

    match parse_inner(data, &mut packet) {
        Ok(consumed) => {
            packet.consumed = consumed;
            if consumed < data.len() {
                packet.trailing = data.len() - consumed;
                packet.error = Some(format!(
                    "包头结束后仍有 {} 个尾随字节（PacketCodec 会拒绝该包）",
                    packet.trailing
                ));
                packet.error_offset = Some(consumed);
                packet.fields.push(raw_field(
                    "trailing_bytes",
                    "未解析的尾随字节",
                    consumed,
                    &data[consumed..],
                    "Java PacketCodec 要求精确消费全部字节",
                    CAT_RAW,
                ));
            }
        }
        Err(error) => {
            packet.error = Some(error.message);
            packet.error_offset = Some(error.pos.min(data.len()));
            packet.consumed = error.pos.min(data.len());
            packet.trailing = data.len().saturating_sub(packet.consumed);
            if packet.consumed < data.len() {
                packet.fields.push(raw_field(
                    "unparsed_bytes",
                    "错误位置之后的原始字节",
                    packet.consumed,
                    &data[packet.consumed..],
                    "解析停止位置之后的全部数据",
                    CAT_RAW,
                ));
            }
        }
    }

    if packet.error.is_none() {
        add_cross_field_warnings(&mut packet);
    }
    packet
}

fn parse_inner(data: &[u8], packet: &mut ParsedPacket) -> ParseResult<usize> {
    let mut cursor = Cursor::new(data);

    let version_offset = cursor.pos;
    let version = cursor.u8().map_err(|error| {
        if data.is_empty() {
            ParseError::new(0, "数据包为空")
        } else {
            error
        }
    })?;
    packet.protocol_version = Some(version);
    packet.fields.push(DataField {
        name: "protocol_version".to_owned(),
        label: "协议版本".to_owned(),
        offset: version_offset,
        length: 1,
        value: format!(
            "{version}{}",
            match version {
                1 => " (LEGACY)",
                2 => " (PREVIOUS)",
                3 => " (COMPACT)",
                4 => " (CURRENT / SESSION V4)",
                _ => " (不支持)",
            }
        ),
        hex: Some(hex(&data[version_offset..version_offset + 1])),
        note: (version > 4).then(|| "本解析器按已知的 1–4 版布局工作".to_owned()),
        category: CAT_HEADER,
        children: Vec::new(),
    });
    if !(1..=4).contains(&version) {
        return Err(ParseError::new(
            version_offset,
            format!("不支持的协议版本：{version}"),
        ));
    }

    let type_offset = cursor.pos;
    let packet_type = cursor.u8()?;
    packet.packet_type = Some(packet_type);
    packet.packet_type_name = packet_type_name(packet_type).to_owned();
    packet.fields.push(DataField {
        name: "packet_type".to_owned(),
        label: "包类型".to_owned(),
        offset: type_offset,
        length: 1,
        value: format!("{packet_type} ({})", packet_type_name(packet_type)),
        hex: Some(hex(&data[type_offset..type_offset + 1])),
        note: None,
        category: CAT_HEADER,
        children: Vec::new(),
    });
    if packet_type_name(packet_type) == "UNKNOWN" {
        return Err(ParseError::new(
            type_offset,
            format!("未知包类型：{packet_type}"),
        ));
    }

    let flags_offset = cursor.pos;
    let flags = cursor.u8()?;
    packet.flags = Some(flags);
    packet.flag_names = flag_names(flags);
    let mut flag_children = Vec::new();
    for (bit, name, chinese) in [
        (FLAG_SIGNED, "SIGNED", "包含签名"),
        (FLAG_COMPRESSED, "COMPRESSED", "加密前已 zlib 压缩"),
        (FLAG_SESSION_RESPONSE, "SESSION_RESPONSE", "会话交换响应"),
    ] {
        if flags & bit != 0 {
            flag_children.push(DataField {
                name: format!("flags.{}", name.to_ascii_lowercase()),
                label: chinese.to_owned(),
                offset: flags_offset,
                length: 1,
                value: format!("{name} (0x{bit:02X})"),
                hex: None,
                note: None,
                category: CAT_HEADER,
                children: Vec::new(),
            });
        }
    }
    let unknown_flags = flags & !KNOWN_FLAGS;
    if unknown_flags != 0 {
        flag_children.push(DataField {
            name: "flags.unknown".to_owned(),
            label: "未知标志位".to_owned(),
            offset: flags_offset,
            length: 1,
            value: format!("0x{unknown_flags:02X}"),
            hex: None,
            note: Some("Krypt04Mcg 的当前实现会拒绝未知标志位".to_owned()),
            category: CAT_HEADER,
            children: Vec::new(),
        });
    }
    packet.fields.push(DataField {
        name: "flags".to_owned(),
        label: "标志位".to_owned(),
        offset: flags_offset,
        length: 1,
        value: format_flags(flags),
        hex: Some(hex(&data[flags_offset..flags_offset + 1])),
        note: (flags & unknown_flags != 0).then(|| "包含未知标志位".to_owned()),
        category: CAT_HEADER,
        children: flag_children,
    });

    let (sender, sender_offset, sender_length) = read_string_field(
        &mut cursor,
        packet,
        "sender",
        "发送者 (sender)",
        CAT_SENDER,
        None,
    )?;
    packet.sender = sender;
    let _ = (sender_offset, sender_length);

    let (receiver, receiver_offset, receiver_length) = read_string_field(
        &mut cursor,
        packet,
        "receiver",
        "接收者 (receiver)",
        CAT_RECEIVER,
        None,
    )?;
    packet.receiver = receiver;
    let _ = (receiver_offset, receiver_length);

    let timestamp_offset = cursor.pos;
    let timestamp = cursor.i64()?;
    packet.timestamp_millis = Some(timestamp);
    let (utc_text, local_text) = format_timestamp(timestamp);
    packet.timestamp_utc = Some(utc_text.clone());
    packet.timestamp_local = Some(local_text.clone());
    packet.fields.push(DataField {
        name: "timestamp_millis".to_owned(),
        label: "时间戳".to_owned(),
        offset: timestamp_offset,
        length: 8,
        value: format!("{local_text} / {utc_text}"),
        hex: Some(hex(&data[timestamp_offset..timestamp_offset + 8])),
        note: Some(format!("Unix 毫秒：{timestamp}")),
        category: CAT_TIMESTAMP,
        children: Vec::new(),
    });

    let message_id_offset = cursor.pos;
    let message_id = cursor.take(16)?;
    let message_id_hex = hex(message_id);
    packet.message_id_hex = message_id_hex.clone();
    packet.fields.push(DataField {
        name: "message_id".to_owned(),
        label: "消息 ID".to_owned(),
        offset: message_id_offset,
        length: 16,
        value: message_id_hex.clone(),
        hex: Some(message_id_hex),
        note: Some("分片头中的 32 位十六进制 ID 对应的 16 字节值".to_owned()),
        category: CAT_MESSAGE_ID,
        children: Vec::new(),
    });

    let session_v4 = version >= 4 && packet_type == 4;
    if session_v4 {
        let session_start = cursor.pos;
        let (session_id, _, _) = read_string_field(
            &mut cursor,
            packet,
            "session_id",
            "会话 ID (sessionId)",
            CAT_SESSION,
            Some("16 字节会话标识的 Base64URL 文本"),
        )?;
        packet.session_id = Some(session_id);

        let sequence_offset = cursor.pos;
        let sequence = cursor.i64()?;
        packet.sequence = Some(sequence);
        packet.fields.push(DataField {
            name: "sequence".to_owned(),
            label: "会话序号 (sequence)".to_owned(),
            offset: sequence_offset,
            length: 8,
            value: sequence.to_string(),
            hex: Some(hex(&data[sequence_offset..sequence_offset + 8])),
            note: Some("i64 大端；由 AEAD AAD 绑定".to_owned()),
            category: CAT_SESSION,
            children: Vec::new(),
        });
        // The string field was pushed as a sibling; wrap the two session fields
        // under one selectable group without changing their byte ranges.
        let split_at = packet.fields.len().saturating_sub(2);
        if split_at >= 1 {
            let session_id_field = packet.fields.remove(split_at);
            let sequence_field = packet.fields.pop().expect("sequence field exists");
            packet.fields.insert(
                split_at,
                DataField {
                    name: "session".to_owned(),
                    label: "会话元数据".to_owned(),
                    offset: session_start,
                    length: cursor.pos - session_start,
                    value: format!(
                        "{}{}",
                        session_id_field.value,
                        sequence_field
                            .value
                            .parse::<i64>()
                            .map(|value| format!(" / seq {value}"))
                            .unwrap_or_default()
                    ),
                    hex: None,
                    note: Some("仅 SESSION_MESSAGE (type 4) 携带".to_owned()),
                    category: CAT_SESSION,
                    children: vec![session_id_field, sequence_field],
                },
            );
        }
    } else if version < 3 {
        let fragment_start = cursor.pos;
        let index = cursor.u16()?;
        packet.fields.push(DataField {
            name: "aad_fragment_index".to_owned(),
            label: "AAD 分片索引（旧版）".to_owned(),
            offset: fragment_start,
            length: 2,
            value: index.to_string(),
            hex: Some(hex(&data[fragment_start..fragment_start + 2])),
            note: Some("仅协议 v1/v2 编码".to_owned()),
            category: CAT_HEADER,
            children: Vec::new(),
        });
        let total_offset = cursor.pos;
        let total = cursor.u16()?;
        packet.fields.push(DataField {
            name: "aad_fragment_total".to_owned(),
            label: "AAD 分片总数（旧版）".to_owned(),
            offset: total_offset,
            length: 2,
            value: total.to_string(),
            hex: Some(hex(&data[total_offset..total_offset + 2])),
            note: Some(format!(
                "协议 v3 起删除此字段；旧字段范围 {}..{}",
                fragment_start, total_offset
            )),
            category: CAT_HEADER,
            children: Vec::new(),
        });
    }

    let algorithms_start = cursor.pos;
    let signed = flags & FLAG_SIGNED != 0;
    let include_kem = version < 3 || !session_v4;
    let include_signature = version < 3 || (signed && !session_v4);

    let kem_part = if include_kem {
        Some(read_string_value(&mut cursor, "KEM 算法")?)
    } else {
        None
    };
    let signature_part = if include_signature {
        Some(read_string_value(&mut cursor, "签名算法")?)
    } else {
        None
    };
    let aead_part = read_string_value(&mut cursor, "AEAD 算法")?;
    let hkdf_part = read_string_value(&mut cursor, "HKDF")?;

    let kem_value = kem_part.as_ref().map(|part| part.0.clone());
    let signature_value = signature_part.as_ref().map(|part| part.0.clone());
    let aead_value = aead_part.0.clone();
    let hkdf_value = hkdf_part.0.clone();
    let algorithms_end = cursor.pos;

    packet.algorithms = Algorithms {
        kem: kem_value.clone().unwrap_or_else(|| "NONE".to_owned()),
        signature: signature_value.clone().unwrap_or_else(|| "NONE".to_owned()),
        aead: aead_value.clone(),
        hkdf: hkdf_value.clone(),
    };

    let mut algorithm_children = Vec::new();
    if let Some((kem, kem_offset, _)) = &kem_part {
        algorithm_children.push(string_field(
            "algorithms.kem",
            "KEM",
            *kem_offset,
            kem,
            CAT_ALGORITHMS,
        ));
    } else {
        algorithm_children.push(absent_string_field(
            "algorithms.kem",
            "KEM",
            algorithms_start,
            "NONE（会话消息不编码此字段）",
        ));
    }
    if let Some((signature, signature_offset, _)) = &signature_part {
        algorithm_children.push(string_field(
            "algorithms.signature",
            "签名",
            *signature_offset,
            signature,
            CAT_ALGORITHMS,
        ));
    } else {
        algorithm_children.push(absent_string_field(
            "algorithms.signature",
            "签名",
            algorithms_start,
            if session_v4 {
                "NONE（会话消息不编码此字段）"
            } else {
                "NONE（无签名标志，字段省略）"
            },
        ));
    }
    algorithm_children.push(string_field(
        "algorithms.aead",
        "AEAD",
        aead_part.1,
        &aead_value,
        CAT_ALGORITHMS,
    ));
    algorithm_children.push(string_field(
        "algorithms.hkdf",
        "HKDF",
        hkdf_part.1,
        &hkdf_value,
        CAT_ALGORITHMS,
    ));
    packet.fields.push(DataField {
        name: "algorithms".to_owned(),
        label: "算法套件".to_owned(),
        offset: algorithms_start,
        length: algorithms_end - algorithms_start,
        value: format!(
            "{} / {} / {} / {}",
            packet.algorithms.kem,
            packet.algorithms.signature,
            packet.algorithms.aead,
            packet.algorithms.hkdf
        ),
        hex: None,
        note: None,
        category: CAT_ALGORITHMS,
        children: algorithm_children,
    });

    let (nonce_start, nonce_total, nonce_data_start, nonce_len) = cursor.bytes16()?;
    packet.nonce_len = nonce_len;
    packet.fields.push(byte_field(
        "nonce",
        "Nonce",
        nonce_start,
        nonce_total,
        nonce_data_start,
        nonce_len,
        data,
        CAT_NONCE,
        (nonce_len != 12)
            .then(|| format!("AES-GCM/ChaCha20 通常使用 12 字节 nonce，这里是 {nonce_len} 字节")),
        2,
    ));

    let (kem_start, kem_total, kem_data_start, kem_len) = cursor.bytes32()?;
    packet.kem_ciphertext_len = kem_len;
    let kem_note = if kem_len == 0 {
        Some("会话消息不携带 KEM 封装".to_owned())
    } else if packet.algorithms.kem.contains('+') {
        Some(format!(
            "混合 KEM 封装共 {kem_len} 字节；内部各分量由 Bouncy Castle 复合封装定义"
        ))
    } else {
        None
    };
    packet.fields.push(byte_field(
        "kem_ciphertext",
        "KEM 封装密文",
        kem_start,
        kem_total,
        kem_data_start,
        kem_len,
        data,
        CAT_KEM_CIPHERTEXT,
        kem_note,
        4,
    ));

    let (cipher_start, cipher_total, cipher_data_start, cipher_len) = cursor.bytes32()?;
    packet.ciphertext_len = cipher_len;
    let uses_aead_tag = has_aead_tag(&packet.algorithms.aead) && cipher_len >= 16;
    let mut cipher_children = vec![length_field(
        "ciphertext.length",
        "长度前缀",
        cipher_start,
        4,
        data,
        CAT_CIPHERTEXT,
    )];
    let mut cipher_note = None;
    if uses_aead_tag {
        let body_len = cipher_len - 16;
        cipher_children.push(DataField {
            name: "ciphertext.encrypted_body".to_owned(),
            label: "加密正文".to_owned(),
            offset: cipher_data_start,
            length: body_len,
            value: format!("{body_len} 字节"),
            hex: Some(hex(&data[cipher_data_start..cipher_data_start + body_len])),
            note: (flags & FLAG_COMPRESSED != 0)
                .then(|| "标志位 COMPRESSED 已设置；AEAD 解密后还需 zlib 解压".to_owned()),
            category: CAT_CIPHERTEXT,
            children: Vec::new(),
        });
        let tag_start = cipher_data_start + body_len;
        cipher_children.push(DataField {
            name: "ciphertext.auth_tag".to_owned(),
            label: "AEAD 认证标签".to_owned(),
            offset: tag_start,
            length: 16,
            value: "16 字节".to_owned(),
            hex: Some(hex(&data[tag_start..tag_start + 16])),
            note: Some(format!("{} 的 128 位认证标签", packet.algorithms.aead)),
            category: CAT_CIPHERTEXT,
            children: Vec::new(),
        });
        cipher_note = Some(format!(
            "{cipher_len} 字节 = {} 字节加密正文 + 16 字节认证标签",
            body_len
        ));
    } else {
        cipher_children.push(raw_field(
            "ciphertext.data",
            "密文数据",
            cipher_data_start,
            &data[cipher_data_start..cipher_data_start + cipher_len],
            "未按已知 AEAD 格式拆分",
            CAT_CIPHERTEXT,
        ));
    }
    packet.fields.push(DataField {
        name: "ciphertext".to_owned(),
        label: "AEAD 密文".to_owned(),
        offset: cipher_start,
        length: cipher_total,
        value: if uses_aead_tag {
            format!("{cipher_len} 字节（含 16 字节认证标签）")
        } else {
            format!("{cipher_len} 字节")
        },
        hex: None,
        note: cipher_note,
        category: CAT_CIPHERTEXT,
        children: cipher_children,
    });

    if !session_v4 {
        let (signature_start, signature_total, signature_data_start, signature_len) =
            cursor.bytes32()?;
        packet.signature_len = signature_len;
        let signature_note = if signature_len == 0 {
            if signed {
                Some("SIGNED 标志已设置，但签名为空".to_owned())
            } else {
                Some("未签名包".to_owned())
            }
        } else if packet.algorithms.signature.contains('+') {
            Some(format!(
                "混合签名共 {signature_len} 字节；内部各分量由 Bouncy Castle 复合签名定义"
            ))
        } else {
            None
        };
        packet.fields.push(byte_field(
            "signature",
            "签名",
            signature_start,
            signature_total,
            signature_data_start,
            signature_len,
            data,
            CAT_SIGNATURE,
            signature_note,
            4,
        ));
    }

    Ok(cursor.pos)
}

fn packet_type_name(packet_type: u8) -> &'static str {
    match packet_type {
        1 => "KEM_MESSAGE",
        2 => "SIGNED_KEM_MESSAGE",
        3 => "SESSION_EXCHANGE",
        4 => "SESSION_MESSAGE",
        _ => "UNKNOWN",
    }
}

pub fn packet_type_chinese(packet_type: u8) -> &'static str {
    match packet_type {
        1 => "KEM 加密消息",
        2 => "签名 KEM 消息",
        3 => "会话交换",
        4 => "会话消息",
        _ => "未知类型",
    }
}

fn flag_names(flags: u8) -> Vec<String> {
    let mut names = Vec::new();
    if flags & FLAG_SIGNED != 0 {
        names.push("SIGNED".to_owned());
    }
    if flags & FLAG_COMPRESSED != 0 {
        names.push("COMPRESSED".to_owned());
    }
    if flags & FLAG_SESSION_RESPONSE != 0 {
        names.push("SESSION_RESPONSE".to_owned());
    }
    let unknown = flags & !KNOWN_FLAGS;
    if unknown != 0 {
        names.push(format!("UNKNOWN(0x{unknown:02X})"));
    }
    names
}

fn format_flags(flags: u8) -> String {
    let names = flag_names(flags);
    if names.is_empty() {
        format!("0x{flags:02X} (无)")
    } else {
        format!("0x{flags:02X} ({})", names.join(", "))
    }
}

fn read_string_value(
    cursor: &mut Cursor<'_>,
    field_name: &str,
) -> ParseResult<(String, usize, usize)> {
    let (value, start, length) = cursor.string16().map_err(|mut error| {
        error.message = format!("读取{field_name}失败：{}", error.message);
        error
    })?;
    Ok((value, start, length))
}

fn read_string_field(
    cursor: &mut Cursor<'_>,
    packet: &mut ParsedPacket,
    name: &str,
    label: &str,
    category: u8,
    note: Option<&str>,
) -> ParseResult<(String, usize, usize)> {
    let (value, start, length) = cursor.string16().map_err(|mut error| {
        error.message = format!("读取{label}失败：{}", error.message);
        error
    })?;
    packet.fields.push(string_field_with_note(
        name, label, start, &value, category, note,
    ));
    Ok((value, start, length))
}

fn string_field(name: &str, label: &str, start: usize, value: &str, category: u8) -> DataField {
    string_field_with_note(name, label, start, value, category, None)
}

fn string_field_with_note(
    name: &str,
    label: &str,
    start: usize,
    value: &str,
    category: u8,
    note: Option<&str>,
) -> DataField {
    let length = 2 + value.len();
    DataField {
        name: name.to_owned(),
        label: label.to_owned(),
        offset: start,
        length,
        value: value.to_owned(),
        hex: None,
        note: note.map(str::to_owned),
        category,
        children: vec![
            DataField {
                name: format!("{name}.length"),
                label: "长度前缀".to_owned(),
                offset: start,
                length: 2,
                value: value.len().to_string(),
                hex: None,
                note: Some("u16 大端 UTF-8 字节数".to_owned()),
                category,
                children: Vec::new(),
            },
            DataField {
                name: format!("{name}.utf8"),
                label: "UTF-8 文本".to_owned(),
                offset: start + 2,
                length: value.len(),
                value: value.to_owned(),
                hex: Some(hex(value.as_bytes())),
                note: None,
                category,
                children: Vec::new(),
            },
        ],
    }
}

fn absent_string_field(name: &str, label: &str, offset: usize, value: &str) -> DataField {
    DataField {
        name: name.to_owned(),
        label: label.to_owned(),
        offset,
        length: 0,
        value: value.to_owned(),
        hex: None,
        note: Some("该字段在当前包布局中不存在，不占用字节".to_owned()),
        category: CAT_ALGORITHMS,
        children: Vec::new(),
    }
}

fn length_field(
    name: &str,
    label: &str,
    start: usize,
    prefix_len: usize,
    data: &[u8],
    category: u8,
) -> DataField {
    let end = start.saturating_add(prefix_len);
    let (value, note) = if end <= data.len() && prefix_len == 2 {
        (
            u16::from_be_bytes([data[start], data[start + 1]]).to_string(),
            "u16 大端",
        )
    } else if end <= data.len() && prefix_len == 4 {
        (
            i32::from_be_bytes(data[start..end].try_into().expect("4-byte slice")).to_string(),
            "i32 大端",
        )
    } else {
        ("?".to_owned(), "长度前缀")
    };
    DataField {
        name: name.to_owned(),
        label: label.to_owned(),
        offset: start,
        length: prefix_len,
        value,
        hex: (end <= data.len()).then(|| hex(&data[start..end])),
        note: Some(note.to_owned()),
        category,
        children: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn byte_field(
    name: &str,
    label: &str,
    start: usize,
    total_length: usize,
    data_start: usize,
    data_len: usize,
    data: &[u8],
    category: u8,
    note: Option<String>,
    prefix_len: usize,
) -> DataField {
    let data_end = data_start.saturating_add(data_len);
    let safe_end = data_end.min(data.len());
    let mut children = vec![length_field(
        &format!("{name}.length"),
        "长度前缀",
        start,
        prefix_len,
        data,
        category,
    )];
    if data_start <= safe_end {
        children.push(DataField {
            name: format!("{name}.bytes"),
            label: "原始字节".to_owned(),
            offset: data_start,
            length: safe_end.saturating_sub(data_start),
            value: format!("{data_len} 字节"),
            hex: Some(hex(&data[data_start.min(data.len())..safe_end])),
            note: (!data.is_empty()).then(|| {
                format!(
                    "起始预览：{}",
                    hex_preview(&data[data_start.min(data.len())..safe_end], 24)
                )
            }),
            category,
            children: Vec::new(),
        });
    }
    DataField {
        name: name.to_owned(),
        label: label.to_owned(),
        offset: start,
        length: total_length,
        value: format!("{data_len} 字节"),
        hex: None,
        note,
        category,
        children,
    }
}

fn raw_field(
    name: &str,
    label: &str,
    start: usize,
    bytes: &[u8],
    note: &str,
    category: u8,
) -> DataField {
    DataField {
        name: name.to_owned(),
        label: label.to_owned(),
        offset: start,
        length: bytes.len(),
        value: format!("{} 字节", bytes.len()),
        hex: Some(hex(bytes)),
        note: Some(note.to_owned()),
        category,
        children: Vec::new(),
    }
}

fn has_aead_tag(aead: &str) -> bool {
    let upper = aead.to_ascii_uppercase();
    upper.contains("GCM") || upper.contains("CHACHA") || upper.contains("POLY1305")
}

fn add_cross_field_warnings(packet: &mut ParsedPacket) {
    let Some(flags) = packet.flags else {
        return;
    };
    let Some(packet_type) = packet.packet_type else {
        return;
    };
    let signed = flags & FLAG_SIGNED != 0;

    if flags & !KNOWN_FLAGS != 0 {
        packet
            .warnings
            .push(format!("标志位包含未知位：0x{:02X}", flags & !KNOWN_FLAGS));
    }
    if packet_type == 4 && signed {
        packet
            .warnings
            .push("会话消息不允许 SIGNED 标志".to_owned());
    }
    if packet_type != 3 && flags & FLAG_SESSION_RESPONSE != 0 {
        packet
            .warnings
            .push("SESSION_RESPONSE 只允许出现在 SESSION_EXCHANGE 包".to_owned());
    }
    if packet_type == 2 && !signed {
        packet
            .warnings
            .push("类型为 SIGNED_KEM_MESSAGE，但未设置 SIGNED 标志".to_owned());
    }
    if packet_type == 4 && packet.protocol_version.unwrap_or(0) < 4 {
        packet
            .warnings
            .push("SESSION_MESSAGE 只有协议 v4 布局；当前版本可能使用了旧格式".to_owned());
    }
    if signed && packet.signature_len == 0 && packet_type != 4 {
        packet
            .warnings
            .push("SIGNED 标志已设置，但签名字段为空".to_owned());
    }
    if !signed && packet.signature_len > 0 {
        packet
            .warnings
            .push("未设置 SIGNED 标志，但签名字段非空".to_owned());
    }
    if packet_type == 4 && packet.kem_ciphertext_len > 0 {
        packet.warnings.push("会话消息不应携带 KEM 封装".to_owned());
    }
    if packet.nonce_len != 12 {
        packet.warnings.push(format!(
            "nonce 长度为 {}，项目通常使用 12 字节",
            packet.nonce_len
        ));
    }
    if !packet.algorithms.hkdf.is_empty() && packet.algorithms.hkdf != "HKDF-SHA256" {
        packet.warnings.push(format!(
            "未知 HKDF 标识：{}（项目实现只支持 HKDF-SHA256）",
            packet.algorithms.hkdf
        ));
    }
    if let Some(timestamp) = packet.timestamp_millis
        && DateTime::<Utc>::from_timestamp_millis(timestamp).is_none()
    {
        packet
            .warnings
            .push("时间戳超出 chrono 可表示范围".to_owned());
    }
    if let Some(session_id) = &packet.session_id {
        use base64::Engine as _;
        match base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(session_id) {
            Ok(bytes) if bytes.len() == 16 => {}
            Ok(bytes) => packet.warnings.push(format!(
                "sessionId 解码后为 {} 字节，预期 16 字节",
                bytes.len()
            )),
            Err(_) => packet
                .warnings
                .push("sessionId 不是合法的无填充 Base64URL".to_owned()),
        }
    }
}

fn format_timestamp(millis: i64) -> (String, String) {
    let Some(utc) = DateTime::<Utc>::from_timestamp_millis(millis) else {
        return ("无效时间戳".to_owned(), "无效时间戳".to_owned());
    };
    let local = utc.with_timezone(&Local);
    (
        utc.format("%Y-%m-%d %H:%M:%S%.3f UTC").to_string(),
        local.format("%Y-%m-%d %H:%M:%S%.3f %:z").to_string(),
    )
}

pub fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub fn hex_preview(bytes: &[u8], limit: usize) -> String {
    let shown = bytes.len().min(limit);
    let mut text = hex(&bytes[..shown]);
    if shown < bytes.len() {
        text.push('…');
    }
    text
}

pub fn flatten_fields<'a>(fields: &'a [DataField], out: &mut Vec<FlatField<'a>>) {
    fn walk<'a>(
        fields: &'a [DataField],
        depth: usize,
        top_level: usize,
        out: &mut Vec<FlatField<'a>>,
    ) {
        for field in fields {
            out.push(FlatField {
                field,
                depth,
                top_level,
            });
            walk(&field.children, depth + 1, top_level, out);
        }
    }

    for (index, field) in fields.iter().enumerate() {
        out.push(FlatField {
            field,
            depth: 0,
            top_level: index,
        });
        walk(&field.children, 1, index, out);
    }
}

pub struct FlatField<'a> {
    pub field: &'a DataField,
    pub depth: usize,
    pub top_level: usize,
}

/// Builds a byte -> top-level-field-category map using the most specific
/// (deepest / last-written) field for each byte.
pub fn byte_categories(fields: &[DataField], len: usize) -> Vec<Option<u8>> {
    let mut categories = vec![None; len];
    fn walk(fields: &[DataField], categories: &mut [Option<u8>]) {
        for field in fields {
            let available = categories.len().saturating_sub(field.offset);
            let count = field.length.min(available);
            for slot in &mut categories[field.offset..field.offset + count] {
                *slot = Some(field.category);
            }
            walk(&field.children, categories);
        }
    }
    walk(fields, &mut categories);
    categories
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_string(out: &mut Vec<u8>, text: &str) {
        out.extend_from_slice(&(text.len() as u16).to_be_bytes());
        out.extend_from_slice(text.as_bytes());
    }

    fn push_bytes16(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn push_bytes32(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
        out.extend_from_slice(bytes);
    }

    fn sample_kem_packet() -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&[4, 1, 2]);
        push_string(&mut out, "tester");
        push_string(&mut out, "peer_abc123");
        out.extend_from_slice(&1_792_595_888_914_i64.to_be_bytes());
        out.extend_from_slice(&[
            0x9f, 0x0e, 0xe3, 0x1e, 0x29, 0x6a, 0x77, 0xeb, 0x87, 0xfd, 0x73, 0xa3, 0xe8, 0xcc,
            0xed, 0xeb,
        ]);
        push_string(&mut out, "ML-KEM-768+X25519");
        push_string(&mut out, "AES-256-GCM");
        push_string(&mut out, "HKDF-SHA256");
        push_bytes16(&mut out, &[1; 12]);
        push_bytes32(&mut out, &[2; 1120]);
        push_bytes32(&mut out, &[3; 20]);
        push_bytes32(&mut out, &[]);
        out
    }

    #[test]
    fn parses_kem_packet_and_offsets() {
        let data = sample_kem_packet();
        let packet = parse_packet(&data);
        assert!(packet.error.is_none(), "{:?}", packet.error);
        assert_eq!(packet.protocol_version, Some(4));
        assert_eq!(packet.packet_type, Some(1));
        assert_eq!(packet.sender, "tester");
        assert_eq!(packet.receiver, "peer_abc123");
        assert_eq!(packet.algorithms.kem, "ML-KEM-768+X25519");
        assert_eq!(packet.nonce_len, 12);
        assert_eq!(packet.kem_ciphertext_len, 1120);
        assert_eq!(packet.ciphertext_len, 20);
        assert_eq!(packet.signature_len, 0);
        assert_eq!(packet.consumed, data.len());
        assert_top_level_coverage(&packet, data.len());

        let mut flat = Vec::new();
        flatten_fields(&packet.fields, &mut flat);
        let sender = flat
            .iter()
            .find(|field| field.field.name == "sender")
            .unwrap();
        assert_eq!(sender.field.offset, 3);
        assert_eq!(sender.field.length, 8);
        assert_eq!(sender.field.value, "tester");

        let nonce = flat
            .iter()
            .find(|field| field.field.name == "nonce")
            .unwrap();
        assert_eq!(nonce.field.offset, 93);
        assert_eq!(nonce.field.children[0].offset, 93);
        assert_eq!(nonce.field.children[0].length, 2);
        assert_eq!(nonce.field.children[0].value, "12");
        assert_eq!(nonce.field.children[1].offset, 95);
        assert_eq!(nonce.field.children[1].length, 12);
    }

    fn assert_top_level_coverage(packet: &ParsedPacket, len: usize) {
        let mut position = 0;
        for field in &packet.fields {
            assert_eq!(
                field.offset, position,
                "field {} has a gap or overlap",
                field.name
            );
            position = field.end();
        }
        assert_eq!(position, len, "fields do not cover the whole packet");
        let categories = byte_categories(&packet.fields, len);
        assert!(
            categories.iter().all(Option::is_some),
            "every byte should belong to a field"
        );
    }

    #[test]
    fn parses_v4_session_packet_without_signature() {
        let mut data = Vec::new();
        data.extend_from_slice(&[4, 4, 2]);
        push_string(&mut data, "peer_abc123");
        push_string(&mut data, "tester");
        data.extend_from_slice(&1_792_608_196_096_i64.to_be_bytes());
        data.extend_from_slice(&[7; 16]);
        push_string(&mut data, "yuzu610s7JbIoO4GSGU4eQ");
        data.extend_from_slice(&7_i64.to_be_bytes());
        push_string(&mut data, "AES-256-GCM");
        push_string(&mut data, "HKDF-SHA256");
        push_bytes16(&mut data, &[8; 12]);
        push_bytes32(&mut data, &[]);
        push_bytes32(&mut data, &[9; 51]);

        let packet = parse_packet(&data);
        assert!(packet.error.is_none(), "{:?}", packet.error);
        assert_eq!(packet.session_id.as_deref(), Some("yuzu610s7JbIoO4GSGU4eQ"));
        assert_eq!(packet.sequence, Some(7));
        assert_eq!(packet.signature_len, 0);
        assert_eq!(packet.ciphertext_len, 51);
        assert_eq!(packet.consumed, data.len());
        assert_top_level_coverage(&packet, data.len());
    }

    #[test]
    fn parses_v3_unsigned_packet_without_signature_algorithm() {
        let mut data = Vec::new();
        data.extend_from_slice(&[3, 1, 0x02]);
        push_string(&mut data, "alice");
        push_string(&mut data, "bob");
        data.extend_from_slice(&123_i64.to_be_bytes());
        data.extend_from_slice(&[4; 16]);
        push_string(&mut data, "ML-KEM-768+X25519");
        push_string(&mut data, "AES-256-GCM");
        push_string(&mut data, "HKDF-SHA256");
        push_bytes16(&mut data, &[5; 12]);
        push_bytes32(&mut data, &[6; 4]);
        push_bytes32(&mut data, &[7; 20]);
        push_bytes32(&mut data, &[]);

        let packet = parse_packet(&data);
        assert!(packet.error.is_none(), "{:?}", packet.error);
        assert_eq!(packet.algorithms.kem, "ML-KEM-768+X25519");
        assert_eq!(packet.algorithms.signature, "NONE");
        assert_eq!(packet.signature_len, 0);
        assert_top_level_coverage(&packet, data.len());
    }

    #[test]
    fn parses_legacy_fragment_metadata() {
        let mut data = Vec::new();
        data.extend_from_slice(&[2, 2, 0x01]);
        push_string(&mut data, "alice");
        push_string(&mut data, "bob");
        data.extend_from_slice(&123_i64.to_be_bytes());
        data.extend_from_slice(&[8; 16]);
        data.extend_from_slice(&2_u16.to_be_bytes());
        data.extend_from_slice(&3_u16.to_be_bytes());
        push_string(&mut data, "ML-KEM-768+X25519");
        push_string(&mut data, "MLDSA65-Ed25519-SHA512");
        push_string(&mut data, "AES-256-GCM");
        push_string(&mut data, "HKDF-SHA256");
        push_bytes16(&mut data, &[9; 12]);
        push_bytes32(&mut data, &[10; 8]);
        push_bytes32(&mut data, &[11; 20]);
        push_bytes32(&mut data, &[12; 16]);

        let packet = parse_packet(&data);
        assert!(packet.error.is_none(), "{:?}", packet.error);
        let flat = {
            let mut flat = Vec::new();
            flatten_fields(&packet.fields, &mut flat);
            flat
        };
        let index = flat
            .iter()
            .find(|field| field.field.name == "aad_fragment_index")
            .unwrap();
        assert_eq!(index.field.value, "2");
        assert_eq!(index.field.length, 2);
        let total = flat
            .iter()
            .find(|field| field.field.name == "aad_fragment_total")
            .unwrap();
        assert_eq!(total.field.value, "3");
        assert_eq!(packet.signature_len, 16);
        assert_top_level_coverage(&packet, data.len());
    }

    #[test]
    fn reports_trailing_bytes_and_keeps_fields() {
        let mut data = sample_kem_packet();
        data.extend_from_slice(&[0xde, 0xad]);
        let packet = parse_packet(&data);
        assert!(packet.error.is_some());
        assert_eq!(packet.trailing, 2);
        assert!(
            packet
                .fields
                .iter()
                .any(|field| field.name == "trailing_bytes")
        );
    }

    #[test]
    fn rejects_truncated_packet() {
        let data = sample_kem_packet();
        let packet = parse_packet(&data[..40]);
        assert!(packet.error.is_some());
        assert!(packet.consumed <= 40);
    }
}
