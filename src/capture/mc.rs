//! Minecraft 26.3 packet framing and custom-payload extraction.
//!
//! Packet framing, compression and primitive field decoding are delegated to
//! `mc_protocol`; the numeric packet identifiers come from `minecraft_data`
//! instead of being hard-coded here.

use std::collections::BTreeSet;
use std::io::Cursor;
use std::path::Path;

use mc_protocol::packet::RawPacket;
use mc_protocol::ser::{Deserialize, deserialize_string_with_max};
use mc_protocol::varint::VarInt;
use minecraft_data as data;
use tcpstreams::{Conversation, Direction, Timestamp};
use uuid::Uuid;

use super::{CaptureTime, McConnection, Side};

// The packet identifier table must stay on Minecraft 26.3 / protocol 777.
const _: () = assert!(
    minecraft_data::PROTOCOL_VERSION == 777,
    "minecraft_data must be the 26.3 / protocol 777 data release"
);

const MAX_CUSTOM_PAYLOAD: usize = 2_097_151;
const MAX_WARNINGS: usize = 160;

pub fn is_capture_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("pcap") || extension.eq_ignore_ascii_case("pcapng")
        })
}

pub(crate) struct RawChannelMessage {
    pub channel: String,
    pub data: Vec<u8>,
    pub side: Side,
    pub time: CaptureTime,
    pub offset: u64,
    pub frame_index: usize,
}

pub(crate) struct ParsedConnection {
    pub info: McConnection,
    pub messages: Vec<RawChannelMessage>,
    pub warnings: Vec<String>,
}

struct Timeline {
    entries: Vec<(u64, Timestamp)>,
}

impl Timeline {
    fn build(conversation: &Conversation<'_>, direction: Direction) -> Self {
        let Some(base) = stream_base(conversation, direction) else {
            return Self {
                entries: Vec::new(),
            };
        };
        let mut entries = Vec::new();
        for segment in conversation.data_segments() {
            if segment.direction != direction || segment.payload.is_empty() {
                continue;
            }
            let payload_seq = segment.seq.wrapping_add(u32::from(segment.flags.syn()));
            let offset = payload_seq.wrapping_sub(base) as u64;
            entries.push((offset, segment.timestamp));
        }
        entries.sort_by_key(|(offset, timestamp)| (*offset, timestamp.secs, timestamp.nanos));
        entries.dedup_by_key(|(offset, _)| *offset);
        Self { entries }
    }

    fn time_at(&self, offset: u64, fallback: Timestamp) -> Timestamp {
        if self.entries.is_empty() {
            return fallback;
        }
        let index = self
            .entries
            .partition_point(|(entry_offset, _)| *entry_offset <= offset);
        if index == 0 {
            self.entries[0].1
        } else {
            self.entries[index - 1].1
        }
    }

    /// Smallest captured stream offset whose segment was sent strictly after
    /// `time`. Used to locate the client's first compressed frame.
    fn first_offset_after(&self, time: Timestamp) -> Option<u64> {
        self.entries
            .iter()
            .filter(|(_, timestamp)| *timestamp > time)
            .map(|(offset, _)| *offset)
            .min()
    }
}

fn stream_base(conversation: &Conversation<'_>, direction: Direction) -> Option<u32> {
    let mut first_payload = None;
    for segment in conversation.segments_in(direction) {
        if segment.flags.syn() {
            return Some(segment.seq.wrapping_add(1));
        }
        if first_payload.is_none() && !segment.payload.is_empty() {
            first_payload = Some(segment.seq);
        }
    }
    first_payload
}

struct Frame {
    packet_id: i32,
    payload: Vec<u8>,
    offset: u64,
    time: CaptureTime,
    index: usize,
}

struct FrameReader<'a> {
    data: &'a [u8],
    pos: usize,
    threshold: Option<i32>,
    compression_start: usize,
    timeline: &'a Timeline,
    fallback: Timestamp,
    index: usize,
}

impl<'a> FrameReader<'a> {
    fn new(
        data: &'a [u8],
        timeline: &'a Timeline,
        fallback: Timestamp,
        threshold: Option<i32>,
        compression_start: usize,
    ) -> Self {
        Self {
            data,
            pos: 0,
            threshold,
            compression_start,
            timeline,
            fallback,
            index: 0,
        }
    }

    fn enable_compression(&mut self, threshold: Option<i32>) {
        self.threshold = threshold;
        self.compression_start = self.pos;
    }

    fn next(&mut self) -> Result<Option<Frame>, String> {
        if self.pos >= self.data.len() {
            return Ok(None);
        }
        let offset = self.pos as u64;
        let threshold = if self.pos >= self.compression_start {
            self.threshold
        } else {
            None
        };
        let mut cursor = Cursor::new(&self.data[self.pos..]);
        let raw = RawPacket::read_sync(&mut cursor)
            .map_err(|error| format!("偏移 {} 处无法读取数据包帧：{error}", self.pos))?;
        let consumed = cursor.position() as usize;
        if consumed == 0 || self.pos + consumed > self.data.len() {
            return Err(format!("偏移 {} 处数据包帧长度无效", self.pos));
        }
        let packet = match raw.uncompress(threshold) {
            Ok(packet) => packet,
            Err(error) => {
                // A capture can be cut between Set Compression and the first
                // compressed frame, or a heuristic compression offset can be
                // one packet early. Retry as an uncompressed frame before
                // giving up.
                if threshold.is_some() {
                    raw.uncompress(None)
                        .map_err(|_| format!("偏移 {} 处数据包解压失败：{error}", self.pos))?
                } else {
                    return Err(format!("偏移 {} 处数据包解析失败：{error}", self.pos));
                }
            }
        };
        self.pos += consumed;
        self.index += 1;
        let time = CaptureTime::from_timestamp(self.timeline.time_at(offset, self.fallback));
        Ok(Some(Frame {
            packet_id: packet.packet_id,
            payload: packet.payload,
            offset,
            time,
            index: self.index - 1,
        }))
    }
}

struct PacketIds {
    login_compression: i32,
    login_finished: i32,
    login_disconnect: i32,
    login_hello: i32,
    login_acknowledged: i32,
    config_custom_c: i32,
    config_custom_s: i32,
    config_finish_c: i32,
    config_finish_s: i32,
    play_custom_c: i32,
    play_custom_s: i32,
    play_start_configuration: i32,
    play_configuration_acknowledged: i32,
}

impl PacketIds {
    fn new() -> Self {
        Self {
            login_compression: data::clientbound_login::login_compression.id() as i32,
            login_finished: data::clientbound_login::login_finished.id() as i32,
            login_disconnect: data::clientbound_login::login_disconnect.id() as i32,
            login_hello: data::serverbound_login::hello.id() as i32,
            login_acknowledged: data::serverbound_login::login_acknowledged.id() as i32,
            config_custom_c: data::clientbound_configuration::custom_payload.id() as i32,
            config_custom_s: data::serverbound_configuration::custom_payload.id() as i32,
            config_finish_c: data::clientbound_configuration::finish_configuration.id() as i32,
            config_finish_s: data::serverbound_configuration::finish_configuration.id() as i32,
            play_custom_c: data::clientbound_play::custom_payload.id() as i32,
            play_custom_s: data::serverbound_play::custom_payload.id() as i32,
            play_start_configuration: data::clientbound_play::start_configuration.id() as i32,
            play_configuration_acknowledged: data::serverbound_play::configuration_acknowledged.id()
                as i32,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnectionState {
    Handshake,
    Login,
    Configuration,
    Play,
    Status,
    Closed,
}

pub(crate) fn parse_conversation(
    conversation: &Conversation<'_>,
    source: &str,
    index: usize,
) -> Option<ParsedConnection> {
    let client_is_a = conversation.client() == conversation.a();
    let c2s_direction = if client_is_a {
        Direction::AToB
    } else {
        Direction::BToA
    };
    let s2c_direction = c2s_direction.flip();
    let c2s_timeline = Timeline::build(conversation, c2s_direction);
    let s2c_timeline = Timeline::build(conversation, s2c_direction);
    let c2s = conversation.reassemble(c2s_direction);
    let s2c = conversation.reassemble(s2c_direction);

    let mut warnings = Vec::new();
    if !c2s.is_complete() {
        warnings.push(format!(
            "客户端方向重组存在 {} 个缺失区间，相关帧可能无法解析",
            c2s.gaps().len()
        ));
    }
    if !s2c.is_complete() {
        warnings.push(format!(
            "服务端方向重组存在 {} 个缺失区间，相关帧可能无法解析",
            s2c.gaps().len()
        ));
    }

    let start = CaptureTime::from_timestamp(conversation.start());
    let end = CaptureTime::from_timestamp(conversation.end());
    let mut info = McConnection {
        index,
        source: source.to_owned(),
        client: conversation.client().to_string(),
        server: conversation.server().to_string(),
        status: "unknown".to_owned(),
        player: None,
        player_uuid: None,
        protocol_version: None,
        protocol_supported: false,
        client_brand: None,
        server_brand: None,
        compression_threshold: None,
        registered_channels: Vec::new(),
        start,
        end,
        chat_fragment_messages: 0,
        public_key_messages: 0,
        control_messages: 0,
        tunnel_messages: 0,
        data_records: 0,
        warnings: Vec::new(),
    };
    let ids = PacketIds::new();
    let mut messages = Vec::new();
    let mut registered: BTreeSet<String> = BTreeSet::new();
    let mut client_state = ConnectionState::Handshake;
    let mut compression_threshold = None;

    // ------------------------------------------------------------------
    // Clientbound direction: find Set Compression and the login payload.
    // ------------------------------------------------------------------
    let mut server_state = ConnectionState::Login;
    let mut compression_time = None;
    let mut reader = FrameReader::new(s2c.data(), &s2c_timeline, conversation.start(), None, 0);
    loop {
        let frame = match reader.next() {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                push_warning(&mut warnings, error);
                break;
            }
        };
        match server_state {
            ConnectionState::Login => {
                if frame.packet_id == ids.login_compression {
                    match VarInt::deserialize(&mut Cursor::new(&frame.payload)) {
                        Ok(threshold) if threshold.0 >= 0 => {
                            let threshold = threshold.0 as u32;
                            info.compression_threshold = Some(threshold);
                            compression_threshold = Some(threshold as i32);
                            compression_time = Some(Timestamp {
                                secs: frame.time.secs,
                                nanos: frame.time.nanos,
                            });
                            reader.enable_compression(Some(threshold as i32));
                        }
                        Ok(_) => {
                            reader.enable_compression(None);
                            push_warning(
                                &mut warnings,
                                "服务端发送了负数压缩阈值，按未压缩处理".to_owned(),
                            );
                        }
                        Err(error) => {
                            push_warning(
                                &mut warnings,
                                format!("无法解析 Set Compression 负载：{error}"),
                            );
                            reader.enable_compression(None);
                        }
                    }
                } else if frame.packet_id == ids.login_finished {
                    server_state = ConnectionState::Configuration;
                    parse_login_finished(&frame.payload, &mut info);
                } else if frame.packet_id == ids.login_disconnect {
                    server_state = ConnectionState::Closed;
                }
            }
            ConnectionState::Configuration => {
                if frame.packet_id == ids.config_custom_c {
                    handle_custom_payload(
                        &frame,
                        Side::ServerToClient,
                        &mut info,
                        &mut registered,
                        &mut messages,
                        &mut warnings,
                    );
                } else if frame.packet_id == ids.config_finish_c {
                    server_state = ConnectionState::Play;
                }
            }
            ConnectionState::Play => {
                if frame.packet_id == ids.play_custom_c {
                    handle_custom_payload(
                        &frame,
                        Side::ServerToClient,
                        &mut info,
                        &mut registered,
                        &mut messages,
                        &mut warnings,
                    );
                } else if frame.packet_id == ids.play_start_configuration {
                    server_state = ConnectionState::Configuration;
                }
            }
            ConnectionState::Closed => break,
            _ => {}
        }
    }

    // ------------------------------------------------------------------
    // Serverbound direction: handshake, login, configuration and play.
    // ------------------------------------------------------------------
    let client_compression_start = match (compression_threshold, compression_time) {
        (Some(_), Some(time)) => c2s_timeline
            .first_offset_after(time)
            .map(|offset| offset as usize)
            .unwrap_or(c2s.data().len()),
        _ => c2s.data().len(),
    };
    let mut reader = FrameReader::new(
        c2s.data(),
        &c2s_timeline,
        conversation.start(),
        compression_threshold,
        client_compression_start,
    );
    loop {
        let frame = match reader.next() {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(error) => {
                push_warning(&mut warnings, error);
                break;
            }
        };
        match client_state {
            ConnectionState::Handshake => {
                if frame.packet_id != data::serverbound_handshake::intention.id() as i32 {
                    push_warning(
                        &mut warnings,
                        format!(
                            "客户端方向的第一个数据包不是握手包（id {}）",
                            frame.packet_id
                        ),
                    );
                    client_state = ConnectionState::Closed;
                    continue;
                }
                match parse_handshake(&frame.payload) {
                    Ok((protocol, _address, _port, next_state)) => {
                        info.protocol_version = Some(protocol);
                        info.protocol_supported = protocol == data::PROTOCOL_VERSION as i32;
                        if !info.protocol_supported {
                            push_warning(
                                &mut warnings,
                                format!(
                                    "抓包协议版本为 {protocol}，本工具的数据包 ID 表来自 Minecraft {}（协议 {}）",
                                    data::NAME_VERSION,
                                    data::PROTOCOL_VERSION
                                ),
                            );
                        }
                        client_state = if matches!(next_state, 2 | 3) {
                            ConnectionState::Login
                        } else {
                            info.status = "status".to_owned();
                            ConnectionState::Status
                        };
                    }
                    Err(error) => {
                        push_warning(&mut warnings, error);
                        client_state = ConnectionState::Closed;
                    }
                }
            }
            ConnectionState::Login => {
                if frame.packet_id == ids.login_hello {
                    match parse_login_hello(&frame.payload) {
                        Ok((name, uuid)) => {
                            info.player = Some(name);
                            info.player_uuid = Some(uuid.to_string());
                        }
                        Err(error) => push_warning(&mut warnings, error),
                    }
                } else if frame.packet_id == ids.login_acknowledged {
                    client_state = ConnectionState::Configuration;
                }
            }
            ConnectionState::Configuration => {
                if frame.packet_id == ids.config_custom_s {
                    handle_custom_payload(
                        &frame,
                        Side::ClientToServer,
                        &mut info,
                        &mut registered,
                        &mut messages,
                        &mut warnings,
                    );
                } else if frame.packet_id == ids.config_finish_s {
                    client_state = ConnectionState::Play;
                }
            }
            ConnectionState::Play => {
                if frame.packet_id == ids.play_custom_s {
                    handle_custom_payload(
                        &frame,
                        Side::ClientToServer,
                        &mut info,
                        &mut registered,
                        &mut messages,
                        &mut warnings,
                    );
                } else if frame.packet_id == ids.play_configuration_acknowledged {
                    // The client accepted a server-initiated reconfiguration.
                    client_state = ConnectionState::Configuration;
                }
            }
            ConnectionState::Status | ConnectionState::Closed => break,
        }
    }

    info.status = match client_state {
        ConnectionState::Play => "play".to_owned(),
        ConnectionState::Configuration => "configuration".to_owned(),
        ConnectionState::Login => "login".to_owned(),
        ConnectionState::Status => "status".to_owned(),
        _ => "closed".to_owned(),
    };
    if info.player.is_none() {
        info.player = None;
    }
    info.registered_channels = registered.into_iter().collect();
    messages.sort_by_key(|message| {
        (
            message.time.sort_key(),
            match message.side {
                Side::ServerToClient => 0,
                Side::ClientToServer => 1,
            },
            message.offset,
        )
    });
    info.warnings = warnings.clone();

    if info.status != "play" && messages.is_empty() {
        return None;
    }
    Some(ParsedConnection {
        info,
        messages,
        warnings,
    })
}

fn parse_handshake(payload: &[u8]) -> Result<(i32, String, u16, i32), String> {
    let mut cursor = Cursor::new(payload);
    let protocol = VarInt::deserialize(&mut cursor)
        .map_err(|error| format!("无法解析握手协议版本：{error}"))?;
    let address = String::deserialize(&mut cursor)
        .map_err(|error| format!("无法解析握手服务器地址：{error}"))?;
    let port =
        u16::deserialize(&mut cursor).map_err(|error| format!("无法解析握手端口：{error}"))?;
    let next_state = VarInt::deserialize(&mut cursor)
        .map_err(|error| format!("无法解析握手下一状态：{error}"))?;
    Ok((protocol.0, address, port, next_state.0))
}

fn parse_login_hello(payload: &[u8]) -> Result<(String, Uuid), String> {
    let mut cursor = Cursor::new(payload);
    let name =
        String::deserialize(&mut cursor).map_err(|error| format!("无法解析登录用户名：{error}"))?;
    let uuid =
        Uuid::deserialize(&mut cursor).map_err(|error| format!("无法解析登录 UUID：{error}"))?;
    Ok((name, uuid))
}

fn parse_login_finished(payload: &[u8], info: &mut McConnection) {
    let mut cursor = Cursor::new(payload);
    let Ok(uuid) = Uuid::deserialize(&mut cursor) else {
        return;
    };
    let Ok(name) = String::deserialize(&mut cursor) else {
        return;
    };
    if info.player.is_none() {
        info.player = Some(name);
    }
    if info.player_uuid.is_none() {
        info.player_uuid = Some(uuid.to_string());
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_custom_payload(
    frame: &Frame,
    side: Side,
    info: &mut McConnection,
    registered: &mut BTreeSet<String>,
    messages: &mut Vec<RawChannelMessage>,
    warnings: &mut Vec<String>,
) {
    let mut cursor = Cursor::new(&frame.payload);
    let channel = match deserialize_string_with_max(&mut cursor, 32_767) {
        Ok(channel) => channel,
        Err(error) => {
            push_warning(
                warnings,
                format!("偏移 {} 处无法解析自定义通道名：{error}", frame.offset),
            );
            return;
        }
    };
    if !valid_channel(&channel) {
        push_warning(
            warnings,
            format!("偏移 {} 处通道名格式无效：{channel:?}", frame.offset),
        );
        return;
    }
    let data = &frame.payload[cursor.position() as usize..];
    if data.len() > MAX_CUSTOM_PAYLOAD {
        push_warning(
            warnings,
            format!(
                "偏移 {} 处通道 {channel} 的负载为 {} 字节，超过上限",
                frame.offset,
                data.len()
            ),
        );
        return;
    }
    match channel.as_str() {
        "minecraft:brand" => {
            let kind = deserialize_string_with_max(&mut Cursor::new(data), 32_767).ok();
            match side {
                Side::ClientToServer => info.client_brand = kind,
                Side::ServerToClient => info.server_brand = kind,
            }
            return;
        }
        "minecraft:register" | "minecraft:unregister" => {
            for name in data.split(|byte| *byte == 0) {
                if name.is_empty() {
                    continue;
                }
                let Ok(name) = std::str::from_utf8(name) else {
                    continue;
                };
                if !valid_channel(name) {
                    continue;
                }
                if channel == "minecraft:register" {
                    registered.insert(name.to_owned());
                } else {
                    registered.remove(name);
                }
            }
            return;
        }
        _ => {}
    }
    if !is_krypt_channel(&channel) {
        return;
    }
    messages.push(RawChannelMessage {
        channel,
        data: data.to_vec(),
        side,
        time: frame.time.clone(),
        offset: frame.offset,
        frame_index: frame.index,
    });
}

pub(crate) fn is_krypt_channel(channel: &str) -> bool {
    let Some((namespace, _)) = channel.split_once(':') else {
        return false;
    };
    matches!(
        namespace,
        "krypt04mcg" | "krypt04mcg_stream" | "krypt04mcg_file"
    )
}

fn valid_channel(channel: &str) -> bool {
    let Some((namespace, path)) = channel.split_once(':') else {
        return false;
    };
    if namespace.is_empty() || path.is_empty() {
        return false;
    }
    if namespace.len() > 32_767 || path.len() > 32_767 {
        return false;
    }
    namespace.bytes().all(|byte| {
        byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-' | b'.')
    }) && path.bytes().all(|byte| {
        byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'_' | b'-' | b'.' | b'/')
    })
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < MAX_WARNINGS {
        warnings.push(warning);
    }
}
