//! Krypt04Mcg channel decoding, stream reassembly and decryption.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::io::Cursor;
use std::path::PathBuf;

use base64::Engine as _;
use chrono::{Local, Utc};
use mc_protocol::ser::{ByteArray, Deserialize};
use mc_protocol::varint::VarInt;
use serde::Serialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::decrypt::{KeyStore, StreamKeyDirection, StreamRecordCipher};
use crate::fragment::{GroupAccumulator, parse_fragment_text};
use crate::model::{
    DecryptionOutcome, DecryptionStatus, FragmentOccurrence, SignatureOutcome, SignatureStatus,
};
use crate::packet::hex_preview;

use super::mc::{ParsedConnection, RawChannelMessage};
use super::{
    ApiStream, ApiStreamDirection, CaptureOptions, CaptureSource, CaptureSummary, CaptureTime,
    ChannelEvent, ChannelObservation, ChannelPayload, ChatTransfer, ControlExchange, ControlHmac,
    McConnection, PublicIdentitySummary, PublicKeyRecordSummary, PublicKeyShare,
    SessionExchangeSummary, Side, StreamContent, StreamRecordInfo,
};

const MAX_CHAT_GROUPS: usize = 32_768;
const MAX_EVENTS: usize = 500_000;
const MAX_STREAM_RECORDS: usize = 2_000_000;
const MAX_KEY_SHARES: usize = 256;
const MAX_CONTROL_BODY: usize = 30_000;
const MAX_KEY_SHARE_CHUNK: usize = 12_000;
const MAX_KEY_SHARE_BYTES: usize = 2 * 1024 * 1024;
const PREVIEW_BYTES: usize = 8 * 1024;
const MAX_RETAINED_JSON: usize = 1024 * 1024;
const MAX_RETAINED_BASE64: usize = 64 * 1024;

/// Complete result of analyzing one or more packet captures.
#[derive(Clone, Debug, Serialize)]
pub struct CaptureAnalysis {
    pub tool: &'static str,
    pub version: &'static str,
    pub format_version: u32,
    pub generated_at_utc: String,
    pub generated_at_local: String,
    pub minecraft_version: String,
    pub protocol_version: u32,
    /// True when at least one packet signature was verified against a loaded
    /// public key.
    pub cryptographic_verification: bool,
    /// True when at least one chat message or stream record was authenticated
    /// and decrypted.
    pub payload_decrypted: bool,
    pub summary: CaptureSummary,
    pub sources: Vec<CaptureSource>,
    pub connections: Vec<McConnection>,
    pub chat_transfers: Vec<ChatTransfer>,
    pub public_key_shares: Vec<PublicKeyShare>,
    pub api_streams: Vec<ApiStream>,
    pub events: Vec<ChannelEvent>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub warnings: Vec<String>,
}

/// Analyzes pcap/pcapng files and extracts every Krypt04Mcg channel message.
pub fn analyze_paths(
    paths: &[PathBuf],
    key_store: &KeyStore,
    options: &CaptureOptions,
) -> Result<CaptureAnalysis, String> {
    if paths.is_empty() {
        return Err("没有指定 pcap/pcapng 文件".to_owned());
    }
    let mut analyzer = Analyzer::new(key_store, options);
    let mut sources = Vec::new();
    for path in paths {
        let capture = tcpstreams::Capture::open(path)
            .map_err(|error| format!("无法打开抓包 {}：{error}", path.display()))?;
        let source_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("(capture)")
            .to_owned();
        let path_text = path.display().to_string();
        let mut source = CaptureSource {
            path: path_text.clone(),
            name: source_name,
            conversations: 0,
            minecraft_connections: 0,
            packets: 0,
            payload_bytes: 0,
            bytes: std::fs::metadata(path).map_or(0, |metadata| metadata.len()),
        };
        for conversation in &capture {
            source.conversations += 1;
            source.packets += conversation.packet_count(None);
            source.payload_bytes += conversation.payload_bytes(None);
            let index = analyzer.connections.len();
            if let Some(parsed) = super::mc::parse_conversation(&conversation, &path_text, index) {
                source.minecraft_connections += 1;
                analyzer.process_connection(parsed);
            }
        }
        sources.push(source);
    }
    Ok(analyzer.finish(sources))
}

struct Analyzer<'a> {
    key_store: &'a KeyStore,
    options: &'a CaptureOptions,
    connections: Vec<McConnection>,
    events: Vec<ChannelEvent>,
    chat: GroupAccumulator,
    chat_keys: HashSet<(String, String)>,
    key_shares: KeyShareAssembler,
    streams: StreamTable,
    channels: BTreeMap<String, usize>,
    warnings: Vec<String>,
    chat_fragments: usize,
    data_records: usize,
    unique_data_records: usize,
    decrypted_data_records: usize,
    total_plaintext_bytes: u64,
}

impl<'a> Analyzer<'a> {
    fn new(key_store: &'a KeyStore, options: &'a CaptureOptions) -> Self {
        Self {
            key_store,
            options,
            connections: Vec::new(),
            events: Vec::new(),
            chat: GroupAccumulator::new(),
            chat_keys: HashSet::new(),
            key_shares: KeyShareAssembler::default(),
            streams: StreamTable::default(),
            channels: BTreeMap::new(),
            warnings: Vec::new(),
            chat_fragments: 0,
            data_records: 0,
            unique_data_records: 0,
            decrypted_data_records: 0,
            total_plaintext_bytes: 0,
        }
    }

    fn process_connection(&mut self, parsed: ParsedConnection) {
        let ParsedConnection {
            mut info,
            messages,
            warnings,
        } = parsed;
        for warning in &warnings {
            push_warning(
                &mut self.warnings,
                format!("连接 {}：{warning}", info.index),
            );
        }
        info.warnings = warnings;
        let local = info.player.clone().unwrap_or_default();
        let mut runtime = ConnectionRuntime::new(local);

        for message in messages {
            *self.channels.entry(message.channel.clone()).or_default() += 1;
            let event = match message.channel.as_str() {
                "krypt04mcg:chat_fragment" => {
                    info.chat_fragment_messages += 1;
                    self.handle_chat_fragment(&message, &mut info)
                }
                "krypt04mcg:public_key" => {
                    info.public_key_messages += 1;
                    self.handle_public_key(&message, &mut info)
                }
                "krypt04mcg_stream:control" => {
                    info.control_messages += 1;
                    self.handle_control(&message, &mut info, &mut runtime)
                }
                "krypt04mcg:tunnel" => {
                    info.tunnel_messages += 1;
                    self.handle_tunnel(&message, &mut info)
                }
                channel if channel.starts_with("krypt04mcg_stream:data/") => {
                    info.data_records += 1;
                    self.handle_data(&message, &mut info, &mut runtime)
                }
                _ => Some(ChannelEvent {
                    index: 0,
                    time: message.time.clone(),
                    connection: info.index,
                    side: message.side,
                    channel: message.channel.clone(),
                    frame_offset: message.offset,
                    payload: ChannelPayload::Unknown {
                        payload_length: message.data.len(),
                        raw_hex_preview: hex_preview(&message.data, 32),
                    },
                    error: Some("未识别的 krypt04mcg 通道，仅保留原始预览".to_owned()),
                }),
            };
            if let Some(event) = event {
                if self.events.len() < MAX_EVENTS {
                    self.events.push(event);
                } else if self.events.len() == MAX_EVENTS {
                    push_warning(
                        &mut self.warnings,
                        format!("通道事件超过 {MAX_EVENTS} 条，后续事件被丢弃"),
                    );
                    self.events.push(ChannelEvent {
                        index: 0,
                        time: CaptureTime::default(),
                        connection: info.index,
                        side: Side::ClientToServer,
                        channel: "(limit)".to_owned(),
                        frame_offset: 0,
                        payload: ChannelPayload::Unknown {
                            payload_length: 0,
                            raw_hex_preview: String::new(),
                        },
                        error: Some("事件数量达到上限".to_owned()),
                    });
                }
            }
        }
        self.connections.push(info);
    }

    fn handle_chat_fragment(
        &mut self,
        message: &RawChannelMessage,
        info: &mut McConnection,
    ) -> Option<ChannelEvent> {
        let decoded = decode_peer_fragment(&message.data, 256);
        let mut event = ChannelEvent {
            index: 0,
            time: message.time.clone(),
            connection: info.index,
            side: message.side,
            channel: message.channel.clone(),
            frame_offset: message.offset,
            payload: ChannelPayload::ChatFragment {
                peer: String::new(),
                version: 0,
                fragment: String::new(),
                message_id: None,
                fragment_index: None,
                fragment_total: None,
                fragment_payload_length: None,
            },
            error: None,
        };
        let (peer, fragment, version) = match decoded {
            Ok(value) => value,
            Err(error) => {
                event.error = Some(error);
                return Some(event);
            }
        };
        let parsed = parse_fragment_text(&fragment);
        if let ChannelPayload::ChatFragment {
            peer: event_peer,
            version: event_version,
            fragment: event_fragment,
            message_id,
            fragment_index,
            fragment_total,
            fragment_payload_length,
        } = &mut event.payload
        {
            *event_peer = peer.clone();
            *event_version = version;
            *event_fragment = fragment.clone();
            if let Ok(wire) = &parsed {
                *message_id = Some(wire.message_id.clone());
                *fragment_index = Some(wire.index);
                *fragment_total = Some(wire.total);
                *fragment_payload_length = Some(wire.payload.len());
            }
        }
        let wire = match parsed {
            Ok(wire) => wire,
            Err(error) => {
                event.error = Some(error);
                return Some(event);
            }
        };
        let sender = match message.side {
            Side::ClientToServer => runtime_sender(&info.player),
            Side::ServerToClient => peer.clone(),
        };
        if sender.is_empty() || sender == "(未知)" {
            event.error = Some("无法确定分片发送者，未加入重组".to_owned());
            return Some(event);
        }
        let chat_key = (sender.to_ascii_lowercase(), wire.message_id.clone());
        if !self.chat_keys.contains(&chat_key) && self.chat_keys.len() >= MAX_CHAT_GROUPS {
            push_warning(
                &mut self.warnings,
                format!("加密聊天消息超过 {MAX_CHAT_GROUPS} 条，后续分片被忽略"),
            );
            return Some(event);
        }
        self.chat_keys.insert(chat_key);
        let payload_length = wire.payload.len();
        let occurrence = FragmentOccurrence {
            source_path: info.source.clone(),
            source_name: format!("连接 {} {}", info.index, message.side.label()),
            line: message.frame_index + 1,
            timestamp: message.time.log_timestamp(),
            index: wire.index,
            total: wire.total,
            payload: wire.payload,
            payload_length,
        };
        self.chat
            .add_occurrence(&sender, &wire.message_id, occurrence);
        self.chat_fragments += 1;
        Some(event)
    }

    fn handle_public_key(
        &mut self,
        message: &RawChannelMessage,
        info: &mut McConnection,
    ) -> Option<ChannelEvent> {
        let decoded = decode_peer_fragment(&message.data, 12_100);
        let mut event = ChannelEvent {
            index: 0,
            time: message.time.clone(),
            connection: info.index,
            side: message.side,
            channel: message.channel.clone(),
            frame_offset: message.offset,
            payload: ChannelPayload::PublicKey {
                peer: String::new(),
                version: 0,
                fragment: String::new(),
                transfer_id: None,
                chunk_index: None,
                chunk_total: None,
                chunk_length: None,
            },
            error: None,
        };
        let (peer, fragment, version) = match decoded {
            Ok(value) => value,
            Err(error) => {
                event.error = Some(error);
                return Some(event);
            }
        };
        let chunk = parse_key_chunk(&fragment);
        if let ChannelPayload::PublicKey {
            peer: event_peer,
            version: event_version,
            fragment: event_fragment,
            transfer_id,
            chunk_index,
            chunk_total,
            chunk_length,
        } = &mut event.payload
        {
            *event_peer = peer.clone();
            *event_version = version;
            *event_fragment = fragment.clone();
            if let Ok(chunk) = &chunk {
                *transfer_id = Some(chunk.transfer_id.clone());
                *chunk_index = Some(chunk.index);
                *chunk_total = Some(chunk.total);
                *chunk_length = Some(chunk.data.len());
            }
        }
        if version != 1 {
            event.error = Some(format!("公钥通道版本为 {version}，预期 1"));
            return Some(event);
        }
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                event.error = Some(error);
                return Some(event);
            }
        };
        let sender = match message.side {
            Side::ClientToServer => runtime_sender(&info.player),
            Side::ServerToClient => peer.clone(),
        };
        let receiver = match message.side {
            Side::ClientToServer => peer.clone(),
            Side::ServerToClient => runtime_sender(&info.player),
        };
        if sender.is_empty() || sender == "(未知)" {
            event.error = Some("无法确定公钥分片发送者，未加入重组".to_owned());
            return Some(event);
        }
        self.key_shares.accept(
            &sender,
            &receiver,
            version,
            chunk,
            ChannelObservation {
                connection: info.index,
                side: message.side,
                time: message.time.clone(),
                chunk_index: 0,
            },
        );
        Some(event)
    }

    fn handle_control(
        &mut self,
        message: &RawChannelMessage,
        info: &mut McConnection,
        runtime: &mut ConnectionRuntime,
    ) -> Option<ChannelEvent> {
        let wire = match decode_control(&message.data) {
            Ok(wire) => wire,
            Err(error) => {
                return Some(ChannelEvent {
                    index: 0,
                    time: message.time.clone(),
                    connection: info.index,
                    side: message.side,
                    channel: message.channel.clone(),
                    frame_offset: message.offset,
                    payload: ChannelPayload::Unknown {
                        payload_length: message.data.len(),
                        raw_hex_preview: hex_preview(&message.data, 32),
                    },
                    error: Some(error),
                });
            }
        };
        let kind = control_kind_name(wire.kind.0);
        let stream_uuid = wire.id;
        let mut event = ChannelEvent {
            index: 0,
            time: message.time.clone(),
            connection: info.index,
            side: message.side,
            channel: message.channel.clone(),
            frame_offset: message.offset,
            payload: ChannelPayload::Control {
                kind: kind.to_owned(),
                peer: wire.peer.clone(),
                stream_id: stream_uuid.to_string(),
                slot: wire.slot,
                business_channel: wire.channel.clone(),
                session_id: wire.session_id.clone(),
                sequence: wire.sequence,
                body_length: wire.body.0.len(),
                hmac: None,
                exchange: None,
            },
            error: None,
        };

        if kind == "EXCHANGE" {
            let (packet, mut outcome, signature) = self.key_store.analyze_packet(&wire.body.0);
            let summary = session_exchange_summary(&outcome);
            if summary
                .as_ref()
                .is_some_and(|summary| summary.has_session_secret)
            {
                // Never export a decrypted exchange that happens to contain
                // session material.
                outcome.plaintext = None;
                outcome.json = None;
                outcome.plaintext_hex = None;
                outcome.plaintext_base64url = None;
                outcome.plaintext_bytes.clear();
            }
            if let ChannelPayload::Control { exchange, .. } = &mut event.payload {
                *exchange = Some(Box::new(ControlExchange {
                    packet,
                    decryption: outcome,
                    signature,
                    session_exchange: summary,
                    binary: wire.body.0.clone(),
                }));
            }
            return Some(event);
        }

        let slot_for_mac = if kind == "OPEN" { -1 } else { wire.slot };
        let (source, target) = match message.side {
            Side::ClientToServer => (runtime.local.clone(), wire.peer.clone()),
            Side::ServerToClient => (wire.peer.clone(), runtime.local.clone()),
        };
        let mut hmac = None;
        if matches!(kind, "ASSIGNED" | "ABORT") {
            // ASSIGNED and ABORT are generated by the relay and are
            // deliberately not authenticated by the receiving client.
            hmac = Some(ControlHmac {
                verified: false,
                source: source.clone(),
                target: target.clone(),
                error: Some(format!("{kind} 由 relay 生成，客户端不校验 HMAC")),
            });
        } else if wire.body.0.len() == 32 && !wire.session_id.is_empty() {
            match self.key_store.verify_stream_control(
                &wire.session_id,
                &source,
                &target,
                kind,
                stream_uuid,
                slot_for_mac,
                &wire.channel,
                wire.sequence,
                &wire.body.0,
            ) {
                Ok(verified) => {
                    hmac = Some(ControlHmac {
                        verified,
                        source: source.clone(),
                        target: target.clone(),
                        error: (!verified).then(|| "HMAC-SHA256 校验失败".to_owned()),
                    });
                }
                Err(error) => {
                    hmac = Some(ControlHmac {
                        verified: false,
                        source: source.clone(),
                        target: target.clone(),
                        error: Some(error),
                    });
                }
            }
        } else if wire.body.0.len() != 32 {
            hmac = Some(ControlHmac {
                verified: false,
                source: source.clone(),
                target: target.clone(),
                error: Some(format!(
                    "控制体长度为 {} 字节，预期 32 字节 HMAC",
                    wire.body.0.len()
                )),
            });
        }
        if let ChannelPayload::Control { hmac: slot, .. } = &mut event.payload {
            *slot = hmac;
        }

        // Update stream metadata and slot bindings for this connection.
        let (initiator, responder) = match (kind, message.side) {
            ("OPEN", Side::ClientToServer) => (local_sender(&runtime.local), wire.peer.clone()),
            ("OPEN", Side::ServerToClient) => (wire.peer.clone(), local_sender(&runtime.local)),
            ("ASSIGNED", _) => (local_sender(&runtime.local), wire.peer.clone()),
            _ => (String::new(), String::new()),
        };
        self.streams.upsert_meta(
            stream_uuid,
            &wire.channel,
            &wire.session_id,
            &initiator,
            &responder,
            &message.time,
            kind,
        );
        if wire.slot >= 0
            && (matches!(kind, "OPEN" | "ASSIGNED")
                || (kind == "READY" && !runtime.slots.contains_key(&wire.slot)))
        {
            runtime.slots.insert(
                wire.slot,
                StreamBinding {
                    stream_id: stream_uuid,
                    channel: wire.channel.clone(),
                    session_id: wire.session_id.clone(),
                    peer: wire.peer.clone(),
                    local_end: false,
                    remote_end: false,
                },
            );
        }
        if kind == "END" {
            if wire.slot >= 0
                && let Some(binding) = runtime.slots.get_mut(&wire.slot)
                && binding.stream_id == stream_uuid
            {
                match message.side {
                    Side::ClientToServer => binding.local_end = true,
                    Side::ServerToClient => binding.remote_end = true,
                }
                // A stream is half-closed: the local side may finish sending
                // while data from the peer is still in flight. Release the slot
                // only after both directions have sent END.
                if binding.local_end && binding.remote_end {
                    runtime.slots.remove(&wire.slot);
                }
            }
            self.streams.end(stream_uuid, kind, &message.time);
        } else if matches!(kind, "RESET" | "ABORT") {
            if wire.slot >= 0 {
                runtime.slots.remove(&wire.slot);
            }
            self.streams.end(stream_uuid, kind, &message.time);
        }
        Some(event)
    }

    fn handle_tunnel(
        &mut self,
        message: &RawChannelMessage,
        info: &mut McConnection,
    ) -> Option<ChannelEvent> {
        let mut event = ChannelEvent {
            index: 0,
            time: message.time.clone(),
            connection: info.index,
            side: message.side,
            channel: message.channel.clone(),
            frame_offset: message.offset,
            payload: ChannelPayload::Tunnel {
                peer: String::new(),
                stream_id: String::new(),
                lease: 0,
                envelope_length: 0,
                packet: None,
                decryption: None,
                signature: None,
                packet_binary: Vec::new(),
            },
            error: None,
        };
        let (peer, envelope) = match decode_tunnel(&message.data) {
            Ok(value) => value,
            Err(error) => {
                event.error = Some(error);
                return Some(event);
            }
        };
        if envelope.len() < 24 {
            event.error = Some(format!(
                "隧道信封只有 {} 字节，至少需要 24 字节",
                envelope.len()
            ));
            return Some(event);
        }
        let stream_id = Uuid::from_bytes(envelope[..16].try_into().expect("16 bytes"));
        let lease = i64::from_be_bytes(envelope[16..24].try_into().expect("8 bytes"));
        let packet = crate::packet::parse_packet(&envelope[24..]);
        let decryption = if packet.error.is_none() {
            Some(Box::new(self.key_store.decrypt_legacy_tunnel(
                &envelope[24..],
                stream_id,
                lease,
            )))
        } else {
            None
        };
        if let ChannelPayload::Tunnel {
            peer: event_peer,
            stream_id: event_stream,
            lease: event_lease,
            envelope_length,
            packet: event_packet,
            decryption: event_decryption,
            signature: _,
            packet_binary,
        } = &mut event.payload
        {
            *event_peer = peer;
            *event_stream = stream_id.to_string();
            *event_lease = lease;
            *envelope_length = envelope.len();
            *event_packet = Some(Box::new(packet));
            *event_decryption = decryption;
            *packet_binary = envelope[24..].to_vec();
        }
        Some(event)
    }

    fn handle_data(
        &mut self,
        message: &RawChannelMessage,
        info: &mut McConnection,
        runtime: &mut ConnectionRuntime,
    ) -> Option<ChannelEvent> {
        let Some(slot) = parse_data_slot(&message.channel) else {
            return Some(ChannelEvent {
                index: 0,
                time: message.time.clone(),
                connection: info.index,
                side: message.side,
                channel: message.channel.clone(),
                frame_offset: message.offset,
                payload: ChannelPayload::Unknown {
                    payload_length: message.data.len(),
                    raw_hex_preview: hex_preview(&message.data, 32),
                },
                error: Some("数据通道槽位不是 0..=255".to_owned()),
            });
        };
        if !(16..=16 * 1024 + 16).contains(&message.data.len()) {
            return Some(ChannelEvent {
                index: 0,
                time: message.time.clone(),
                connection: info.index,
                side: message.side,
                channel: message.channel.clone(),
                frame_offset: message.offset,
                payload: ChannelPayload::Unknown {
                    payload_length: message.data.len(),
                    raw_hex_preview: hex_preview(&message.data, 32),
                },
                error: Some(format!(
                    "流记录长度为 {} 字节，超出 16..={} 范围",
                    message.data.len(),
                    16 * 1024 + 16
                )),
            });
        }
        let Some(binding) = runtime.slots.get(&slot).cloned() else {
            return Some(ChannelEvent {
                index: 0,
                time: message.time.clone(),
                connection: info.index,
                side: message.side,
                channel: message.channel.clone(),
                frame_offset: message.offset,
                payload: ChannelPayload::Unknown {
                    payload_length: message.data.len(),
                    raw_hex_preview: hex_preview(&message.data, 32),
                },
                error: Some(format!("槽位 {slot} 尚未绑定到任何流")),
            });
        };
        let (sender, receiver) = match message.side {
            Side::ClientToServer => (local_sender(&runtime.local), binding.peer.clone()),
            Side::ServerToClient => (binding.peer.clone(), local_sender(&runtime.local)),
        };
        let direction = match message.side {
            Side::ClientToServer => StreamKeyDirection::Send,
            Side::ServerToClient => StreamKeyDirection::Receive,
        };
        let cipher_key = (
            binding.stream_id,
            matches!(message.side, Side::ClientToServer),
        );
        if !runtime.ciphers.contains_key(&cipher_key) {
            let state = if runtime.local.is_empty() || binding.peer.is_empty() {
                CipherSlot::NoKey("缺少本地玩家或对端身份".to_owned())
            } else {
                match self.key_store.stream_cipher(
                    &binding.session_id,
                    binding.stream_id,
                    slot,
                    &binding.channel,
                    &runtime.local,
                    &binding.peer,
                    direction,
                ) {
                    Ok(cipher) => CipherSlot::Cipher(cipher),
                    Err(error) => CipherSlot::NoKey(error),
                }
            };
            runtime.ciphers.insert(cipher_key, state);
        }

        let state = runtime.ciphers.remove(&cipher_key);
        let (index, status, plaintext, error, state) = match state {
            Some(CipherSlot::Cipher(mut cipher)) => {
                let index = cipher.counter();
                match cipher.decrypt_next(&message.data) {
                    Ok(plaintext) => (
                        index,
                        RecordStatus::Decrypted,
                        Some(plaintext),
                        None,
                        Some(CipherSlot::Cipher(cipher)),
                    ),
                    Err(error) => (
                        index,
                        RecordStatus::Failed,
                        None,
                        Some(error),
                        Some(CipherSlot::Failed {
                            next_index: index.saturating_add(1),
                        }),
                    ),
                }
            }
            Some(CipherSlot::NoKey(error)) => {
                let index = runtime
                    .fallback_counters
                    .entry((
                        binding.stream_id,
                        matches!(message.side, Side::ClientToServer),
                    ))
                    .or_insert(0);
                let value = *index;
                *index = index.saturating_add(1);
                let record_error = (value == 0).then(|| error.clone());
                (
                    value,
                    RecordStatus::NoKey,
                    None,
                    record_error,
                    Some(CipherSlot::NoKey(error)),
                )
            }
            Some(CipherSlot::Failed { mut next_index }) => {
                let value = next_index;
                next_index = next_index.saturating_add(1);
                (
                    value,
                    RecordStatus::Failed,
                    None,
                    Some("前置流记录认证失败，后续记录无法定位计数器".to_owned()),
                    Some(CipherSlot::Failed { next_index }),
                )
            }
            None => (
                0,
                RecordStatus::NoKey,
                None,
                Some("流密钥状态丢失".to_owned()),
                None,
            ),
        };
        if let Some(state) = state {
            runtime.ciphers.insert(cipher_key, state);
        }

        self.data_records += 1;
        let inserted = self.streams.add_record(StreamRecordInput {
            stream_id: binding.stream_id,
            channel: &binding.channel,
            session_id: &binding.session_id,
            sender: &sender,
            receiver: &receiver,
            index,
            connection: info.index,
            side: message.side,
            time: &message.time,
            ciphertext_len: message.data.len(),
            status,
            plaintext: plaintext.as_deref(),
            error,
            retain_stream_data: self.options.retain_stream_data,
        });
        if inserted {
            self.unique_data_records += 1;
        }
        if inserted && status == RecordStatus::Decrypted {
            self.decrypted_data_records += 1;
            if let Some(plaintext) = &plaintext {
                self.total_plaintext_bytes += plaintext.len() as u64;
            }
        }
        None
    }

    fn finish(mut self, sources: Vec<CaptureSource>) -> CaptureAnalysis {
        // Public-key shares are assembled first so signatures on earlier chat
        // or control traffic can still be verified by keys shared later.
        let public_key_shares = self.key_shares.finish();
        let mut registry = self.key_store.signatures.clone();
        for share in &public_key_shares {
            if !share.complete {
                continue;
            }
            let Some(identity) = &share.identity else {
                continue;
            };
            if !identity.owner.eq_ignore_ascii_case(&share.sender) {
                continue;
            }
            if let Some(json) = &share.json {
                let _ = registry
                    .ingest_identity_value(json, &format!("抓包公钥共享 {}", share.transfer_id));
            }
        }

        // Chat transfers.
        let groups = std::mem::take(&mut self.chat).finish();
        let mut chat_transfers = Vec::with_capacity(groups.len());
        let mut chat_transfers_decrypted = 0usize;
        for group in &groups {
            let decryption = group
                .packet
                .as_ref()
                .map(|_| self.key_store.decrypt_message(group));
            if decryption
                .as_ref()
                .is_some_and(|outcome| outcome.status == DecryptionStatus::Decrypted)
            {
                chat_transfers_decrypted += 1;
            }
            let binary = group.binary.as_deref();
            let signature = group
                .packet
                .as_ref()
                .map(|packet| registry.verify_packet(packet, binary.unwrap_or_default()));
            chat_transfers.push(ChatTransfer {
                message_id: group.message_id.clone(),
                sender: group.transport_sender.clone(),
                status: group.status,
                fragment_total: group.total,
                unique_fragments: group.unique_fragments(),
                occurrence_count: group.occurrences(),
                duplicate_count: group.duplicate_count,
                conflicts: group.conflicts,
                missing_indices: group.missing_indices(),
                warnings: group.warnings.clone(),
                binary_length: binary.map(<[u8]>::len),
                binary_base64url: binary
                    .filter(|binary| binary.len() <= MAX_RETAINED_BASE64)
                    .map(|binary| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(binary)),
                packet: group.packet.clone(),
                decryption,
                signature,
                binary: group.binary.clone(),
                fragments: group
                    .all_occurrences_sorted()
                    .into_iter()
                    .cloned()
                    .collect(),
            });
        }

        // Verify signatures on packets embedded in control exchanges and
        // legacy tunnels now that every captured public identity is known.
        let mut signature_counts = SignatureCounts::default();
        for transfer in &chat_transfers {
            signature_counts.observe(transfer.signature.as_ref());
        }
        for event in &mut self.events {
            match &mut event.payload {
                ChannelPayload::Control {
                    exchange: Some(exchange),
                    ..
                } => {
                    exchange.signature = registry.verify_packet(&exchange.packet, &exchange.binary);
                    signature_counts.observe(Some(&exchange.signature));
                }
                ChannelPayload::Tunnel {
                    packet: Some(packet),
                    signature,
                    packet_binary,
                    ..
                } => {
                    let outcome = registry.verify_packet(packet, packet_binary);
                    signature_counts.observe(Some(&outcome));
                    *signature = Some(Box::new(outcome));
                }
                _ => {}
            }
        }

        let api_streams = self.streams.finish(self.options.retain_stream_data);

        // Stable event order and global indices.
        self.events.sort_by_key(|event| {
            (
                event.time.sort_key(),
                event.connection,
                match event.side {
                    Side::ServerToClient => 0,
                    Side::ClientToServer => 1,
                },
                event.frame_offset,
            )
        });
        for (index, event) in self.events.iter_mut().enumerate() {
            event.index = index;
        }

        let krypt_connections = self
            .connections
            .iter()
            .filter(|connection| {
                connection.chat_fragment_messages
                    + connection.public_key_messages
                    + connection.control_messages
                    + connection.tunnel_messages
                    + connection.data_records
                    > 0
            })
            .count();
        let mut summary = CaptureSummary {
            capture_files: sources.len(),
            conversations: sources.iter().map(|source| source.conversations).sum(),
            minecraft_connections: self.connections.len(),
            krypt_connections,
            channel_messages: self.events.len(),
            chat_fragments: self.chat_fragments,
            chat_transfers: chat_transfers.len(),
            chat_transfers_decrypted,
            public_key_shares: public_key_shares.len(),
            api_streams: api_streams.len(),
            api_data_records: self.unique_data_records,
            api_data_record_observations: self.data_records,
            api_data_records_decrypted: self.decrypted_data_records,
            signature_packets: signature_counts.packets,
            signatures_verified: signature_counts.verified,
            signatures_no_key: signature_counts.no_key,
            signatures_unsupported: signature_counts.unsupported,
            signatures_failed: signature_counts.failed,
            total_plaintext_bytes: self.total_plaintext_bytes,
            channels: std::mem::take(&mut self.channels),
            warnings: Vec::new(),
        };
        summary.warnings = self.warnings.clone();

        let now_utc = Utc::now();
        CaptureAnalysis {
            tool: "K04M 日志解析器",
            version: env!("CARGO_PKG_VERSION"),
            format_version: 1,
            generated_at_utc: now_utc.to_rfc3339(),
            generated_at_local: now_utc.with_timezone(&Local).to_rfc3339(),
            minecraft_version: minecraft_data::NAME_VERSION.to_owned(),
            protocol_version: minecraft_data::PROTOCOL_VERSION,
            cryptographic_verification: signature_counts.verified > 0,
            payload_decrypted: self.decrypted_data_records > 0 || chat_transfers_decrypted > 0,
            summary,
            sources,
            connections: self.connections,
            chat_transfers,
            public_key_shares,
            api_streams,
            events: self.events,
            warnings: self.warnings,
        }
    }
}

fn runtime_sender(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "(未知)".to_owned())
}

fn local_sender(value: &str) -> String {
    if value.is_empty() {
        "(未知)".to_owned()
    } else {
        value.to_owned()
    }
}

struct ConnectionRuntime {
    local: String,
    slots: HashMap<i32, StreamBinding>,
    ciphers: HashMap<(Uuid, bool), CipherSlot>,
    fallback_counters: HashMap<(Uuid, bool), u64>,
}

impl ConnectionRuntime {
    fn new(local: String) -> Self {
        Self {
            local,
            slots: HashMap::new(),
            ciphers: HashMap::new(),
            fallback_counters: HashMap::new(),
        }
    }
}

#[derive(Clone)]
struct StreamBinding {
    stream_id: Uuid,
    channel: String,
    session_id: String,
    peer: String,
    local_end: bool,
    remote_end: bool,
}

enum CipherSlot {
    Cipher(StreamRecordCipher),
    NoKey(String),
    Failed { next_index: u64 },
}

#[derive(Default)]
struct SignatureCounts {
    packets: usize,
    verified: usize,
    no_key: usize,
    unsupported: usize,
    failed: usize,
}

impl SignatureCounts {
    fn observe(&mut self, outcome: Option<&SignatureOutcome>) {
        let Some(outcome) = outcome else {
            return;
        };
        match outcome.status {
            SignatureStatus::Verified => {
                self.packets += 1;
                self.verified += 1;
            }
            SignatureStatus::NoKey => {
                self.packets += 1;
                self.no_key += 1;
            }
            SignatureStatus::Unsupported => {
                self.packets += 1;
                self.unsupported += 1;
            }
            SignatureStatus::Failed => {
                self.packets += 1;
                self.failed += 1;
            }
            SignatureStatus::NotAttempted | SignatureStatus::NotPresent => {}
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum RecordStatus {
    Decrypted,
    NoKey,
    Failed,
}

impl RecordStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Decrypted => "decrypted",
            Self::NoKey => "no_key",
            Self::Failed => "failed",
        }
    }
}

struct StreamRecordInput<'a> {
    stream_id: Uuid,
    channel: &'a str,
    session_id: &'a str,
    sender: &'a str,
    receiver: &'a str,
    index: u64,
    connection: usize,
    side: Side,
    time: &'a CaptureTime,
    ciphertext_len: usize,
    status: RecordStatus,
    plaintext: Option<&'a [u8]>,
    error: Option<String>,
    retain_stream_data: bool,
}

#[derive(Default)]
struct StreamTable {
    streams: BTreeMap<Uuid, StreamState>,
}

impl StreamTable {
    #[allow(clippy::too_many_arguments)]
    fn upsert_meta(
        &mut self,
        stream_id: Uuid,
        channel: &str,
        session_id: &str,
        initiator: &str,
        responder: &str,
        time: &CaptureTime,
        kind: &str,
    ) {
        let state = self.streams.entry(stream_id).or_default();
        state.stream_id = stream_id.to_string();
        if !channel.is_empty() {
            if state.channel.is_empty() {
                state.channel = channel.to_owned();
            } else if state.channel != channel {
                push_warning(
                    &mut state.warnings,
                    format!("流的业务通道发生变化：{} -> {channel}", state.channel),
                );
            }
        }
        if !session_id.is_empty() {
            if state.session_id.is_empty() {
                state.session_id = session_id.to_owned();
            } else if state.session_id != session_id {
                push_warning(
                    &mut state.warnings,
                    format!(
                        "流的 sessionId 发生变化：{} -> {session_id}",
                        state.session_id
                    ),
                );
            }
        }
        if !initiator.is_empty() && state.initiator.is_empty() {
            state.initiator = initiator.to_owned();
        }
        if !responder.is_empty() && state.responder.is_empty() {
            state.responder = responder.to_owned();
        }
        state.first_seen.get_or_insert_with(|| time.clone());
        state.last_seen = Some(time.clone());
        if matches!(kind, "END" | "RESET" | "ABORT") {
            state.end_reason = Some(kind.to_owned());
        }
    }

    fn end(&mut self, stream_id: Uuid, kind: &str, time: &CaptureTime) {
        let state = self.streams.entry(stream_id).or_default();
        state.stream_id = stream_id.to_string();
        state.end_reason = Some(kind.to_owned());
        state.last_seen = Some(time.clone());
    }

    #[allow(clippy::too_many_arguments)]
    fn add_record(&mut self, input: StreamRecordInput<'_>) -> bool {
        let state = self.streams.entry(input.stream_id).or_default();
        state.stream_id = input.stream_id.to_string();
        if state.channel.is_empty() {
            state.channel = input.channel.to_owned();
        }
        if state.session_id.is_empty() {
            state.session_id = input.session_id.to_owned();
        }
        state.first_seen.get_or_insert_with(|| input.time.clone());
        state.last_seen = Some(input.time.clone());
        let key = (input.sender.to_owned(), input.receiver.to_owned());
        let direction = state.directions.entry(key).or_insert_with(|| {
            DirectionState::new(
                input.sender.to_owned(),
                input.receiver.to_owned(),
                input.channel,
            )
        });
        direction.add(input)
    }

    fn finish(self, retain_stream_data: bool) -> Vec<ApiStream> {
        let mut streams = Vec::new();
        for (_, state) in self.streams {
            let mut directions = Vec::new();
            for (_, direction) in state.directions {
                directions.push(direction.finish(retain_stream_data));
            }
            directions.sort_by(|a, b| {
                a.sender
                    .to_ascii_lowercase()
                    .cmp(&b.sender.to_ascii_lowercase())
                    .then_with(|| {
                        a.receiver
                            .to_ascii_lowercase()
                            .cmp(&b.receiver.to_ascii_lowercase())
                    })
            });
            streams.push(ApiStream {
                stream_id: state.stream_id,
                channel: state.channel,
                session_id: state.session_id,
                initiator: non_empty(state.initiator, "(未知)"),
                responder: non_empty(state.responder, "(未知)"),
                first_seen: state.first_seen,
                last_seen: state.last_seen,
                end_reason: state.end_reason,
                directions,
                warnings: state.warnings,
            });
        }
        streams.sort_by_key(|stream| {
            stream
                .first_seen
                .as_ref()
                .map_or((i64::MAX, u32::MAX), CaptureTime::sort_key)
        });
        streams
    }
}

#[derive(Default)]
struct StreamState {
    stream_id: String,
    channel: String,
    session_id: String,
    initiator: String,
    responder: String,
    first_seen: Option<CaptureTime>,
    last_seen: Option<CaptureTime>,
    end_reason: Option<String>,
    directions: BTreeMap<(String, String), DirectionState>,
    warnings: Vec<String>,
}

struct DirectionState {
    sender: String,
    receiver: String,
    content_channel: String,
    records: Vec<StreamRecordInfo>,
    positions: HashMap<u64, usize>,
    hasher: Sha256,
    total_len: u64,
    preview: Vec<u8>,
    retained: Vec<u8>,
    ciphertext_bytes: u64,
    decrypted_records: usize,
    failed_records: usize,
    first_decryption_error: Option<String>,
    warning: Option<String>,
}

impl DirectionState {
    fn new(sender: String, receiver: String, channel: &str) -> Self {
        Self {
            sender,
            receiver,
            content_channel: channel.to_owned(),
            records: Vec::new(),
            positions: HashMap::new(),
            hasher: Sha256::new(),
            total_len: 0,
            preview: Vec::new(),
            retained: Vec::new(),
            ciphertext_bytes: 0,
            decrypted_records: 0,
            failed_records: 0,
            first_decryption_error: None,
            warning: None,
        }
    }

    fn add(&mut self, input: StreamRecordInput<'_>) -> bool {
        self.ciphertext_bytes += input.ciphertext_len as u64;
        if let Some(position) = self.positions.get(&input.index).copied() {
            if let Some(record) = self.records.get_mut(position) {
                record.observations += 1;
                if record.status != "decrypted" && input.status == RecordStatus::Decrypted {
                    self.warning = Some(
                        "同一记录的另一侧观测可解密，但内容统计已按先出现的观测生成".to_owned(),
                    );
                    record.status = "decrypted".to_owned();
                    record.plaintext_length = input.plaintext.map(<[u8]>::len);
                    record.error = None;
                }
            }
            return false;
        }
        if self.records.len() >= MAX_STREAM_RECORDS {
            self.warning = Some(format!(
                "单个方向的流记录超过 {MAX_STREAM_RECORDS} 条，后续记录被忽略"
            ));
            return false;
        }
        if input.status == RecordStatus::Decrypted {
            self.decrypted_records += 1;
            if let Some(plaintext) = input.plaintext {
                self.hasher.update(plaintext);
                self.total_len += plaintext.len() as u64;
                let remaining = PREVIEW_BYTES.saturating_sub(self.preview.len());
                if remaining > 0 {
                    self.preview
                        .extend_from_slice(&plaintext[..remaining.min(plaintext.len())]);
                }
                if input.retain_stream_data {
                    self.retained.extend_from_slice(plaintext);
                }
            }
        } else if input.status == RecordStatus::Failed {
            self.failed_records += 1;
            if self.first_decryption_error.is_none() {
                self.first_decryption_error = input.error.clone();
            }
        }
        let (preview_text, preview_hex) = record_preview(input.plaintext);
        let record = StreamRecordInfo {
            index: input.index,
            connection: input.connection,
            side: input.side,
            time: input.time.clone(),
            ciphertext_length: input.ciphertext_len,
            plaintext_length: input.plaintext.map(<[u8]>::len),
            status: input.status.label().to_owned(),
            error: if input.status == RecordStatus::Decrypted {
                None
            } else {
                input.error
            },
            observations: 1,
            preview_text,
            preview_hex,
        };
        self.positions.insert(input.index, self.records.len());
        self.records.push(record);
        true
    }

    fn finish(mut self, retain_stream_data: bool) -> ApiStreamDirection {
        self.records.sort_by_key(|record| record.index);
        let decryption = if self.records.is_empty() {
            "no_records".to_owned()
        } else if self.decrypted_records == self.records.len() {
            "decrypted".to_owned()
        } else if self.decrypted_records > 0 && self.failed_records > 0 {
            "partial".to_owned()
        } else if self.failed_records > 0 {
            "failed".to_owned()
        } else {
            "no_key".to_owned()
        };
        let mut content = analyze_content(
            &self.content_channel,
            &self.preview,
            &self.retained,
            self.total_len,
            &mut self.hasher,
            retain_stream_data,
        );
        if self.decrypted_records == 0 && !self.records.is_empty() {
            content.kind = "unavailable".to_owned();
        }
        let data = if retain_stream_data {
            std::mem::take(&mut self.retained)
        } else {
            Vec::new()
        };
        ApiStreamDirection {
            sender: self.sender.clone(),
            receiver: self.receiver.clone(),
            record_count: self.records.len(),
            ciphertext_bytes: self.ciphertext_bytes,
            decrypted_records: self.decrypted_records,
            failed_records: self.failed_records,
            decryption,
            content,
            records: self.records,
            warnings: self.warning.into_iter().collect(),
            data,
        }
    }
}

fn record_preview(plaintext: Option<&[u8]>) -> (Option<String>, Option<String>) {
    if let Some(plaintext) = plaintext {
        let preview = &plaintext[..plaintext.len().min(64)];
        if let Ok(text) = std::str::from_utf8(preview)
            && text
                .chars()
                .all(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        {
            return (Some(text.to_owned()), None);
        }
        return (None, Some(hex_preview(preview, 32)));
    }
    (None, None)
}

fn analyze_content(
    channel: &str,
    preview: &[u8],
    retained: &[u8],
    total_len: u64,
    hasher: &mut Sha256,
    retain_stream_data: bool,
) -> StreamContent {
    let full = if usize::try_from(total_len).ok() == Some(preview.len()) {
        // The whole stream fits in the retained preview.
        Some(preview)
    } else if retain_stream_data && retained.len() as u64 == total_len {
        Some(retained)
    } else {
        None
    };
    let source = full.unwrap_or(preview);
    let valid_utf8_prefix = utf8_prefix(source);
    let mut content = StreamContent {
        kind: if total_len == 0 {
            "empty".to_owned()
        } else {
            "binary".to_owned()
        },
        length: total_len,
        sha256: None,
        valid_utf8_prefix,
        file_name: None,
        declared_file_size: None,
        text_preview: None,
        json: None,
        base64url: None,
        preview_truncated: total_len > preview.len() as u64,
    };
    if total_len > 0 {
        let digest = hasher.finalize_reset();
        content.sha256 = Some(digest.iter().map(|byte| format!("{byte:02x}")).collect());
    }
    if let Some(full) = full {
        if full.len() <= MAX_RETAINED_BASE64 {
            content.base64url = Some(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(full));
        }
        if full.len() <= MAX_RETAINED_JSON
            && let Ok(value) = serde_json::from_slice::<serde_json::Value>(full)
            && (value.is_object() || value.is_array())
        {
            content.kind = "json".to_owned();
            content.json = Some(value);
        }
    }
    if channel == "krypt04mcg_file:stream"
        && let Some((name, size)) = parse_file_header(source)
    {
        content.kind = "file".to_owned();
        content.file_name = Some(name);
        content.declared_file_size = Some(size);
    } else if content.json.is_none() && valid_utf8_prefix && printable_ratio(preview) > 0.92 {
        content.kind = "text".to_owned();
    }
    if valid_utf8_prefix && matches!(content.kind.as_str(), "text" | "json") {
        let text = String::from_utf8_lossy(&source[..source.len().min(PREVIEW_BYTES)]);
        content.text_preview = Some(text.chars().take(4096).collect());
    }
    content
}

fn utf8_prefix(bytes: &[u8]) -> bool {
    match std::str::from_utf8(bytes) {
        Ok(_) => true,
        Err(error) => error.error_len().is_none() && error.valid_up_to() + 4 > bytes.len(),
    }
}

fn printable_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let printable = bytes
        .iter()
        .filter(|byte| {
            **byte == b'\n'
                || **byte == b'\r'
                || **byte == b'\t'
                || (0x20..0x7f).contains(*byte)
                || **byte >= 0x80
        })
        .count();
    printable as f64 / bytes.len() as f64
}

/// Parses the `krypt04mcg_file:stream` envelope:
/// Java `writeUTF(name)` (`u16` bytes, modified UTF-8) followed by `writeInt(size)`.
fn parse_file_header(bytes: &[u8]) -> Option<(String, u64)> {
    if bytes.len() < 2 {
        return None;
    }
    let name_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if name_len == 0 || name_len > 540 || bytes.len() < 2 + name_len + 4 {
        return None;
    }
    let name = decode_modified_utf8(&bytes[2..2 + name_len])?;
    if name.chars().count() > 180 {
        return None;
    }
    let size = i32::from_be_bytes(bytes[2 + name_len..2 + name_len + 4].try_into().ok()?);
    if size < 0 || size as u64 > 10 * 1024 * 1024 {
        return None;
    }
    Some((name, size as u64))
}

/// Decodes Java's modified UTF-8 into a Rust string.
fn decode_modified_utf8(bytes: &[u8]) -> Option<String> {
    let mut units = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        let first = bytes[index];
        if first & 0x80 == 0 {
            units.push(u16::from(first));
            index += 1;
        } else if first & 0xe0 == 0xc0 {
            let second = *bytes.get(index + 1)?;
            if second & 0xc0 != 0x80 {
                return None;
            }
            let value = (u16::from(first & 0x1f) << 6) | u16::from(second & 0x3f);
            units.push(value);
            index += 2;
        } else if first & 0xf0 == 0xe0 {
            let second = *bytes.get(index + 1)?;
            let third = *bytes.get(index + 2)?;
            if second & 0xc0 != 0x80 || third & 0xc0 != 0x80 {
                return None;
            }
            let value = (u16::from(first & 0x0f) << 12)
                | (u16::from(second & 0x3f) << 6)
                | u16::from(third & 0x3f);
            units.push(value);
            index += 3;
        } else {
            return None;
        }
    }
    String::from_utf16(&units).ok()
}

fn non_empty(value: String, fallback: &str) -> String {
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value
    }
}

// ---------------------------------------------------------------------------
// Channel payload decoding
// ---------------------------------------------------------------------------

#[derive(mc_protocol::Packet)]
struct PeerFragmentWire {
    peer: String,
    fragment: String,
    version: VarInt,
}

fn decode_peer_fragment(data: &[u8], max_fragment: usize) -> Result<(String, String, i32), String> {
    let mut cursor = Cursor::new(data);
    let wire = PeerFragmentWire::deserialize(&mut cursor)
        .map_err(|error| format!("无法解析通道负载：{error}"))?;
    if cursor.position() != data.len() as u64 {
        return Err(format!(
            "通道负载存在 {} 个尾随字节",
            data.len() as u64 - cursor.position()
        ));
    }
    validate_peer(&wire.peer)?;
    if wire.version.0 < 0 {
        return Err(format!("通道版本为负数：{}", wire.version.0));
    }
    if wire.fragment.encode_utf16().count() > max_fragment {
        return Err(format!(
            "分片文本为 {} 个 UTF-16 单元，超过上限 {max_fragment}",
            wire.fragment.encode_utf16().count()
        ));
    }
    Ok((wire.peer, wire.fragment, wire.version.0))
}

#[derive(mc_protocol::Packet)]
struct ControlWire {
    kind: VarInt,
    peer: String,
    id: Uuid,
    slot: i32,
    channel: String,
    session_id: String,
    sequence: i64,
    body: ByteArray,
}

fn decode_control(data: &[u8]) -> Result<ControlWire, String> {
    let mut cursor = Cursor::new(data);
    let wire = ControlWire::deserialize(&mut cursor)
        .map_err(|error| format!("无法解析流控制负载：{error}"))?;
    if cursor.position() != data.len() as u64 {
        return Err(format!(
            "流控制负载存在 {} 个尾随字节",
            data.len() as u64 - cursor.position()
        ));
    }
    if !(0..=6).contains(&wire.kind.0) {
        return Err(format!("未知的流控制类型：{}", wire.kind.0));
    }
    validate_peer(&wire.peer)?;
    if wire.slot < -1 || wire.slot >= 256 {
        return Err(format!("流控制槽位越界：{}", wire.slot));
    }
    if wire.channel.chars().count() > 256 {
        return Err("流控制业务通道名超过 256 字符".to_owned());
    }
    if wire.session_id.chars().count() > 64 {
        return Err("流控制 sessionId 超过 64 字符".to_owned());
    }
    if wire.sequence < 0 {
        return Err(format!("流控制序号为负数：{}", wire.sequence));
    }
    if wire.body.0.len() > MAX_CONTROL_BODY {
        return Err(format!(
            "流控制体为 {} 字节，超过 {MAX_CONTROL_BODY} 字节上限",
            wire.body.0.len()
        ));
    }
    Ok(wire)
}

fn control_kind_name(kind: i32) -> &'static str {
    match kind {
        0 => "EXCHANGE",
        1 => "OPEN",
        2 => "ASSIGNED",
        3 => "READY",
        4 => "END",
        5 => "RESET",
        6 => "ABORT",
        _ => "UNKNOWN",
    }
}

#[derive(mc_protocol::Packet)]
struct TunnelWire {
    peer: String,
    envelope: ByteArray,
}

fn decode_tunnel(data: &[u8]) -> Result<(String, Vec<u8>), String> {
    let mut cursor = Cursor::new(data);
    let wire = TunnelWire::deserialize(&mut cursor)
        .map_err(|error| format!("无法解析隧道负载：{error}"))?;
    if cursor.position() != data.len() as u64 {
        return Err("隧道负载存在尾随字节".to_owned());
    }
    validate_peer(&wire.peer)?;
    if wire.envelope.0.len() > 24 * 1024 {
        return Err(format!(
            "隧道信封为 {} 字节，超过 24 KiB 上限",
            wire.envelope.0.len()
        ));
    }
    Ok((wire.peer, wire.envelope.0))
}

fn validate_peer(peer: &str) -> Result<(), String> {
    if peer.is_empty()
        || peer.len() > 16
        || !peer
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(format!("玩家名不符合 [A-Za-z0-9_]{{1,16}}：{peer:?}"));
    }
    Ok(())
}

fn parse_data_slot(channel: &str) -> Option<i32> {
    let suffix = channel.strip_prefix("krypt04mcg_stream:data/")?;
    let slot = suffix.parse::<i32>().ok()?;
    (0..256).contains(&slot).then_some(slot)
}

// ---------------------------------------------------------------------------
// Session exchange summary
// ---------------------------------------------------------------------------

fn session_exchange_summary(outcome: &DecryptionOutcome) -> Option<SessionExchangeSummary> {
    let value = outcome.json.as_ref()?;
    Some(SessionExchangeSummary {
        version: value.get("version").and_then(serde_json::Value::as_i64),
        kind: value
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
        initiator: json_string(value, "initiator"),
        initiator_uuid: json_string(value, "initiatorUuid"),
        responder: json_string(value, "responder"),
        responder_uuid: json_string(value, "responderUuid"),
        session_id: json_string(value, "sessionId"),
        request_message_id: json_string(value, "requestMessageId"),
        ephemeral_kem: json_string(value, "ephemeralKem"),
        initiator_fingerprint: json_string(value, "initiatorFingerprint"),
        responder_fingerprint: json_string(value, "responderFingerprint"),
        created_at_millis: value
            .get("createdAtMillis")
            .and_then(serde_json::Value::as_i64),
        previous_session_id: json_string(value, "previousSessionId"),
        request_epoch: value
            .get("requestEpoch")
            .and_then(serde_json::Value::as_i64),
        has_session_secret: value
            .get("sessionSecret")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|secret| !secret.is_empty()),
        ephemeral_public_key_length: value
            .get("ephemeralPublicKey")
            .and_then(serde_json::Value::as_str)
            .map_or(0, str::len),
        error: None,
    })
}

fn json_string(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
}

// ---------------------------------------------------------------------------
// Public-key optional transfer assembly
// ---------------------------------------------------------------------------

struct KeyChunk {
    transfer_id: String,
    index: usize,
    total: usize,
    data: String,
}

fn parse_key_chunk(fragment: &str) -> Result<KeyChunk, String> {
    let mut parts = fragment.splitn(4, ':');
    let Some(id_text) = parts.next() else {
        return Err("公钥分片缺少传输 ID".to_owned());
    };
    let Some(index_text) = parts.next() else {
        return Err("公钥分片缺少索引".to_owned());
    };
    let Some(total_text) = parts.next() else {
        return Err("公钥分片缺少总数".to_owned());
    };
    let Some(data) = parts.next() else {
        return Err("公钥分片缺少数据".to_owned());
    };
    let transfer_id =
        Uuid::parse_str(id_text).map_err(|_| format!("公钥分片传输 ID 不是 UUID：{id_text:?}"))?;
    if transfer_id.to_string() != id_text.to_ascii_lowercase() {
        return Err(format!("公钥分片传输 ID 不是规范小写 UUID：{id_text:?}"));
    }
    if index_text.is_empty()
        || index_text.len() > 4
        || !index_text.bytes().all(|byte| byte.is_ascii_digit())
        || total_text.is_empty()
        || total_text.len() > 4
        || !total_text.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err("公钥分片索引/总数不是十进制数字".to_owned());
    }
    let index = index_text
        .parse::<usize>()
        .map_err(|_| "公钥分片索引无效".to_owned())?;
    let total = total_text
        .parse::<usize>()
        .map_err(|_| "公钥分片总数无效".to_owned())?;
    if total == 0 || total > 512 || index >= total {
        return Err(format!("公钥分片索引越界：{index}/{total}"));
    }
    if data.is_empty() || data.len() > MAX_KEY_SHARE_CHUNK {
        return Err(format!("公钥分片数据长度为 {} 字节，超出范围", data.len()));
    }
    Ok(KeyChunk {
        transfer_id: transfer_id.to_string(),
        index,
        total,
        data: data.to_owned(),
    })
}

#[derive(Default)]
struct KeyShareAssembler {
    entries: BTreeMap<(String, String), KeyShareEntry>,
}

struct KeyShareEntry {
    transfer_id: String,
    sender: String,
    receiver: Option<String>,
    version: i32,
    total: usize,
    parts: Vec<Option<String>>,
    observations: Vec<ChannelObservation>,
    first_seen: Option<CaptureTime>,
    last_seen: Option<CaptureTime>,
    warnings: Vec<String>,
    conflicts: usize,
}

impl KeyShareAssembler {
    fn accept(
        &mut self,
        sender: &str,
        receiver: &str,
        version: i32,
        chunk: KeyChunk,
        mut observation: ChannelObservation,
    ) {
        let key = (sender.to_ascii_lowercase(), chunk.transfer_id.clone());
        if !self.entries.contains_key(&key) {
            if self.entries.len() >= MAX_KEY_SHARES {
                return;
            }
            self.entries.insert(
                key.clone(),
                KeyShareEntry {
                    transfer_id: chunk.transfer_id.clone(),
                    sender: sender.to_owned(),
                    receiver: None,
                    version,
                    total: chunk.total,
                    parts: vec![None; chunk.total],
                    observations: Vec::new(),
                    first_seen: None,
                    last_seen: None,
                    warnings: Vec::new(),
                    conflicts: 0,
                },
            );
        }
        let entry = self.entries.get_mut(&key).expect("entry inserted");
        observation.chunk_index = chunk.index;
        entry
            .first_seen
            .get_or_insert_with(|| observation.time.clone());
        entry.last_seen = Some(observation.time.clone());
        entry.observations.push(observation);
        if !receiver.is_empty() {
            match &entry.receiver {
                None => entry.receiver = Some(receiver.to_owned()),
                Some(existing) if !existing.eq_ignore_ascii_case(receiver) => {
                    push_warning(
                        &mut entry.warnings,
                        format!("同一公钥传输出现不同接收者：{existing} / {receiver}"),
                    );
                }
                _ => {}
            }
        }
        if entry.total != chunk.total {
            entry.conflicts += 1;
            push_warning(
                &mut entry.warnings,
                format!("公钥传输总数冲突：{} / {}", entry.total, chunk.total),
            );
            return;
        }
        match &entry.parts[chunk.index] {
            None => entry.parts[chunk.index] = Some(chunk.data),
            Some(existing) if existing == &chunk.data => {}
            Some(_) => {
                entry.conflicts += 1;
                push_warning(
                    &mut entry.warnings,
                    format!("公钥分片索引 {} 出现不同数据", chunk.index),
                );
            }
        }
    }

    fn finish(self) -> Vec<PublicKeyShare> {
        let mut shares = Vec::new();
        for (_, entry) in self.entries {
            let received = entry.parts.iter().filter(|part| part.is_some()).count();
            let complete = received == entry.total && entry.conflicts == 0;
            let assembled = if complete {
                let mut text = String::new();
                for part in entry.parts.iter().flatten() {
                    if text.len() + part.len() > MAX_KEY_SHARE_BYTES {
                        break;
                    }
                    text.push_str(part);
                }
                Some(text)
            } else {
                None
            };
            let mut warnings = entry.warnings;
            let (json, identity) = match assembled {
                Some(text) if text.len() <= MAX_KEY_SHARE_BYTES => {
                    match serde_json::from_str::<serde_json::Value>(&text) {
                        Ok(value) => {
                            let identity = identity_summary(&value);
                            if identity.is_none() {
                                push_warning(
                                    &mut warnings,
                                    "公钥 JSON 缺少完整身份字段".to_owned(),
                                );
                            } else if let Some(identity) = &identity
                                && !identity.owner.eq_ignore_ascii_case(&entry.sender)
                            {
                                push_warning(
                                    &mut warnings,
                                    format!(
                                        "公钥 JSON 的 owner {} 与发送者 {} 不一致",
                                        identity.owner, entry.sender
                                    ),
                                );
                            }
                            (Some(value), identity)
                        }
                        Err(error) => {
                            push_warning(&mut warnings, format!("公钥 JSON 解析失败：{error}"));
                            (None, None)
                        }
                    }
                }
                _ => (None, None),
            };
            shares.push(PublicKeyShare {
                transfer_id: entry.transfer_id,
                sender: entry.sender,
                receiver: entry.receiver,
                version: entry.version,
                total_chunks: entry.total,
                received_chunks: received,
                complete,
                identity,
                json,
                warnings,
                observations: entry.observations,
            });
        }
        shares.sort_by_key(|share| {
            share
                .observations
                .first()
                .map_or((i64::MAX, u32::MAX), |observation| {
                    observation.time.sort_key()
                })
        });
        shares
    }
}

fn identity_summary(value: &serde_json::Value) -> Option<PublicIdentitySummary> {
    let owner = value.get("owner")?.as_str()?.to_owned();
    let uuid = value.get("uuid")?.as_str()?.to_owned();
    let kem = value
        .get("kemPublicKey")
        .and_then(public_key_record_summary);
    let signature = value
        .get("signaturePublicKey")
        .and_then(public_key_record_summary);
    Some(PublicIdentitySummary {
        owner,
        uuid,
        kem_public_key: kem,
        signature_public_key: signature,
    })
}

fn public_key_record_summary(value: &serde_json::Value) -> Option<PublicKeyRecordSummary> {
    Some(PublicKeyRecordSummary {
        algorithm: value.get("algorithm")?.as_str()?.to_owned(),
        uuid: value.get("uuid")?.as_str()?.to_owned(),
        fingerprint: value.get("fingerprint")?.as_str()?.to_owned(),
        created_at: value
            .get("createdAt")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned),
    })
}

fn push_warning(warnings: &mut Vec<String>, warning: String) {
    if warnings.len() < 160 {
        warnings.push(warning);
    }
}
