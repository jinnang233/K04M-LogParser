//! End-to-end capture tests built from a synthetic pcapng fixture.
//!
//! All identities, UUIDs and secrets here are test-only values.

use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use sha2::Sha256;
use uuid::Uuid;

use super::{CaptureOptions, analyze_captures};
use crate::decrypt::KeyStore;

const CLIENT_PORT: u16 = 40_000;
const SERVER_PORT: u16 = 25_565;
const CLIENT_SEQ: u32 = 1_000;
const SERVER_SEQ: u32 = 5_000;
const ALICE: &str = "alice";
const BOB: &str = "bob";
const SESSION_ID: &str = "oKGio6SlpqeoqaqrrK2urw";
const SESSION_SECRET: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
const STREAM_ID: &str = "00112233-4455-6677-8899-aabbccddeeff";
const BUSINESS_CHANNEL: &str = "example:test";
const CHAT_MESSAGE_ID: &str = "0123456789abcdef0123456789abcdef";
const COMPRESSION_THRESHOLD: usize = 256;
const TUNNEL_MESSAGE_ID: [u8; 16] = [0x22; 16];
const TUNNEL_TIMESTAMP: i64 = 1_234;
const TUNNEL_BODY: &[u8] = b"tunnel hello";

#[test]
fn analyzes_synthetic_capture_channels() {
    let dir = temp_root("channels");
    let pcap_path = dir.join("fixture.pcapng");
    let packets = fixture_packets();
    fs::write(&pcap_path, build_pcapng(&packets)).unwrap();
    let store = session_store();
    let options = CaptureOptions {
        retain_stream_data: true,
    };
    let analysis = analyze_captures(&[pcap_path], &store, &options).unwrap();

    assert_eq!(analysis.summary.capture_files, 1);
    assert_eq!(analysis.summary.minecraft_connections, 1);
    assert_eq!(analysis.connections.len(), 1);
    let connection = &analysis.connections[0];
    assert_eq!(connection.player.as_deref(), Some(ALICE));
    assert_eq!(connection.protocol_version, Some(777));
    assert_eq!(connection.server_brand.as_deref(), Some("TestServer"));
    assert_eq!(connection.client_brand.as_deref(), Some("TestClient"));
    assert!(
        connection
            .registered_channels
            .iter()
            .any(|channel| channel == "krypt04mcg_stream:data/0")
    );
    assert!(
        connection
            .registered_channels
            .iter()
            .any(|channel| channel == "krypt04mcg:chat_fragment")
    );

    // Encrypted chat fragments are grouped globally and seen from both
    // directions.
    assert_eq!(analysis.chat_transfers.len(), 1);
    let transfer = &analysis.chat_transfers[0];
    assert_eq!(transfer.message_id, CHAT_MESSAGE_ID);
    assert_eq!(transfer.sender, ALICE);
    assert_eq!(transfer.status, crate::model::MessageStatus::Parsed);
    assert_eq!(transfer.duplicate_count, transfer.fragment_total);
    assert_eq!(transfer.occurrence_count, transfer.fragment_total * 2);

    // Public-key chunks are reassembled into the identity JSON.
    assert_eq!(analysis.public_key_shares.len(), 1);
    let share = &analysis.public_key_shares[0];
    assert!(share.complete, "{:?}", share.warnings);
    assert_eq!(share.sender, ALICE);
    assert_eq!(share.receiver.as_deref(), Some(BOB));
    assert_eq!(
        share
            .identity
            .as_ref()
            .map(|identity| identity.owner.as_str()),
        Some(ALICE)
    );

    // Legacy tunnel framing and decryption use the separate tunnel KDF.
    let tunnel = analysis
        .events
        .iter()
        .find(|event| matches!(event.payload, super::ChannelPayload::Tunnel { .. }))
        .expect("tunnel event");
    match &tunnel.payload {
        super::ChannelPayload::Tunnel {
            stream_id,
            lease,
            packet,
            decryption,
            ..
        } => {
            assert_eq!(stream_id, STREAM_ID);
            assert_eq!(*lease, 7);
            assert_eq!(
                packet
                    .as_ref()
                    .map(|packet| packet.packet_type_name.as_str()),
                Some("SESSION_MESSAGE")
            );
            let outcome = decryption.as_ref().expect("tunnel decryption");
            assert_eq!(
                outcome.status,
                crate::model::DecryptionStatus::Decrypted,
                "{:?}",
                outcome.error
            );
            assert_eq!(outcome.plaintext.as_deref(), Some("tunnel hello"));
        }
        _ => unreachable!(),
    }

    // The API stream is bound through control messages and decrypted with the
    // synthetic stream-api session.
    assert_eq!(analysis.api_streams.len(), 1);
    let stream = &analysis.api_streams[0];
    assert_eq!(stream.stream_id, STREAM_ID);
    assert_eq!(stream.channel, BUSINESS_CHANNEL);
    assert_eq!(stream.initiator, ALICE);
    assert_eq!(stream.responder, BOB);
    assert_eq!(stream.directions.len(), 1);
    let direction = &stream.directions[0];
    assert_eq!(direction.sender, ALICE);
    assert_eq!(direction.receiver, BOB);
    assert_eq!(direction.record_count, 2);
    assert_eq!(direction.decryption, "decrypted");
    assert_eq!(direction.content.length, 12);
    assert_eq!(direction.data, b"hello stream");

    let open = analysis
        .events
        .iter()
        .find(|event| matches!(&event.payload, super::ChannelPayload::Control { kind, .. } if kind == "OPEN"))
        .expect("OPEN control event");
    if let super::ChannelPayload::Control {
        hmac: Some(hmac), ..
    } = &open.payload
    {
        assert!(hmac.verified, "{hmac:?}");
    } else {
        panic!("OPEN control without HMAC result");
    }

    let _ = fs::remove_dir_all(dir);
}

fn temp_root(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "k04m-log-parser-capture-test-{}-{name}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn session_store() -> KeyStore {
    let dir = temp_root("session");
    let record = serde_json::json!({
        "peer": BOB,
        "sessionId": SESSION_ID,
        "secret": SESSION_SECRET,
    });
    fs::write(
        dir.join("session.json"),
        serde_json::to_vec(&record).unwrap(),
    )
    .unwrap();
    let mut store = KeyStore::default();
    let summary = store.load_paths(std::slice::from_ref(&dir));
    assert_eq!(summary.sessions_added, 1, "{:?}", summary.warnings);
    let _ = fs::remove_dir_all(dir);
    store
}

fn fixture_packets() -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut client_seq = CLIENT_SEQ;
    let mut server_seq = SERVER_SEQ;

    // TCP handshake.
    packets.push(tcp_packet(
        CLIENT_PORT,
        SERVER_PORT,
        CLIENT_SEQ,
        0,
        0x02,
        &[],
    ));
    client_seq += 1;
    packets.push(tcp_packet(
        SERVER_PORT,
        CLIENT_PORT,
        SERVER_SEQ,
        client_seq,
        0x12,
        &[],
    ));
    server_seq += 1;
    packets.push(tcp_packet(
        CLIENT_PORT,
        SERVER_PORT,
        client_seq,
        server_seq,
        0x10,
        &[],
    ));

    // Client handshake and login start.
    let mut handshake_payload = Vec::new();
    write_varint(&mut handshake_payload, 777);
    write_string(&mut handshake_payload, "localhost");
    handshake_payload.extend_from_slice(&SERVER_PORT.to_be_bytes());
    write_varint(&mut handshake_payload, 2);
    let mut login_payload = Vec::new();
    write_string(&mut login_payload, ALICE);
    login_payload
        .extend_from_slice(Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888).as_bytes());

    // Server login success and configuration.
    let mut login_finished = Vec::new();
    login_finished
        .extend_from_slice(Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888).as_bytes());
    write_string(&mut login_finished, ALICE);
    write_varint(&mut login_finished, 0);

    let mut register_payload = Vec::new();
    write_string(&mut register_payload, "minecraft:register");
    register_payload.extend_from_slice(
        b"krypt04mcg:chat_fragment\0krypt04mcg:public_key\0krypt04mcg_stream:control\0krypt04mcg_stream:data/0",
    );
    let mut client_info_payload = Vec::new();
    write_string(&mut client_info_payload, "minecraft:brand");
    write_string(&mut client_info_payload, "TestClient");

    // Frames in a realistic interleaving. Each direction's TCP sequence number
    // advances independently.
    let ordered = [
        (
            Side::ClientToServer,
            mc_packet(
                minecraft_data::serverbound_handshake::intention.id() as i32,
                &handshake_payload,
            ),
        ),
        (
            Side::ClientToServer,
            mc_packet(
                minecraft_data::serverbound_login::hello.id() as i32,
                &login_payload,
            ),
        ),
        (
            Side::ServerToClient,
            mc_packet(
                minecraft_data::clientbound_login::login_compression.id() as i32,
                &compression_threshold_payload(),
            ),
        ),
        (
            Side::ServerToClient,
            mc_packet(
                minecraft_data::clientbound_login::login_finished.id() as i32,
                &login_finished,
            ),
        ),
        (
            Side::ClientToServer,
            mc_packet(
                minecraft_data::serverbound_login::login_acknowledged.id() as i32,
                &[],
            ),
        ),
        (
            Side::ServerToClient,
            mc_packet(
                minecraft_data::clientbound_configuration::custom_payload.id() as i32,
                &brand_payload("TestServer"),
            ),
        ),
        (
            Side::ClientToServer,
            mc_packet(
                minecraft_data::serverbound_configuration::custom_payload.id() as i32,
                &client_info_payload,
            ),
        ),
        (
            Side::ClientToServer,
            mc_packet(
                minecraft_data::serverbound_configuration::custom_payload.id() as i32,
                &register_payload,
            ),
        ),
        (
            Side::ServerToClient,
            mc_packet(
                minecraft_data::clientbound_configuration::finish_configuration.id() as i32,
                &[],
            ),
        ),
        (
            Side::ClientToServer,
            mc_packet(
                minecraft_data::serverbound_configuration::finish_configuration.id() as i32,
                &[],
            ),
        ),
        (
            Side::ClientToServer,
            play_custom_payload(
                Side::ClientToServer,
                "krypt04mcg_stream:control",
                &open_control(),
            ),
        ),
        (
            Side::ServerToClient,
            play_custom_payload(
                Side::ServerToClient,
                "krypt04mcg_stream:control",
                &assigned_control(),
            ),
        ),
    ];
    let mut ordered: Vec<(Side, Vec<u8>)> = ordered.into_iter().collect();

    // Chat fragments are sent in both directions for the same message.
    let fragments = chat_fragments();
    for fragment in &fragments {
        ordered.push((
            Side::ClientToServer,
            play_custom_payload(
                Side::ClientToServer,
                "krypt04mcg:chat_fragment",
                &peer_fragment_payload(BOB, fragment),
            ),
        ));
    }
    for fragment in &fragments {
        ordered.push((
            Side::ServerToClient,
            play_custom_payload(
                Side::ServerToClient,
                "krypt04mcg:chat_fragment",
                &peer_fragment_payload(ALICE, fragment),
            ),
        ));
    }

    // Public-key offer from alice to bob.
    ordered.push((
        Side::ClientToServer,
        play_custom_payload(
            Side::ClientToServer,
            "krypt04mcg:public_key",
            &peer_fragment_payload(BOB, &key_share_chunk()),
        ),
    ));

    // Legacy tunnel envelope encrypted with the synthetic chat session.
    ordered.push((
        Side::ClientToServer,
        play_custom_payload(Side::ClientToServer, "krypt04mcg:tunnel", &tunnel_payload()),
    ));

    // API stream data and END.
    for (index, plaintext) in [b"hello ".as_slice(), b"stream".as_slice()]
        .into_iter()
        .enumerate()
    {
        ordered.push((
            Side::ClientToServer,
            play_custom_payload(
                Side::ClientToServer,
                "krypt04mcg_stream:data/0",
                &encrypt_record(plaintext, index as u64),
            ),
        ));
    }
    ordered.push((
        Side::ClientToServer,
        play_custom_payload(
            Side::ClientToServer,
            "krypt04mcg_stream:control",
            &end_control(),
        ),
    ));

    let mut compression_enabled = false;
    let mut saw_set_compression = false;
    for (side, frame) in ordered {
        let frame = if compression_enabled {
            compression_frame(&frame)
        } else {
            frame
        };
        match side {
            Side::ClientToServer => {
                packets.push(tcp_packet(
                    CLIENT_PORT,
                    SERVER_PORT,
                    client_seq,
                    server_seq,
                    0x18,
                    &frame,
                ));
                client_seq += frame.len() as u32;
            }
            Side::ServerToClient => {
                packets.push(tcp_packet(
                    SERVER_PORT,
                    CLIENT_PORT,
                    server_seq,
                    client_seq,
                    0x18,
                    &frame,
                ));
                server_seq += frame.len() as u32;
            }
        }
        // The Set Compression packet itself is not compressed; every frame
        // after it uses the compressed framing.
        if side == Side::ServerToClient
            && !saw_set_compression
            && let Some(packet_id) = first_packet_id(&frame)
            && packet_id == minecraft_data::clientbound_login::login_compression.id() as i32
        {
            saw_set_compression = true;
            compression_enabled = true;
        }
    }
    packets
}

fn compression_threshold_payload() -> Vec<u8> {
    let mut payload = Vec::new();
    write_varint(&mut payload, COMPRESSION_THRESHOLD as i32);
    payload
}

fn compression_frame(frame: &[u8]) -> Vec<u8> {
    // `mc_packet` already added the outer length prefix; the compression
    // header replaces it, so strip it to recover [packet_id][fields].
    let inner = strip_frame_length(frame);
    let mut body = Vec::new();
    if inner.len() >= COMPRESSION_THRESHOLD {
        use std::io::Write as _;
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(inner).unwrap();
        let compressed = encoder.finish().unwrap();
        write_varint(&mut body, inner.len() as i32);
        body.extend_from_slice(&compressed);
    } else {
        write_varint(&mut body, 0);
        body.extend_from_slice(inner);
    }
    let mut out = Vec::new();
    write_varint(&mut out, body.len() as i32);
    out.extend_from_slice(&body);
    out
}

fn strip_frame_length(frame: &[u8]) -> &[u8] {
    let mut shift = 0;
    for (index, byte) in frame.iter().enumerate() {
        if byte & 0x80 == 0 {
            return &frame[index + 1..];
        }
        shift += 7;
        if shift > 35 {
            break;
        }
    }
    frame
}

fn first_packet_id(frame: &[u8]) -> Option<i32> {
    let mut value = 0i32;
    let mut shift = 0;
    for byte in frame {
        value |= i32::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Some(value);
        }
        shift += 7;
        if shift > 35 {
            return None;
        }
    }
    None
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    ClientToServer,
    ServerToClient,
}

fn play_custom_payload(side: Side, channel: &str, data: &[u8]) -> Vec<u8> {
    let packet_id = match side {
        Side::ClientToServer => minecraft_data::serverbound_play::custom_payload.id() as i32,
        Side::ServerToClient => minecraft_data::clientbound_play::custom_payload.id() as i32,
    };
    let mut payload = Vec::new();
    write_string(&mut payload, channel);
    payload.extend_from_slice(data);
    mc_packet(packet_id, &payload)
}

fn brand_payload(brand: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    write_string(&mut payload, "minecraft:brand");
    write_string(&mut payload, brand);
    payload
}

fn peer_fragment_payload(peer: &str, fragment: &str) -> Vec<u8> {
    let mut payload = Vec::new();
    write_string(&mut payload, peer);
    write_string(&mut payload, fragment);
    write_varint(&mut payload, 1);
    payload
}

fn chat_fragments() -> Vec<String> {
    let packet = sample_packet();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&packet);
    let chunk_size = 200;
    let total = encoded.len().div_ceil(chunk_size);
    (0..total)
        .map(|index| {
            let start = index * chunk_size;
            let end = (start + chunk_size).min(encoded.len());
            format!(
                "[KRYPT04MCG] {CHAT_MESSAGE_ID} {index} {total} {}",
                &encoded[start..end]
            )
        })
        .collect()
}

fn sample_packet() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[4, 1, 0x02]);
    push_string(&mut out, ALICE);
    push_string(&mut out, BOB);
    out.extend_from_slice(&123_i64.to_be_bytes());
    out.extend_from_slice(&[7; 16]);
    push_string(&mut out, "ML-KEM-768+X25519");
    push_string(&mut out, "AES-256-GCM");
    push_string(&mut out, "HKDF-SHA256");
    push_bytes16(&mut out, &[8; 12]);
    push_bytes32(&mut out, &[9; 4]);
    push_bytes32(&mut out, &[10; 20]);
    push_bytes32(&mut out, &[]);
    out
}

fn key_share_chunk() -> String {
    let identity = serde_json::json!({
        "owner": ALICE,
        "uuid": "11112222-3333-4444-5555-666677778888",
        "kemPublicKey": {
            "algorithm": "ML-KEM-768+X25519/public",
            "owner": ALICE,
            "uuid": "11112222-3333-4444-5555-666677778888",
            "fingerprint": "00",
            "createdAt": "2026-01-01T00:00:00Z",
            "keyData": "AA"
        },
        "signaturePublicKey": {
            "algorithm": "MLDSA65-Ed25519-SHA512/public",
            "owner": ALICE,
            "uuid": "11112222-3333-4444-5555-666677778888",
            "fingerprint": "11",
            "createdAt": "2026-01-01T00:00:00Z",
            "keyData": "AA"
        }
    });
    format!(
        "{}:0:1:{}",
        Uuid::from_u128(0xaaaabbbb_cccc_dddd_eeee_ffff00001111),
        serde_json::to_string(&identity).unwrap()
    )
}

fn open_control() -> Vec<u8> {
    control_payload(
        1,
        BOB,
        -1,
        5,
        &hex_decode("041c5af5d648f06aef9a9acd9c495dd4d46cd9639f3ff075448272d4f632e1ff"),
    )
}

fn assigned_control() -> Vec<u8> {
    control_payload(2, BOB, 0, 1, &[0u8; 32])
}

fn end_control() -> Vec<u8> {
    control_payload(4, BOB, 0, 2, &[0u8; 32])
}

fn control_payload(kind: i32, peer: &str, slot: i32, sequence: i64, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::new();
    write_varint(&mut payload, kind);
    write_string(&mut payload, peer);
    payload.extend_from_slice(Uuid::parse_str(STREAM_ID).unwrap().as_bytes());
    payload.extend_from_slice(&slot.to_be_bytes());
    write_string(&mut payload, BUSINESS_CHANNEL);
    write_string(&mut payload, SESSION_ID);
    payload.extend_from_slice(&sequence.to_be_bytes());
    write_varint(&mut payload, body.len() as i32);
    payload.extend_from_slice(body);
    payload
}

fn hkdf(ikm: &[u8], salt: Option<&[u8]>, info: &[u8]) -> [u8; 32] {
    let hkdf = Hkdf::<Sha256>::new(salt, ikm);
    let mut key = [0u8; 32];
    hkdf.expand(info, &mut key).unwrap();
    key
}

fn encrypt_record(plaintext: &[u8], counter: u64) -> Vec<u8> {
    let session_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(SESSION_ID)
        .unwrap();
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(SESSION_SECRET)
        .unwrap();
    let uuid = Uuid::parse_str(STREAM_ID).unwrap();
    let context = format!("{SESSION_ID}/{uuid}/0/{BUSINESS_CHANNEL}");
    let info = format!("krypt04mcg_stream/v1/data/{context}/{ALICE}/{BOB}");
    let key = hkdf(&secret, Some(&session_id), info.as_bytes());
    let aad = format!("krypt04mcg_stream/v1/{context}");
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(uuid.as_bytes());
    nonce[16..].copy_from_slice(&counter.to_be_bytes());
    let cipher = XChaCha20Poly1305::new_from_slice(&key).unwrap();
    cipher
        .encrypt(
            &XNonce::try_from(&nonce[..]).unwrap(),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .unwrap()
}

fn tunnel_payload() -> Vec<u8> {
    let session_id = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(SESSION_ID)
        .unwrap();
    let secret = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(SESSION_SECRET)
        .unwrap();
    let uuid = Uuid::parse_str(STREAM_ID).unwrap();
    let lease = 7_i64;
    let tunnel_info = format!("krypt04mcg tunnel v1\n{uuid}\n{lease}\n{ALICE}\n{BOB}");
    let tunnel_key = hkdf(&secret, Some(session_id.as_slice()), tunnel_info.as_bytes());
    let message_key = hkdf(
        &tunnel_key,
        Some(&TUNNEL_MESSAGE_ID[..]),
        b"krypt04mcg session",
    );

    let aad = session_message_aad();
    let nonce = [0x55u8; 12];
    let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&message_key).unwrap();
    let ciphertext = cipher
        .encrypt(
            &chacha20poly1305::Nonce::try_from(&nonce[..]).unwrap(),
            Payload {
                msg: TUNNEL_BODY,
                aad: &aad,
            },
        )
        .unwrap();

    let mut packet = Vec::new();
    packet.extend_from_slice(&[4, 4, 0]);
    push_string(&mut packet, ALICE);
    push_string(&mut packet, BOB);
    packet.extend_from_slice(&TUNNEL_TIMESTAMP.to_be_bytes());
    packet.extend_from_slice(&TUNNEL_MESSAGE_ID);
    push_string(&mut packet, SESSION_ID);
    packet.extend_from_slice(&0_i64.to_be_bytes());
    push_string(&mut packet, "CHACHA20-POLY1305");
    push_string(&mut packet, "HKDF-SHA256");
    push_bytes16(&mut packet, &nonce);
    push_bytes32(&mut packet, &[]);
    push_bytes32(&mut packet, &ciphertext);

    let mut envelope = Vec::new();
    envelope.extend_from_slice(uuid.as_bytes());
    envelope.extend_from_slice(&lease.to_be_bytes());
    envelope.extend_from_slice(&packet);

    let mut payload = Vec::new();
    write_string(&mut payload, BOB);
    write_varint(&mut payload, envelope.len() as i32);
    payload.extend_from_slice(&envelope);
    payload
}

fn session_message_aad() -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(&[4, 4, 0]);
    push_string(&mut aad, ALICE);
    push_string(&mut aad, BOB);
    aad.extend_from_slice(&TUNNEL_TIMESTAMP.to_be_bytes());
    aad.extend_from_slice(&TUNNEL_MESSAGE_ID);
    push_string(&mut aad, SESSION_ID);
    aad.extend_from_slice(&0_i64.to_be_bytes());
    push_string(&mut aad, "CHACHA20-POLY1305");
    push_string(&mut aad, "HKDF-SHA256");
    aad
}

fn mc_packet(id: i32, payload: &[u8]) -> Vec<u8> {
    let mut inner = Vec::new();
    write_varint(&mut inner, id);
    inner.extend_from_slice(payload);
    let mut frame = Vec::new();
    write_varint(&mut frame, inner.len() as i32);
    frame.extend(inner);
    frame
}

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

fn write_string(out: &mut Vec<u8>, text: &str) {
    write_varint(out, text.len() as i32);
    out.extend_from_slice(text.as_bytes());
}

fn write_varint(out: &mut Vec<u8>, mut value: i32) {
    loop {
        let mut byte = (value as u8) & 0x7f;
        value = ((value as u32) >> 7) as i32;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn hex_decode(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = (pair[0] as char).to_digit(16).unwrap() as u8;
            let low = (pair[1] as char).to_digit(16).unwrap() as u8;
            (high << 4) | low
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Minimal pcapng / Ethernet / IPv4 / TCP fixture writer
// ---------------------------------------------------------------------------

fn build_pcapng(packets: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut shb = Vec::new();
    shb.extend_from_slice(&0x1A2B_3C4D_u32.to_le_bytes());
    shb.extend_from_slice(&1u16.to_le_bytes());
    shb.extend_from_slice(&0u16.to_le_bytes());
    shb.extend_from_slice(&(-1i64).to_le_bytes());
    push_block(&mut out, 0x0A0D_0D0A, &shb);

    let mut idb = Vec::new();
    idb.extend_from_slice(&1u16.to_le_bytes());
    idb.extend_from_slice(&0u16.to_le_bytes());
    idb.extend_from_slice(&262_144u32.to_le_bytes());
    push_block(&mut out, 1, &idb);

    let base_micros = 1_793_000_000_000_000i64;
    for (index, packet) in packets.iter().enumerate() {
        let mut padded = packet.clone();
        while padded.len() % 4 != 0 {
            padded.push(0);
        }
        let timestamp = base_micros + index as i64 * 1_000;
        let mut body = Vec::new();
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&((timestamp >> 32) as u32).to_le_bytes());
        body.extend_from_slice(&(timestamp as u32).to_le_bytes());
        body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        body.extend_from_slice(&(packet.len() as u32).to_le_bytes());
        body.extend_from_slice(&padded);
        push_block(&mut out, 6, &body);
    }
    out
}

fn push_block(out: &mut Vec<u8>, kind: u32, body: &[u8]) {
    let total = (12 + body.len()) as u32;
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(&total.to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&total.to_le_bytes());
}

fn tcp_packet(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut tcp = Vec::new();
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&ack.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&65_535u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(&0u16.to_be_bytes());
    tcp.extend_from_slice(payload);

    let mut ip = Vec::new();
    ip.push(0x45);
    ip.push(0);
    ip.extend_from_slice(&((20 + tcp.len()) as u16).to_be_bytes());
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&0x4000u16.to_be_bytes());
    ip.push(64);
    ip.push(6);
    ip.extend_from_slice(&0u16.to_be_bytes());
    ip.extend_from_slice(&[127, 0, 0, 1]);
    ip.extend_from_slice(&[127, 0, 0, 1]);
    ip.extend_from_slice(&tcp);

    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    frame.extend_from_slice(&0x0800u16.to_be_bytes());
    frame.extend_from_slice(&ip);
    frame
}
