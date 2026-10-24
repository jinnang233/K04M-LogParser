//! Signature verification vectors generated with Krypt04Mcg's Bouncy Castle
//! implementation (bcprov-jdk18on 1.86).
//!
//! Each case contains a signed packet and the sender's public identity. The
//! identity's private keys are throwaway test material and are not included.

use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use k04m_log_parser::decrypt::KeyStore;
use k04m_log_parser::export::to_json_string;
use k04m_log_parser::log_reader::load_paths;
use k04m_log_parser::model::{
    FragmentGroup, LogTimestamp, MessageStatus, SignatureOutcome, SignatureStatus,
};
use k04m_log_parser::packet::parse_packet;

fn vector_document() -> serde_json::Value {
    serde_json::from_str(include_str!("data/signature-vectors.json")).unwrap()
}

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "k04m-log-parser-signature-test-{}",
        std::process::id()
    ))
}

fn group_from_base64(packet_base64: &str) -> (FragmentGroup, Vec<u8>) {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(packet_base64)
        .unwrap();
    let packet = parse_packet(&bytes);
    assert!(
        packet.error.is_none(),
        "packet parse error: {:?}",
        packet.error
    );
    let group = FragmentGroup {
        message_id: packet.message_id_hex.clone(),
        transport_sender: packet.sender.clone(),
        total: 1,
        slots: Default::default(),
        first_seen: LogTimestamp::default(),
        last_seen: LogTimestamp::default(),
        first_order: 0,
        duplicate_count: 0,
        conflicts: 0,
        warnings: Vec::new(),
        binary: Some(bytes.clone()),
        packet: Some(packet),
        status: MessageStatus::Parsed,
        decryption: None,
        signature: None,
    };
    (group, bytes)
}

fn verify(group: &FragmentGroup, identity: &serde_json::Value) -> SignatureOutcome {
    use std::sync::atomic::{AtomicUsize, Ordering};
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let root = temp_root().join(format!(
        "case-{}-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
        group.message_id
    ));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("identity.json"),
        serde_json::to_vec_pretty(identity).unwrap(),
    )
    .unwrap();
    let mut store = KeyStore::default();
    store.load_paths(std::slice::from_ref(&root));
    let outcome = store.verify_message(group);
    let _ = fs::remove_dir_all(root);
    outcome
}

#[test]
fn verifies_all_bouncy_castle_signature_vectors() {
    let document = vector_document();
    let cases = document["cases"].as_array().unwrap();
    assert!(cases.len() >= 9);

    for case in cases {
        let name = case["name"].as_str().unwrap();
        let algorithm = case["signature_algorithm"].as_str().unwrap();
        let (group, _) = group_from_base64(case["packet_base64url"].as_str().unwrap());
        let outcome = verify(&group, &case["sender_identity"]);

        assert_eq!(
            outcome.status,
            SignatureStatus::Verified,
            "{name} ({algorithm}) failed: {outcome:?}"
        );
        assert_eq!(outcome.algorithm.as_deref(), Some(algorithm));
        assert_eq!(
            outcome.key_owner.as_deref(),
            case["sender_identity"]["owner"].as_str()
        );
        assert!(outcome.is_verified(), "{name}");
    }
}

#[test]
fn rejects_tampered_signatures_for_every_vector() {
    let document = vector_document();
    for case in document["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let (group, mut bytes) = group_from_base64(case["packet_base64url"].as_str().unwrap());
        let packet = group.packet.as_ref().unwrap();
        assert!(packet.signature_len > 0, "{name} has no signature");
        let offset = packet.signature_data_offset;
        bytes[offset] ^= 0x01;

        let packet = parse_packet(&bytes);
        let tampered = FragmentGroup {
            binary: Some(bytes),
            packet: Some(packet),
            ..group.clone()
        };
        let outcome = verify(&tampered, &case["sender_identity"]);
        assert_eq!(
            outcome.status,
            SignatureStatus::Failed,
            "{name} should reject a flipped signature bit: {outcome:?}"
        );
    }
}

#[test]
fn verifies_signature_after_log_fragment_reassembly() {
    let document = vector_document();
    let case = &document["cases"][1];
    let packet = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(case["packet_base64url"].as_str().unwrap())
        .unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&packet);
    let chunks: Vec<_> = encoded.as_bytes().chunks(97).collect();
    let total = chunks.len();
    let message_id = "0123456789abcdef0123456789abcdef";
    let mut lines = Vec::new();
    for (index, chunk) in chunks.iter().enumerate() {
        lines.push(format!(
            "[12:00:{index:02}] [Server thread/INFO]: <alice> [KRYPT04MCG] {message_id} {index} {total} {}",
            std::str::from_utf8(chunk).unwrap()
        ));
    }

    let root = temp_root().join("log-case");
    let _ = fs::remove_dir_all(&root);
    let log_dir = root.join("logs");
    fs::create_dir_all(&log_dir).unwrap();
    fs::write(log_dir.join("latest.log"), lines.join("\n")).unwrap();
    let identity_path = root.join("identity.json");
    fs::write(
        &identity_path,
        serde_json::to_vec_pretty(&case["sender_identity"]).unwrap(),
    )
    .unwrap();

    let mut loaded = load_paths([log_dir]).unwrap();
    let mut store = KeyStore::default();
    store.load_paths(std::slice::from_ref(&identity_path));
    store.decrypt_loaded(&mut loaded);

    assert_eq!(loaded.messages.len(), 1);
    assert_eq!(
        loaded.messages[0].signature.as_ref().map(|s| s.status),
        Some(SignatureStatus::Verified)
    );
    let json: serde_json::Value = serde_json::from_str(&to_json_string(&loaded).unwrap()).unwrap();
    assert_eq!(json["cryptographic_verification"], true);
    assert_eq!(json["messages"][0]["signature"]["status"], "verified");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn reports_missing_public_key() {
    let document = vector_document();
    let case = &document["cases"][0];
    let (group, _) = group_from_base64(case["packet_base64url"].as_str().unwrap());
    let store = KeyStore::default();
    let outcome = store.verify_message(&group);
    assert_eq!(outcome.status, SignatureStatus::NoKey);
}
