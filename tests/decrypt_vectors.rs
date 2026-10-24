//! End-to-end decryption vectors generated with Krypt04Mcg's Bouncy Castle
//! implementation (bcprov-jdk18on 1.86).
//!
//! Each case contains a packet produced by `CryptoService`, the recipient's
//! `LocalKeyMaterial`, and the expected plaintext. Regenerate with
//! `tools/generate_decryption_vectors.java` if the reference implementation
//! changes.

use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use k04m_log_parser::decrypt::KeyStore;
use k04m_log_parser::model::{FragmentGroup, LogTimestamp, MessageKind, MessageStatus};
use k04m_log_parser::packet::parse_packet;

fn vector_document() -> serde_json::Value {
    serde_json::from_str(include_str!("data/decryption-vectors.json")).unwrap()
}

fn temp_root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "k04m-log-parser-decrypt-test-{}",
        std::process::id()
    ))
}

fn message_from_base64(packet_base64: &str) -> FragmentGroup {
    let packet_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(packet_base64)
        .unwrap();
    let packet = parse_packet(&packet_bytes);
    assert!(
        packet.error.is_none(),
        "packet parse error: {:?}",
        packet.error
    );
    FragmentGroup {
        kind: MessageKind::Chat,
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
        binary: Some(packet_bytes),
        packet: Some(packet),
        status: MessageStatus::Parsed,
        decryption: None,
        signature: None,
    }
}

#[test]
fn decrypts_bouncy_castle_vectors() {
    let root = temp_root().join("vectors");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let document = vector_document();
    let cases = document["cases"].as_array().unwrap();
    assert!(cases.len() >= 9);

    for (index, case) in cases.iter().enumerate() {
        let name = case["name"].as_str().unwrap();
        let dir = root.join(format!("case-{index}"));
        fs::create_dir_all(&dir).unwrap();
        if let Some(receiver_key) = case.get("receiver_key") {
            fs::write(
                dir.join("local.json"),
                serde_json::to_vec_pretty(receiver_key).unwrap(),
            )
            .unwrap();
        }
        if let Some(secret) = case.get("session_secret") {
            let record = serde_json::json!({
                "peer": case["session_peer"],
                "sessionId": case["session_id"],
                "secret": secret,
            });
            fs::write(
                dir.join("session.json"),
                serde_json::to_vec_pretty(&record).unwrap(),
            )
            .unwrap();
        }

        let mut store = KeyStore::default();
        let summary = store.load_paths(std::slice::from_ref(&dir));
        assert!(
            summary.warnings.is_empty(),
            "{name}: unexpected key-load warnings: {:?}",
            summary.warnings
        );
        let expected_keys = usize::from(case.get("receiver_key").is_some());
        let expected_sessions = usize::from(case.get("session_secret").is_some());
        assert_eq!(summary.keys_added, expected_keys, "{name}");
        assert_eq!(summary.sessions_added, expected_sessions, "{name}");

        let message = message_from_base64(case["packet_base64url"].as_str().unwrap());
        let outcome = store.decrypt_message(&message);
        assert_eq!(
            outcome.status,
            k04m_log_parser::model::DecryptionStatus::Decrypted,
            "{name}: error={:?} attempts={:?}",
            outcome.error,
            outcome.attempts
        );
        let expected = case["expected_plaintext"].as_str().unwrap();
        assert_eq!(outcome.plaintext.as_deref(), Some(expected), "{name}");
        assert!(!outcome.plaintext_bytes.is_empty(), "{name}");
        assert!(
            outcome
                .attempts
                .last()
                .is_some_and(|attempt| attempt.success),
            "{name}: last attempt should be the successful one"
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn selects_the_right_key_among_multiple_loaded_keys() {
    let root = temp_root().join("multiple");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let document = vector_document();
    let cases = document["cases"].as_array().unwrap();
    let default_case = &cases[0];
    let hybrid_case = &cases[2];
    fs::write(
        root.join("bob.json"),
        serde_json::to_vec_pretty(&default_case["receiver_key"]).unwrap(),
    )
    .unwrap();
    fs::write(
        root.join("carol.json"),
        serde_json::to_vec_pretty(&hybrid_case["receiver_key"]).unwrap(),
    )
    .unwrap();

    let mut store = KeyStore::default();
    let summary = store.load_paths(std::slice::from_ref(&root));
    assert!(summary.warnings.is_empty(), "{:?}", summary.warnings);
    assert_eq!(summary.keys_added, 2);

    for (case, expected_owner) in [(default_case, "bob"), (hybrid_case, "carol")] {
        let message = message_from_base64(case["packet_base64url"].as_str().unwrap());
        let outcome = store.decrypt_message(&message);
        assert_eq!(
            outcome.status,
            k04m_log_parser::model::DecryptionStatus::Decrypted,
            "error={:?} attempts={:?}",
            outcome.error,
            outcome.attempts
        );
        assert_eq!(outcome.key_owner.as_deref(), Some(expected_owner));
        assert_eq!(
            outcome.plaintext.as_deref(),
            case["expected_plaintext"].as_str()
        );
    }

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn decrypts_kmcg_encrypted_account_storage() {
    let root = temp_root().join("account");
    let _ = fs::remove_dir_all(&root);
    let document = vector_document();
    let account = &document["encrypted_account"];
    for (relative, encoded) in account["files"].as_object().unwrap() {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded.as_str().unwrap())
            .unwrap();
        fs::write(path, bytes).unwrap();
    }

    let mut store = KeyStore::default();
    let summary = store.load_paths(std::slice::from_ref(&root));
    assert!(
        summary.warnings.is_empty(),
        "unexpected warnings: {:?}",
        summary.warnings
    );
    assert_eq!(summary.keys_added, 1);
    assert_eq!(summary.sessions_added, 1);

    let key_message = message_from_base64(account["key_file_packet"].as_str().unwrap());
    let outcome = store.decrypt_message(&key_message);
    assert_eq!(
        outcome.status,
        k04m_log_parser::model::DecryptionStatus::Decrypted,
        "error={:?} attempts={:?}",
        outcome.error,
        outcome.attempts
    );
    assert_eq!(
        outcome.plaintext.as_deref(),
        account["expected_key_plaintext"].as_str()
    );

    let session_message = message_from_base64(account["session_file_packet"].as_str().unwrap());
    let outcome = store.decrypt_message(&session_message);
    assert_eq!(
        outcome.status,
        k04m_log_parser::model::DecryptionStatus::Decrypted,
        "error={:?} attempts={:?}",
        outcome.error,
        outcome.attempts
    );
    assert_eq!(
        outcome.plaintext.as_deref(),
        account["expected_session_plaintext"].as_str()
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn incomplete_messages_are_not_attempted() {
    let store = KeyStore::default();
    let message = FragmentGroup {
        kind: MessageKind::Chat,
        message_id: "0".repeat(32),
        transport_sender: "tester".to_owned(),
        total: 2,
        slots: Default::default(),
        first_seen: LogTimestamp::default(),
        last_seen: LogTimestamp::default(),
        first_order: 0,
        duplicate_count: 0,
        conflicts: 0,
        warnings: Vec::new(),
        binary: None,
        packet: None,
        status: MessageStatus::Incomplete,
        decryption: None,
        signature: None,
    };
    let outcome = store.decrypt_message(&message);
    assert_eq!(
        outcome.status,
        k04m_log_parser::model::DecryptionStatus::NotAttempted
    );
}
