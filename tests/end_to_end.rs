use std::fs;
use std::path::PathBuf;

use base64::Engine as _;
use k04m_log_parser::export::to_json_string;
use k04m_log_parser::log_reader::load_paths;
use k04m_log_parser::model::MessageStatus;

fn push_string(out: &mut Vec<u8>, value: &str) {
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value.as_bytes());
}

fn push_bytes16(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn push_bytes32(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as i32).to_be_bytes());
    out.extend_from_slice(bytes);
}

fn sample_packet() -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&[4, 1, 0x02]);
    push_string(&mut out, "alice");
    push_string(&mut out, "bob");
    out.extend_from_slice(&1_792_595_888_914_i64.to_be_bytes());
    out.extend_from_slice(&[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef,
    ]);
    push_string(&mut out, "ML-KEM-768+X25519");
    push_string(&mut out, "AES-256-GCM");
    push_string(&mut out, "HKDF-SHA256");
    push_bytes16(&mut out, &[0x11; 12]);
    push_bytes32(&mut out, &[0x22; 32]);
    push_bytes32(&mut out, &[0x33; 20]);
    push_bytes32(&mut out, &[]);
    out
}

fn temp_dir(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("k04m-log-parser-e2e-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fragment_lines(packet: &[u8], include_last: bool) -> Vec<String> {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(packet);
    let chunks: Vec<&str> = encoded
        .as_bytes()
        .chunks(97)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect();
    let total = chunks.len();
    let id = "0123456789abcdef0123456789abcdef";
    let mut lines = Vec::new();
    for (index, chunk) in chunks.iter().enumerate() {
        if !include_last && index == total - 1 {
            continue;
        }
        lines.push(format!(
            "[12:00:{index:02}] [Server thread/INFO]: [Not Secure] <alice> [KRYPT04MCG] {id} {index} {total} {chunk}"
        ));
    }
    lines
}

#[test]
fn reassembles_out_of_order_duplicate_fragments_and_exports_json() {
    let dir = temp_dir("complete");
    let packet = sample_packet();
    let mut lines = fragment_lines(&packet, true);
    // Deliver out of order and repeat one physical line.
    lines.rotate_left(1);
    let duplicate = lines[1].clone();
    lines.push(duplicate);
    lines.insert(
        0,
        "[12:00:00] [Server thread/INFO]: unrelated chat line".to_owned(),
    );
    fs::write(dir.join("2026-10-21-1.log"), lines.join("\n")).unwrap();

    let loaded = load_paths([dir.clone()]).unwrap();
    assert_eq!(loaded.messages.len(), 1);
    let message = &loaded.messages[0];
    assert_eq!(message.status, MessageStatus::Parsed);
    assert_eq!(message.duplicate_count, 1);
    assert_eq!(message.binary.as_deref(), Some(packet.as_slice()));
    let parsed = message.packet.as_ref().expect("packet parsed");
    assert_eq!(parsed.sender, "alice");
    assert_eq!(parsed.receiver, "bob");
    assert!(message.warnings.is_empty(), "{:?}", message.warnings);

    let json = to_json_string(&loaded).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(value["messages"][0]["status"], "parsed");
    assert_eq!(
        value["messages"][0]["packet"]["sender"],
        serde_json::Value::String("alice".to_owned())
    );
    assert_eq!(
        value["messages"][0]["binary_base64url"],
        serde_json::Value::String(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&packet))
    );
    let fields = value["messages"][0]["packet"]["fields"].as_array().unwrap();
    let sender = fields
        .iter()
        .find(|field| field["name"] == "sender")
        .unwrap();
    assert_eq!(sender["offset"], 3);
    assert_eq!(sender["length"], 7);
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn reports_missing_fragments_as_incomplete() {
    let dir = temp_dir("incomplete");
    let packet = sample_packet();
    let lines = fragment_lines(&packet, false);
    {
        let file = fs::File::create(dir.join("2026-10-21-2.log.gz")).unwrap();
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        use std::io::Write as _;
        encoder.write_all(lines.join("\n").as_bytes()).unwrap();
        encoder.finish().unwrap();
    }

    let loaded = load_paths([dir.clone()]).unwrap();
    assert_eq!(loaded.messages.len(), 1);
    let message = &loaded.messages[0];
    assert_eq!(message.status, MessageStatus::Incomplete);
    assert_eq!(message.missing_indices(), vec![message.total - 1]);
    assert!(message.binary.is_none());
    let _ = fs::remove_dir_all(dir);
}
