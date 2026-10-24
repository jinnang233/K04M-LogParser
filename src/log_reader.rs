//! Log-file discovery, `.gz` decompression, line scanning and reassembly.

use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};

use chrono::{Local, NaiveDate};

use crate::capture::is_capture_extension;
use crate::fragment::{GroupAccumulator, PREFIX, parse_fragment_line};
use crate::model::{FragmentOccurrence, LoadedLogs, LogTimestamp, SourceInfo};

/// Log and capture files discovered below the paths selected in the GUI.
#[derive(Clone, Debug, Default)]
pub struct DiscoveredInputs {
    pub logs: Vec<PathBuf>,
    pub captures: Vec<PathBuf>,
}

/// Classifies explicit files and recursively scans directories. Explicit
/// files are logs unless their extension is `.pcap`/`.pcapng`; directories
/// only contribute `.log`, `.log.gz`, `.pcap` and `.pcapng` files.
pub fn discover_inputs(
    paths: impl IntoIterator<Item = PathBuf>,
) -> Result<DiscoveredInputs, String> {
    let mut inputs = DiscoveredInputs::default();
    for path in paths {
        collect_input(&path, &mut inputs, 0)?;
    }
    inputs.logs.sort();
    inputs.logs.dedup();
    inputs.captures.sort();
    inputs.captures.dedup();
    Ok(inputs)
}

fn collect_input(path: &Path, inputs: &mut DiscoveredInputs, depth: usize) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("无法读取路径 {}：{error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        if is_capture_extension(path) {
            inputs.captures.push(path.to_path_buf());
        } else {
            inputs.logs.push(path.to_path_buf());
        }
        return Ok(());
    }
    if !metadata.is_dir() || depth >= 8 {
        return Ok(());
    }
    let entries =
        fs::read_dir(path).map_err(|error| format!("无法读取目录 {}：{error}", path.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("读取 {} 的目录项失败：{error}", path.display()))?;
        let child = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("读取 {} 的类型失败：{error}", child.display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_input(&child, inputs, depth + 1)?;
        } else if file_type.is_file() {
            if is_log_name(&child) {
                inputs.logs.push(child);
            } else if is_capture_extension(&child) {
                inputs.captures.push(child);
            }
        }
    }
    Ok(())
}

/// Loads explicit files or recursively discovers logs below directories.
pub fn load_paths(paths: impl IntoIterator<Item = PathBuf>) -> Result<LoadedLogs, String> {
    let mut files = Vec::new();
    for path in paths {
        collect_path(&path, &mut files, 0)?;
    }
    files.sort();
    files.dedup();

    if files.is_empty() {
        return Err("没有找到可读取的 .log 或 .log.gz 文件".to_owned());
    }

    let mut loaded = LoadedLogs::default();
    let mut accumulator = GroupAccumulator::new();

    for path in files {
        scan_file(&path, &mut loaded, &mut accumulator);
    }

    loaded.messages = accumulator.finish();
    loaded.messages.sort_by_key(|message| message.first_order);
    Ok(loaded)
}

fn collect_path(path: &Path, files: &mut Vec<PathBuf>, depth: usize) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("无法读取路径 {}：{error}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Ok(());
    }
    if metadata.is_file() {
        files.push(path.to_path_buf());
        return Ok(());
    }
    if !metadata.is_dir() {
        return Ok(());
    }
    if depth >= 8 {
        return Ok(());
    }

    let entries =
        fs::read_dir(path).map_err(|error| format!("无法读取目录 {}：{error}", path.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("读取 {} 的目录项失败：{error}", path.display()))?;
        let child = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|error| format!("读取 {} 的类型失败：{error}", child.display()))?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_path(&child, files, depth + 1)?;
        } else if file_type.is_file() && is_log_name(&child) {
            files.push(child);
        }
    }
    Ok(())
}

fn is_log_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let lower = name.to_ascii_lowercase();
    lower.ends_with(".log") || lower.ends_with(".log.gz")
}

fn scan_file(path: &Path, loaded: &mut LoadedLogs, accumulator: &mut GroupAccumulator) {
    let source_path = path.display().to_string();
    let source_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or(&source_path)
        .to_owned();
    let date = infer_source_date(path);
    let metadata = fs::metadata(path).ok();
    let bytes = metadata.as_ref().map_or(0, fs::Metadata::len);

    let reader: Box<dyn Read> = match File::open(path) {
        Ok(file) => {
            if path
                .extension()
                .and_then(|extension| extension.to_str())
                .is_some_and(|extension| extension.eq_ignore_ascii_case("gz"))
            {
                Box::new(flate2::read::MultiGzDecoder::new(file))
            } else {
                Box::new(file)
            }
        }
        Err(error) => {
            loaded
                .warnings
                .push(format!("无法打开 {}：{error}", path.display()));
            return;
        }
    };
    let mut reader = BufReader::new(reader);
    let mut buffer = Vec::new();
    let mut line_number = 0usize;
    let mut file_fragments = 0usize;

    loop {
        buffer.clear();
        match reader.read_until(b'\n', &mut buffer) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) => {
                loaded.warnings.push(format!(
                    "读取 {} 时出错（已处理 {line_number} 行）：{error}",
                    path.display()
                ));
                break;
            }
        }
        line_number += 1;
        while matches!(buffer.last().copied(), Some(b'\n' | b'\r')) {
            buffer.pop();
        }
        let text = String::from_utf8_lossy(&buffer);
        if !text.contains(PREFIX) {
            continue;
        }

        let Some(parsed) = parse_fragment_line(&text) else {
            continue;
        };
        let fragment = match parsed {
            Ok(fragment) => fragment,
            Err(reason) => {
                loaded.malformed_lines += 1;
                if loaded.warnings.len() < 80 {
                    loaded.warnings.push(format!(
                        "{}:{} 无法解析分片：{reason}",
                        path.display(),
                        line_number
                    ));
                }
                continue;
            }
        };

        let timestamp = combine_timestamp(&date, &fragment.line_time);
        let occurrence = FragmentOccurrence {
            source_path: source_path.clone(),
            source_name: source_name.clone(),
            line: line_number,
            timestamp,
            index: fragment.index,
            total: fragment.total,
            payload_length: fragment.payload.len(),
            payload: fragment.payload.clone(),
        };
        accumulator.add_occurrence(&fragment.transport_sender, &fragment.message_id, occurrence);
        file_fragments += 1;
        loaded.fragment_lines += 1;
    }

    loaded.sources.push(SourceInfo {
        path: source_path,
        name: source_name,
        date,
        bytes,
        lines: line_number,
        fragments: file_fragments,
    });
}

fn infer_source_date(path: &Path) -> Option<String> {
    let name = path.file_name().and_then(|name| name.to_str())?;
    if name.len() >= 10
        && let Some(prefix) = name.get(..10)
        && NaiveDate::parse_from_str(prefix, "%Y-%m-%d").is_ok()
    {
        return Some(prefix.to_owned());
    }
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let date: chrono::DateTime<Local> = modified.into();
    Some(date.format("%Y-%m-%d").to_string())
}

fn combine_timestamp(date: &Option<String>, time: &str) -> LogTimestamp {
    let text = match (date.as_deref(), time.is_empty()) {
        (Some(date), false) => format!("{date} {time}"),
        (Some(date), true) => date.to_owned(),
        (None, false) => time.to_owned(),
        (None, true) => String::new(),
    };
    LogTimestamp {
        text,
        date: date.clone(),
        time: time.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn temp_dir(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "k04m-log-parser-test-{}-{name}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn scans_plain_and_gzip_logs_and_groups_fragments() {
        let dir = temp_dir("plain-gz");
        let plain = dir.join("2026-10-21-1.log");
        fs::write(
            &plain,
            "[23:18:08] [Server thread/INFO]: <tester> [KRYPT04MCG] 0123456789abcdef0123456789abcdef 0 2 AA\n\
             [23:18:09] [Server thread/INFO]: <tester> [KRYPT04MCG] 0123456789abcdef0123456789abcdef 1 2 AQ\n",
        )
        .unwrap();

        let gz_path = dir.join("2026-10-21-2.log.gz");
        let file = File::create(&gz_path).unwrap();
        let mut encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
        writeln!(
            encoder,
            "[23:19:00] [Server thread/INFO]: <peer_abc123> [KRYPT04MCG] fedcba9876543210fedcba9876543210 0 1 AA"
        )
        .unwrap();
        encoder.finish().unwrap();

        let result = load_paths([dir.clone()]).unwrap();
        assert_eq!(result.sources.len(), 2);
        assert_eq!(result.fragment_lines, 3);
        assert_eq!(result.messages.len(), 2);
        assert_eq!(
            result.messages[0].first_seen.date.as_deref(),
            Some("2026-10-21")
        );
        assert_eq!(result.messages[0].unique_fragments(), 2);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn infers_date_from_rotated_name() {
        let path = Path::new("/tmp/2026-10-21-4.log.gz");
        assert_eq!(infer_source_date(path).as_deref(), Some("2026-10-21"));
    }

    #[test]
    fn classifies_logs_and_captures_for_the_gui() {
        let dir = temp_dir("classify");
        fs::write(dir.join("latest.log"), "").unwrap();
        fs::write(dir.join("old.log.gz"), "").unwrap();
        fs::write(dir.join("traffic.pcap"), "").unwrap();
        fs::write(dir.join("traffic.pcapng"), "").unwrap();
        fs::write(dir.join("keys.json"), "").unwrap();

        let discovered = discover_inputs([dir.clone()]).unwrap();
        assert_eq!(discovered.logs.len(), 2);
        assert_eq!(discovered.captures.len(), 2);
        assert!(
            discovered
                .logs
                .iter()
                .all(|path| path.extension().is_some_and(|ext| ext != "json"))
        );

        let explicit = discover_inputs([dir.join("traffic.pcapng")]).unwrap();
        assert!(explicit.logs.is_empty());
        assert_eq!(explicit.captures.len(), 1);

        let _ = fs::remove_dir_all(dir);
    }
}
