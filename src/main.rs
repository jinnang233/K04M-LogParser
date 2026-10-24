use std::path::PathBuf;

use k04m_log_parser::app::K04MApp;
use k04m_log_parser::capture::{
    CaptureOptions, analyze_captures, export_capture_json, extract_stream_data,
    is_capture_extension,
};
use k04m_log_parser::decrypt::KeyStore;
use k04m_log_parser::export::export_json;
use k04m_log_parser::log_reader::load_paths;

#[derive(Default)]
struct Cli {
    paths: Vec<PathBuf>,
    pcap_paths: Vec<PathBuf>,
    keys: Vec<PathBuf>,
    export: Option<PathBuf>,
    extract_streams: Option<PathBuf>,
    help: bool,
    version: bool,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("错误：{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let cli = parse_args()?;
    if cli.help {
        print_help();
        return Ok(());
    }
    if cli.version {
        println!("k04m-log-parser {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }

    if cli.extract_streams.is_some() && cli.pcap_paths.is_empty() {
        return Err("--extract-streams 只适用于 pcap/pcapng 输入".to_owned());
    }

    if !cli.pcap_paths.is_empty() && (cli.export.is_some() || cli.extract_streams.is_some()) {
        if !cli.paths.is_empty() {
            return Err("不能在同一次运行中混合日志与 pcap/pcapng 输入；请分别导出".to_owned());
        }
        let mut key_store = KeyStore::default();
        let key_summary = if cli.keys.is_empty() {
            None
        } else {
            Some(key_store.load_paths(&cli.keys))
        };
        let options = CaptureOptions {
            retain_stream_data: cli.extract_streams.is_some(),
        };
        let analysis = analyze_captures(&cli.pcap_paths, &key_store, &options)?;
        if let Some(export_path) = &cli.export {
            export_capture_json(export_path, &analysis)?;
        }
        let extracted = if let Some(directory) = &cli.extract_streams {
            let count = extract_stream_data(directory, &analysis)?;
            Some(count)
        } else {
            None
        };
        print_capture_summary(&analysis, &key_store, key_summary.as_ref());
        if let Some(export_path) = &cli.export {
            println!("JSON 已写入 {}", export_path.display());
        }
        if let (Some(directory), Some(count)) = (&cli.extract_streams, extracted) {
            println!("已提取 {count} 个流方向到 {}", directory.display());
        }
        return Ok(());
    }

    if let Some(export_path) = &cli.export {
        if cli.paths.is_empty() {
            return Err("--export 需要至少一个日志文件或目录".to_owned());
        }
        let mut key_store = KeyStore::default();
        let key_summary = if cli.keys.is_empty() {
            None
        } else {
            Some(key_store.load_paths(&cli.keys))
        };
        let mut loaded = load_paths(cli.paths)?;
        key_store.decrypt_loaded(&mut loaded);
        export_json(export_path, &loaded)?;
        println!(
            "已解析 {} 个文件、{} 条分片，重组 {} 条消息（已解析 {} / 不完整 {} / 错误 {}）",
            loaded.sources.len(),
            loaded.fragment_lines,
            loaded.messages.len(),
            loaded.parsed_count(),
            loaded.incomplete_count(),
            loaded.invalid_count()
        );
        if let Some(summary) = &key_summary {
            println!("密钥：{}", summary.message());
        }
        let decrypted = loaded
            .messages
            .iter()
            .filter(|message| {
                message
                    .decryption
                    .as_ref()
                    .is_some_and(|outcome| outcome.is_decrypted())
            })
            .count();
        println!(
            "已解密 {decrypted} 条消息（加载私钥 {} 个、会话密钥 {} 个）",
            key_store.private_keys.len(),
            key_store.sessions.len()
        );
        let signed = loaded.signed_packet_count();
        if signed > 0 {
            println!(
                "签名：检查 {signed} 个已签名包，有效 {}、缺少公钥 {}、不支持 {}、无效 {}",
                loaded.signature_count(k04m_log_parser::model::SignatureStatus::Verified),
                loaded.signature_count(k04m_log_parser::model::SignatureStatus::NoKey),
                loaded.signature_count(k04m_log_parser::model::SignatureStatus::Unsupported),
                loaded.signature_count(k04m_log_parser::model::SignatureStatus::Failed),
            );
        }
        println!("JSON 已写入 {}", export_path.display());
        return Ok(());
    }

    if !cli.pcap_paths.is_empty() && !cli.paths.is_empty() {
        return Err("不能在同一次运行中混合日志与 pcap/pcapng 输入；请分别打开".to_owned());
    }
    let mut initial_paths = cli.paths;
    initial_paths.extend(cli.pcap_paths);

    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([1040.0, 640.0])
            .with_title("K04M 日志解析器 · Krypt04Mcg"),
        ..Default::default()
    };
    eframe::run_native(
        "K04M 日志解析器",
        options,
        Box::new(move |cc| Ok(Box::new(K04MApp::new(cc, initial_paths, cli.keys)))),
    )
    .map_err(|error| format!("启动图形界面失败：{error}"))
}

fn parse_args() -> Result<Cli, String> {
    let mut cli = Cli::default();
    let mut args = std::env::args_os().skip(1);
    while let Some(argument) = args.next() {
        let text = argument.to_string_lossy();
        match text.as_ref() {
            "-h" | "--help" => cli.help = true,
            "-V" | "--version" => cli.version = true,
            "--export" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--export 缺少输出路径".to_owned())?;
                cli.export = Some(PathBuf::from(value));
            }
            "--pcap" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--pcap 缺少 pcap/pcapng 路径".to_owned())?;
                cli.pcap_paths.push(PathBuf::from(value));
            }
            "--extract-streams" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--extract-streams 缺少输出目录".to_owned())?;
                cli.extract_streams = Some(PathBuf::from(value));
            }
            _ if text.starts_with("--export=") => {
                let value = &text["--export=".len()..];
                if value.is_empty() {
                    return Err("--export= 缺少输出路径".to_owned());
                }
                cli.export = Some(PathBuf::from(value));
            }
            _ if text.starts_with("--pcap=") => {
                let value = &text["--pcap=".len()..];
                if value.is_empty() {
                    return Err("--pcap= 缺少 pcap/pcapng 路径".to_owned());
                }
                cli.pcap_paths.push(PathBuf::from(value));
            }
            _ if text.starts_with("--extract-streams=") => {
                let value = &text["--extract-streams=".len()..];
                if value.is_empty() {
                    return Err("--extract-streams= 缺少输出目录".to_owned());
                }
                cli.extract_streams = Some(PathBuf::from(value));
            }
            "--key" | "--keys" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--key 缺少私钥文件或账户目录".to_owned())?;
                cli.keys.push(PathBuf::from(value));
            }
            _ if text.starts_with("--key=") => {
                let value = &text["--key=".len()..];
                if value.is_empty() {
                    return Err("--key= 缺少私钥文件或账户目录".to_owned());
                }
                cli.keys.push(PathBuf::from(value));
            }
            _ if text.starts_with("--keys=") => {
                let value = &text["--keys=".len()..];
                if value.is_empty() {
                    return Err("--keys= 缺少私钥文件或账户目录".to_owned());
                }
                cli.keys.push(PathBuf::from(value));
            }
            _ if text.starts_with('-') => {
                return Err(format!("未知参数：{text}（使用 --help 查看用法）"));
            }
            _ => {
                let path = PathBuf::from(argument);
                if is_capture_extension(&path) {
                    cli.pcap_paths.push(path);
                } else {
                    cli.paths.push(path);
                }
            }
        }
    }
    Ok(cli)
}

fn print_capture_summary(
    analysis: &k04m_log_parser::capture::CaptureAnalysis,
    key_store: &KeyStore,
    key_summary: Option<&k04m_log_parser::decrypt::KeyLoadSummary>,
) {
    let summary = &analysis.summary;
    println!(
        "已解析 {} 个抓包、{} 个 TCP 会话、{} 个 Minecraft 连接（其中 {} 个包含 Krypt04Mcg 数据）",
        summary.capture_files,
        summary.conversations,
        summary.minecraft_connections,
        summary.krypt_connections
    );
    println!(
        "通道消息 {} 条，聊天分片 {} 条，重组聊天 {} 条（已解密 {}）",
        summary.channel_messages,
        summary.chat_fragments,
        summary.chat_transfers,
        summary.chat_transfers_decrypted
    );
    println!(
        "签名：已签名包 {} 个，有效 {}、缺少公钥 {}、不支持 {}、无效 {}",
        summary.signature_packets,
        summary.signatures_verified,
        summary.signatures_no_key,
        summary.signatures_unsupported,
        summary.signatures_failed
    );
    println!(
        "公钥共享 {} 组，API 流 {} 条，流记录 {} 条（线上观测 {} 条，已解密 {} 条），明文 {} 字节",
        summary.public_key_shares,
        summary.api_streams,
        summary.api_data_records,
        summary.api_data_record_observations,
        summary.api_data_records_decrypted,
        summary.total_plaintext_bytes
    );
    if let Some(summary) = key_summary {
        println!("密钥：{}", summary.message());
    }
    println!(
        "已加载私钥 {} 个、会话密钥 {} 个",
        key_store.private_keys.len(),
        key_store.sessions.len()
    );
    if !analysis.warnings.is_empty() {
        println!("提示：{} 条（详见 JSON）", analysis.warnings.len());
    }
}

fn print_help() {
    println!(
        concat!(
            "K04M 日志解析器 {}\n",
            "\n",
            "用法：\n",
            "  k04m-log-parser [日志文件或目录 ...]\n",
            "  k04m-log-parser [--key <私钥或账户目录> ...] [日志文件或目录 ...]\n",
            "  k04m-log-parser --export <输出.json> [--key <路径> ...] [日志文件或目录 ...]\n",
            "  k04m-log-parser --pcap <抓包.pcapng> [--export <输出.json>] [--key <路径> ...]\n",
            "  k04m-log-parser --pcap <抓包.pcapng> --extract-streams <目录> [--key <路径> ...]\n",
            "\n",
            "参数：\n",
            "  --key <路径>     加载私钥/会话密钥/签名公钥；可重复。可指向\n",
            "                   LocalKeyMaterial (local.json)、sessions/stream-api\n",
            "                   sessions、keys/public、Krypt04Mcg 账户目录或\n",
            "                   包含多个账户的父目录\n",
            "  --pcap <路径>    打开 pcap/pcapng 抓包；可重复。位置参数中的 .pcap/.pcapng\n",
            "                   也会自动识别。与 --export/--extract-streams 同时使用时\n",
            "                   只做命令行分析，否则启动图形界面\n",
            "  --extract-streams <目录>\n",
            "                   把已解密的 API 流方向写入目录（需要匹配的 stream-api 会话密钥）\n",
            "  --export <路径>  解析后导出 JSON，不启动图形界面\n",
            "  -h, --help      显示帮助\n",
            "  -V, --version   显示版本\n",
            "\n",
            "图形界面支持 .log/.log.gz 与 .pcap/.pcapng，可打开文件或递归扫描文件夹。\n",
            "抓包分析支持 Minecraft 26.3（协议 777）的 krypt04mcg:chat_fragment、\n",
            "krypt04mcg:public_key、krypt04mcg:tunnel、krypt04mcg_stream:control 与\n",
            "krypt04mcg_stream:data/* 通道。加载签名公钥（keys/public、local.json 或\n",
            "抓包公钥共享）后会自动验证包签名。",
        ),
        env!("CARGO_PKG_VERSION")
    );
}
