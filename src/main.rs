use std::path::PathBuf;

use k04m_log_parser::app::K04MApp;
use k04m_log_parser::export::export_json;
use k04m_log_parser::log_reader::load_paths;

#[derive(Default)]
struct Cli {
    paths: Vec<PathBuf>,
    export: Option<PathBuf>,
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

    if let Some(export_path) = &cli.export {
        if cli.paths.is_empty() {
            return Err("--export 需要至少一个日志文件或目录".to_owned());
        }
        let loaded = load_paths(cli.paths)?;
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
        println!("JSON 已写入 {}", export_path.display());
        return Ok(());
    }

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
        Box::new(move |cc| Ok(Box::new(K04MApp::new(cc, cli.paths)))),
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
            _ if text.starts_with("--export=") => {
                let value = &text["--export=".len()..];
                if value.is_empty() {
                    return Err("--export= 缺少输出路径".to_owned());
                }
                cli.export = Some(PathBuf::from(value));
            }
            _ if text.starts_with('-') => {
                return Err(format!("未知参数：{text}（使用 --help 查看用法）"));
            }
            _ => cli.paths.push(PathBuf::from(argument)),
        }
    }
    Ok(cli)
}

fn print_help() {
    println!(
        "K04M 日志解析器 {}\n\
         \n\
         用法：\n\
           k04m-log-parser [日志文件或目录 ...]\n\
           k04m-log-parser --export <输出.json> [日志文件或目录 ...]\n\
         \n\
         参数：\n\
           --export <路径>  解析后导出 JSON，不启动图形界面\n\
           -h, --help      显示帮助\n\
           -V, --version   显示版本\n\
         \n\
         图形界面支持 .log 和 .log.gz，可打开文件或递归扫描 logs 文件夹。",
        env!("CARGO_PKG_VERSION")
    );
}
