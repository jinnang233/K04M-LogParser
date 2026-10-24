//! egui desktop front end.

use std::collections::BTreeMap;
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use chrono::{Local, NaiveDateTime};
use eframe::egui::{
    self, Align, Color32, FontData, FontDefinitions, FontFamily, FontId, Frame, Label, Layout,
    Margin, RichText, ScrollArea, Sense, Stroke, TextEdit, TextStyle, Ui, Vec2,
};

use crate::capture::{
    ApiStream, ApiStreamDirection, CaptureAnalysis, CaptureOptions, ChannelEvent, ChannelPayload,
    ChatTransfer, PublicKeyShare, analyze_captures, export_capture_json,
};
use crate::decrypt::{KeyLoadSummary, KeyStore};
use crate::export::export_json;
use crate::log_reader::{discover_inputs, load_paths};
use crate::model::{
    DataField, DecryptionOutcome, DecryptionStatus, FragmentGroup, FragmentSlot, LoadedLogs,
    MessageKind, MessageStatus, ParsedPacket, SignatureStatus, SourceInfo,
};
use crate::packet::{
    FlatField, byte_categories, flatten_fields, hex, hex_preview, packet_type_chinese,
};

/// The GUI keeps decrypted stream bytes so API-stream rows can show their
/// fields and full binary. The CLI defaults to not retaining them.
const GUI_CAPTURE_OPTIONS: CaptureOptions = CaptureOptions {
    retain_stream_data: true,
};

const ACCENT: Color32 = Color32::from_rgb(88, 166, 255);
const DIM: Color32 = Color32::from_rgb(140, 150, 165);
const FIELD_COLORS: [Color32; 12] = [
    Color32::from_rgb(108, 180, 255),
    Color32::from_rgb(255, 178, 92),
    Color32::from_rgb(123, 211, 153),
    Color32::from_rgb(239, 154, 154),
    Color32::from_rgb(200, 160, 255),
    Color32::from_rgb(98, 210, 214),
    Color32::from_rgb(242, 201, 108),
    Color32::from_rgb(162, 196, 112),
    Color32::from_rgb(240, 138, 180),
    Color32::from_rgb(128, 170, 255),
    Color32::from_rgb(236, 146, 92),
    Color32::from_rgb(170, 170, 180),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MessageFilter {
    All,
    Parsed,
    Incomplete,
    Invalid,
}

impl MessageFilter {
    fn matches(self, status: MessageStatus) -> bool {
        match self {
            Self::All => true,
            Self::Parsed => status == MessageStatus::Parsed,
            Self::Incomplete => status == MessageStatus::Incomplete,
            Self::Invalid => status == MessageStatus::Invalid,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::All => "全部",
            Self::Parsed => "已解析",
            Self::Incomplete => "不完整",
            Self::Invalid => "错误",
        }
    }
}

#[derive(Clone, Debug)]
struct SelectedField {
    message_index: usize,
    key: String,
    label: String,
    offset: usize,
    length: usize,
    note: Option<String>,
}

impl SelectedField {
    fn range(&self) -> Range<usize> {
        self.offset..self.offset.saturating_add(self.length)
    }
}

pub struct K04MApp {
    data: Option<LoadedLogs>,
    /// Present when the current inputs are packet captures.
    capture: Option<CaptureAnalysis>,
    paths: Vec<PathBuf>,
    key_store: KeyStore,
    key_summary: Option<KeyLoadSummary>,
    selected_message: Option<usize>,
    selected_field: Option<SelectedField>,
    pending_hex_offset: Option<usize>,
    search: String,
    filter: MessageFilter,
    only_decrypted: bool,
    colorize_fields: bool,
    dark: bool,
    status: String,
    status_error: bool,
    show_sources: bool,
    show_warnings: bool,
    show_keys: bool,
    show_capture: bool,
}

impl K04MApp {
    pub fn new(
        cc: &eframe::CreationContext<'_>,
        initial_paths: Vec<PathBuf>,
        initial_keys: Vec<PathBuf>,
    ) -> Self {
        install_fonts(&cc.egui_ctx);
        let mut app = Self {
            data: None,
            capture: None,
            paths: Vec::new(),
            key_store: KeyStore::default(),
            key_summary: None,
            selected_message: None,
            selected_field: None,
            pending_hex_offset: None,
            search: String::new(),
            filter: MessageFilter::All,
            only_decrypted: false,
            colorize_fields: true,
            dark: true,
            status: "就绪：打开 .log 或 .log.gz 日志开始解析".to_owned(),
            status_error: false,
            show_sources: false,
            show_warnings: false,
            show_keys: false,
            show_capture: false,
        };
        Self::apply_theme(&cc.egui_ctx, app.dark);
        if !initial_keys.is_empty() {
            app.load_keys(initial_keys);
            app.show_keys = false;
        }
        if !initial_paths.is_empty() {
            app.load(initial_paths);
        }
        app
    }

    fn apply_theme(ctx: &egui::Context, dark: bool) {
        // Pin the theme instead of following the OS preference: egui only learns
        // the system theme after the first frame, so on Windows the active style
        // could switch to the unthemed light style while the app still draws
        // dark backgrounds, mixing light and dark widgets.
        let theme = if dark {
            egui::Theme::Dark
        } else {
            egui::Theme::Light
        };
        ctx.set_theme(theme);
        let mut visuals = if dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        if dark {
            visuals.panel_fill = Color32::from_rgb(20, 23, 29);
            visuals.window_fill = Color32::from_rgb(24, 28, 35);
            visuals.extreme_bg_color = Color32::from_rgb(13, 16, 21);
            visuals.faint_bg_color = Color32::from_rgb(29, 34, 42);
            visuals.code_bg_color = Color32::from_rgb(16, 19, 24);
            visuals.widgets.noninteractive.bg_stroke =
                Stroke::new(1.0_f32, Color32::from_rgb(42, 48, 58));
            visuals.widgets.inactive.bg_fill = Color32::from_rgb(35, 41, 51);
            visuals.widgets.hovered.bg_fill = Color32::from_rgb(46, 55, 69);
            visuals.widgets.active.bg_fill = Color32::from_rgb(55, 67, 84);
        } else {
            visuals.panel_fill = Color32::from_rgb(244, 246, 249);
            visuals.window_fill = Color32::from_rgb(252, 253, 255);
            visuals.extreme_bg_color = Color32::from_rgb(230, 234, 240);
            visuals.faint_bg_color = Color32::from_rgb(236, 239, 244);
            visuals.code_bg_color = Color32::from_rgb(238, 241, 246);
        }
        visuals.selection.bg_fill = ACCENT.gamma_multiply(0.45);
        visuals.selection.stroke = Stroke::new(1.0_f32, ACCENT);
        visuals.hyperlink_color = ACCENT;
        let mut style = (*ctx.style_of(theme)).clone();
        style.visuals = visuals;
        style.spacing.item_spacing = Vec2::new(8.0, 6.0);
        style.spacing.button_padding = Vec2::new(9.0, 5.0);
        style.spacing.scroll.bar_width = 10.0;
        style.text_styles.insert(
            TextStyle::Heading,
            FontId::new(21.0, FontFamily::Proportional),
        );
        style
            .text_styles
            .insert(TextStyle::Body, FontId::new(14.0, FontFamily::Proportional));
        style.text_styles.insert(
            TextStyle::Monospace,
            FontId::new(13.5, FontFamily::Monospace),
        );
        ctx.set_style_of(theme, style);
    }

    fn load(&mut self, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        self.paths = dedupe_paths(paths);
        let inputs = match discover_inputs(self.paths.clone()) {
            Ok(inputs) => inputs,
            Err(error) => {
                self.fail(error);
                return;
            }
        };
        if !inputs.logs.is_empty() && !inputs.captures.is_empty() {
            self.fail(
                "不能在同一次加载中混合日志与 pcap/pcapng 输入；请分别打开（或先用 --export 分别导出）"
                    .to_owned(),
            );
            return;
        }
        if !inputs.captures.is_empty() {
            self.load_captures(inputs.captures);
        } else {
            self.load_logs(inputs.logs);
        }
    }

    fn load_logs(&mut self, paths: Vec<PathBuf>) {
        self.capture = None;
        match load_paths(paths) {
            Ok(data) => {
                let summary = if data.messages.is_empty() {
                    format!(
                        "已扫描 {} 个文件、{} 条分片，但没有找到完整的 Krypt04Mcg 消息",
                        data.sources.len(),
                        data.fragment_lines
                    )
                } else {
                    format!(
                        "已加载 {} 个文件、{} 条分片，重组出 {} 条消息（已解析 {} / 不完整 {} / 错误 {}）",
                        data.sources.len(),
                        data.fragment_lines,
                        data.messages.len(),
                        data.parsed_count(),
                        data.incomplete_count(),
                        data.invalid_count()
                    )
                };
                self.selected_message = (!data.messages.is_empty()).then_some(0);
                self.selected_field = None;
                self.pending_hex_offset = None;
                self.search.clear();
                self.filter = MessageFilter::All;
                self.status_error = false;
                self.status = summary;
                self.data = Some(data);
                self.redecrypt();
            }
            Err(error) => self.fail(error),
        }
    }

    fn load_captures(&mut self, paths: Vec<PathBuf>) {
        match analyze_captures(&paths, &self.key_store, &GUI_CAPTURE_OPTIONS) {
            Ok(analysis) => {
                let data = capture_to_loaded(&analysis);
                let summary = analysis.summary.clone();
                let control_count = analysis
                    .events
                    .iter()
                    .filter(|event| matches!(event.payload, ChannelPayload::Control { .. }))
                    .count();
                self.status_error = false;
                self.status = format!(
                    "已解析 {} 个抓包、{} 个 TCP 会话、{} 个 Minecraft 连接；聊天 {} 条（已解密 {}、已验签 {}）· 控制 {} 条 · 公钥共享 {} 条 · API 流 {} 条",
                    summary.capture_files,
                    summary.conversations,
                    summary.minecraft_connections,
                    summary.chat_transfers,
                    summary.chat_transfers_decrypted,
                    summary.signatures_verified,
                    control_count,
                    summary.public_key_shares,
                    summary.api_streams
                );
                self.selected_message = (!data.messages.is_empty()).then_some(0);
                self.selected_field = None;
                self.pending_hex_offset = None;
                self.search.clear();
                self.filter = MessageFilter::All;
                self.data = Some(data);
                self.capture = Some(analysis);
            }
            Err(error) => self.fail(error),
        }
    }

    fn refresh_capture(&mut self) {
        let paths = self.paths.clone();
        if paths.is_empty() {
            return;
        }
        let inputs = match discover_inputs(paths) {
            Ok(inputs) => inputs,
            Err(error) => {
                self.fail(error);
                return;
            }
        };
        if inputs.captures.is_empty() {
            return;
        }
        match analyze_captures(&inputs.captures, &self.key_store, &GUI_CAPTURE_OPTIONS) {
            Ok(analysis) => {
                let data = capture_to_loaded(&analysis);
                let selected = self
                    .selected_message
                    .filter(|index| *index < data.messages.len());
                self.selected_message = selected.or((!data.messages.is_empty()).then_some(0));
                self.selected_field = None;
                self.pending_hex_offset = None;
                self.data = Some(data);
                self.capture = Some(analysis);
            }
            Err(error) => self.fail(error),
        }
    }

    fn fail(&mut self, error: String) {
        self.status_error = true;
        self.status = error;
    }

    fn redecrypt(&mut self) {
        if self.capture.is_some() {
            self.refresh_capture();
        } else if let Some(data) = &mut self.data {
            self.key_store.decrypt_loaded(data);
        }
    }

    fn decrypted_count(&self) -> usize {
        self.data.as_ref().map_or(0, |data| {
            data.messages
                .iter()
                .filter(|message| {
                    message
                        .decryption
                        .as_ref()
                        .is_some_and(DecryptionOutcome::is_decrypted)
                })
                .count()
        })
    }

    fn signature_count(&self, status: SignatureStatus) -> usize {
        if let Some(capture) = &self.capture {
            let summary = &capture.summary;
            return match status {
                SignatureStatus::Verified => summary.signatures_verified,
                SignatureStatus::NoKey => summary.signatures_no_key,
                SignatureStatus::Unsupported => summary.signatures_unsupported,
                SignatureStatus::Failed => summary.signatures_failed,
                SignatureStatus::NotPresent | SignatureStatus::NotAttempted => 0,
            };
        }
        self.data
            .as_ref()
            .map_or(0, |data| data.signature_count(status))
    }

    fn load_keys(&mut self, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        let summary = self.key_store.load_paths(&paths);
        self.redecrypt();
        let message = format!(
            "{}；当前共 {} 个私钥、{} 个会话密钥，已解密 {} 条消息",
            summary.message(),
            self.key_store.private_keys.len(),
            self.key_store.sessions.len(),
            self.decrypted_count()
        );
        self.status_error = false;
        self.status = message;
        self.key_summary = Some(summary);
        self.show_keys = true;
    }

    fn open_key_files_dialog(&mut self) {
        let mut dialog = rfd::FileDialog::new()
            .add_filter("Krypt04Mcg 密钥/公钥/会话 JSON", &["json"])
            .add_filter("所有文件", &["*"]);
        if let Some(directory) = self.initial_directory() {
            dialog = dialog.set_directory(directory);
        }
        if let Some(paths) = dialog.pick_files() {
            self.load_keys(paths);
        }
    }

    fn open_key_folder_dialog(&mut self) {
        let mut dialog = rfd::FileDialog::new();
        if let Some(directory) = self.initial_directory() {
            dialog = dialog.set_directory(directory);
        }
        if let Some(path) = dialog.pick_folder() {
            self.load_keys(vec![path]);
        }
    }

    fn reload(&mut self) {
        if self.paths.is_empty() {
            self.status_error = true;
            self.status = "尚未打开任何日志".to_owned();
            return;
        }
        self.load(self.paths.clone());
    }

    fn open_files_dialog(&mut self) {
        let mut dialog = rfd::FileDialog::new()
            .add_filter("日志与抓包", &["log", "gz", "pcap", "pcapng"])
            .add_filter("Minecraft 日志", &["log", "gz"])
            .add_filter("pcap/pcapng 抓包", &["pcap", "pcapng"])
            .add_filter("所有文件", &["*"]);
        if let Some(directory) = self.initial_directory() {
            dialog = dialog.set_directory(directory);
        }
        if let Some(paths) = dialog.pick_files() {
            self.load(paths);
        }
    }

    fn open_folder_dialog(&mut self) {
        let mut dialog = rfd::FileDialog::new();
        if let Some(directory) = self.initial_directory() {
            dialog = dialog.set_directory(directory);
        }
        if let Some(path) = dialog.pick_folder() {
            self.load(vec![path]);
        }
    }

    fn initial_directory(&self) -> Option<PathBuf> {
        let first = self.paths.first()?;
        if first.is_dir() {
            Some(first.clone())
        } else {
            first.parent().map(Path::to_path_buf)
        }
    }

    fn export_dialog(&mut self) {
        let Some(data) = &self.data else {
            self.status_error = true;
            self.status = "没有可导出的消息".to_owned();
            return;
        };
        let prefix = if self.capture.is_some() {
            "krypt04mcg-capture"
        } else {
            "krypt04mcg-parsed"
        };
        let name = format!("{prefix}-{}.json", Local::now().format("%Y%m%d-%H%M%S"));
        let mut dialog = rfd::FileDialog::new()
            .add_filter("JSON", &["json"])
            .set_file_name(&name);
        if let Some(directory) = self.initial_directory() {
            dialog = dialog.set_directory(directory);
        }
        let Some(mut path) = dialog.save_file() else {
            return;
        };
        if path.extension().is_none() {
            path.set_extension("json");
        }
        if let Some(capture) = &self.capture {
            match export_capture_json(&path, capture) {
                Ok(()) => {
                    self.status_error = false;
                    self.status = format!(
                        "已导出 {} 个连接、{} 条聊天消息、{} 条 API 流到 {}",
                        capture.connections.len(),
                        capture.chat_transfers.len(),
                        capture.api_streams.len(),
                        path.display()
                    );
                }
                Err(error) => self.fail(error),
            }
            return;
        }
        match export_json(&path, data) {
            Ok(()) => {
                self.status_error = false;
                self.status = format!("已导出 {} 条消息到 {}", data.messages.len(), path.display());
            }
            Err(error) => {
                self.status_error = true;
                self.status = error;
            }
        }
    }

    fn filtered_messages(&self) -> Vec<usize> {
        let Some(data) = &self.data else {
            return Vec::new();
        };
        let query = self.search.trim().to_lowercase();
        data.messages
            .iter()
            .enumerate()
            .filter(|(_, message)| self.filter.matches(message.status))
            .filter(|(_, message)| {
                !self.only_decrypted
                    || message
                        .decryption
                        .as_ref()
                        .is_some_and(DecryptionOutcome::is_decrypted)
            })
            .filter(|(_, message)| {
                if query.is_empty() {
                    return true;
                }
                let packet_hit = message.packet.as_ref().is_some_and(|packet| {
                    packet.sender.to_lowercase().contains(&query)
                        || packet.receiver.to_lowercase().contains(&query)
                        || packet.packet_type_name.to_lowercase().contains(&query)
                        || packet.message_id_hex.to_lowercase().contains(&query)
                        || packet.algorithms.kem.to_lowercase().contains(&query)
                        || packet.algorithms.aead.to_lowercase().contains(&query)
                        || packet
                            .session_id
                            .as_deref()
                            .is_some_and(|value| value.to_lowercase().contains(&query))
                        || packet
                            .timestamp_utc
                            .as_deref()
                            .is_some_and(|value| value.to_lowercase().contains(&query))
                });
                let plaintext_hit = message
                    .decryption
                    .as_ref()
                    .and_then(|outcome| outcome.plaintext.as_deref())
                    .is_some_and(|text| text.to_lowercase().contains(&query));
                message.message_id.contains(&query)
                    || message.transport_sender.to_lowercase().contains(&query)
                    || message.kind.label().to_lowercase().contains(&query)
                    || message.first_seen.text.to_lowercase().contains(&query)
                    || packet_hit
                    || plaintext_hit
            })
            .map(|(index, _)| index)
            .collect()
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let mut open = false;
        let mut folder = false;
        let mut reload = false;
        let mut export = false;
        let mut keys = false;
        ctx.input_mut(|input| {
            // Check the more specific shortcut first: egui's modifier matching
            // intentionally ignores extra Shift for Cmd/Ctrl shortcuts.
            folder = input.consume_key(
                egui::Modifiers::COMMAND | egui::Modifiers::SHIFT,
                egui::Key::O,
            );
            open = input.consume_key(egui::Modifiers::COMMAND, egui::Key::O);
            reload = input.consume_key(egui::Modifiers::COMMAND, egui::Key::R);
            export = input.consume_key(egui::Modifiers::COMMAND, egui::Key::E);
            keys = input.consume_key(egui::Modifiers::COMMAND, egui::Key::K);
        });
        if folder {
            self.open_folder_dialog();
        } else if open {
            self.open_files_dialog();
        } else if reload {
            self.reload();
        } else if export {
            self.export_dialog();
        } else if keys {
            self.show_keys = true;
        }
    }

    fn handle_dropped_files(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx.input_mut(|input| {
            std::mem::take(&mut input.raw.dropped_files)
                .into_iter()
                .filter_map(|file| file.path)
                .collect()
        });
        if dropped.is_empty() {
            return;
        }
        let mut key_paths = Vec::new();
        let mut log_paths = Vec::new();
        for path in dropped {
            if is_key_path(&path) {
                key_paths.push(path);
            } else {
                log_paths.push(path);
            }
        }
        if !key_paths.is_empty() {
            self.load_keys(key_paths);
        }
        if !log_paths.is_empty() {
            self.load(log_paths);
        }
    }

    fn toolbar(&mut self, ctx: &egui::Context) {
        let mut open_files = false;
        let mut open_folder = false;
        let mut reload = false;
        let mut export = false;
        let mut toggle_theme = false;
        let mut open_keys = false;

        egui::TopBottomPanel::top("toolbar")
            .frame(
                Frame::new()
                    .fill(ctx.style().visuals.panel_fill)
                    .inner_margin(Margin::symmetric(14, 10)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(RichText::new("K04M").size(23.0).strong().color(ACCENT));
                    ui.label(RichText::new("日志解析器").size(18.0).strong());
                    ui.add_space(8.0);
                    if ui.button("打开文件…").on_hover_text("Ctrl+O").clicked() {
                        open_files = true;
                    }
                    if ui
                        .button("打开文件夹…")
                        .on_hover_text("Ctrl+Shift+O；递归读取 .log / .log.gz / .pcap / .pcapng")
                        .clicked()
                    {
                        open_folder = true;
                    }
                    if ui.button("重新加载").on_hover_text("Ctrl+R").clicked() {
                        reload = true;
                    }
                    let can_export = self.data.is_some();
                    if ui
                        .add_enabled(can_export, egui::Button::new("导出 JSON"))
                        .on_hover_text("Ctrl+E；导出当前加载的全部消息，包括不完整消息和解密结果")
                        .clicked()
                    {
                        export = true;
                    }
                    let key_count = self.key_store.private_keys.len()
                        + self.key_store.sessions.len()
                        + self.key_store.signatures.entries().len();
                    if ui
                        .button(format!("密钥 {key_count}"))
                        .on_hover_text("Ctrl+K；加载私钥/会话密钥解密，加载签名公钥验签")
                        .clicked()
                    {
                        open_keys = true;
                    }

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        if ui
                            .button(if self.dark { "浅色" } else { "深色" })
                            .on_hover_text("切换界面主题")
                            .clicked()
                        {
                            toggle_theme = true;
                        }
                        if let Some(data) = &self.data {
                            if !data.warnings.is_empty()
                                && ui.button(format!("警告 {}", data.warnings.len())).clicked()
                            {
                                self.show_warnings = true;
                            }
                            if ui.button(format!("来源 {}", data.sources.len())).clicked() {
                                self.show_sources = true;
                            }
                        }
                        if let Some(capture) = &self.capture
                            && ui
                                .button(format!(
                                    "抓包详情 · {} 连接 / {} 流",
                                    capture.connections.len(),
                                    capture.api_streams.len()
                                ))
                                .clicked()
                        {
                            self.show_capture = true;
                        }
                        ui.add(
                            TextEdit::singleline(&mut self.search)
                                .hint_text("搜索 ID / 玩家 / 类型")
                                .desired_width(210.0),
                        );
                    });
                });

                if let Some(data) = &self.data {
                    ui.add_space(2.0);
                    let capture = self.capture.as_ref();
                    let unit = if capture.is_some() {
                        "抓包"
                    } else {
                        "文件"
                    };
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(format!("{} 个{unit}", data.sources.len()))
                                .small()
                                .color(DIM),
                        );
                        ui.separator();
                        ui.label(
                            RichText::new(format!("{} 条分片", data.fragment_lines))
                                .small()
                                .color(DIM),
                        );
                        ui.separator();
                        ui.label(
                            RichText::new(format!(
                                "{} 条{}",
                                data.messages.len(),
                                if capture.is_some() {
                                    "聊天消息"
                                } else {
                                    "消息"
                                }
                            ))
                            .small()
                            .color(DIM),
                        );
                        if let Some(capture) = capture {
                            ui.separator();
                            ui.label(
                                RichText::new(format!(
                                    "{} 个连接 · {} 个 API 流 · {} 个公钥共享",
                                    capture.connections.len(),
                                    capture.api_streams.len(),
                                    capture.public_key_shares.len()
                                ))
                                .small()
                                .color(DIM),
                            );
                        }
                        for (label, count, color) in [
                            ("已解析", data.parsed_count(), MessageStatus::Parsed.color()),
                            (
                                "不完整",
                                data.incomplete_count(),
                                MessageStatus::Incomplete.color(),
                            ),
                            ("错误", data.invalid_count(), MessageStatus::Invalid.color()),
                        ] {
                            if count > 0 {
                                ui.label(
                                    RichText::new(format!("{label} {count}"))
                                        .small()
                                        .color(color),
                                );
                            }
                        }
                        if data.malformed_lines > 0 {
                            ui.label(
                                RichText::new(format!("畸形行 {}", data.malformed_lines))
                                    .small()
                                    .color(MessageStatus::Invalid.color()),
                            );
                        }
                        let decrypted = self.decrypted_count();
                        if decrypted > 0 {
                            ui.label(
                                RichText::new(format!("已解密 {decrypted}"))
                                    .small()
                                    .color(DecryptionStatus::Decrypted.color()),
                            );
                        }
                        let verified = self.signature_count(SignatureStatus::Verified);
                        if verified > 0 {
                            ui.label(
                                RichText::new(format!("已验签 {verified}"))
                                    .small()
                                    .color(SignatureStatus::Verified.color()),
                            );
                        }
                        let no_key = self.signature_count(SignatureStatus::NoKey);
                        if no_key > 0 {
                            ui.label(
                                RichText::new(format!("待验签 {no_key}"))
                                    .small()
                                    .color(SignatureStatus::NoKey.color()),
                            )
                            .on_hover_text("存在签名包，但没有对应的签名公钥");
                        }
                        let failed = self.signature_count(SignatureStatus::Failed);
                        if failed > 0 {
                            ui.label(
                                RichText::new(format!("验签失败 {failed}"))
                                    .small()
                                    .color(SignatureStatus::Failed.color()),
                            );
                        }
                        if !self.paths.is_empty() {
                            ui.separator();
                            let sources = self
                                .paths
                                .iter()
                                .map(|path| path.display().to_string())
                                .collect::<Vec<_>>()
                                .join("  ·  ");
                            ui.label(RichText::new(truncate(&sources, 110)).small().color(DIM))
                                .on_hover_text(sources);
                        }
                    });
                }
            });

        if open_files {
            self.open_files_dialog();
        } else if open_folder {
            self.open_folder_dialog();
        } else if reload {
            self.reload();
        } else if export {
            self.export_dialog();
        }
        if toggle_theme {
            self.dark = !self.dark;
            Self::apply_theme(ctx, self.dark);
        }
        if open_keys {
            self.show_keys = true;
        }
    }

    fn message_list(&mut self, ctx: &egui::Context) {
        let filtered = self.filtered_messages();
        let mut clicked = None;

        egui::SidePanel::left("message_list")
            .resizable(true)
            .default_width(390.0)
            .min_width(300.0)
            .max_width(560.0)
            .show(ctx, |ui| {
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    ui.heading("消息");
                    ui.label(
                        RichText::new(format!(
                            "{} 条可见 / {} 条总数",
                            filtered.len(),
                            self.data.as_ref().map_or(0, |data| data.messages.len())
                        ))
                        .small()
                        .color(DIM),
                    );
                });
                ui.horizontal_wrapped(|ui| {
                    for filter in [
                        MessageFilter::All,
                        MessageFilter::Parsed,
                        MessageFilter::Incomplete,
                        MessageFilter::Invalid,
                    ] {
                        if ui
                            .selectable_label(self.filter == filter, filter.label())
                            .clicked()
                        {
                            self.filter = filter;
                        }
                    }
                    ui.checkbox(&mut self.only_decrypted, "只看已解密")
                        .on_hover_text("只显示 AEAD 认证成功并得到明文的包");
                });
                ui.separator();

                if let Some(data) = &self.data {
                    if data.messages.is_empty() {
                        ui.add_space(24.0);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new("没有找到 Krypt04Mcg 消息").color(DIM));
                            ui.label(
                                RichText::new(if self.capture.is_some() {
                                    "抓包中需要包含 krypt04mcg:chat_fragment、public_key 或 stream:control/data 通道"
                                } else {
                                    "日志中需要包含 [KRYPT04MCG] 分片行"
                                })
                                .small()
                                .color(DIM),
                            );
                        });
                        return;
                    }
                    ScrollArea::vertical()
                        .id_salt("message_scroll")
                        .auto_shrink([false, false])
                        .show(ui, |ui| {
                            ui.set_width(ui.available_width());
                            for index in filtered {
                                let message = &data.messages[index];
                                let selected = self.selected_message == Some(index);
                                let response =
                                    message_row(ui, index, message, selected, ui.available_width());
                                if response.clicked() {
                                    clicked = Some(index);
                                }
                                ui.add_space(3.0);
                            }
                        });
                } else {
                    ui.add_space(24.0);
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new("尚未加载日志或抓包").color(DIM));
                    });
                }
            });

        if let Some(index) = clicked
            && self.selected_message != Some(index)
        {
            self.selected_message = Some(index);
            self.selected_field = None;
            self.pending_hex_offset = None;
        }
    }

    fn central(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let Some(message_index) = self.selected_message else {
                self.welcome(ui);
                return;
            };
            let Some(data) = &self.data else {
                self.welcome(ui);
                return;
            };
            let Some(message) = data.messages.get(message_index) else {
                self.welcome(ui);
                return;
            };

            let mut new_selected_field: Option<SelectedField> = None;
            let mut new_hover_range: Option<Range<usize>> = None;
            let mut pending_hex_offset = self.pending_hex_offset.take();
            let mut colorize_fields = self.colorize_fields;
            let mut show_fragments = false;
            let mut open_key_dialog = false;

            message_header(ui, message, message_index, ctx);
            ui.add_space(6.0);
            decryption_panel(ui, message, ctx, &mut open_key_dialog);
            ui.add_space(6.0);
            signature_panel(ui, message, ctx, &mut open_key_dialog);
            ui.add_space(6.0);

            if let Some(packet) = &message.packet
                && let Some(error) = &packet.error
            {
                    Frame::new()
                        .fill(MessageStatus::Invalid.color().gamma_multiply(0.16))
                        .stroke(Stroke::new(1.0_f32,
                            MessageStatus::Invalid.color().gamma_multiply(0.7),
                        ))
                        .corner_radius(6)
                        .inner_margin(Margin::symmetric(10, 8))
                        .show(ui, |ui| {
                            ui.label(
                                RichText::new(format!("二进制结构解析错误：{error}"))
                                    .color(MessageStatus::Invalid.color()),
                            );
                            if let Some(offset) = packet.error_offset {
                                ui.label(
                                    RichText::new(format!("错误偏移：0x{offset:04X} ({offset})"))
                                        .small()
                                        .color(DIM),
                                );
                            }
                        });
                    ui.add_space(6.0);
            }

            let warning_count = message.warnings.len();
            if warning_count > 0 {
                egui::CollapsingHeader::new(
                    RichText::new(format!("警告与不一致 ({warning_count})"))
                        .color(MessageStatus::Incomplete.color()),
                )
                .id_salt(("warnings", message_index))
                .default_open(false)
                .show(ui, |ui| {
                    ScrollArea::vertical()
                        .id_salt("warning_scroll")
                        .max_height(130.0)
                        .show(ui, |ui| {
                            for warning in &message.warnings {
                                ui.label(
                                    RichText::new(format!("· {warning}"))
                                        .small()
                                        .color(MessageStatus::Incomplete.color()),
                                );
                            }
                        });
                });
                ui.add_space(4.0);
            }

            if message.kind.is_chat() {
                let fragment_label = format!(
                    "分片与来源 · {}/{} 唯一分片 · {} 次出现{}",
                    message.unique_fragments(),
                    message.total,
                    message.occurrences(),
                    if message.duplicate_count > 0 {
                        format!(" · {} 次重复", message.duplicate_count)
                    } else {
                        String::new()
                    }
                );
                egui::CollapsingHeader::new(fragment_label)
                    .id_salt(("fragments", message_index))
                    .default_open(false)
                    .show(ui, |ui| {
                        show_fragments = true;
                        fragments_table(ui, message);
                    });
                if show_fragments {
                    ui.add_space(4.0);
                }
            }

            let available = ui.available_size();
            if available.y < 120.0 {
                ui.add_space(4.0);
            }
            let panel_height = available.y.max(180.0);
            let gap = 10.0;
            let fields_width = (ui.available_width() * 0.38).clamp(280.0, 580.0);
            let hex_width = (ui.available_width() - fields_width - gap).max(320.0);

            ui.horizontal_top(|ui| {
                ui.allocate_ui_with_layout(
                    Vec2::new(fields_width, panel_height),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ui.set_min_height(panel_height);
                        ui.set_max_width(fields_width);
                        Frame::new()
                            .fill(if self.dark {
                                Color32::from_rgb(25, 29, 36)
                            } else {
                                Color32::from_rgb(250, 251, 253)
                            })
                            .stroke(Stroke::new(1.0_f32,
                                if self.dark {
                                    Color32::from_rgb(43, 49, 60)
                                } else {
                                    Color32::from_rgb(220, 225, 232)
                                },
                            ))
                            .corner_radius(8)
                            .inner_margin(Margin::symmetric(10, 8))
                            .show(ui, |ui| {
                                ui.set_min_height(panel_height - 18.0);
                                ui.horizontal(|ui| {
                                    ui.label(RichText::new("字段").strong());
                                    ui.label(
                                        RichText::new("点击字段 -> 高亮对应二进制")
                                            .small()
                                            .color(DIM),
                                    );
                                });
                                ui.separator();
                                if let Some(packet) = &message.packet {
                                    let result = fields_panel(
                                        ui,
                                        packet,
                                        message_index,
                                        self.selected_field.as_ref(),
                                    );
                                    if new_selected_field.is_none() {
                                        new_selected_field = result.clicked;
                                    }
                                    new_hover_range = result.hovered;
                                } else {
                                    ui.add_space(16.0);
                                    let text = if message.status == MessageStatus::Invalid {
                                        "二进制重组或结构解析失败，无法显示包字段。请查看上方警告。"
                                    } else {
                                        "该消息尚未完整重组，无法解析包字段。展开上方“分片与来源”查看缺失分片。"
                                    };
                                    ui.label(RichText::new(text).color(DIM));
                                }
                            });
                    },
                );
                ui.add_space(gap);
                ui.allocate_ui_with_layout(
                    Vec2::new(hex_width, panel_height),
                    Layout::top_down(Align::Min),
                    |ui| {
                        ui.set_min_height(panel_height);
                        ui.set_max_width(hex_width);
                        Frame::new()
                            .fill(if self.dark {
                                Color32::from_rgb(25, 29, 36)
                            } else {
                                Color32::from_rgb(250, 251, 253)
                            })
                            .stroke(Stroke::new(1.0_f32,
                                if self.dark {
                                    Color32::from_rgb(43, 49, 60)
                                } else {
                                    Color32::from_rgb(220, 225, 232)
                                },
                            ))
                            .corner_radius(8)
                            .inner_margin(Margin::symmetric(10, 8))
                            .show(ui, |ui| {
                                ui.set_min_height(panel_height - 18.0);
                                hex_panel(
                                    ui,
                                    message,
                                    message_index,
                                    self.selected_field.as_ref(),
                                    new_hover_range.as_ref(),
                                    &mut pending_hex_offset,
                                    &mut colorize_fields,
                                );
                            });
                    },
                );
            });

            if let Some(selection) = &new_selected_field {
                pending_hex_offset = Some(selection.offset);
            }
            if new_selected_field.is_some() {
                self.selected_field = new_selected_field;
            }
            self.pending_hex_offset = pending_hex_offset;
            self.colorize_fields = colorize_fields;
            if open_key_dialog {
                self.show_keys = true;
            }
        });
    }

    fn welcome(&mut self, ui: &mut Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.label(
                RichText::new("Krypt04Mcg 日志解析器")
                    .size(30.0)
                    .strong()
                    .color(ACCENT),
            );
            ui.add_space(8.0);
            ui.label(
                RichText::new(
                    "读取 Minecraft 服务端日志或 pcap/pcapng 抓包，重组 [KRYPT04MCG] 分片，解析二进制包、验签并高亮字段字节。",
                )
                .size(15.0)
                .color(DIM),
            );
            ui.add_space(22.0);
            ui.horizontal(|ui| {
                let total_width = 560.0;
                ui.add_space(((ui.available_width() - total_width) / 2.0).max(0.0));
                if ui.button("打开日志/抓包…").clicked() {
                    self.open_files_dialog();
                }
                if ui.button("打开日志/抓包文件夹…").clicked() {
                    self.open_folder_dialog();
                }
                if ui.button("加载私钥…").clicked() {
                    self.show_keys = true;
                }
            });
            ui.add_space(30.0);
            Frame::new()
                .fill(if self.dark {
                    Color32::from_rgb(26, 31, 39)
                } else {
                    Color32::from_rgb(250, 251, 253)
                })
                .stroke(Stroke::new(1.0_f32, Color32::from_rgb(50, 58, 70)))
                .corner_radius(10)
                .inner_margin(Margin::symmetric(24, 18))
                .show(ui, |ui| {
                    ui.set_max_width(600.0);
                    ui.label(RichText::new("使用方式").strong());
                    ui.add_space(6.0);
                    for line in [
                        "1. 打开 latest.log、包含多个 .log / .log.gz 的 logs 文件夹，或 .pcap / .pcapng 抓包。",
                        "2. 日志支持乱序分片、重复分片和跨文件合并；抓包会自动重组 TCP 与 Krypt04Mcg 通道。",
                        "3. 左侧选择消息（抓包中还有控制、公钥共享和 API 流），右侧查看字段与二进制；抓包模式还可打开“抓包详情”。",
                        "4. 点击字段，二进制中对应字节会以黄色高亮；悬停字段可临时预览。",
                        "5. 加载私钥、会话密钥与签名公钥（Ctrl+K），解密正文并验证包签名。",
                        "6. “导出 JSON” 会导出全部结果：日志为消息/字段/明文，抓包为连接/事件/流/公钥共享。",
                    ] {
                        ui.label(RichText::new(line).small().color(DIM));
                    }
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(
                            "说明：没有匹配的私钥/会话密钥时只能查看密文结构；没有签名公钥时无法验签。签名有效只证明包由该公钥持有者签发，不建立额外信任或新鲜度。",
                        )
                        .small()
                        .color(MessageStatus::Incomplete.color()),
                    );
                });
            ui.add_space(20.0);
            ui.label(
                RichText::new("也可以把文件或文件夹直接拖入窗口。")
                    .small()
                    .color(DIM),
            );
            if self.status_error {
                ui.add_space(12.0);
                ui.label(RichText::new(&self.status).color(MessageStatus::Invalid.color()));
            }
        });
    }

    fn status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar")
            .frame(
                Frame::new()
                    .fill(ctx.style().visuals.faint_bg_color)
                    .inner_margin(Margin::symmetric(12, 5)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    let color = if self.status_error {
                        MessageStatus::Invalid.color()
                    } else {
                        DIM
                    };
                    ui.label(
                        RichText::new(truncate(&self.status, 150))
                            .small()
                            .color(color),
                    )
                    .on_hover_text(&self.status);
                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        ui.label(
                            RichText::new(
                                "Ctrl+O 打开日志/抓包 · Ctrl+Shift+O 文件夹 · Ctrl+K 密钥/公钥 · Ctrl+R 重载 · Ctrl+E 导出",
                            )
                            .small()
                            .color(DIM),
                        );
                    });
                });
            });
    }

    fn capture_details(&mut self, ctx: &egui::Context) {
        if !self.show_capture {
            return;
        }
        let Some(analysis) = &self.capture else {
            self.show_capture = false;
            return;
        };
        let mut open = self.show_capture;
        egui::Window::new("抓包详情")
            .open(&mut open)
            .default_width(1120.0)
            .show(ctx, |ui| {
                ScrollArea::vertical()
                    .id_salt("capture_details_scroll")
                    .auto_shrink([false, false])
                    .show(ui, |ui| {
                        capture_overview(ui, analysis);
                        ui.separator();
                        capture_connections(ui, analysis);
                        ui.separator();
                        capture_public_keys(ui, analysis);
                        ui.separator();
                        capture_streams(ui, analysis);
                        ui.separator();
                        capture_events(ui, analysis);
                        if !analysis.warnings.is_empty() {
                            ui.separator();
                            egui::CollapsingHeader::new(format!(
                                "抓包警告 ({})",
                                analysis.warnings.len()
                            ))
                            .default_open(false)
                            .show(ui, |ui| {
                                for warning in &analysis.warnings {
                                    ui.label(
                                        RichText::new(format!("· {warning}"))
                                            .small()
                                            .color(MessageStatus::Incomplete.color()),
                                    );
                                }
                            });
                        }
                        ui.separator();
                        egui::CollapsingHeader::new("抓包来源")
                            .default_open(false)
                            .show(ui, |ui| {
                                egui::Grid::new("capture_sources_grid")
                                    .num_columns(5)
                                    .striped(true)
                                    .show(ui, |ui| {
                                        ui.strong("文件");
                                        ui.strong("TCP 会话");
                                        ui.strong("Minecraft 连接");
                                        ui.strong("数据包");
                                        ui.strong("大小");
                                        ui.end_row();
                                        for source in &analysis.sources {
                                            ui.label(&source.name).on_hover_text(&source.path);
                                            ui.label(source.conversations.to_string());
                                            ui.label(source.minecraft_connections.to_string());
                                            ui.label(source.packets.to_string());
                                            ui.label(format!("{} B", source.bytes));
                                            ui.end_row();
                                        }
                                    });
                            });
                    });
            });
        self.show_capture = open;
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        self.capture_details(ctx);
        if self.show_sources {
            let mut open = self.show_sources;
            egui::Window::new("输入来源")
                .open(&mut open)
                .default_width(720.0)
                .show(ctx, |ui| {
                    if let Some(data) = &self.data {
                        ui.label(
                            RichText::new(format!(
                                "{} 个文件 · {} 条分片 · {} 条畸形行",
                                data.sources.len(),
                                data.fragment_lines,
                                data.malformed_lines
                            ))
                            .small()
                            .color(DIM),
                        );
                        ui.separator();
                        ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                            egui::Grid::new("source_grid")
                                .num_columns(4)
                                .striped(true)
                                .show(ui, |ui| {
                                    ui.strong("文件");
                                    ui.strong("日期");
                                    ui.strong("行数");
                                    ui.strong("分片");
                                    ui.end_row();
                                    for source in &data.sources {
                                        ui.label(&source.name).on_hover_text(&source.path);
                                        ui.label(source.date.as_deref().unwrap_or("-"));
                                        ui.label(source.lines.to_string());
                                        ui.label(source.fragments.to_string());
                                        ui.end_row();
                                    }
                                });
                        });
                    }
                });
            self.show_sources = open;
        }

        if self.show_keys {
            let mut open = self.show_keys;
            let mut load_files = false;
            let mut load_folder = false;
            let mut clear = false;
            let mut remove_key: Option<usize> = None;
            let mut remove_session: Option<usize> = None;
            let mut remove_public: Option<usize> = None;
            egui::Window::new("私钥、会话密钥与签名公钥")
                .open(&mut open)
                .default_width(980.0)
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} 个私钥 · {} 个会话密钥 · {} 个签名公钥 · 已解密 {} 条消息 · 已验签 {} 条",
                            self.key_store.private_keys.len(),
                            self.key_store.sessions.len(),
                            self.key_store.signatures.entries().len(),
                            self.decrypted_count(),
                            self.signature_count(SignatureStatus::Verified)
                        ))
                        .small()
                        .color(DIM),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("加载密钥/公钥文件…").clicked() {
                            load_files = true;
                        }
                        if ui.button("加载账户/密钥目录…").clicked() {
                            load_folder = true;
                        }
                        if ui
                            .add_enabled(
                                !self.key_store.is_empty(),
                                egui::Button::new("清空全部"),
                            )
                            .clicked()
                        {
                            clear = true;
                        }
                    });
                    ui.label(
                        RichText::new(
                            "支持 Krypt04Mcg 的 LocalKeyMaterial（keys/private/local.json）、sessions/*.json、keys/public/*.json、账户目录，以及包含多个账户的父目录。KMCGSEC1 加密文件会自动使用同目录 secrets/master.key 解密。私钥只保存在内存中，绝不会写入导出 JSON；签名公钥只用于验签。",
                        )
                        .small()
                        .color(DIM),
                    );
                    if let Some(summary) = &self.key_summary {
                        ui.add_space(3.0);
                        ui.label(RichText::new(summary.message()).small().color(ACCENT));
                    }
                    ui.separator();

                    if self.key_store.private_keys.is_empty()
                        && self.key_store.sessions.is_empty()
                        && self.key_store.signatures.is_empty()
                    {
                        ui.add_space(12.0);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new("尚未加载任何密钥").color(DIM));
                            ui.label(
                                RichText::new(
                                    "私钥用于解密 KEM 消息与会话交换请求；会话密钥用于解密 SESSION_MESSAGE；签名公钥用于验证包签名（keys/public 或抓包中的公钥共享）。",
                                )
                                .small()
                                .color(DIM),
                            );
                        });
                    } else {
                        ScrollArea::vertical()
                            .id_salt("keys_scroll")
                            .max_height(430.0)
                            .show(ui, |ui| {
                                egui::Grid::new("keys_grid")
                                    .num_columns(6)
                                    .striped(true)
                                    .spacing([12.0, 6.0])
                                    .show(ui, |ui| {
                                        ui.strong("类型");
                                        ui.strong("所有者");
                                        ui.strong("算法 / 会话");
                                        ui.strong("指纹");
                                        ui.strong("来源");
                                        ui.strong("");
                                        ui.end_row();

                                        for (index, key) in
                                            self.key_store.private_keys.iter().enumerate()
                                        {
                                            ui.label(
                                                RichText::new("私钥")
                                                    .small()
                                                    .color(DecryptionStatus::Decrypted.color()),
                                            );
                                            ui.label(&key.owner)
                                                .on_hover_text(format!("UUID：{}", key.uuid));
                                            ui.label(
                                                RichText::new(&key.algorithm)
                                                    .small()
                                                    .monospace(),
                                            )
                                            .on_hover_text(if key.signature_algorithm.is_empty() {
                                                "KEM 私钥".to_owned()
                                            } else {
                                                format!(
                                                    "KEM 私钥\n签名算法：{}",
                                                    key.signature_algorithm
                                                )
                                            });
                                            ui.label(
                                                RichText::new(truncate(&key.fingerprint, 16))
                                                    .small()
                                                    .monospace()
                                                    .color(DIM),
                                            )
                                            .on_hover_text(&key.fingerprint);
                                            ui.label(
                                                RichText::new(truncate(&key.source, 42))
                                                    .small()
                                                    .color(DIM),
                                            )
                                            .on_hover_text(&key.source);
                                            if ui.small_button("移除").clicked() {
                                                remove_key = Some(index);
                                            }
                                            ui.end_row();
                                        }

                                        for (index, session) in
                                            self.key_store.sessions.iter().enumerate()
                                        {
                                            ui.label(
                                                RichText::new("会话")
                                                    .small()
                                                    .color(DecryptionStatus::NoKey.color()),
                                            );
                                            ui.label(&session.peer);
                                            ui.label(
                                                RichText::new(format!(
                                                    "session {}",
                                                    truncate(&session.session_id, 22)
                                                ))
                                                .small()
                                                .monospace(),
                                            )
                                            .on_hover_text(&session.session_id);
                                            ui.label(RichText::new("-").small().color(DIM));
                                            ui.label(
                                                RichText::new(truncate(&session.source, 42))
                                                    .small()
                                                    .color(DIM),
                                            )
                                            .on_hover_text(&session.source);
                                            if ui.small_button("移除").clicked() {
                                                remove_session = Some(index);
                                            }
                                            ui.end_row();
                                        }

                                        for (index, key) in
                                            self.key_store.signatures.entries().iter().enumerate()
                                        {
                                            ui.label(
                                                RichText::new("签名公钥")
                                                    .small()
                                                    .color(ACCENT),
                                            );
                                            ui.label(&key.owner)
                                                .on_hover_text(format!("UUID：{}", key.uuid));
                                            ui.label(
                                                RichText::new(&key.algorithm)
                                                    .small()
                                                    .monospace(),
                                            );
                                            ui.label(
                                                RichText::new(truncate(&key.fingerprint, 16))
                                                    .small()
                                                    .monospace()
                                                    .color(DIM),
                                            )
                                            .on_hover_text(&key.fingerprint);
                                            ui.label(
                                                RichText::new(truncate(&key.source, 42))
                                                    .small()
                                                    .color(DIM),
                                            )
                                            .on_hover_text(&key.source);
                                            if ui.small_button("移除").clicked() {
                                                remove_public = Some(index);
                                            }
                                            ui.end_row();
                                        }
                                    });
                            });
                    }

                    if !self.key_store.signatures.warnings().is_empty() {
                        ui.separator();
                        egui::CollapsingHeader::new(format!(
                            "签名公钥提示 ({})",
                            self.key_store.signatures.warnings().len()
                        ))
                        .default_open(false)
                        .show(ui, |ui| {
                            for warning in self.key_store.signatures.warnings() {
                                ui.label(
                                    RichText::new(format!("· {warning}"))
                                        .small()
                                        .color(MessageStatus::Incomplete.color()),
                                );
                            }
                        });
                    }
                    if !self.key_store.warnings.is_empty() {
                        ui.separator();
                        egui::CollapsingHeader::new(format!(
                            "加载提示 ({})",
                            self.key_store.warnings.len()
                        ))
                        .default_open(false)
                        .show(ui, |ui| {
                            for warning in &self.key_store.warnings {
                                ui.label(
                                    RichText::new(format!("· {warning}"))
                                        .small()
                                        .color(MessageStatus::Incomplete.color()),
                                );
                            }
                        });
                    }
                });
            self.show_keys = open;
            if load_files {
                self.open_key_files_dialog();
            } else if load_folder {
                self.open_key_folder_dialog();
            }
            if clear {
                self.key_store.clear();
                self.key_summary = None;
                self.redecrypt();
                self.status_error = false;
                self.status = "已清空全部私钥与会话密钥".to_owned();
            }
            if let Some(index) = remove_key {
                self.key_store.private_keys.remove(index);
                self.key_summary = None;
                self.redecrypt();
                self.status_error = false;
                self.status = "已移除一个私钥并重新解密".to_owned();
            }
            if let Some(index) = remove_session {
                self.key_store.sessions.remove(index);
                self.key_summary = None;
                self.redecrypt();
                self.status_error = false;
                self.status = "已移除一个会话密钥并重新解密".to_owned();
            }
            if let Some(index) = remove_public {
                self.key_store.signatures.remove(index);
                self.key_summary = None;
                self.redecrypt();
                self.status_error = false;
                self.status = "已移除一个签名公钥并重新验签".to_owned();
            }
        }

        if self.show_warnings {
            let mut open = self.show_warnings;
            egui::Window::new("加载警告")
                .open(&mut open)
                .default_width(720.0)
                .show(ctx, |ui| {
                    if let Some(data) = &self.data {
                        if data.warnings.is_empty() {
                            ui.label("没有加载警告");
                        } else {
                            ScrollArea::vertical().max_height(420.0).show(ui, |ui| {
                                for warning in &data.warnings {
                                    ui.label(
                                        RichText::new(format!("· {warning}"))
                                            .small()
                                            .color(MessageStatus::Incomplete.color()),
                                    );
                                }
                            });
                        }
                    }
                });
            self.show_warnings = open;
        }
    }
}

fn capture_overview(ui: &mut Ui, analysis: &CaptureAnalysis) {
    let summary = &analysis.summary;
    egui::CollapsingHeader::new("抓包概览")
        .default_open(true)
        .show(ui, |ui| {
            egui::Grid::new("capture_summary_grid")
                .num_columns(2)
                .spacing([18.0, 5.0])
                .show(ui, |ui| {
                    for (label, value) in [
                        ("抓包文件", summary.capture_files.to_string()),
                        ("TCP 会话", summary.conversations.to_string()),
                        (
                            "Minecraft 连接",
                            format!(
                                "{}（{} 个含 Krypt04Mcg）",
                                summary.minecraft_connections, summary.krypt_connections
                            ),
                        ),
                        ("通道消息", summary.channel_messages.to_string()),
                        ("聊天分片", summary.chat_fragments.to_string()),
                        (
                            "聊天消息",
                            format!(
                                "{}（已解密 {}）",
                                summary.chat_transfers, summary.chat_transfers_decrypted
                            ),
                        ),
                        ("公钥共享", summary.public_key_shares.to_string()),
                        (
                            "API 流",
                            format!(
                                "{} 条 / {} 条记录（已解密 {}）",
                                summary.api_streams,
                                summary.api_data_record_observations,
                                summary.api_data_records_decrypted
                            ),
                        ),
                        (
                            "签名",
                            format!(
                                "检查 {}：有效 {} / 缺公钥 {} / 不支持 {} / 无效 {}",
                                summary.signature_packets,
                                summary.signatures_verified,
                                summary.signatures_no_key,
                                summary.signatures_unsupported,
                                summary.signatures_failed
                            ),
                        ),
                        (
                            "明文字节",
                            summary.total_plaintext_bytes.to_string(),
                        ),
                        ("Minecraft 版本", analysis.minecraft_version.clone()),
                        ("协议版本", analysis.protocol_version.to_string()),
                    ] {
                        ui.label(RichText::new(label).small().color(DIM));
                        ui.label(RichText::new(value).small().monospace());
                        ui.end_row();
                    }
                });
            ui.label(
                RichText::new(
                    "公钥共享与 keys/public 中的签名公钥用于验签；签名有效只证明包由该公钥持有者签发，不建立额外信任或新鲜度。",
                )
                .small()
                .color(DIM),
            );
        });
}

fn capture_connections(ui: &mut Ui, analysis: &CaptureAnalysis) {
    egui::CollapsingHeader::new(format!("Minecraft 连接 ({})", analysis.connections.len()))
        .default_open(true)
        .show(ui, |ui| {
            if analysis.connections.is_empty() {
                ui.label(
                    RichText::new("没有识别到 Minecraft 连接")
                        .small()
                        .color(DIM),
                );
                return;
            }
            egui::Grid::new("capture_connections_grid")
                .num_columns(7)
                .striped(true)
                .spacing([12.0, 5.0])
                .show(ui, |ui| {
                    ui.strong("#");
                    ui.strong("玩家");
                    ui.strong("连接");
                    ui.strong("协议");
                    ui.strong("Brand");
                    ui.strong("通道消息");
                    ui.strong("状态");
                    ui.end_row();
                    for connection in &analysis.connections {
                        ui.label(connection.index.to_string());
                        ui.label(connection.player.as_deref().unwrap_or("(未知)"))
                            .on_hover_text(connection.player_uuid.as_deref().unwrap_or(""));
                        ui.label(
                            RichText::new(format!(
                                "{} -> {}",
                                connection.client, connection.server
                            ))
                            .small()
                            .monospace(),
                        );
                        ui.label(
                            connection
                                .protocol_version
                                .map(|version| version.to_string())
                                .unwrap_or_else(|| "?".to_owned()),
                        );
                        ui.label(format!(
                            "{}/{}",
                            connection.client_brand.as_deref().unwrap_or("-"),
                            connection.server_brand.as_deref().unwrap_or("-")
                        ));
                        ui.label(format!(
                            "聊天 {} · 公钥 {} · 控制 {} · 隧道 {} · 流记录 {}",
                            connection.chat_fragment_messages,
                            connection.public_key_messages,
                            connection.control_messages,
                            connection.tunnel_messages,
                            connection.data_records
                        ));
                        ui.label(&connection.status);
                        ui.end_row();
                    }
                });
        });
}

fn capture_public_keys(ui: &mut Ui, analysis: &CaptureAnalysis) {
    egui::CollapsingHeader::new(format!("公钥共享 ({})", analysis.public_key_shares.len()))
        .default_open(false)
        .show(ui, |ui| {
            if analysis.public_key_shares.is_empty() {
                ui.label(RichText::new("抓包中没有公钥共享").small().color(DIM));
                return;
            }
            for share in &analysis.public_key_shares {
                let state = if share.complete {
                    format!(
                        "{}/{} 分片 · 完整",
                        share.received_chunks, share.total_chunks
                    )
                } else {
                    format!(
                        "{}/{} 分片 · 不完整",
                        share.received_chunks, share.total_chunks
                    )
                };
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(&share.sender).strong());
                    ui.label(
                        RichText::new(format!("→ {}", share.receiver.as_deref().unwrap_or("?")))
                            .small()
                            .color(DIM),
                    );
                    ui.label(RichText::new(state).small().color(DIM));
                    if let Some(identity) = &share.identity {
                        ui.label(
                            RichText::new(format!("owner={}", identity.owner))
                                .small()
                                .monospace(),
                        );
                        if let Some(kem) = &identity.kem_public_key {
                            ui.label(
                                RichText::new(format!("KEM {}", kem.algorithm))
                                    .small()
                                    .color(DIM),
                            );
                        }
                        if let Some(signature) = &identity.signature_public_key {
                            ui.label(
                                RichText::new(format!("签名 {}", signature.algorithm))
                                    .small()
                                    .color(ACCENT),
                            );
                        }
                    } else {
                        ui.label(
                            RichText::new("未解析出身份")
                                .small()
                                .color(SignatureStatus::NoKey.color()),
                        );
                    }
                });
                for warning in &share.warnings {
                    ui.label(
                        RichText::new(format!("· {warning}"))
                            .small()
                            .color(MessageStatus::Incomplete.color()),
                    );
                }
            }
        });
}

fn capture_streams(ui: &mut Ui, analysis: &CaptureAnalysis) {
    egui::CollapsingHeader::new(format!("API 流 ({})", analysis.api_streams.len()))
        .default_open(false)
        .show(ui, |ui| {
            if analysis.api_streams.is_empty() {
                ui.label(RichText::new("抓包中没有 API 流").small().color(DIM));
                return;
            }
            for stream in &analysis.api_streams {
                egui::CollapsingHeader::new(format!(
                    "{} · {} · {} -> {}",
                    truncate(&stream.stream_id, 18),
                    stream.channel,
                    stream.initiator,
                    stream.responder
                ))
                .id_salt(("capture_stream", &stream.stream_id))
                .default_open(false)
                .show(ui, |ui| {
                    ui.label(
                        RichText::new(format!(
                            "session {} · 状态 {}",
                            truncate(&stream.session_id, 24),
                            stream.end_reason.as_deref().unwrap_or("-")
                        ))
                        .small()
                        .color(DIM),
                    );
                    for direction in &stream.directions {
                        ui.horizontal_wrapped(|ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{} → {}",
                                    direction.sender, direction.receiver
                                ))
                                .small(),
                            );
                            ui.label(
                                RichText::new(format!(
                                    "· {} 条记录 / 已解密 {} / 失败 {} · {}",
                                    direction.record_count,
                                    direction.decrypted_records,
                                    direction.failed_records,
                                    direction.content.kind
                                ))
                                .small()
                                .color(
                                    if direction.failed_records == 0 {
                                        DecryptionStatus::Decrypted.color()
                                    } else {
                                        DecryptionStatus::Failed.color()
                                    },
                                ),
                            );
                            if let Some(name) = &direction.content.file_name {
                                ui.label(RichText::new(format!("· 文件 {name}")).small());
                            }
                            ui.label(
                                RichText::new(format!("· {} 字节", direction.content.length))
                                    .small()
                                    .color(DIM),
                            );
                        });
                        if let Some(preview) = &direction.content.text_preview {
                            ui.label(
                                RichText::new(truncate(preview, 180))
                                    .small()
                                    .monospace()
                                    .color(DIM),
                            );
                        }
                        for warning in &direction.warnings {
                            ui.label(
                                RichText::new(format!("· {warning}"))
                                    .small()
                                    .color(MessageStatus::Incomplete.color()),
                            );
                        }
                    }
                });
            }
        });
}

fn capture_events(ui: &mut Ui, analysis: &CaptureAnalysis) {
    let other_events: Vec<_> = analysis
        .events
        .iter()
        .filter(|event| event.channel != "krypt04mcg:chat_fragment")
        .collect();
    egui::CollapsingHeader::new(format!(
        "通道事件 ({})",
        analysis.events.len()
    ))
    .default_open(false)
    .show(ui, |ui| {
        ui.label(
            RichText::new(format!(
                "共 {} 个通道事件；解析后的聊天、流控制、公钥共享和 API 流已进入主消息列表，这里按原始通道事件列出其余 {} 个（最多 3000 个）。",
                analysis.events.len(),
                other_events.len()
            ))
            .small()
            .color(DIM),
        );
        for event in other_events.iter().take(3000) {
            let kind = match &event.payload {
                ChannelPayload::PublicKey { peer, .. } => format!("public_key → {peer}"),
                ChannelPayload::Control {
                    kind,
                    peer,
                    slot,
                    business_channel,
                    hmac,
                    exchange,
                    ..
                } => {
                    let signature = exchange
                        .as_ref()
                        .map(|exchange| exchange.signature.status.label())
                        .unwrap_or("-");
                    let hmac = hmac
                        .as_ref()
                        .map(|hmac| if hmac.verified { "通过" } else { "未通过" })
                        .unwrap_or("-");
                    format!(
                        "control {kind} → {peer} slot={slot} channel={business_channel} HMAC={hmac} 验签={signature}"
                    )
                }
                ChannelPayload::Tunnel {
                    peer,
                    stream_id,
                    lease,
                    signature,
                    ..
                } => format!(
                    "tunnel → {peer} stream={} lease={lease} 验签={}",
                    truncate(stream_id, 18),
                    signature
                        .as_ref()
                        .map(|outcome| outcome.status.label())
                        .unwrap_or("-")
                ),
                ChannelPayload::Unknown {
                    payload_length, ..
                } => format!("unknown {payload_length} B"),
                ChannelPayload::ChatFragment { .. } => "chat_fragment".to_owned(),
            };
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(&event.time.local)
                        .small()
                        .monospace()
                        .color(DIM),
                );
                ui.label(RichText::new(&event.channel).small().color(ACCENT));
                ui.label(RichText::new(kind).small());
                if let Some(error) = &event.error {
                    ui.label(
                        RichText::new(truncate(error, 120))
                            .small()
                            .color(MessageStatus::Invalid.color()),
                    );
                }
            });
        }
        if other_events.len() > 3000 {
            ui.label(
                RichText::new("事件过多，仅显示前 3000 个；完整内容请导出 JSON。")
                    .small()
                    .color(MessageStatus::Incomplete.color()),
            );
        }
    });
}

/// Converts every capture entity into the common message view used by the
/// left list and the packet detail panes: chat transfers, stream control
/// messages, public-key shares and API stream directions.
fn capture_to_loaded(analysis: &CaptureAnalysis) -> LoadedLogs {
    let sources = analysis
        .sources
        .iter()
        .map(|source| SourceInfo {
            path: source.path.clone(),
            name: source.name.clone(),
            date: None,
            bytes: source.bytes,
            lines: usize::try_from(source.packets).unwrap_or(usize::MAX),
            fragments: 0,
        })
        .collect();

    let mut rows: Vec<(i64, usize, FragmentGroup)> = Vec::new();
    let mut order = 0usize;
    for transfer in &analysis.chat_transfers {
        let millis = transfer
            .fragments
            .iter()
            .filter_map(|fragment| log_timestamp_millis(&fragment.timestamp.text))
            .min()
            .unwrap_or(i64::MAX);
        rows.push((millis, order, chat_transfer_to_message(transfer)));
        order += 1;
    }
    for event in &analysis.events {
        if matches!(event.payload, ChannelPayload::Control { .. }) {
            rows.push((
                event.time.epoch_millis,
                order,
                control_event_to_message(event),
            ));
            order += 1;
        }
    }
    for share in &analysis.public_key_shares {
        let millis = share
            .observations
            .first()
            .map_or(i64::MAX, |observation| observation.time.epoch_millis);
        rows.push((millis, order, key_share_to_message(share)));
        order += 1;
    }
    for stream in &analysis.api_streams {
        let millis = stream
            .first_seen
            .as_ref()
            .map_or(i64::MAX, |time| time.epoch_millis);
        if stream.directions.is_empty() {
            rows.push((millis, order, api_stream_to_message(stream, None)));
            order += 1;
        } else {
            for direction in &stream.directions {
                rows.push((
                    millis,
                    order,
                    api_stream_to_message(stream, Some(direction)),
                ));
                order += 1;
            }
        }
    }
    rows.sort_by_key(|(millis, order, _)| (*millis, *order));
    let messages = rows
        .into_iter()
        .enumerate()
        .map(|(index, (_, _, mut message))| {
            message.first_order = index;
            message
        })
        .collect();

    LoadedLogs {
        sources,
        messages,
        fragment_lines: analysis
            .chat_transfers
            .iter()
            .map(|transfer| transfer.occurrence_count)
            .sum(),
        malformed_lines: 0,
        warnings: analysis.warnings.clone(),
    }
}

fn log_timestamp_millis(text: &str) -> Option<i64> {
    if text.is_empty() {
        return None;
    }
    for format in [
        "%Y-%m-%d %H:%M:%S%.3f",
        "%Y-%m-%d %H:%M:%S%.6f",
        "%Y-%m-%d %H:%M:%S%.9f",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(text, format) {
            return naive
                .and_local_timezone(Local)
                .earliest()
                .map(|value| value.timestamp_millis());
        }
    }
    None
}

fn chat_transfer_to_message(transfer: &ChatTransfer) -> FragmentGroup {
    let mut slots: BTreeMap<usize, FragmentSlot> = BTreeMap::new();
    for occurrence in &transfer.fragments {
        let slot = slots.entry(occurrence.index).or_default();
        if slot.payload.is_empty() {
            slot.payload = occurrence.payload.clone();
        }
        slot.occurrences.push(occurrence.clone());
    }
    let first_seen = transfer
        .fragments
        .iter()
        .map(|fragment| fragment.timestamp.clone())
        .min_by(|left, right| left.text.cmp(&right.text))
        .unwrap_or_default();
    let last_seen = transfer
        .fragments
        .iter()
        .map(|fragment| fragment.timestamp.clone())
        .max_by(|left, right| left.text.cmp(&right.text))
        .unwrap_or_default();
    let binary = transfer.binary.clone().or_else(|| {
        transfer.binary_base64url.as_ref().and_then(|text| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(text)
                .ok()
        })
    });
    FragmentGroup {
        kind: MessageKind::Chat,
        message_id: transfer.message_id.clone(),
        transport_sender: transfer.sender.clone(),
        total: transfer.fragment_total,
        slots,
        first_seen,
        last_seen,
        first_order: 0,
        duplicate_count: transfer.duplicate_count,
        conflicts: transfer.conflicts,
        warnings: transfer.warnings.clone(),
        binary,
        packet: transfer.packet.clone(),
        status: transfer.status,
        decryption: transfer.decryption.clone(),
        signature: transfer.signature.clone(),
    }
}

fn control_event_to_message(event: &ChannelEvent) -> FragmentGroup {
    let ChannelPayload::Control {
        kind,
        peer,
        sender,
        receiver,
        stream_id,
        slot: _,
        business_channel: _,
        session_id,
        sequence,
        body_length: _,
        hmac,
        exchange,
        fields,
        binary,
    } = &event.payload
    else {
        unreachable!("control_event_to_message requires a control event");
    };

    let inner = exchange.as_ref().map(|exchange| &exchange.packet);
    let (packet_sender, packet_receiver) = match inner {
        Some(packet) => (packet.sender.clone(), packet.receiver.clone()),
        None => (sender.clone(), receiver.clone()),
    };

    let mut warnings = Vec::new();
    if let Some(error) = &event.error {
        warnings.push(error.clone());
    }
    if let Some(hmac) = hmac {
        if hmac.verified {
            // Successful HMAC is shown in the fields panel; not a warning.
        } else if let Some(error) = &hmac.error {
            warnings.push(format!("HMAC：{error}"));
        } else {
            warnings.push("HMAC-SHA256 校验未通过".to_owned());
        }
    }
    if let Some(inner) = inner {
        for warning in &inner.warnings {
            if !warnings.contains(warning) {
                warnings.push(warning.clone());
            }
        }
    }

    let hmac_mismatch = hmac
        .as_ref()
        .is_some_and(|hmac| !hmac.verified && hmac.error.is_none());
    let hmac_missing_key = hmac.as_ref().is_some_and(|hmac| {
        hmac.error
            .as_deref()
            .is_some_and(|error| error.contains("没有 sessionId"))
    });
    let status = if event.error.is_some()
        || inner.is_some_and(|packet| packet.error.is_some())
        || hmac_mismatch
    {
        MessageStatus::Invalid
    } else if hmac_missing_key {
        MessageStatus::Incomplete
    } else {
        MessageStatus::Parsed
    };

    // Start from the inner packet when this is an EXCHANGE so algorithms and
    // type information remain visible; otherwise synthesize a control packet.
    let mut packet = inner.cloned().unwrap_or_default();
    packet.packet_type_name = match inner {
        Some(inner) if !inner.packet_type_name.is_empty() => {
            format!("{kind} · {}", inner.packet_type_name)
        }
        _ => kind.clone(),
    };
    packet.sender = packet_sender.clone();
    packet.receiver = packet_receiver.clone();
    packet.timestamp_millis = Some(event.time.epoch_millis);
    packet.timestamp_utc = Some(event.time.utc.clone());
    packet.timestamp_local = Some(event.time.local.clone());
    if packet.message_id_hex.is_empty() {
        packet.message_id_hex = stream_id.clone();
    }
    if packet.session_id.is_none() && !session_id.is_empty() {
        packet.session_id = Some(session_id.clone());
    }
    if packet.sequence.is_none() {
        packet.sequence = Some(*sequence);
    }
    packet.fields = fields.clone();
    packet.consumed = binary.len();
    packet.trailing = 0;
    packet.error = inner.and_then(|packet| packet.error.clone());
    packet.error_offset = inner.and_then(|packet| packet.error_offset);

    let first_seen = event.time.log_timestamp();
    FragmentGroup {
        kind: MessageKind::Control,
        message_id: if stream_id.is_empty() {
            format!("控制 {kind} · {peer}")
        } else {
            stream_id.clone()
        },
        transport_sender: packet_sender,
        total: 1,
        slots: BTreeMap::new(),
        first_seen: first_seen.clone(),
        last_seen: first_seen,
        first_order: 0,
        duplicate_count: 0,
        conflicts: 0,
        warnings,
        binary: Some(binary.clone()),
        packet: Some(packet),
        status,
        decryption: exchange
            .as_ref()
            .map(|exchange| exchange.decryption.clone()),
        signature: exchange.as_ref().map(|exchange| exchange.signature.clone()),
    }
}

fn key_share_to_message(share: &PublicKeyShare) -> FragmentGroup {
    let first_time = share
        .observations
        .first()
        .map(|observation| observation.time.log_timestamp())
        .unwrap_or_default();
    let status = if !share.complete {
        MessageStatus::Incomplete
    } else if share.json.is_some() {
        MessageStatus::Parsed
    } else {
        MessageStatus::Invalid
    };
    let sender = share.sender.clone();
    let receiver = share
        .receiver
        .clone()
        .unwrap_or_else(|| "(未知)".to_owned());
    let binary = share.binary.clone();

    let mut fields = vec![
        meta_field(
            "keyshare.transfer_id",
            "传输 ID",
            share.transfer_id.clone(),
            "公钥分片传输 UUID",
        ),
        meta_field(
            "keyshare.sender",
            "发送者",
            share.sender.clone(),
            "分片发送者",
        ),
        meta_field(
            "keyshare.receiver",
            "接收者",
            share
                .receiver
                .clone()
                .unwrap_or_else(|| "(未知)".to_owned()),
            "分片接收者",
        ),
        meta_field(
            "keyshare.version",
            "通道版本",
            share.version.to_string(),
            "krypt04mcg:public_key 版本",
        ),
        meta_field(
            "keyshare.chunks",
            "分片",
            format!("{}/{}", share.received_chunks, share.total_chunks),
            if share.complete {
                "所有分片均已收到"
            } else {
                "存在缺失分片，无法重组身份 JSON"
            },
        ),
    ];

    if let Some(identity) = &share.identity {
        let mut identity_fields = Vec::new();
        identity_fields.push(value_field(
            "keyshare.identity.owner",
            "所有者",
            &binary,
            &identity.owner,
            "身份 JSON 中的 owner",
        ));
        identity_fields.push(value_field(
            "keyshare.identity.uuid",
            "UUID",
            &binary,
            &identity.uuid,
            "身份 JSON 中的 uuid",
        ));
        if let Some(kem) = &identity.kem_public_key {
            identity_fields.extend(public_key_record_fields(
                "keyshare.identity.kem",
                "KEM 公钥",
                &binary,
                kem,
                share
                    .json
                    .as_ref()
                    .and_then(|json| json.get("kemPublicKey")),
            ));
        }
        if let Some(signature) = &identity.signature_public_key {
            identity_fields.extend(public_key_record_fields(
                "keyshare.identity.signature",
                "签名公钥",
                &binary,
                signature,
                share
                    .json
                    .as_ref()
                    .and_then(|json| json.get("signaturePublicKey")),
            ));
        }
        fields.push(DataField {
            name: "keyshare.identity".to_owned(),
            label: "身份摘要".to_owned(),
            offset: 0,
            length: binary.len(),
            value: format!("owner={} · uuid={}", identity.owner, identity.uuid),
            hex: None,
            note: Some("从身份 JSON 中提取的字段；标有偏移的子字段可在二进制中高亮".to_owned()),
            category: 5,
            children: identity_fields,
        });
    }

    if !binary.is_empty() {
        fields.push(DataField {
            name: "keyshare.json".to_owned(),
            label: "身份 JSON".to_owned(),
            offset: 0,
            length: binary.len(),
            value: format!(
                "{} 字节{}",
                binary.len(),
                if share.json.is_some() {
                    " · 有效 JSON"
                } else {
                    " · JSON 解析失败"
                }
            ),
            hex: None,
            note: Some("完整重组后的 public_key 分片文本".to_owned()),
            category: 5,
            children: Vec::new(),
        });
    }

    let mut chunk_fields = Vec::new();
    for (position, observation) in share.observations.iter().enumerate() {
        chunk_fields.push(meta_field(
            &format!("keyshare.observation.{position}"),
            &format!("分片 #{}", observation.chunk_index),
            format!(
                "连接 {} · {} · {}",
                observation.connection,
                observation.side.label(),
                observation.time.local
            ),
            "该分片在抓包中的观测位置",
        ));
    }
    if !chunk_fields.is_empty() {
        fields.push(DataField {
            name: "keyshare.observations".to_owned(),
            label: "分片观测".to_owned(),
            offset: 0,
            length: 0,
            value: format!("{} 次", share.observations.len()),
            hex: None,
            note: None,
            category: 11,
            children: chunk_fields,
        });
    }

    let mut packet = ParsedPacket {
        packet_type_name: "public_key".to_owned(),
        sender: sender.clone(),
        receiver: receiver.clone(),
        timestamp_millis: share
            .observations
            .first()
            .map(|observation| observation.time.epoch_millis),
        timestamp_utc: share
            .observations
            .first()
            .map(|observation| observation.time.utc.clone()),
        timestamp_local: share
            .observations
            .first()
            .map(|observation| observation.time.local.clone()),
        message_id_hex: share.transfer_id.clone(),
        consumed: binary.len(),
        fields,
        ..Default::default()
    };
    packet.trailing = 0;

    FragmentGroup {
        kind: MessageKind::PublicKey,
        message_id: share.transfer_id.clone(),
        transport_sender: sender,
        total: 1,
        slots: BTreeMap::new(),
        first_seen: first_time.clone(),
        last_seen: first_time,
        first_order: 0,
        duplicate_count: 0,
        conflicts: if share.complete {
            0
        } else {
            share.total_chunks.saturating_sub(share.received_chunks)
        },
        warnings: share.warnings.clone(),
        binary: (!binary.is_empty()).then_some(binary),
        packet: Some(packet),
        status,
        decryption: None,
        signature: None,
    }
}

fn public_key_record_fields(
    prefix: &str,
    label: &str,
    binary: &[u8],
    record: &crate::capture::PublicKeyRecordSummary,
    json_record: Option<&serde_json::Value>,
) -> Vec<DataField> {
    let mut fields = vec![
        value_field(
            &format!("{prefix}.algorithm"),
            &format!("{label}算法"),
            binary,
            &record.algorithm,
            "algorithm",
        ),
        value_field(
            &format!("{prefix}.uuid"),
            &format!("{label} UUID"),
            binary,
            &record.uuid,
            "uuid",
        ),
        value_field(
            &format!("{prefix}.fingerprint"),
            &format!("{label}指纹"),
            binary,
            &record.fingerprint,
            "fingerprint",
        ),
        record.created_at.as_deref().map_or_else(
            || DataField {
                name: format!("{prefix}.created_at"),
                label: format!("{label}创建时间"),
                offset: 0,
                length: 0,
                value: "-".to_owned(),
                hex: None,
                note: Some("JSON 中没有 createdAt".to_owned()),
                category: 5,
                children: Vec::new(),
            },
            |created_at| {
                value_field(
                    &format!("{prefix}.created_at"),
                    &format!("{label}创建时间"),
                    binary,
                    created_at,
                    "createdAt",
                )
            },
        ),
    ];
    if let Some(json_record) = json_record {
        if let Some(owner) = json_record.get("owner").and_then(serde_json::Value::as_str) {
            fields.push(value_field(
                &format!("{prefix}.owner"),
                &format!("{label}所有者"),
                binary,
                owner,
                "owner",
            ));
        }
        if let Some(key_data) = json_record
            .get("keyData")
            .and_then(serde_json::Value::as_str)
        {
            let (offset, length) = find_bytes(binary, key_data.as_bytes()).unwrap_or((0, 0));
            fields.push(DataField {
                name: format!("{prefix}.key_data"),
                label: format!("{label} keyData"),
                offset,
                length,
                value: format!("{} 字符", key_data.chars().count()),
                hex: None,
                note: Some(format!(
                    "公钥编码文本（base64url）：{}{}",
                    truncate(key_data, 64),
                    if length == 0 {
                        "\n未能在 JSON 文本中定位"
                    } else {
                        ""
                    }
                )),
                category: 6,
                children: Vec::new(),
            });
        }
    }
    fields
}

fn api_stream_to_message(
    stream: &ApiStream,
    direction: Option<&ApiStreamDirection>,
) -> FragmentGroup {
    let first_time = stream
        .first_seen
        .as_ref()
        .or(stream.last_seen.as_ref())
        .map(|time| time.log_timestamp())
        .unwrap_or_default();
    let sender = direction.map_or_else(|| stream.initiator.clone(), |d| d.sender.clone());
    let receiver = direction.map_or_else(|| stream.responder.clone(), |d| d.receiver.clone());
    let data = direction.map_or(&[][..], |direction| direction.data.as_slice());

    let mut warnings = stream.warnings.clone();
    if let Some(direction) = direction {
        warnings.extend(direction.warnings.iter().cloned());
    }
    let status = match direction {
        None => {
            warnings.push("该流没有捕获到数据记录；可能未捕获数据通道或槽位未绑定".to_owned());
            MessageStatus::Incomplete
        }
        Some(direction) if direction.record_count == 0 => {
            warnings.push("该方向没有数据记录".to_owned());
            MessageStatus::Incomplete
        }
        Some(direction) if direction.decrypted_records == direction.record_count => {
            MessageStatus::Parsed
        }
        Some(direction) if direction.decrypted_records > 0 => MessageStatus::Incomplete,
        // All records were seen but no session key was available.
        Some(direction) if direction.failed_records == 0 => MessageStatus::Incomplete,
        Some(_) => MessageStatus::Invalid,
    };

    let mut packet = ParsedPacket {
        packet_type_name: format!("stream · {}", stream.channel),
        sender: sender.clone(),
        receiver: receiver.clone(),
        timestamp_millis: stream.first_seen.as_ref().map(|time| time.epoch_millis),
        timestamp_utc: stream.first_seen.as_ref().map(|time| time.utc.clone()),
        timestamp_local: stream.first_seen.as_ref().map(|time| time.local.clone()),
        message_id_hex: stream.stream_id.clone(),
        session_id: (!stream.session_id.is_empty()).then(|| stream.session_id.clone()),
        consumed: data.len(),
        fields: stream_fields(stream, direction, data),
        ..Default::default()
    };
    packet.trailing = 0;

    FragmentGroup {
        kind: MessageKind::ApiStream,
        message_id: match direction {
            Some(direction) => format!(
                "{} {}→{}",
                stream.stream_id, direction.sender, direction.receiver
            ),
            None => stream.stream_id.clone(),
        },
        transport_sender: sender,
        total: 1,
        slots: BTreeMap::new(),
        first_seen: first_time.clone(),
        last_seen: stream
            .last_seen
            .as_ref()
            .map(|time| time.log_timestamp())
            .unwrap_or(first_time),
        first_order: 0,
        duplicate_count: 0,
        conflicts: 0,
        warnings,
        binary: (!data.is_empty()).then(|| data.to_vec()),
        packet: Some(packet),
        status,
        decryption: direction.and_then(|direction| stream_decryption(stream, direction, data)),
        signature: None,
    }
}

fn stream_decryption(
    stream: &ApiStream,
    direction: &ApiStreamDirection,
    data: &[u8],
) -> Option<DecryptionOutcome> {
    let status = match direction.decryption.as_str() {
        "decrypted" => DecryptionStatus::Decrypted,
        "partial" | "failed" => DecryptionStatus::Failed,
        "no_key" => DecryptionStatus::NoKey,
        _ => return None,
    };
    let plaintext_length = usize::try_from(direction.content.length).unwrap_or(usize::MAX);
    let mut plaintext = None;
    let mut json = None;
    let mut plaintext_hex = None;
    let mut error = None;
    if status == DecryptionStatus::Decrypted {
        if matches!(direction.content.kind.as_str(), "text" | "json")
            && let Ok(text) = std::str::from_utf8(data)
        {
            const MAX_INLINE_TEXT: usize = 64 * 1024;
            if text.len() <= MAX_INLINE_TEXT {
                plaintext = Some(text.to_owned());
            } else {
                let mut end = MAX_INLINE_TEXT;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                plaintext = Some(format!(
                    "[明文共 {} 字节，此处仅显示前 {} 字节；完整内容见右侧二进制面板]\n{}",
                    text.len(),
                    end,
                    &text[..end]
                ));
            }
        }
        if let Some(value) = &direction.content.json
            && data.len() <= 256 * 1024
        {
            json = Some(value.clone());
        }
        if plaintext.is_none() && json.is_none() && !data.is_empty() && data.len() <= 4096 {
            plaintext_hex = Some(hex(data));
        }
        if direction.failed_records > 0 {
            error = Some(format!(
                "{} 条记录解密失败；以上为成功记录拼接的明文",
                direction.failed_records
            ));
        }
    } else {
        error = direction
            .records
            .iter()
            .find_map(|record| record.error.clone())
            .or_else(|| {
                Some(format!(
                    "{} 条流记录无法解密；请加载该会话对应的 sessions/*.json 会话密钥",
                    direction.record_count
                ))
            });
    }

    Some(DecryptionOutcome {
        status,
        key_kind: Some("session_secret".to_owned()),
        session_id: (!stream.session_id.is_empty()).then(|| stream.session_id.clone()),
        compressed: false,
        plaintext_length,
        plaintext,
        json,
        plaintext_hex,
        error,
        ..Default::default()
    })
}

fn stream_fields(
    stream: &ApiStream,
    direction: Option<&ApiStreamDirection>,
    data: &[u8],
) -> Vec<DataField> {
    let mut fields = vec![
        meta_field(
            "stream.id",
            "流 ID",
            stream.stream_id.clone(),
            "krypt04mcg_stream 流 UUID",
        ),
        meta_field(
            "stream.channel",
            "业务通道",
            stream.channel.clone(),
            "对端应用选择的业务通道名",
        ),
        meta_field(
            "stream.session_id",
            "会话 ID",
            stream.session_id.clone(),
            "用于派生流密钥的会话",
        ),
        meta_field(
            "stream.initiator",
            "发起者",
            stream.initiator.clone(),
            "OPEN 控制消息中的发起者",
        ),
        meta_field(
            "stream.responder",
            "响应者",
            stream.responder.clone(),
            "OPEN 控制消息中的响应者",
        ),
        meta_field(
            "stream.end_reason",
            "结束原因",
            stream
                .end_reason
                .clone()
                .unwrap_or_else(|| "(未看到结束控制)".to_owned()),
            "END / RESET / ABORT",
        ),
    ];

    if let Some(direction) = direction {
        fields.push(meta_field(
            "stream.direction.sender",
            "方向发送者",
            direction.sender.clone(),
            "该方向的发送者",
        ));
        fields.push(meta_field(
            "stream.direction.receiver",
            "方向接收者",
            direction.receiver.clone(),
            "该方向的接收者",
        ));
        fields.push(meta_field(
            "stream.direction.records",
            "记录数",
            format!(
                "{} 条（已解密 {} / 失败 {}）",
                direction.record_count, direction.decrypted_records, direction.failed_records
            ),
            format!("密文字节：{}", direction.ciphertext_bytes),
        ));
        fields.push(meta_field(
            "stream.content.kind",
            "内容类型",
            direction.content.kind.clone(),
            "根据业务通道与明文前缀推断",
        ));
        fields.push(meta_field(
            "stream.content.length",
            "明文长度",
            format!("{} 字节", direction.content.length),
            "所有成功解密记录拼接后的长度",
        ));
        if let Some(sha256) = &direction.content.sha256 {
            fields.push(meta_field(
                "stream.content.sha256",
                "SHA-256",
                sha256.clone(),
                "拼接后明文的 SHA-256",
            ));
        }
        if let Some(file_name) = &direction.content.file_name {
            fields.push(meta_field(
                "stream.content.file_name",
                "文件名",
                file_name.clone(),
                "krypt04mcg_file:stream 头部中的文件名",
            ));
        }
        if let Some(size) = direction.content.declared_file_size {
            fields.push(meta_field(
                "stream.content.declared_file_size",
                "声明文件大小",
                format!("{size} 字节"),
                "krypt04mcg_file:stream 头部中的 i32 文件大小",
            ));
        }

        if direction.content.file_name.is_some() {
            fields.extend(file_stream_header_fields(data));
        }

        if direction.content.json.is_some() && !data.is_empty() {
            fields.push(DataField {
                name: "stream.content.json".to_owned(),
                label: "JSON 明文".to_owned(),
                offset: 0,
                length: data.len(),
                value: format!("{} 字节", data.len()),
                hex: None,
                note: Some("明文可解析为 JSON；解密面板显示格式化结果".to_owned()),
                category: 9,
                children: Vec::new(),
            });
        }

        const MAX_RECORD_FIELDS: usize = 200;
        let mut record_fields = Vec::new();
        for record in direction.records.iter().take(MAX_RECORD_FIELDS) {
            let mut note = format!(
                "连接 {} · {} · {}\n观察 {} 次",
                record.connection,
                record.side.label(),
                record.time.local,
                record.observations
            );
            if let Some(preview) = &record.preview_text {
                note.push_str(&format!("\n文本预览：{preview}"));
            } else if let Some(preview) = &record.preview_hex {
                note.push_str(&format!("\n十六进制预览：{preview}"));
            }
            if let Some(error) = &record.error {
                note.push_str(&format!("\n错误：{error}"));
            }
            record_fields.push(meta_field(
                &format!("stream.record.{}", record.index),
                &format!("记录 #{}", record.index),
                format!(
                    "{} · 密文 {} B · 明文 {} · {}",
                    record.status,
                    record.ciphertext_length,
                    record
                        .plaintext_length
                        .map_or_else(|| "-".to_owned(), |length| format!("{length} B")),
                    record.time.local
                ),
                note,
            ));
        }
        if !record_fields.is_empty() {
            fields.push(DataField {
                name: "stream.records".to_owned(),
                label: "流记录".to_owned(),
                offset: 0,
                length: 0,
                value: format!(
                    "{} 条{}",
                    direction.records.len(),
                    if direction.records.len() > MAX_RECORD_FIELDS {
                        format!("（仅列出前 {MAX_RECORD_FIELDS} 条）")
                    } else {
                        String::new()
                    }
                ),
                hex: None,
                note: Some("每条记录的索引、状态、长度与时间".to_owned()),
                category: 9,
                children: record_fields,
            });
        }
    }

    fields
}

/// Exact byte ranges for the `krypt04mcg_file:stream` name/length header.
fn file_stream_header_fields(binary: &[u8]) -> Vec<DataField> {
    if binary.len() < 2 {
        return Vec::new();
    }
    let name_len = u16::from_be_bytes([binary[0], binary[1]]) as usize;
    if name_len == 0 || name_len > 540 || binary.len() < 2 + name_len + 4 {
        return Vec::new();
    }
    let size_offset = 2 + name_len;
    let declared = i32::from_be_bytes(
        binary[size_offset..size_offset + 4]
            .try_into()
            .expect("4-byte slice"),
    );
    let content_offset = size_offset + 4;
    let name = String::from_utf8_lossy(&binary[2..size_offset]).into_owned();
    vec![
        range_field(
            "stream.file.name_length",
            "文件名长度",
            0,
            2,
            name_len.to_string(),
            "Java writeUTF 的 u16 大端字节长度",
            9,
        ),
        range_field(
            "stream.file.name",
            "文件名",
            2,
            name_len,
            name,
            "Java modified UTF-8",
            9,
        ),
        range_field(
            "stream.file.declared_size",
            "声明文件大小",
            size_offset,
            4,
            declared.to_string(),
            "i32 大端，最大 10 MiB",
            9,
        ),
        range_field(
            "stream.file.content",
            "文件内容",
            content_offset,
            binary.len().saturating_sub(content_offset),
            format!("{} 字节", binary.len().saturating_sub(content_offset)),
            "文件原始字节",
            9,
        ),
    ]
}

fn meta_field(name: &str, label: &str, value: String, note: impl Into<String>) -> DataField {
    DataField {
        name: name.to_owned(),
        label: label.to_owned(),
        offset: 0,
        length: 0,
        value,
        hex: None,
        note: Some(note.into()),
        category: 11,
        children: Vec::new(),
    }
}

fn range_field(
    name: &str,
    label: &str,
    offset: usize,
    length: usize,
    value: String,
    note: impl Into<String>,
    category: u8,
) -> DataField {
    DataField {
        name: name.to_owned(),
        label: label.to_owned(),
        offset,
        length,
        value,
        hex: None,
        note: Some(note.into()),
        category,
        children: Vec::new(),
    }
}

/// Finds `value` in the identity JSON so clicking the field can highlight the
/// corresponding bytes. JSON escaping can defeat the search; callers then get
/// a zero-length field instead of a wrong range.
fn value_field(name: &str, label: &str, binary: &[u8], value: &str, note: &str) -> DataField {
    let (offset, length) = find_bytes(binary, value.as_bytes()).unwrap_or((0, 0));
    DataField {
        name: name.to_owned(),
        label: label.to_owned(),
        offset,
        length,
        value: value.to_owned(),
        hex: None,
        note: Some(if length == 0 {
            format!("{note}；未能在 JSON 文本中定位")
        } else {
            format!("{note}；JSON 文本中的值")
        }),
        category: 5,
        children: Vec::new(),
    }
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<(usize, usize)> {
    if needle.is_empty() || needle.len() > haystack.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
        .map(|offset| (offset, needle.len()))
}

impl eframe::App for K04MApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.handle_shortcuts(ctx);
        self.handle_dropped_files(ctx);
        self.toolbar(ctx);
        self.status_bar(ctx);
        self.message_list(ctx);
        self.central(ctx);
        self.dialogs(ctx);
    }
}

fn message_row(
    ui: &mut Ui,
    index: usize,
    message: &FragmentGroup,
    selected: bool,
    width: f32,
) -> egui::Response {
    let fill = if selected {
        ui.visuals().selection.bg_fill
    } else {
        ui.visuals().faint_bg_color
    };
    let stroke = if selected {
        Stroke::new(1.0_f32, ACCENT.gamma_multiply(0.8))
    } else {
        Stroke::new(1.0_f32, ui.visuals().widgets.noninteractive.bg_stroke.color)
    };
    let frame = Frame::new()
        .fill(fill)
        .stroke(stroke)
        .corner_radius(7)
        .inner_margin(Margin::symmetric(10, 7))
        .show(ui, |ui| {
            ui.set_width((width - 24.0).max(120.0));
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(message.status.label())
                        .small()
                        .strong()
                        .color(message.status.color()),
                );
                let arrow = message
                    .packet
                    .as_ref()
                    .map_or(message.transport_sender.as_str(), |packet| {
                        packet.sender.as_str()
                    });
                let receiver = message
                    .packet
                    .as_ref()
                    .map_or("?", |packet| packet.receiver.as_str());
                ui.label(RichText::new(format!("{arrow} -> {receiver}")).strong());
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if let Some(packet) = &message.packet {
                        if let Some(timestamp) = &packet.timestamp_local {
                            let short = timestamp
                                .split_once(' ')
                                .map_or(timestamp.as_str(), |(_, time)| time);
                            ui.label(RichText::new(short).small().color(DIM));
                        }
                    } else {
                        ui.label(
                            RichText::new(truncate(&message.last_seen.time, 12))
                                .small()
                                .color(DIM),
                        );
                    }
                });
            });
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "#{}",
                        &message.message_id[..12.min(message.message_id.len())]
                    ))
                    .monospace()
                    .small()
                    .color(DIM),
                );
                ui.label(
                    RichText::new(message.kind.label())
                        .small()
                        .strong()
                        .color(ACCENT),
                );
                ui.label(
                    RichText::new(truncate(&message_type_label(message), 28))
                        .small()
                        .color(DIM),
                );
                if let Some(outcome) = &message.decryption {
                    if outcome.is_decrypted() {
                        ui.label(
                            RichText::new("明文")
                                .small()
                                .strong()
                                .color(DecryptionStatus::Decrypted.color()),
                        );
                    } else if outcome.status == DecryptionStatus::NoKey {
                        ui.label(
                            RichText::new("无密钥")
                                .small()
                                .color(DecryptionStatus::NoKey.color()),
                        );
                    }
                }
                if let Some(outcome) = &message.signature {
                    match outcome.status {
                        SignatureStatus::Verified => {
                            ui.label(
                                RichText::new("已验签")
                                    .small()
                                    .strong()
                                    .color(SignatureStatus::Verified.color()),
                            );
                        }
                        SignatureStatus::NoKey => {
                            ui.label(
                                RichText::new("签名无公钥")
                                    .small()
                                    .color(SignatureStatus::NoKey.color()),
                            );
                        }
                        SignatureStatus::Failed => {
                            ui.label(
                                RichText::new("验签失败")
                                    .small()
                                    .strong()
                                    .color(SignatureStatus::Failed.color()),
                            );
                        }
                        SignatureStatus::Unsupported => {
                            ui.label(
                                RichText::new("验签不支持")
                                    .small()
                                    .color(SignatureStatus::Unsupported.color()),
                            );
                        }
                        SignatureStatus::NotAttempted | SignatureStatus::NotPresent => {}
                    }
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let detail = if message.kind.is_chat() {
                        if message.binary_len() > 0 {
                            format!("{} B", message.binary_len())
                        } else {
                            format!("{}/{} 分片", message.unique_fragments(), message.total)
                        }
                    } else if message.binary_len() > 0 {
                        format!("{} B", message.binary_len())
                    } else {
                        "无二进制".to_owned()
                    };
                    ui.label(RichText::new(detail).small().color(DIM));
                    if message.duplicate_count > 0 && message.kind.is_chat() {
                        ui.label(
                            RichText::new(format!("重复 {}", message.duplicate_count))
                                .small()
                                .color(MessageStatus::Incomplete.color()),
                        );
                    }
                });
            });
        });
    ui.interact(
        frame.response.rect,
        ui.make_persistent_id(("message_row", index)),
        Sense::click(),
    )
    .on_hover_cursor(egui::CursorIcon::PointingHand)
}

fn message_type_label(message: &FragmentGroup) -> String {
    match &message.packet {
        Some(packet) if message.kind.is_chat() => {
            let packet_type = packet.packet_type.unwrap_or(0);
            format!("{} ({packet_type})", packet_type_chinese(packet_type))
        }
        Some(packet) => packet.packet_type_name.clone(),
        None if message.kind.is_chat() => "未得到完整包".to_owned(),
        None => message.kind.label().to_owned(),
    }
}

fn message_header(ui: &mut Ui, message: &FragmentGroup, message_index: usize, ctx: &egui::Context) {
    Frame::new()
        .fill(if ui.visuals().dark_mode {
            Color32::from_rgb(26, 31, 39)
        } else {
            Color32::from_rgb(249, 251, 254)
        })
        .stroke(Stroke::new(1.0_f32, Color32::from_rgb(48, 57, 70)))
        .corner_radius(8)
        .inner_margin(Margin::symmetric(12, 9))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                status_badge(ui, message.status);
                ui.label(
                    RichText::new(truncate(&message.message_id, 40))
                        .monospace()
                        .strong(),
                )
                .on_hover_text(&message.message_id);
                if ui.small_button("复制 ID").clicked() {
                    ctx.copy_text(message.message_id.clone());
                }
                if let Some(binary) = &message.binary
                    && ui.small_button("复制 Base64URL").clicked()
                {
                    ctx.copy_text(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(binary));
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    let detail = if message.kind.is_chat() {
                        format!(
                            "{}/{} 分片 · {} 次出现",
                            message.unique_fragments(),
                            message.total,
                            message.occurrences()
                        )
                    } else {
                        format!("{} · {} 字节", message.kind.label(), message.binary_len())
                    };
                    ui.label(RichText::new(detail).small().color(DIM));
                });
            });
            ui.add_space(4.0);

            let (sender, receiver, type_label, flags, size) = if let Some(packet) = &message.packet
            {
                (
                    packet.sender.as_str(),
                    packet.receiver.as_str(),
                    message_type_label(message),
                    packet
                        .flags
                        .map(|flags| format!("0x{flags:02X} {}", packet.flag_names.join(",")))
                        .unwrap_or_else(|| "-".to_owned()),
                    format!("{} B", message.binary_len()),
                )
            } else {
                (
                    message.transport_sender.as_str(),
                    "?",
                    "未解析".to_owned(),
                    "-".to_owned(),
                    "-".to_owned(),
                )
            };

            ui.horizontal_wrapped(|ui| {
                info_chip(ui, "发送", sender);
                ui.label(RichText::new("->").color(DIM));
                info_chip(ui, "接收", receiver);
                info_chip(ui, "类型", &type_label);
                info_chip(ui, "标志", &flags);
                info_chip(ui, "大小", &size);
                info_chip(
                    ui,
                    if message.kind.is_chat() {
                        "日志时间"
                    } else {
                        "抓包时间"
                    },
                    if message.first_seen.text.is_empty() {
                        "-"
                    } else {
                        &message.first_seen.text
                    },
                );
            });

            if let Some(packet) = &message.packet {
                let show_algorithms = !(packet.algorithms.kem.is_empty()
                    && packet.algorithms.signature.is_empty()
                    && packet.algorithms.aead.is_empty()
                    && packet.algorithms.hkdf.is_empty());
                let show_lengths = packet.nonce_len > 0
                    || packet.kem_ciphertext_len > 0
                    || packet.ciphertext_len > 0
                    || packet.signature_len > 0;
                let show_session = packet.session_id.is_some() && packet.sequence.is_some();
                let show_time = packet.packet_type.is_some() && packet.timestamp_local.is_some();
                if show_algorithms || show_lengths || show_session || show_time {
                    ui.add_space(3.0);
                    ui.horizontal_wrapped(|ui| {
                        let mut needs_separator = false;
                        if show_algorithms {
                            ui.label(
                                RichText::new(format!(
                                    "算法：{} · {} · {} · {}",
                                    packet.algorithms.kem,
                                    packet.algorithms.signature,
                                    packet.algorithms.aead,
                                    packet.algorithms.hkdf
                                ))
                                .small()
                                .monospace()
                                .color(DIM),
                            );
                            needs_separator = true;
                        }
                        if show_lengths {
                            if needs_separator {
                                ui.separator();
                            }
                            ui.label(
                                RichText::new(format!(
                                    "nonce {} B · KEM {} B · 密文 {} B · 签名 {} B",
                                    packet.nonce_len,
                                    packet.kem_ciphertext_len,
                                    packet.ciphertext_len,
                                    packet.signature_len
                                ))
                                .small()
                                .color(DIM),
                            );
                            needs_separator = true;
                        }
                        if show_session
                            && let (Some(session_id), Some(sequence)) =
                                (&packet.session_id, packet.sequence)
                        {
                            if needs_separator {
                                ui.separator();
                            }
                            ui.label(
                                RichText::new(format!("session {session_id} · seq {sequence}"))
                                    .small()
                                    .color(DIM),
                            );
                            needs_separator = true;
                        }
                        if show_time && let Some(timestamp) = &packet.timestamp_local {
                            if needs_separator {
                                ui.separator();
                            }
                            ui.label(
                                RichText::new(format!("包时间 {}", short_packet_time(timestamp)))
                                    .small()
                                    .color(DIM),
                            )
                            .on_hover_text(timestamp);
                        }
                    });
                }
            }
            let _ = message_index;
        });
}

fn decryption_panel(
    ui: &mut Ui,
    message: &FragmentGroup,
    ctx: &egui::Context,
    open_key_dialog: &mut bool,
) {
    let Some(packet) = &message.packet else {
        return;
    };
    if packet.error.is_some() {
        return;
    }
    let Some(outcome) = &message.decryption else {
        return;
    };
    if outcome.status == DecryptionStatus::NotAttempted {
        return;
    }

    let color = outcome.status.color();
    Frame::new()
        .fill(color.gamma_multiply(0.10))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.65)))
        .corner_radius(6)
        .inner_margin(Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("解密结果").strong().color(color));
                Frame::new()
                    .fill(color.gamma_multiply(0.18))
                    .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.8)))
                    .corner_radius(9)
                    .inner_margin(Margin::symmetric(7, 1))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(outcome.status.label())
                                .small()
                                .strong()
                                .color(color),
                        );
                    });

                if let Some(owner) = &outcome.key_owner {
                    let kind = match outcome.key_kind.as_deref() {
                        Some("session_secret") => "会话密钥",
                        _ => "私钥",
                    };
                    ui.label(RichText::new(format!("{kind}：{owner}")).small().color(DIM));
                }
                if let Some(algorithm) = &outcome.key_algorithm {
                    ui.label(
                        RichText::new(format!("· {algorithm}"))
                            .small()
                            .monospace()
                            .color(DIM),
                    );
                }
                if outcome.compressed {
                    ui.label(RichText::new("· 已解压").small().color(DIM));
                }
                if packet.flag_names.iter().any(|name| name == "SIGNED") {
                    ui.label(RichText::new("· 已签名").small().color(DIM));
                }
                if outcome.status == DecryptionStatus::Decrypted {
                    ui.label(
                        RichText::new(format!("· {} 字节", outcome.plaintext_length))
                            .small()
                            .color(DIM),
                    );
                }

                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if outcome.status == DecryptionStatus::Decrypted {
                        if ui.small_button("复制明文").clicked()
                            && let Some(text) = &outcome.plaintext
                        {
                            ctx.copy_text(text.clone());
                        }
                        if outcome.json.is_some()
                            && ui.small_button("复制格式化 JSON").clicked()
                            && let Some(json) = &outcome.json
                        {
                            let pretty = serde_json::to_string_pretty(json)
                                .unwrap_or_else(|_| outcome.plaintext.clone().unwrap_or_default());
                            ctx.copy_text(pretty);
                        }
                    } else if ui.small_button("加载私钥…").clicked() {
                        *open_key_dialog = true;
                    }
                });
            });

            if outcome.status == DecryptionStatus::Decrypted {
                if let Some(error) = &outcome.error {
                    ui.label(RichText::new(error).small().color(color));
                }
                if let Some(json) = &outcome.json {
                    let pretty = serde_json::to_string_pretty(json)
                        .unwrap_or_else(|_| outcome.plaintext.clone().unwrap_or_default());
                    egui::CollapsingHeader::new("JSON 明文")
                        .id_salt(("decrypted_json", &message.message_id))
                        .default_open(true)
                        .show(ui, |ui| {
                            ScrollArea::vertical()
                                .id_salt("decrypted_json_scroll")
                                .max_height(220.0)
                                .show(ui, |ui| {
                                    ui.add(
                                        Label::new(
                                            RichText::new(pretty)
                                                .small()
                                                .monospace()
                                                .color(ui.visuals().text_color()),
                                        )
                                        .wrap(),
                                    );
                                });
                        });
                } else if let Some(text) = &outcome.plaintext {
                    ScrollArea::vertical()
                        .id_salt("decrypted_text_scroll")
                        .max_height(200.0)
                        .show(ui, |ui| {
                            ui.add(
                                Label::new(
                                    RichText::new(text)
                                        .monospace()
                                        .color(ui.visuals().text_color()),
                                )
                                .wrap(),
                            );
                        });
                } else if let Some(hex_text) = &outcome.plaintext_hex {
                    ui.label(
                        RichText::new("明文不是有效 UTF-8，以下为十六进制：")
                            .small()
                            .color(DIM),
                    );
                    ScrollArea::vertical()
                        .id_salt("decrypted_hex_scroll")
                        .max_height(200.0)
                        .show(ui, |ui| {
                            ui.add(
                                Label::new(
                                    RichText::new(hex_text).small().monospace().color(DIM),
                                )
                                .wrap(),
                            );
                        });
                } else if outcome.plaintext_length > 0 {
                    ui.label(
                        RichText::new(
                            "明文为二进制或过大，未在解密面板中内联显示；请查看下方字段与二进制面板。",
                        )
                        .small()
                        .color(DIM),
                    );
                }
                ui.label(
                    RichText::new(if message.kind == MessageKind::ApiStream {
                        "流记录已通过 XChaCha20-Poly1305 AEAD 认证；会话密钥只用于解密。"
                    } else {
                        "AEAD 认证成功；签名是否有效见下方“验签结果”。解密与验签相互独立。"
                    })
                    .small()
                    .color(DIM),
                );
                if let Some(source) = &outcome.key_source {
                    ui.label(
                        RichText::new(format!("密钥来源：{source}"))
                            .small()
                            .color(DIM),
                    )
                    .on_hover_text(source);
                }
            } else {
                if let Some(error) = &outcome.error {
                    ui.label(RichText::new(error).small().color(color));
                }
                if !outcome.attempts.is_empty() {
                    egui::CollapsingHeader::new(format!(
                        "已尝试的密钥 ({})",
                        outcome.attempts.len()
                    ))
                    .id_salt(("decryption_attempts", &message.message_id))
                    .default_open(false)
                    .show(ui, |ui| {
                        for attempt in &outcome.attempts {
                            ui.label(
                                RichText::new(format!(
                                    "{} · {} · {}{}",
                                    attempt.key_owner,
                                    attempt.key_kind,
                                    attempt.algorithm,
                                    if attempt.success { " · 成功" } else { "" }
                                ))
                                .small()
                                .color(if attempt.success {
                                    DecryptionStatus::Decrypted.color()
                                } else {
                                    DIM
                                }),
                            )
                            .on_hover_text(format!(
                                "{}\n{}",
                                attempt.key_source,
                                attempt.error.as_deref().unwrap_or("无错误")
                            ));
                        }
                    });
                }
            }
        });
}

fn signature_panel(
    ui: &mut Ui,
    message: &FragmentGroup,
    ctx: &egui::Context,
    open_key_dialog: &mut bool,
) {
    let Some(outcome) = &message.signature else {
        return;
    };
    if matches!(
        outcome.status,
        SignatureStatus::NotAttempted | SignatureStatus::NotPresent
    ) {
        return;
    }
    let color = outcome.status.color();
    Frame::new()
        .fill(color.gamma_multiply(0.10))
        .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.65)))
        .corner_radius(6)
        .inner_margin(Margin::symmetric(10, 8))
        .show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("验签结果").strong().color(color));
                Frame::new()
                    .fill(color.gamma_multiply(0.18))
                    .stroke(Stroke::new(1.0_f32, color.gamma_multiply(0.8)))
                    .corner_radius(9)
                    .inner_margin(Margin::symmetric(7, 1))
                    .show(ui, |ui| {
                        ui.label(
                            RichText::new(outcome.status.label())
                                .small()
                                .strong()
                                .color(color),
                        );
                    });
                if let Some(signer) = &outcome.signer {
                    ui.label(
                        RichText::new(format!("签名者：{signer}"))
                            .small()
                            .color(DIM),
                    );
                }
                if let Some(algorithm) = &outcome.algorithm {
                    ui.label(
                        RichText::new(format!("· {algorithm}"))
                            .small()
                            .monospace()
                            .color(DIM),
                    );
                }
                if let Some(owner) = &outcome.key_owner {
                    ui.label(
                        RichText::new(format!("· 公钥所有者：{owner}"))
                            .small()
                            .color(DIM),
                    );
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    if outcome.status != SignatureStatus::Verified
                        && ui.small_button("加载公钥…").clicked()
                    {
                        *open_key_dialog = true;
                    }
                    if outcome.status == SignatureStatus::Verified
                        && ui.small_button("复制结论").clicked()
                    {
                        ctx.copy_text(format!(
                            "签名有效：{} · {} · 公钥 {}",
                            outcome.signer.as_deref().unwrap_or("?"),
                            outcome.algorithm.as_deref().unwrap_or("?"),
                            outcome.key_owner.as_deref().unwrap_or("?")
                        ));
                    }
                });
            });
            if let Some(error) = &outcome.error {
                ui.label(RichText::new(error).small().color(color));
            }
            if let Some(source) = &outcome.key_source {
                ui.label(
                    RichText::new(format!("公钥来源：{source}"))
                        .small()
                        .color(DIM),
                )
                .on_hover_text(source);
            }
            if !outcome.attempts.is_empty() {
                egui::CollapsingHeader::new(format!("已尝试的公钥 ({})", outcome.attempts.len()))
                    .id_salt(("signature_attempts", &message.message_id))
                    .default_open(false)
                    .show(ui, |ui| {
                        for attempt in &outcome.attempts {
                            ui.label(
                                RichText::new(format!(
                                    "{} · {}{}",
                                    attempt.key_owner,
                                    attempt.algorithm,
                                    if attempt.success { " · 成功" } else { "" }
                                ))
                                .small()
                                .color(if attempt.success {
                                    SignatureStatus::Verified.color()
                                } else {
                                    DIM
                                }),
                            )
                            .on_hover_text(format!(
                                "{}\n{}",
                                attempt.key_source,
                                attempt.error.as_deref().unwrap_or("无错误")
                            ));
                        }
                    });
            }
        });
}

fn is_key_path(path: &Path) -> bool {
    if path.is_file() {
        return path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
    }
    if path.is_dir() {
        return path
            .join("keys")
            .join("private")
            .join("local.json")
            .is_file()
            || path.join("private").join("local.json").is_file()
            || path.join("accounts").is_dir()
            || path.join("keys").is_dir()
            || (path.join("secrets").join("master.key").is_file()
                && path.join("sessions").is_dir());
    }
    false
}

fn status_badge(ui: &mut Ui, status: MessageStatus) {
    Frame::new()
        .fill(status.color().gamma_multiply(0.18))
        .stroke(Stroke::new(1.0_f32, status.color().gamma_multiply(0.8)))
        .corner_radius(10)
        .inner_margin(Margin::symmetric(8, 2))
        .show(ui, |ui| {
            ui.label(
                RichText::new(status.label())
                    .small()
                    .strong()
                    .color(status.color()),
            );
        });
}

fn short_packet_time(timestamp: &str) -> &str {
    timestamp.split_once(' ').map_or(timestamp, |(_, rest)| {
        rest.split_once(' ').map_or(rest, |(time, _)| time)
    })
}

fn info_chip(ui: &mut Ui, label: &str, value: &str) {
    Frame::new()
        .fill(ui.visuals().faint_bg_color)
        .corner_radius(5)
        .inner_margin(Margin::symmetric(7, 2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).small().color(DIM));
                ui.label(RichText::new(value).small().monospace());
            });
        });
}

struct FieldsResult {
    clicked: Option<SelectedField>,
    hovered: Option<Range<usize>>,
}

fn fields_panel(
    ui: &mut Ui,
    packet: &ParsedPacket,
    message_index: usize,
    selected: Option<&SelectedField>,
) -> FieldsResult {
    let mut flat: Vec<FlatField<'_>> = Vec::new();
    flatten_fields(&packet.fields, &mut flat);
    let mut clicked = None;
    let mut hovered = None;
    let mut last_hovered: Option<(usize, usize)> = None;
    let selected_key = selected
        .filter(|selection| selection.message_index == message_index)
        .map(|selection| selection.key.as_str());

    ScrollArea::vertical()
        .id_salt(("fields_scroll", message_index))
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            for field in flat {
                let data = field.field;
                let indent = 2.0 + field.depth as f32 * 15.0;
                let is_selected = selected_key == Some(data.name.as_str());
                let fill = if is_selected {
                    ui.visuals().selection.bg_fill.gamma_multiply(0.75)
                } else {
                    Color32::TRANSPARENT
                };
                let frame = Frame::new()
                    .fill(fill)
                    .corner_radius(4)
                    .inner_margin(Margin::symmetric(5, 3))
                    .show(ui, |ui| {
                        ui.set_width(ui.available_width());
                        ui.horizontal(|ui| {
                            ui.add_space(indent);
                            if field.depth == 0 {
                                let color = category_color(data.category);
                                let (rect, _) =
                                    ui.allocate_exact_size(Vec2::new(8.0, 8.0), Sense::hover());
                                ui.painter().rect_filled(rect, 2.0, color);
                            } else {
                                ui.add_space(8.0);
                            }
                            ui.label(RichText::new(&data.label).strong().size(13.0).color(
                                if is_selected {
                                    ui.visuals().strong_text_color()
                                } else {
                                    ui.visuals().text_color()
                                },
                            ));
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                ui.label(
                                    RichText::new(if data.length == 0 {
                                        format!("@{}", data.offset)
                                    } else {
                                        format!("{}..{}", data.offset, data.end())
                                    })
                                    .small()
                                    .monospace()
                                    .color(DIM),
                                );
                                ui.label(
                                    RichText::new(format!("{}B", data.length))
                                        .small()
                                        .color(DIM),
                                );
                            });
                        });
                        ui.horizontal(|ui| {
                            ui.add_space(indent + 14.0);
                            let value_width = ui.available_width().max(40.0);
                            let response = ui
                                .allocate_ui_with_layout(
                                    Vec2::new(value_width, 16.0),
                                    Layout::left_to_right(Align::Center),
                                    |ui| {
                                        ui.add(
                                            Label::new(
                                                RichText::new(&data.value)
                                                    .small()
                                                    .monospace()
                                                    .color(if is_selected {
                                                        ui.visuals().text_color()
                                                    } else {
                                                        DIM
                                                    }),
                                            )
                                            .truncate(),
                                        )
                                    },
                                )
                                .inner;
                            let mut hover = data.value.clone();
                            if let Some(note) = &data.note {
                                hover.push_str("\n\n");
                                hover.push_str(note);
                            }
                            response.on_hover_text(hover);
                        });
                    });
                let response = ui.interact(
                    frame.response.rect,
                    ui.make_persistent_id(("field_row", message_index, &data.name)),
                    Sense::click(),
                );
                if response.hovered() {
                    last_hovered = Some((data.offset, data.length));
                }
                if response.clicked() {
                    clicked = Some(SelectedField {
                        message_index,
                        key: data.name.clone(),
                        label: data.label.clone(),
                        offset: data.offset,
                        length: data.length,
                        note: data.note.clone(),
                    });
                }
                ui.add_space(1.0);
            }
        });

    // A hover preview is intentionally limited to small fields. Previewing a
    // multi-kilobyte KEM blob by filling the viewport with blue is noisy and
    // makes it hard to distinguish the deliberate yellow selection.
    if let Some((offset, length)) = last_hovered
        && (1..=64).contains(&length)
    {
        hovered = Some(offset..offset.saturating_add(length));
    }
    FieldsResult { clicked, hovered }
}

#[allow(clippy::too_many_arguments, clippy::needless_range_loop)]
fn hex_panel(
    ui: &mut Ui,
    message: &FragmentGroup,
    message_index: usize,
    selected: Option<&SelectedField>,
    hover_range: Option<&Range<usize>>,
    pending_offset: &mut Option<usize>,
    colorize_fields: &mut bool,
) {
    let selected = selected.filter(|selection| selection.message_index == message_index);
    let binary = message.binary.as_deref();

    ui.horizontal(|ui| {
        ui.label(RichText::new("二进制").strong());
        if let Some(binary) = binary {
            ui.label(
                RichText::new(format!("{} 字节", binary.len()))
                    .small()
                    .color(DIM),
            );
        }
        ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
            ui.checkbox(colorize_fields, "字段着色");
            if let Some(binary) = binary
                && ui
                    .small_button("复制全部十六进制")
                    .on_hover_text("复制完整二进制为十六进制文本")
                    .clicked()
            {
                ui.ctx().copy_text(hex(binary));
            }
        });
    });

    if let Some(selection) = selected {
        ui.add_space(2.0);
        Frame::new()
            .fill(ui.visuals().selection.bg_fill.gamma_multiply(0.35))
            .corner_radius(5)
            .inner_margin(Margin::symmetric(7, 4))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let color = category_color(category_of_selected(message, selection));
                    ui.label(RichText::new("已选字段").small().color(DIM));
                    ui.label(
                        RichText::new(&selection.label)
                            .small()
                            .strong()
                            .color(color),
                    );
                    ui.label(
                        RichText::new(format!(
                            "{}..{} · {} 字节",
                            selection.offset,
                            selection.offset.saturating_add(selection.length),
                            selection.length
                        ))
                        .small()
                        .monospace()
                        .color(DIM),
                    );
                    if let Some(binary) = binary {
                        let bytes = selected_bytes(binary, selection);
                        if !bytes.is_empty() && ui.small_button("复制字段字节").clicked() {
                            ui.ctx().copy_text(hex(bytes));
                        }
                    }
                });
                let preview = match binary {
                    Some(binary) if selection.length > 0 => {
                        let bytes = selected_bytes(binary, selection);
                        let preview = hex_preview(bytes, 48);
                        if let Some(note) = &selection.note {
                            format!("{preview}  ·  {note}")
                        } else {
                            preview
                        }
                    }
                    _ => "该字段不占用字节".to_owned(),
                };
                ui.label(RichText::new(preview).small().monospace().color(DIM));
            });
    } else {
        ui.label(
            RichText::new("选择左侧字段以高亮对应字节；悬停字段可临时预览。")
                .small()
                .color(DIM),
        );
    }
    ui.separator();

    let Some(binary) = binary else {
        ui.add_space(18.0);
        let text = match message.kind {
            MessageKind::Chat if message.status == MessageStatus::Invalid => {
                "二进制重组或结构解析失败，没有可显示的完整二进制。"
            }
            MessageKind::Chat => "消息尚未完整重组，没有可显示的二进制。",
            MessageKind::Control => "该控制消息没有保留原始字节。",
            MessageKind::PublicKey => "公钥分片尚未完整重组，没有可显示的身份 JSON 二进制。",
            MessageKind::ApiStream => {
                "该方向没有可显示的明文数据；可能缺少会话密钥或未捕获数据记录。"
            }
        };
        ui.label(RichText::new(text).color(message.status.color()));
        if message.kind.is_chat() {
            let missing = message.missing_indices();
            if !missing.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "缺失分片：{}",
                        missing
                            .iter()
                            .map(usize::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ))
                    .small()
                    .color(DIM),
                );
            }
        }
        return;
    };

    if binary.is_empty() {
        ui.label("二进制为空");
        return;
    }

    let font = FontId::new(12.0, FontFamily::Monospace);
    let row_height = ui.text_style_height(&TextStyle::Monospace) + 4.0;
    // Add margin for font rasterization/rounding; otherwise the ASCII column
    // can be pushed just past the clip rectangle when the window is narrow.
    let char_width = ui.fonts(|fonts| fonts.glyph_width(&font, '0')).max(1.0) * 1.02;
    let available_width = (ui.available_width() - 22.0).max(1.0);
    let bytes_per_row = if available_width >= 78.0 * char_width {
        16
    } else if available_width >= 46.0 * char_width {
        8
    } else if available_width >= 29.0 * char_width {
        4
    } else {
        1
    };
    let total_rows = binary.len().div_ceil(bytes_per_row);
    let packet_fields: &[DataField] = message
        .packet
        .as_ref()
        .map(|packet| packet.fields.as_slice())
        .unwrap_or(&[]);
    // Building one entry per byte is cheap for packets but not for multi-MB
    // API streams; skip per-byte field coloring above a sane threshold.
    const MAX_COLORIZE_BYTES: usize = 1024 * 1024;
    let categories = if binary.len() <= MAX_COLORIZE_BYTES {
        byte_categories(packet_fields, binary.len())
    } else {
        Vec::new()
    };
    let selected_range = selected
        .map(SelectedField::range)
        .filter(|range| !range.is_empty());
    let base_text = ui.visuals().text_color();
    let dim_text = DIM;
    let selection_bg = Color32::from_rgb(255, 200, 61);
    let hover_bg = Color32::from_rgb(94, 200, 255);
    let panel_fill = ui.visuals().panel_fill;
    let colorize = *colorize_fields;

    let mut scroll = ScrollArea::vertical()
        .id_salt(("hex_scroll", message_index))
        .auto_shrink([false, false]);
    if let Some(offset) = pending_offset.take() {
        let row = offset / bytes_per_row;
        scroll = scroll.vertical_scroll_offset(row.saturating_sub(2) as f32 * row_height);
    }
    scroll.show_rows(ui, row_height, total_rows, |ui, rows| {
        ui.spacing_mut().item_spacing.y = 0.0;
        for row in rows {
            let start = row * bytes_per_row;
            let end = (start + bytes_per_row).min(binary.len());
            let mut job = egui::text::LayoutJob::default();
            job.wrap.max_width = f32::INFINITY;
            append_span(
                &mut job,
                &format!("{start:08X}  "),
                font.clone(),
                dim_text,
                None,
            );
            for offset in start..start + bytes_per_row {
                if offset < end {
                    let in_selected = selected_range
                        .as_ref()
                        .is_some_and(|range| range.contains(&offset));
                    let in_hover = hover_range.is_some_and(|range| range.contains(&offset));
                    let background = if in_selected {
                        Some(selection_bg)
                    } else if in_hover {
                        Some(hover_bg)
                    } else if colorize {
                        categories
                            .get(offset)
                            .and_then(|category| *category)
                            .map(|category| blend(panel_fill, category_color(category), 0.18))
                    } else {
                        None
                    };
                    let color = if in_selected || in_hover {
                        Color32::BLACK
                    } else {
                        base_text
                    };
                    append_span(
                        &mut job,
                        &format!("{:02X}", binary[offset]),
                        font.clone(),
                        color,
                        background,
                    );
                } else {
                    append_span(&mut job, "  ", font.clone(), base_text, None);
                }
                append_span(&mut job, " ", font.clone(), base_text, None);
                if offset == start + bytes_per_row / 2 - 1 && bytes_per_row > 4 {
                    append_span(&mut job, " ", font.clone(), base_text, None);
                }
            }
            append_span(&mut job, " | ", font.clone(), dim_text, None);
            for offset in start..start + bytes_per_row {
                if offset < end {
                    let in_selected = selected_range
                        .as_ref()
                        .is_some_and(|range| range.contains(&offset));
                    let in_hover = hover_range.is_some_and(|range| range.contains(&offset));
                    let background = if in_selected {
                        Some(selection_bg)
                    } else if in_hover {
                        Some(hover_bg)
                    } else if colorize {
                        categories
                            .get(offset)
                            .and_then(|category| *category)
                            .map(|category| blend(panel_fill, category_color(category), 0.18))
                    } else {
                        None
                    };
                    let color = if in_selected || in_hover {
                        Color32::BLACK
                    } else {
                        base_text
                    };
                    let character = binary[offset];
                    let text = if (0x20..=0x7e).contains(&character) {
                        (character as char).to_string()
                    } else {
                        ".".to_owned()
                    };
                    append_span(&mut job, &text, font.clone(), color, background);
                } else {
                    append_span(&mut job, " ", font.clone(), base_text, None);
                }
            }
            ui.add(Label::new(job).extend().selectable(false));
        }
    });
}

fn selected_bytes<'a>(binary: &'a [u8], selection: &SelectedField) -> &'a [u8] {
    let start = selection.offset.min(binary.len());
    let end = selection
        .offset
        .saturating_add(selection.length)
        .min(binary.len());
    &binary[start..end]
}

fn category_of_selected(message: &FragmentGroup, selection: &SelectedField) -> u8 {
    let Some(packet) = &message.packet else {
        return 11;
    };
    let mut flat = Vec::new();
    flatten_fields(&packet.fields, &mut flat);
    flat.iter()
        .find(|field| field.field.name == selection.key)
        .map_or(11, |field| field.field.category)
}

fn append_span(
    job: &mut egui::text::LayoutJob,
    text: &str,
    font: FontId,
    color: Color32,
    background: Option<Color32>,
) {
    let format = egui::TextFormat {
        font_id: font,
        color,
        background: background.unwrap_or(Color32::TRANSPARENT),
        ..Default::default()
    };
    job.append(text, 0.0, format);
}

fn category_color(category: u8) -> Color32 {
    FIELD_COLORS
        .get(category as usize)
        .copied()
        .unwrap_or(FIELD_COLORS[11])
}

fn blend(background: Color32, foreground: Color32, amount: f32) -> Color32 {
    let amount = amount.clamp(0.0, 1.0);
    let mix = |a: u8, b: u8| -> u8 {
        (a as f32 * (1.0 - amount) + b as f32 * amount)
            .round()
            .clamp(0.0, 255.0) as u8
    };
    Color32::from_rgb(
        mix(background.r(), foreground.r()),
        mix(background.g(), foreground.g()),
        mix(background.b(), foreground.b()),
    )
}

fn fragments_table(ui: &mut Ui, message: &FragmentGroup) {
    let missing = message.missing_indices();
    if !missing.is_empty() {
        ui.label(
            RichText::new(format!(
                "缺失 {} 个分片：{}",
                missing.len(),
                missing
                    .iter()
                    .map(usize::to_string)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .small()
            .color(MessageStatus::Invalid.color()),
        );
    }
    if message.conflicts > 0 {
        ui.label(
            RichText::new(format!(
                "检测到 {} 个冲突（同一索引不同载荷或不同总数）",
                message.conflicts
            ))
            .small()
            .color(MessageStatus::Invalid.color()),
        );
    }
    ScrollArea::vertical()
        .id_salt("fragment_scroll")
        .max_height(150.0)
        .show(ui, |ui| {
            egui::Grid::new("fragment_grid")
                .num_columns(5)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong("索引");
                    ui.strong("行时间");
                    ui.strong("来源");
                    ui.strong("长度");
                    ui.strong("状态");
                    ui.end_row();
                    for occurrence in message.all_occurrences_sorted() {
                        ui.monospace(format!("{:04}", occurrence.index));
                        ui.label(&occurrence.timestamp.time);
                        ui.label(format!("{}:{}", occurrence.source_name, occurrence.line))
                            .on_hover_text(&occurrence.source_path);
                        ui.label(format!("{} B", occurrence.payload_length));
                        let duplicate = message
                            .slots
                            .get(&occurrence.index)
                            .is_some_and(|slot| slot.occurrences.len() > 1);
                        if duplicate {
                            ui.label(
                                RichText::new("重复出现")
                                    .small()
                                    .color(MessageStatus::Incomplete.color()),
                            );
                        } else {
                            ui.label(RichText::new("唯一").small().color(DIM));
                        }
                        ui.end_row();
                    }
                    for index in missing {
                        ui.monospace(format!("{index:04}"));
                        ui.label("-");
                        ui.label("-");
                        ui.label("-");
                        ui.label(
                            RichText::new("缺失")
                                .small()
                                .color(MessageStatus::Invalid.color()),
                        );
                        ui.end_row();
                    }
                });
        });
}

fn truncate(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        return text.to_owned();
    }
    let mut result: String = text.chars().take(max_chars.saturating_sub(1)).collect();
    result.push('…');
    result
}

fn dedupe_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut result = Vec::new();
    for path in paths {
        let canonical = std::fs::canonicalize(&path).unwrap_or(path);
        if !result.contains(&canonical) {
            result.push(canonical);
        }
    }
    result
}

fn font_definitions() -> FontDefinitions {
    let mut fonts = FontDefinitions::default();
    let candidates = [
        "/usr/share/fonts/truetype/droid/DroidSansFallbackFull.ttf",
        "/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
        "/usr/share/fonts/truetype/wqy/wqy-microhei.ttc",
        "/System/Library/Fonts/PingFang.ttc",
        "/System/Library/Fonts/STHeiti Light.ttc",
        "C:\\Windows\\Fonts\\msyh.ttc",
        "C:\\Windows\\Fonts\\simhei.ttf",
        "C:\\Windows\\Fonts\\simsun.ttc",
    ];
    for path in candidates {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        fonts.font_data.insert(
            "cjk_fallback".to_owned(),
            Arc::new(FontData::from_owned(bytes)),
        );
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push("cjk_fallback".to_owned());
        }
        break;
    }
    // The bundled Hack font covers arrows such as "→", which neither the
    // default proportional font nor several CJK fallback fonts (e.g. Droid
    // Sans Fallback) contain; without it arrows render as tofu boxes in the
    // capture details.
    fonts
        .families
        .entry(FontFamily::Proportional)
        .or_default()
        .push("Hack".to_owned());
    fonts
}

fn install_fonts(ctx: &egui::Context) {
    ctx.set_fonts(font_definitions());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureSource, CaptureSummary, ChatTransfer};
    use crate::model::{FragmentOccurrence, LogTimestamp, SignatureOutcome};

    #[test]
    fn capture_chat_transfers_map_to_gui_messages() {
        let fragment = FragmentOccurrence {
            source_path: "capture.pcapng".to_owned(),
            source_name: "连接 0 C2S".to_owned(),
            line: 7,
            timestamp: LogTimestamp {
                text: "2026-10-24 12:00:00".to_owned(),
                date: Some("2026-10-24".to_owned()),
                time: "12:00:00".to_owned(),
            },
            index: 0,
            total: 1,
            payload: "AA".to_owned(),
            payload_length: 1,
        };
        let analysis = CaptureAnalysis {
            tool: "test",
            version: "test",
            format_version: 1,
            generated_at_utc: String::new(),
            generated_at_local: String::new(),
            minecraft_version: "26.3".to_owned(),
            protocol_version: 777,
            cryptographic_verification: true,
            payload_decrypted: false,
            summary: CaptureSummary::default(),
            sources: vec![CaptureSource {
                path: "/tmp/capture.pcapng".to_owned(),
                name: "capture.pcapng".to_owned(),
                conversations: 1,
                minecraft_connections: 1,
                packets: 10,
                payload_bytes: 100,
                bytes: 200,
            }],
            connections: Vec::new(),
            chat_transfers: vec![ChatTransfer {
                message_id: "id".to_owned(),
                sender: "alice".to_owned(),
                status: MessageStatus::Parsed,
                fragment_total: 1,
                unique_fragments: 1,
                occurrence_count: 1,
                duplicate_count: 0,
                conflicts: 0,
                missing_indices: Vec::new(),
                warnings: Vec::new(),
                binary_length: Some(2),
                binary_base64url: Some("AAA".to_owned()),
                packet: None,
                decryption: None,
                signature: Some(SignatureOutcome::default()),
                binary: Some(vec![1, 2, 3]),
                fragments: vec![fragment],
            }],
            public_key_shares: Vec::new(),
            api_streams: Vec::new(),
            events: Vec::new(),
            warnings: Vec::new(),
        };

        let loaded = capture_to_loaded(&analysis);
        assert_eq!(loaded.sources.len(), 1);
        assert_eq!(loaded.sources[0].lines, 10);
        assert_eq!(loaded.fragment_lines, 1);
        assert_eq!(loaded.messages.len(), 1);
        let message = &loaded.messages[0];
        assert_eq!(message.binary.as_deref(), Some([1, 2, 3].as_slice()));
        assert_eq!(message.unique_fragments(), 1);
        assert_eq!(message.slots[&0].payload, "AA");
        assert!(message.signature.is_some());
    }

    #[test]
    fn capture_control_keyshare_and_streams_map_to_gui_messages() {
        use crate::capture::{
            ApiStream, ApiStreamDirection, CaptureTime, ChannelEvent, ChannelObservation,
            ChannelPayload, ControlHmac, PublicIdentitySummary, PublicKeyRecordSummary,
            PublicKeyShare, Side, StreamContent, StreamRecordInfo,
        };

        let time = CaptureTime {
            epoch_millis: 1_000,
            utc: "2026-10-24 12:00:00.000000000 UTC".to_owned(),
            local: "2026-10-24 20:00:00.000000000 +08:00".to_owned(),
            secs: 1,
            nanos: 0,
        };
        let control_binary = vec![1, 3, b'b', b'o', b'b'];
        let control = ChannelEvent {
            index: 0,
            time: time.clone(),
            connection: 0,
            side: Side::ClientToServer,
            channel: "krypt04mcg_stream:control".to_owned(),
            frame_offset: 0,
            payload: ChannelPayload::Control {
                kind: "OPEN".to_owned(),
                peer: "bob".to_owned(),
                sender: "alice".to_owned(),
                receiver: "bob".to_owned(),
                stream_id: "00112233-4455-6677-8899-aabbccddeeff".to_owned(),
                slot: 0,
                business_channel: "example:test".to_owned(),
                session_id: "session".to_owned(),
                sequence: 1,
                body_length: 0,
                hmac: Some(ControlHmac {
                    verified: true,
                    source: "alice".to_owned(),
                    target: "bob".to_owned(),
                    error: None,
                }),
                exchange: None,
                fields: vec![DataField {
                    name: "control.kind".to_owned(),
                    label: "控制类型".to_owned(),
                    offset: 0,
                    length: 1,
                    value: "OPEN (1)".to_owned(),
                    hex: Some("01".to_owned()),
                    note: None,
                    category: 0,
                    children: Vec::new(),
                }],
                binary: control_binary.clone(),
            },
            error: None,
        };

        let identity_json = serde_json::json!({
            "owner": "alice",
            "uuid": "11112222-3333-4444-5555-666677778888",
        });
        let identity_bytes = serde_json::to_vec(&identity_json).unwrap();
        let share = PublicKeyShare {
            transfer_id: "aaaabbbb-cccc-dddd-eeee-ffff00001111".to_owned(),
            sender: "alice".to_owned(),
            receiver: Some("bob".to_owned()),
            version: 1,
            total_chunks: 1,
            received_chunks: 1,
            complete: true,
            identity: Some(PublicIdentitySummary {
                owner: "alice".to_owned(),
                uuid: "11112222-3333-4444-5555-666677778888".to_owned(),
                kem_public_key: Some(PublicKeyRecordSummary {
                    algorithm: "ML-KEM-768+X25519/public".to_owned(),
                    uuid: "11112222-3333-4444-5555-666677778888".to_owned(),
                    fingerprint: "00".to_owned(),
                    created_at: None,
                }),
                signature_public_key: None,
            }),
            json: Some(identity_json),
            warnings: Vec::new(),
            observations: vec![ChannelObservation {
                connection: 0,
                side: Side::ServerToClient,
                time: CaptureTime {
                    epoch_millis: 2_000,
                    ..time.clone()
                },
                chunk_index: 0,
            }],
            binary: identity_bytes.clone(),
        };

        let direction = ApiStreamDirection {
            sender: "alice".to_owned(),
            receiver: "bob".to_owned(),
            record_count: 1,
            ciphertext_bytes: 10,
            decrypted_records: 1,
            failed_records: 0,
            decryption: "decrypted".to_owned(),
            content: StreamContent {
                kind: "text".to_owned(),
                length: 5,
                sha256: None,
                valid_utf8_prefix: true,
                file_name: None,
                declared_file_size: None,
                text_preview: Some("hello".to_owned()),
                json: None,
                base64url: None,
                preview_truncated: false,
            },
            records: vec![StreamRecordInfo {
                index: 0,
                connection: 0,
                side: Side::ClientToServer,
                time: CaptureTime {
                    epoch_millis: 3_000,
                    ..time.clone()
                },
                ciphertext_length: 10,
                plaintext_length: Some(5),
                status: "decrypted".to_owned(),
                error: None,
                observations: 1,
                preview_text: Some("hello".to_owned()),
                preview_hex: None,
            }],
            warnings: Vec::new(),
            data: b"hello".to_vec(),
        };
        let stream = ApiStream {
            stream_id: "00112233-4455-6677-8899-aabbccddeeff".to_owned(),
            channel: "example:test".to_owned(),
            session_id: "session".to_owned(),
            initiator: "alice".to_owned(),
            responder: "bob".to_owned(),
            first_seen: Some(CaptureTime {
                epoch_millis: 3_000,
                ..time.clone()
            }),
            last_seen: Some(CaptureTime {
                epoch_millis: 3_100,
                ..time.clone()
            }),
            end_reason: Some("END".to_owned()),
            directions: vec![direction],
            warnings: Vec::new(),
        };

        let analysis = CaptureAnalysis {
            tool: "test",
            version: "test",
            format_version: 1,
            generated_at_utc: String::new(),
            generated_at_local: String::new(),
            minecraft_version: "26.3".to_owned(),
            protocol_version: 777,
            cryptographic_verification: false,
            payload_decrypted: true,
            summary: CaptureSummary::default(),
            sources: Vec::new(),
            connections: Vec::new(),
            chat_transfers: Vec::new(),
            public_key_shares: vec![share],
            api_streams: vec![stream],
            events: vec![control],
            warnings: Vec::new(),
        };

        let loaded = capture_to_loaded(&analysis);
        assert_eq!(loaded.messages.len(), 3);
        assert_eq!(loaded.messages[0].kind, MessageKind::Control);
        assert_eq!(
            loaded.messages[0].binary.as_deref(),
            Some(control_binary.as_slice())
        );
        assert_eq!(
            loaded.messages[0]
                .packet
                .as_ref()
                .unwrap()
                .fields
                .first()
                .map(|field| field.name.as_str()),
            Some("control.kind")
        );
        assert_eq!(loaded.messages[1].kind, MessageKind::PublicKey);
        assert_eq!(
            loaded.messages[1].binary.as_deref(),
            Some(identity_bytes.as_slice())
        );
        assert!(
            loaded.messages[1]
                .packet
                .as_ref()
                .unwrap()
                .fields
                .iter()
                .any(|field| field.name == "keyshare.json")
        );
        assert_eq!(loaded.messages[2].kind, MessageKind::ApiStream);
        assert_eq!(
            loaded.messages[2].binary.as_deref(),
            Some(b"hello".as_slice())
        );
        assert_eq!(
            loaded.messages[2]
                .decryption
                .as_ref()
                .map(|outcome| outcome.status),
            Some(crate::model::DecryptionStatus::Decrypted)
        );
        assert!(
            loaded.messages[2]
                .packet
                .as_ref()
                .unwrap()
                .packet_type_name
                .contains("stream")
        );
    }

    #[test]
    fn file_stream_header_fields_map_exact_byte_ranges() {
        let mut data = Vec::new();
        data.extend_from_slice(&3u16.to_be_bytes());
        data.extend_from_slice(b"abc");
        data.extend_from_slice(&5i32.to_be_bytes());
        data.extend_from_slice(&[1, 2, 3, 4, 5]);
        let fields = file_stream_header_fields(&data);
        let name = fields
            .iter()
            .find(|field| field.name == "stream.file.name")
            .unwrap();
        assert_eq!((name.offset, name.length), (2, 3));
        assert_eq!(name.value, "abc");
        let size = fields
            .iter()
            .find(|field| field.name == "stream.file.declared_size")
            .unwrap();
        assert_eq!((size.offset, size.length), (5, 4));
        let content = fields
            .iter()
            .find(|field| field.name == "stream.file.content")
            .unwrap();
        assert_eq!((content.offset, content.length), (9, 5));
        assert_eq!(content.offset + content.length, data.len());
    }

    #[test]
    fn theme_ignores_system_preference_and_applies_to_selected_theme() {
        let ctx = egui::Context::default();
        // Simulate egui starting from a theme other than the app's choice.
        ctx.set_theme(egui::Theme::Light);
        K04MApp::apply_theme(&ctx, true);
        assert_eq!(ctx.theme(), egui::Theme::Dark);
        assert!(ctx.style().visuals.dark_mode);
        assert_eq!(
            ctx.style().visuals.panel_fill,
            Color32::from_rgb(20, 23, 29)
        );

        K04MApp::apply_theme(&ctx, false);
        assert_eq!(ctx.theme(), egui::Theme::Light);
        assert!(!ctx.style().visuals.dark_mode);
        assert_eq!(
            ctx.style().visuals.panel_fill,
            Color32::from_rgb(244, 246, 249)
        );
    }

    #[test]
    fn proportional_font_has_arrow_glyph() {
        let ctx = egui::Context::default();
        ctx.set_fonts(font_definitions());
        let mut has_arrow = false;
        let _ = ctx.run(Default::default(), |ctx| {
            ctx.fonts(|fonts| {
                has_arrow = fonts.has_glyph(&FontId::proportional(14.0), '→');
            });
        });
        assert!(has_arrow);
    }
}
