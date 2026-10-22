//! egui desktop front end.

use std::ops::Range;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use base64::Engine as _;
use chrono::Local;
use eframe::egui::{
    self, Align, Color32, FontData, FontDefinitions, FontFamily, FontId, Frame, Label, Layout,
    Margin, RichText, ScrollArea, Sense, Stroke, TextEdit, TextStyle, Ui, Vec2,
};

use crate::decrypt::{KeyLoadSummary, KeyStore};
use crate::export::export_json;
use crate::log_reader::load_paths;
use crate::model::{
    DataField, DecryptionOutcome, DecryptionStatus, FragmentGroup, LoadedLogs, MessageStatus,
    ParsedPacket,
};
use crate::packet::{
    FlatField, byte_categories, flatten_fields, hex, hex_preview, packet_type_chinese,
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
        };
        app.apply_theme(&cc.egui_ctx);
        if !initial_keys.is_empty() {
            app.load_keys(initial_keys);
            app.show_keys = false;
        }
        if !initial_paths.is_empty() {
            app.load(initial_paths);
        }
        app
    }

    fn apply_theme(&self, ctx: &egui::Context) {
        let mut visuals = if self.dark {
            egui::Visuals::dark()
        } else {
            egui::Visuals::light()
        };
        if self.dark {
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
        let mut style = (*ctx.style()).clone();
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
        ctx.set_style(style);
    }

    fn load(&mut self, paths: Vec<PathBuf>) {
        if paths.is_empty() {
            return;
        }
        self.paths = dedupe_paths(paths);
        match load_paths(self.paths.clone()) {
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
            Err(error) => {
                self.status_error = true;
                self.status = error;
            }
        }
    }

    fn redecrypt(&mut self) {
        if let Some(data) = &mut self.data {
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
            .add_filter("Krypt04Mcg 密钥/会话 JSON", &["json"])
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
            .add_filter("Minecraft 日志", &["log", "gz"])
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
        let name = format!(
            "krypt04mcg-parsed-{}.json",
            Local::now().format("%Y%m%d-%H%M%S")
        );
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
                        || packet.algorithms.kem.to_lowercase().contains(&query)
                        || packet.algorithms.aead.to_lowercase().contains(&query)
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
                        .on_hover_text("Ctrl+Shift+O；递归读取 .log / .log.gz")
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
                    let key_count =
                        self.key_store.private_keys.len() + self.key_store.sessions.len();
                    if ui
                        .button(format!("密钥 {key_count}"))
                        .on_hover_text("Ctrl+K；加载多个私钥或会话密钥，解密包正文")
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
                        ui.add(
                            TextEdit::singleline(&mut self.search)
                                .hint_text("搜索 ID / 玩家 / 类型")
                                .desired_width(210.0),
                        );
                    });
                });

                if let Some(data) = &self.data {
                    ui.add_space(2.0);
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(format!("{} 个文件", data.sources.len()))
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
                            RichText::new(format!("{} 条消息", data.messages.len()))
                                .small()
                                .color(DIM),
                        );
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
            self.apply_theme(ctx);
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
                                RichText::new("日志中需要包含 [KRYPT04MCG] 分片行")
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
                        ui.label(RichText::new("尚未加载日志").color(DIM));
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
                    "读取 Minecraft 服务端日志，重组 [KRYPT04MCG] 分片，解析二进制包并高亮字段字节。",
                )
                .size(15.0)
                .color(DIM),
            );
            ui.add_space(22.0);
            ui.horizontal(|ui| {
                let total_width = 520.0;
                ui.add_space(((ui.available_width() - total_width) / 2.0).max(0.0));
                if ui.button("打开日志文件…").clicked() {
                    self.open_files_dialog();
                }
                if ui.button("打开 logs 文件夹…").clicked() {
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
                        "1. 打开最新的 latest.log，或包含多个 .log / .log.gz 的 logs 文件夹。",
                        "2. 支持乱序分片、重复分片和跨文件合并；重复行会保留并标记。",
                        "3. 左侧选择消息，右侧查看二进制与全部包字段。",
                        "4. 点击字段，二进制中对应字节会以黄色高亮；悬停字段可临时预览。",
                        "5. 加载私钥与会话密钥（Ctrl+K），自动解密 KEM 消息和会话消息正文。",
                        "6. “导出 JSON” 会导出所有重组结果、字段、分片来源、解密明文和原始数据。",
                    ] {
                        ui.label(RichText::new(line).small().color(DIM));
                    }
                    ui.add_space(8.0);
                    ui.label(
                        RichText::new(
                            "说明：没有匹配的私钥或会话密钥时只能查看密文结构。解密成功表示 AEAD 认证通过；本工具不验证 PQ 签名，也不建立发送者信任。",
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
                                "Ctrl+O 打开 · Ctrl+Shift+O 文件夹 · Ctrl+K 密钥 · Ctrl+R 重载 · Ctrl+E 导出",
                            )
                            .small()
                            .color(DIM),
                        );
                    });
                });
            });
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        if self.show_sources {
            let mut open = self.show_sources;
            egui::Window::new("日志来源")
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
            egui::Window::new("私钥与会话密钥")
                .open(&mut open)
                .default_width(940.0)
                .show(ctx, |ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} 个私钥 · {} 个会话密钥 · 已解密 {} 条消息",
                            self.key_store.private_keys.len(),
                            self.key_store.sessions.len(),
                            self.decrypted_count()
                        ))
                        .small()
                        .color(DIM),
                    );
                    ui.horizontal(|ui| {
                        if ui.button("加载私钥文件…").clicked() {
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
                            "支持 Krypt04Mcg 的 LocalKeyMaterial（keys/private/local.json）、sessions/*.json、账户目录，以及包含多个账户的父目录。KMCGSEC1 加密文件会自动使用同目录 secrets/master.key 解密。私钥只保存在内存中，绝不会写入导出 JSON。",
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
                    {
                        ui.add_space(12.0);
                        ui.vertical_centered(|ui| {
                            ui.label(RichText::new("尚未加载任何密钥").color(DIM));
                            ui.label(
                                RichText::new(
                                    "私钥用于解密 KEM 消息与会话交换请求；会话密钥用于解密 SESSION_MESSAGE。",
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
                                    });
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
                    RichText::new(
                        message
                            .packet
                            .as_ref()
                            .map(|packet| {
                                packet_type_chinese(packet.packet_type.unwrap_or(0)).to_owned()
                            })
                            .unwrap_or_else(|| "未得到完整包".to_owned()),
                    )
                    .small()
                    .color(ACCENT),
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
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new(if message.binary_len() > 0 {
                            format!("{} B", message.binary_len())
                        } else {
                            format!("{}/{} 分片", message.unique_fragments(), message.total)
                        })
                        .small()
                        .color(DIM),
                    );
                    if message.duplicate_count > 0 {
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
                    ui.label(
                        RichText::new(format!(
                            "{}/{} 分片 · {} 次出现",
                            message.unique_fragments(),
                            message.total,
                            message.occurrences()
                        ))
                        .small()
                        .color(DIM),
                    );
                });
            });
            ui.add_space(4.0);

            let (sender, receiver, type_label, flags, size) = if let Some(packet) = &message.packet
            {
                (
                    packet.sender.as_str(),
                    packet.receiver.as_str(),
                    format!(
                        "{} ({})",
                        packet_type_chinese(packet.packet_type.unwrap_or(0)),
                        packet.packet_type.unwrap_or(0)
                    ),
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
                    "日志时间",
                    if message.first_seen.text.is_empty() {
                        "-"
                    } else {
                        &message.first_seen.text
                    },
                );
            });

            if let Some(packet) = &message.packet {
                ui.add_space(3.0);
                ui.horizontal_wrapped(|ui| {
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
                    ui.separator();
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
                    if let (Some(session_id), Some(sequence)) =
                        (&packet.session_id, packet.sequence)
                    {
                        ui.separator();
                        ui.label(
                            RichText::new(format!("session {session_id} · seq {sequence}"))
                                .small()
                                .color(DIM),
                        );
                    }
                    if let Some(timestamp) = &packet.timestamp_local {
                        ui.separator();
                        ui.label(
                            RichText::new(format!("包时间 {}", short_packet_time(timestamp)))
                                .small()
                                .color(DIM),
                        )
                        .on_hover_text(timestamp);
                    }
                });
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
    if packet.error.is_some() || message.status != MessageStatus::Parsed {
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
                    ui.label(
                        RichText::new("· 已签名（本工具未验证）")
                            .small()
                            .color(MessageStatus::Incomplete.color()),
                    );
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
                } else {
                    ui.label(
                        RichText::new("明文不是有效 UTF-8，以下为十六进制：")
                            .small()
                            .color(DIM),
                    );
                    if let Some(hex_text) = &outcome.plaintext_hex {
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
                    }
                }
                ui.label(
                    RichText::new(
                        "AEAD 认证成功；本工具不验证 PQ 签名，也不建立发送者信任或新鲜度。",
                    )
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
        let text = if message.status == MessageStatus::Invalid {
            "二进制重组或结构解析失败，没有可显示的完整二进制。"
        } else {
            "消息尚未完整重组，没有可显示的二进制。"
        };
        ui.label(RichText::new(text).color(message.status.color()));
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
    let categories = byte_categories(packet_fields, binary.len());
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

fn install_fonts(ctx: &egui::Context) {
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
        let mut fonts = FontDefinitions::default();
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
        ctx.set_fonts(fonts);
        return;
    }
}
