use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Instant;

use agent_skill_guard_core::{
    AttackPath, ExternalReference, ExternalReferenceReputation, Finding, FindingConfidence,
    FindingSeverity, PathValidationDisposition, ScanReport, ValidationExecutionMode, Verdict,
};
use eframe::egui::{
    self, Align, Color32, ComboBox, Frame, Layout, RichText, ScrollArea, Stroke, TextEdit, Ui,
};
use rfd::FileDialog;

use crate::{
    display_text_zh, pretty_debug, render_report_for_export, safe_target_label_zh,
    save_report_to_file, scan_with_request, verdict_label, CompletedScan, ExportFormat,
    ScanRequest, UiTab,
};

enum ScanWorkerMessage {
    Finished(Result<CompletedScan, String>),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SeverityFilter {
    All,
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl SeverityFilter {
    fn label(self) -> &'static str {
        match self {
            SeverityFilter::All => "全部严重级别",
            SeverityFilter::Info => "信息",
            SeverityFilter::Low => "低",
            SeverityFilter::Medium => "中",
            SeverityFilter::High => "高",
            SeverityFilter::Critical => "严重",
        }
    }

    fn matches(self, severity: FindingSeverity) -> bool {
        match self {
            SeverityFilter::All => true,
            SeverityFilter::Info => severity == FindingSeverity::Info,
            SeverityFilter::Low => severity == FindingSeverity::Low,
            SeverityFilter::Medium => severity == FindingSeverity::Medium,
            SeverityFilter::High => severity == FindingSeverity::High,
            SeverityFilter::Critical => severity == FindingSeverity::Critical,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConfidenceFilter {
    All,
    High,
    Medium,
    Low,
    InferredCompound,
}

impl ConfidenceFilter {
    fn label(self) -> &'static str {
        match self {
            ConfidenceFilter::All => "全部置信度",
            ConfidenceFilter::High => "高",
            ConfidenceFilter::Medium => "中",
            ConfidenceFilter::Low => "低",
            ConfidenceFilter::InferredCompound => "组合推断",
        }
    }

    fn matches(self, confidence: FindingConfidence) -> bool {
        match self {
            ConfidenceFilter::All => true,
            ConfidenceFilter::High => confidence == FindingConfidence::High,
            ConfidenceFilter::Medium => confidence == FindingConfidence::Medium,
            ConfidenceFilter::Low => confidence == FindingConfidence::Low,
            ConfidenceFilter::InferredCompound => confidence == FindingConfidence::InferredCompound,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PathStatusFilter {
    All,
    Validated,
    Blocked,
    Assumed,
}

impl PathStatusFilter {
    fn label(self) -> &'static str {
        match self {
            PathStatusFilter::All => "全部状态",
            PathStatusFilter::Validated => "已验证 / 部分验证",
            PathStatusFilter::Blocked => "环境阻断",
            PathStatusFilter::Assumed => "仍为假设 / 范围不完整",
        }
    }

    fn matches(self, status: Option<PathValidationDisposition>) -> bool {
        match self {
            PathStatusFilter::All => true,
            PathStatusFilter::Validated => matches!(
                status,
                Some(PathValidationDisposition::Validated)
                    | Some(PathValidationDisposition::PartiallyValidated)
            ),
            PathStatusFilter::Blocked => {
                matches!(
                    status,
                    Some(PathValidationDisposition::BlockedByEnvironment)
                )
            }
            PathStatusFilter::Assumed => matches!(
                status,
                Some(PathValidationDisposition::StillAssumed)
                    | Some(PathValidationDisposition::ScopeIncomplete)
            ),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ReferenceFilter {
    All,
    SuspiciousOnly,
    ReviewNeededOnly,
}

impl ReferenceFilter {
    fn label(self) -> &'static str {
        match self {
            ReferenceFilter::All => "全部外部引用",
            ReferenceFilter::SuspiciousOnly => "仅可疑引用",
            ReferenceFilter::ReviewNeededOnly => "仅需要复核",
        }
    }

    fn matches(self, reference: &ExternalReference) -> bool {
        match self {
            ReferenceFilter::All => true,
            ReferenceFilter::SuspiciousOnly => {
                reference.reputation == ExternalReferenceReputation::Suspicious
            }
            ReferenceFilter::ReviewNeededOnly => {
                reference.reputation == ExternalReferenceReputation::ReviewNeeded
                    || reference.reputation == ExternalReferenceReputation::Suspicious
            }
        }
    }
}

pub struct AgentSkillGuardApp {
    target_path: String,
    runtime_manifest_path: String,
    suppression_path: String,
    policy_config_path: String,
    report_save_path: String,
    validation_mode: ValidationExecutionMode,
    agent_ecosystem: bool,
    active_tab: UiTab,
    scan_running: bool,
    scan_receiver: Option<Receiver<ScanWorkerMessage>>,
    completed_scan: Option<CompletedScan>,
    status_message: Option<String>,
    error_message: Option<String>,
    show_advanced_options: bool,
    theme_initialized: bool,
    scan_started_at: Option<Instant>,
    selected_finding_id: Option<String>,
    selected_path_id: Option<String>,
    selected_subject_id: Option<String>,
    finding_severity_filter: SeverityFilter,
    finding_confidence_filter: ConfidenceFilter,
    finding_category_filter: String,
    path_severity_filter: SeverityFilter,
    path_type_filter: String,
    path_status_filter: PathStatusFilter,
    reference_filter: ReferenceFilter,
}

impl Default for AgentSkillGuardApp {
    fn default() -> Self {
        Self {
            target_path: String::new(),
            runtime_manifest_path: String::new(),
            suppression_path: String::new(),
            policy_config_path: String::new(),
            report_save_path: String::new(),
            validation_mode: ValidationExecutionMode::Planned,
            agent_ecosystem: false,
            active_tab: UiTab::Summary,
            scan_running: false,
            scan_receiver: None,
            completed_scan: None,
            status_message: Some("请选择一个 SKILL.md 文件或目录，然后开始扫描。".to_string()),
            error_message: None,
            show_advanced_options: false,
            theme_initialized: false,
            scan_started_at: None,
            selected_finding_id: None,
            selected_path_id: None,
            selected_subject_id: None,
            finding_severity_filter: SeverityFilter::All,
            finding_confidence_filter: ConfidenceFilter::All,
            finding_category_filter: "全部分类".to_string(),
            path_severity_filter: SeverityFilter::All,
            path_type_filter: "全部类型".to_string(),
            path_status_filter: PathStatusFilter::All,
            reference_filter: ReferenceFilter::All,
        }
    }
}

impl AgentSkillGuardApp {
    pub fn with_completed_scan(completed_scan: CompletedScan, active_tab: UiTab) -> Self {
        let mut app = Self::default();
        app.completed_scan = Some(completed_scan);
        app.active_tab = active_tab;
        app.status_message = Some("已载入演示报告。".to_string());
        app
    }
}

impl eframe::App for AgentSkillGuardApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.ensure_theme(ctx);
        self.poll_scan_results();
        if self.scan_running {
            ctx.request_repaint();
        }

        egui::TopBottomPanel::top("top_bar")
            .resizable(false)
            .show(ctx, |ui| self.render_top_bar(ui));

        egui::SidePanel::left("scan_panel")
            .default_width(390.0)
            .min_width(340.0)
            .resizable(true)
            .show(ctx, |ui| self.render_scan_panel(ui));

        egui::CentralPanel::default().show(ctx, |ui| self.render_main_panel(ui));
    }
}

impl AgentSkillGuardApp {
    fn ensure_theme(&mut self, ctx: &egui::Context) {
        if self.theme_initialized {
            return;
        }

        self.install_cjk_font(ctx);

        let mut visuals = egui::Visuals::light();
        visuals.panel_fill = Color32::from_rgb(242, 246, 249);
        visuals.window_fill = Color32::from_rgb(250, 252, 254);
        visuals.extreme_bg_color = Color32::from_rgb(226, 233, 239);
        visuals.faint_bg_color = Color32::from_rgb(236, 242, 247);
        visuals.code_bg_color = Color32::from_rgb(239, 245, 250);
        visuals.selection.bg_fill = Color32::from_rgb(18, 111, 122);
        visuals.selection.stroke = Stroke::new(1.0, Color32::WHITE);
        visuals.hyperlink_color = Color32::from_rgb(18, 111, 122);
        visuals.widgets.active.bg_fill = Color32::from_rgb(18, 111, 122);
        visuals.widgets.hovered.bg_fill = Color32::from_rgb(222, 237, 244);
        visuals.widgets.inactive.bg_fill = Color32::from_rgb(255, 255, 255);
        visuals.override_text_color = Some(Color32::from_rgb(33, 37, 41));
        ctx.set_visuals(visuals);

        let mut style = (*ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(12.0, 12.0);
        style.spacing.button_padding = egui::vec2(12.0, 9.0);
        style.spacing.indent = 18.0;
        style.spacing.menu_margin = egui::Margin::same(12.0);
        ctx.set_style(style);

        self.theme_initialized = true;
    }

    fn install_cjk_font(&self, ctx: &egui::Context) {
        let font_root = std::env::var_os("WINDIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("Windows"))
            .join("Fonts");

        let candidates = [
            font_root.join("msyh.ttc"),
            font_root.join("msyhbd.ttc"),
            font_root.join("simhei.ttf"),
            font_root.join("simsun.ttc"),
        ];

        for path in candidates {
            let Ok(bytes) = fs::read(&path) else {
                continue;
            };

            let mut fonts = egui::FontDefinitions::default();
            fonts.font_data.insert(
                "windows_cjk".to_owned(),
                egui::FontData::from_owned(bytes).into(),
            );
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
                family.insert(0, "windows_cjk".to_owned());
            }
            if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
                family.push("windows_cjk".to_owned());
            }
            ctx.set_fonts(fonts);
            break;
        }
    }

    fn render_top_bar(&mut self, ui: &mut Ui) {
        Frame::group(ui.style())
            .fill(Color32::from_rgb(255, 255, 255))
            .stroke(Stroke::new(1.0, Color32::from_rgb(216, 226, 235)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.heading(
                            RichText::new("Agent Skill Guard")
                                .size(24.0)
                                .strong()
                                .color(Color32::from_rgb(19, 63, 70)),
                        );
                        ui.label(
                            RichText::new(
                                "中文优先的桌面安全验证器，用于高频审查 OpenClaw Skills 的真实风险。",
                            )
                            .color(Color32::from_rgb(86, 97, 108)),
                        );
                    });

                    ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                        for format in ExportFormat::ALL.into_iter().rev() {
                            let button =
                                egui::Button::new(format!("导出 {}", format.label())).small();
                            if ui
                                .add_enabled(self.completed_scan.is_some(), button)
                                .clicked()
                            {
                                self.export_current_report(format);
                            }
                        }

                        let button_text = if self.scan_running {
                            "扫描进行中…"
                        } else {
                            "开始扫描"
                        };
                        if ui
                            .add_enabled(
                                !self.scan_running,
                                egui::Button::new(
                                    RichText::new(button_text)
                                        .strong()
                                        .color(Color32::WHITE),
                                )
                                .fill(Color32::from_rgb(15, 109, 99)),
                            )
                            .clicked()
                        {
                            self.start_scan();
                        }

                        if let Some(label) = self.top_status_label() {
                            self.status_badge(ui, &label);
                        }
                    });
                });
            });
    }

    fn render_scan_panel(&mut self, ui: &mut Ui) {
        ScrollArea::vertical().show(ui, |ui| {
            Self::section_card(ui, "开始一次扫描", "先选择目标，再决定是否展开高级项。", |ui| {
                ui.label(RichText::new("扫描目标").strong());
                ui.add(
                    TextEdit::singleline(&mut self.target_path)
                        .hint_text("例如：.\\fixtures\\v2\\report-demo、某个 SKILL.md 或 https://github.com/..."),
                );
                ui.horizontal(|ui| {
                    if ui.button("选择 SKILL.md").clicked() {
                        if let Some(path) =
                            FileDialog::new().add_filter("Markdown", &["md"]).pick_file()
                        {
                            self.target_path = path.display().to_string();
                        }
                    }
                    if ui.button("选择目录").clicked() {
                        if let Some(path) = FileDialog::new().pick_folder() {
                            self.target_path = path.display().to_string();
                        }
                    }
                });
                ui.small("支持本地 SKILL.md、skill 目录、skills 根目录，也支持 HTTPS skill 链接。远程内容只会下载后静态扫描，不会执行。");
            });

            Self::section_card(ui, "扫描流程", "主路径收敛为：选目标 -> 开始扫描 -> 看总览。", |ui| {
                ui.horizontal(|ui| {
                    self.step_chip(ui, "1", "选择目标");
                    self.step_chip(ui, "2", "开始扫描");
                    self.step_chip(ui, "3", "查看总览");
                    self.step_chip(ui, "4", "导出报告");
                });

                ui.separator();
                if ui
                    .button(if self.show_advanced_options {
                        "收起高级选项"
                    } else {
                        "展开高级选项"
                    })
                    .clicked()
                {
                    self.show_advanced_options = !self.show_advanced_options;
                }

                if self.show_advanced_options {
                    ui.add_space(4.0);
                    ui.label(RichText::new("运行时 manifest（可选）").strong());
                    ui.add(
                        TextEdit::singleline(&mut self.runtime_manifest_path)
                            .hint_text("JSON 或 YAML，用于 guarded validation"),
                    );
                    if ui.button("选择运行时 manifest").clicked() {
                        if let Some(path) = FileDialog::new()
                            .add_filter("Manifest", &["json", "yaml", "yml"])
                            .pick_file()
                        {
                            self.runtime_manifest_path = path.display().to_string();
                        }
                    }

                    ui.label(RichText::new("Suppression 文件（可选）").strong());
                    ui.add(
                        TextEdit::singleline(&mut self.suppression_path)
                            .hint_text("JSON suppression file"),
                    );
                    if ui.button("选择 suppression 文件").clicked() {
                        if let Some(path) =
                            FileDialog::new().add_filter("JSON", &["json"]).pick_file()
                        {
                            self.suppression_path = path.display().to_string();
                        }
                    }

                    ui.label(RichText::new("策略配置 .openclaw-guard.yml（可选）").strong());
                    ui.add(
                        TextEdit::singleline(&mut self.policy_config_path)
                            .hint_text("用于 CI 阻断、远程输入限制和规则策略"),
                    );
                    if ui.button("选择策略配置").clicked() {
                        if let Some(path) = FileDialog::new()
                            .add_filter("YAML", &["yaml", "yml"])
                            .pick_file()
                        {
                            self.policy_config_path = path.display().to_string();
                        }
                    }

                    ui.label(RichText::new("运行时验证模式").strong());
                    ui.horizontal(|ui| {
                        ui.selectable_value(
                            &mut self.validation_mode,
                            ValidationExecutionMode::Planned,
                            "规划模式（Planned）",
                        );
                        ui.selectable_value(
                            &mut self.validation_mode,
                            ValidationExecutionMode::Guarded,
                            "保护模式（Guarded）",
                        );
                    });
                    ui.small("默认建议先用规划模式；只有在需要利用本地安全事实收窄结论时，再启用 Guarded。");

                    ui.checkbox(
                        &mut self.agent_ecosystem,
                        "启用通用 Agent / MCP / prompt package 生态解析",
                    );
                    ui.small("只解析当前选择范围内的文本和配置；不会启动 MCP server、安装依赖或连接工具。");

                    ui.label(RichText::new("默认导出路径（可选）").strong());
                    ui.add(
                        TextEdit::singleline(&mut self.report_save_path)
                            .hint_text("留空则导出时手动选择位置"),
                    );
                    if ui.button("选择默认导出位置").clicked() {
                        if let Some(path) = FileDialog::new()
            .set_file_name("agent-skill-guard-report.json")
                            .save_file()
                        {
                            self.report_save_path = path.display().to_string();
                        }
                    }
                }
            });

            Self::section_card(ui, "执行扫描", "完成后默认先看总览，再钻入详细页。", |ui| {
                let button = egui::Button::new(
                    RichText::new(if self.scan_running { "扫描中…" } else { "开始扫描" })
                        .strong()
                        .color(Color32::WHITE)
                        .size(18.0),
                )
                .fill(Color32::from_rgb(15, 109, 99))
                .min_size(egui::vec2(ui.available_width(), 44.0));

                if ui.add_enabled(!self.scan_running, button).clicked() {
                    self.start_scan();
                }

                if self.scan_running {
                    ui.horizontal(|ui| {
                        ui.add(egui::Spinner::new());
                        ui.label(self.scan_progress_text());
                    });
                } else {
                    ui.small("你可以直接扫描；只有在需要 runtime manifest 或 suppression 时，才展开高级选项。");
                }

                if let Some(message) = &self.status_message {
                    self.info_banner(
                        ui,
                        message,
                        Color32::from_rgb(232, 246, 241),
                        Color32::from_rgb(19, 106, 94),
                    );
                }
                if let Some(message) = &self.error_message {
                    self.info_banner(
                        ui,
                        message,
                        Color32::from_rgb(253, 238, 238),
                        Color32::from_rgb(178, 60, 60),
                    );
                }
            });
        });
    }

    fn render_main_panel(&mut self, ui: &mut Ui) {
        if self.scan_running {
            self.hero_banner(
                ui,
                "扫描进行中",
                &self.scan_progress_text(),
                Color32::from_rgb(237, 247, 246),
                Color32::from_rgb(15, 109, 99),
            );
            ui.add_space(10.0);
        }

        if self.completed_scan.is_some() {
            self.render_tab_bar(ui);
            ui.add_space(10.0);
        }

        match self.completed_scan.clone() {
            Some(completed) => {
                let active_tab = self.active_tab;
                ScrollArea::vertical().show(ui, |ui| match active_tab {
                    UiTab::Summary => self.render_summary_tab(ui, &completed),
                    UiTab::Findings => self.render_findings_tab(ui, &completed.report),
                    UiTab::Context => self.render_context_tab(ui, &completed.report),
                    UiTab::Paths => self.render_paths_tab(ui, &completed.report),
                    UiTab::Validation => self.render_validation_tab(ui, &completed.report),
                    UiTab::Audit => self.render_audit_tab(ui, &completed.report),
                    UiTab::RawJson => self.render_raw_json_tab(ui, &completed),
                });
            }
            None if self.scan_running => {
                self.empty_state(
                    ui,
                    "正在准备结果总览",
                    "扫描完成后，这里会优先显示风险总览、关键建议和运行时结论。",
                );
            }
            None => {
                self.empty_state(
                    ui,
                    "还没有扫描结果",
                    "先在左侧选择一个 SKILL.md 或目录，然后点击“开始扫描”。完成后默认会先看到总览，再进入发现项、攻击路径、上下文和审计细节。",
                );
            }
        }
    }

    fn render_tab_bar(&mut self, ui: &mut Ui) {
        Frame::group(ui.style())
            .fill(Color32::from_rgb(255, 255, 255))
            .stroke(Stroke::new(1.0, Color32::from_rgb(216, 226, 235)))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    for tab in UiTab::ALL {
                        let active = self.active_tab == tab;
                        let button = egui::Button::new(RichText::new(tab.label()).strong().color(
                            if active {
                                Color32::WHITE
                            } else {
                                Color32::from_rgb(54, 61, 70)
                            },
                        ))
                        .fill(if active {
                            Color32::from_rgb(18, 111, 122)
                        } else {
                            Color32::from_rgb(239, 245, 249)
                        });

                        if ui.add(button).clicked() {
                            self.active_tab = tab;
                        }
                    }
                });
            });
    }

    fn render_summary_tab(&self, ui: &mut Ui, completed: &CompletedScan) {
        let report = &completed.report;

        self.hero_banner(
            ui,
            &format!(
                "{}：{}",
                verdict_label(report.verdict),
                safe_target_label_zh(&report.target.path)
            ),
            &display_text_zh(&report.openclaw_specific_risk_summary),
            verdict_bg(report.verdict),
            verdict_fg(report.verdict),
        );
        ui.add_space(12.0);

        ui.horizontal_wrapped(|ui| {
            self.stat_card(
                ui,
                "最终结论",
                verdict_label(report.verdict),
                verdict_fg(report.verdict),
            );
            self.stat_card(
                ui,
                "风险分数",
                &report.score.to_string(),
                Color32::from_rgb(19, 106, 94),
            );
            self.stat_card(
                ui,
                "发现项",
                &report.findings.len().to_string(),
                Color32::from_rgb(172, 86, 13),
            );
            self.stat_card(
                ui,
                "攻击路径",
                &report.attack_paths.len().to_string(),
                Color32::from_rgb(144, 67, 38),
            );
            self.stat_card(
                ui,
                "依赖风险",
                &report.dependency_audit_summary.findings_count.to_string(),
                Color32::from_rgb(86, 97, 108),
            );
            self.stat_card(
                ui,
                "外部引用",
                &report.external_references.len().to_string(),
                Color32::from_rgb(61, 89, 146),
            );
            self.stat_card(
                ui,
                "组合风险",
                &report.toxic_flow_summary.flows_count.to_string(),
                Color32::from_rgb(171, 52, 52),
            );
        });

        ui.add_space(8.0);
        ui.columns(2, |columns| {
            Self::section_card_in(
                &mut columns[0],
                "关键风险",
                "优先处理最直接影响结论的问题。",
                |ui| {
                    if report.top_risks.is_empty() {
                        ui.label("本次扫描没有生成需要优先提醒的关键风险。");
                    } else {
                        for risk in report.top_risks.iter().take(6) {
                            ui.label(format!("• {}", display_text_zh(risk)));
                        }
                    }
                },
            );

            Self::section_card_in(
                &mut columns[1],
                "环境与运行时结论",
                "先看当前环境会不会放大或收窄风险。",
                |ui| {
                    self.key_value(ui, "运行时 manifest", &report.runtime_manifest_summary);
                    self.key_value(ui, "运行时验证", &report.guarded_validation.summary);
                    self.key_value(ui, "影响评估", &report.consequence_summary.summary);
                    self.key_value(ui, "宿主 / 沙箱", &report.host_vs_sandbox_split.summary);
                },
            );
        });

        ui.columns(2, |columns| {
            Self::section_card_in(
                &mut columns[0],
                "能力摘要",
                "集中查看 corpus、依赖、来源、OpenClaw 配置和组合风险。",
                |ui| {
                    self.summary_line(
                        ui,
                        "威胁模式库",
                        report
                            .context_analysis
                            .threat_corpus_summary
                            .as_deref()
                            .unwrap_or("本次没有触发威胁模式库摘要。"),
                    );
                    self.summary_line(
                        ui,
                        "敏感数据模式库",
                        report
                            .context_analysis
                            .sensitive_data_summary
                            .as_deref()
                            .unwrap_or("本次没有触发敏感数据模式库摘要。"),
                    );
                    self.summary_line(ui, "依赖审计", &report.dependency_audit_summary.summary);
                    self.summary_line(
                        ui,
                        "API / URL 分类",
                        &report.api_classification_summary.summary,
                    );
                    self.summary_line(ui, "来源信誉", &report.source_reputation_summary.summary);
                    self.summary_line(
                        ui,
                        "OpenClaw 配置 / 控制面",
                        &report.openclaw_config_audit_summary.summary,
                    );
                    self.summary_line(ui, "能力 / 权限视图", &report.capability_manifest.summary);
                    self.summary_line(
                        ui,
                        "配套文档审计",
                        &report.companion_doc_audit_summary.summary,
                    );
                    self.summary_line(
                        ui,
                        "来源身份一致性",
                        &report.source_identity_summary.summary,
                    );
                    self.summary_line(
                        ui,
                        "隐藏指令",
                        &report.hidden_instruction_summary.summary_zh,
                    );
                    self.summary_line(ui, "声明 vs 实际", &report.claims_review_summary.summary_zh);
                    self.summary_line(ui, "完整性快照", &report.integrity_snapshot.summary_zh);
                    self.summary_line(
                        ui,
                        "本地配置引用",
                        &report.estate_inventory_summary.summary_zh,
                    );
                    self.summary_line(ui, "Agent 生态", &report.agent_package_index.summary_zh);
                    self.summary_line(
                        ui,
                        "MCP / Tool Schema",
                        &report.mcp_tool_schema_summary.summary_zh,
                    );
                    self.summary_line(ui, "AI BOM", &report.ai_bom.summary_zh);
                    self.summary_line(ui, "组合风险", &report.toxic_flow_summary.summary_zh);
                    if let Some(origin) = &report.input_origin {
                        self.summary_line(
                            ui,
                            "输入来源",
                            &format!(
                                "{} / {}",
                                pretty_debug(&origin.resolved_kind),
                                origin.original_input
                            ),
                        );
                    }
                    self.summary_line(ui, "策略结果", &report.policy_evaluation.reason_zh);
                },
            );

            Self::section_card_in(
                &mut columns[1],
                "建议动作",
                "把高频建议放在首页，不用先钻技术页。",
                |ui| {
                    self.string_list(ui, "立即处理", &report.recommendations.immediate);
                    self.string_list(ui, "短期收敛", &report.recommendations.short_term);
                    self.string_list(ui, "加固建议", &report.recommendations.hardening);
                    self.string_list(
                        ui,
                        "需要进一步验证时",
                        &report.recommendations.dynamic_validation,
                    );
                },
            );
        });

        Self::section_card(
            ui,
            "执行摘要",
            "便于复制到内部审查或沟通语境。",
            |ui| {
                ui.code(&completed.summary_text);
            },
        );
    }

    fn render_findings_tab(&mut self, ui: &mut Ui, report: &ScanReport) {
        ui.heading("发现项");
        ui.label("支持按严重级别、分类、置信度快速筛选，并联动到攻击路径和审计说明。");
        ui.add_space(8.0);

        self.filter_toolbar_findings(ui, report);

        let filtered = report
            .findings
            .iter()
            .filter(|finding| self.finding_matches_filters(finding))
            .collect::<Vec<_>>();

        if report.findings.is_empty() {
            self.empty_panel(ui, "本次扫描没有生成发现项。");
            return;
        }
        if filtered.is_empty() {
            self.empty_panel(ui, "当前筛选条件下没有匹配的发现项。请放宽筛选条件后再看。");
            return;
        }

        for finding in filtered {
            self.finding_card(ui, report, finding);
            ui.add_space(10.0);
        }
    }

    fn render_context_tab(&mut self, ui: &mut Ui, report: &ScanReport) {
        ui.heading("上下文");
        ui.label("把结构化上下文、v2 摘要、外部引用与依赖审计整合到同一页阅读。");
        ui.add_space(8.0);

        let context = &report.context_analysis;
        ui.columns(2, |columns| {
            Self::section_card_in(
                &mut columns[0],
                "基础上下文摘要",
                "先确认这次扫描到底看到了什么。",
                |ui| {
                    self.summary_line(ui, "解析", &context.parsing_summary);
                    self.optional_summary(ui, "元数据", context.metadata_summary.as_deref());
                    self.optional_summary(ui, "安装链", context.install_chain_summary.as_deref());
                    self.optional_summary(ui, "调用策略", context.invocation_summary.as_deref());
                    self.optional_summary(
                        ui,
                        "Prompt / 指令",
                        context.prompt_injection_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "Threat corpus",
                        context.threat_corpus_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "Sensitive corpus",
                        context.sensitive_data_summary.as_deref(),
                    );
                },
            );

            Self::section_card_in(
                &mut columns[1],
                "v2 摘要与来源判断",
                "dependency / API / source 新增能力集中显示。",
                |ui| {
                    self.optional_summary(
                        ui,
                        "依赖审计",
                        context.dependency_audit_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "API 分类",
                        context.api_classification_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "来源信誉",
                        context.source_reputation_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "OpenClaw 配置 / 控制面",
                        context.openclaw_config_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "能力 / 权限视图",
                        context.capability_manifest_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "配套文档",
                        context.companion_doc_audit_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "来源身份",
                        context.source_identity_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "隐藏指令",
                        context.hidden_instruction_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "声明 vs 实际",
                        context.claims_review_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "完整性快照",
                        context.integrity_snapshot_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "本地配置引用",
                        context.estate_inventory_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "Agent 生态",
                        context.agent_package_summary.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "MCP / Tool Schema",
                        context.mcp_tool_schema_summary.as_deref(),
                    );
                    self.optional_summary(ui, "AI BOM", context.ai_bom_summary.as_deref());
                    self.string_list(
                        ui,
                        "配置风险绑定",
                        &report.openclaw_config_audit_summary.risky_bindings,
                    );
                    self.string_list(
                        ui,
                        "能力风险组合",
                        &report.capability_manifest.risky_combinations,
                    );
                    self.string_list(
                        ui,
                        "配套文档风险信号",
                        &report.companion_doc_audit_summary.poisoning_signals,
                    );
                    let identity_signals = report
                        .source_identity_summary
                        .signals
                        .iter()
                        .map(|signal| {
                            let evidence = if signal.evidence.is_empty() {
                                "没有直接证据摘录".to_string()
                            } else {
                                signal.evidence.join("; ")
                            };
                            format!("{}: {} -> {}", signal.signal_kind, signal.summary, evidence)
                        })
                        .collect::<Vec<_>>();
                    self.string_list(ui, "来源身份不一致信号", &identity_signals);
                    let hidden_signals = report
                        .hidden_instruction_summary
                        .signals
                        .iter()
                        .map(|signal| {
                            format!(
                                "{}: {}:{} -> {}",
                                signal.signal_kind,
                                signal.path,
                                signal.line.unwrap_or(1),
                                signal.rationale_zh
                            )
                        })
                        .collect::<Vec<_>>();
                    self.string_list(ui, "隐藏指令信号", &hidden_signals);
                    let claim_mismatches = report
                        .claims_review_summary
                        .mismatches
                        .iter()
                        .map(|item| {
                            format!(
                                "声明：{}；证据：{}；复核：{}",
                                item.claim, item.observed_signal, item.review_question
                            )
                        })
                        .collect::<Vec<_>>();
                    self.string_list(ui, "声明与实际错位", &claim_mismatches);
                    let digest_lines = report
                        .integrity_snapshot
                        .skill_file_digests
                        .iter()
                        .map(|digest| {
                            format!(
                                "{} | SHA-256 {} | {} bytes",
                                digest.path, digest.sha256, digest.bytes
                            )
                        })
                        .collect::<Vec<_>>();
                    self.string_list(ui, "SKILL.md 完整性摘要", &digest_lines);
                    let estate_refs = report
                        .estate_inventory_summary
                        .references
                        .iter()
                        .map(|reference| {
                            format!(
                                "{}: {} ({})",
                                reference.reference_kind, reference.summary_zh, reference.path
                            )
                        })
                        .collect::<Vec<_>>();
                    self.string_list(ui, "本地配置引用", &estate_refs);
                    self.string_list(ui, "AI BOM package", &report.ai_bom.packages);
                    self.string_list(ui, "AI BOM 工具面", &report.ai_bom.tool_surfaces);
                    self.string_list(ui, "AI BOM MCP server", &report.ai_bom.mcp_servers);
                    self.string_list(ui, "AI BOM 命令", &report.ai_bom.commands);
                    self.string_list(ui, "AI BOM 复核问题", &report.ai_bom.review_questions);
                    self.optional_summary(
                        ui,
                        "宿主 / 沙箱判断",
                        context.host_vs_sandbox_assessment.as_deref(),
                    );
                    self.optional_summary(
                        ui,
                        "优先级 / 覆盖关系",
                        context.precedence_summary.as_deref(),
                    );
                },
            );
        });

        Self::section_card(
            ui,
            "依赖审计细读",
            "重点阅读依赖发现项的来源、风险线索和解释依据。",
            |ui| {
                let dependency_findings = report
                    .findings
                    .iter()
                    .filter(|finding| finding.category.starts_with("dependency."))
                    .collect::<Vec<_>>();

                if dependency_findings.is_empty() {
                    ui.label("本次没有依赖审计发现项。");
                    return;
                }

                for finding in dependency_findings {
                    egui::CollapsingHeader::new(format!(
                        "{} | {}",
                        display_text_zh(&finding.title),
                        severity_text(finding.severity)
                    ))
                    .default_open(self.selected_subject_id.as_deref() == Some(finding.id.as_str()))
                    .show(ui, |ui| {
                        ui.label(display_text_zh(&finding.explanation));
                        self.render_expandable_text(
                            ui,
                            "分析说明",
                            &finding.analyst_notes.join("\n"),
                            260,
                        );
                        let notes = subject_provenance_notes(report, &finding.id);
                        if !notes.is_empty() {
                            self.render_expandable_text(ui, "来源说明", &notes.join("\n"), 260);
                        }
                        let score_notes = subject_score_rationales(report, &finding.id);
                        if !score_notes.is_empty() {
                            self.render_expandable_text(
                                ui,
                                "评分理由",
                                &score_notes.join("\n"),
                                260,
                            );
                        }
                        if ui.button("查看审计 / 来源说明").clicked() {
                            self.selected_subject_id = Some(finding.id.clone());
                            self.active_tab = UiTab::Audit;
                        }
                    });
                }
            },
        );

        Self::section_card(
            ui,
            "外部引用与来源信誉",
            "支持快速过滤并展开细节。",
            |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label("筛选：");
                    for filter in [
                        ReferenceFilter::All,
                        ReferenceFilter::SuspiciousOnly,
                        ReferenceFilter::ReviewNeededOnly,
                    ] {
                        ui.selectable_value(&mut self.reference_filter, filter, filter.label());
                    }
                });

                let references = report
                    .external_references
                    .iter()
                    .filter(|reference| self.reference_filter.matches(reference))
                    .collect::<Vec<_>>();

                if report.external_references.is_empty() {
                    ui.label("本次没有抽取到外部引用。");
                    return;
                }
                if references.is_empty() {
                    ui.label("当前筛选条件下没有匹配的外部引用。");
                    return;
                }

                for reference in references {
                    egui::CollapsingHeader::new(format!(
                        "{} | {} | {}",
                        reference.host,
                        pretty_debug(reference.category),
                        pretty_debug(reference.reputation)
                    ))
                    .default_open(false)
                    .show(ui, |ui| {
                        ui.label(RichText::new(&reference.url).strong());
                        ui.label(format!(
                            "服务类型：{}",
                            pretty_debug(reference.service_kind)
                        ));
                        if !reference.risk_signals.is_empty() {
                            ui.label(format!(
                                "风险信号：{}",
                                reference
                                    .risk_signals
                                    .iter()
                                    .map(|item| pretty_debug(*item))
                                    .collect::<Vec<_>>()
                                    .join(" / ")
                            ));
                        }
                        self.render_expandable_text(ui, "判断理由", &reference.rationale, 260);
                        self.render_expandable_text(
                            ui,
                            "证据摘录",
                            &reference.evidence_excerpt,
                            220,
                        );
                        if !reference.locations.is_empty() {
                            let locations = reference
                                .locations
                                .iter()
                                .map(|item| {
                                    format!(
                                        "{}:{}",
                                        safe_target_label_zh(&item.path),
                                        item.line.unwrap_or(1)
                                    )
                                })
                                .collect::<Vec<_>>()
                                .join("\n");
                            self.render_expandable_text(ui, "出现位置", &locations, 200);
                        }

                        if reference.provenance.taxonomy_entry_id.is_some()
                            || !reference.provenance.matched_seed_ids.is_empty()
                            || !reference.provenance.asset_sources.is_empty()
                        {
                            let mut provenance_bits = Vec::new();
                            if let Some(id) = &reference.provenance.taxonomy_entry_id {
                                provenance_bits.push(format!("taxonomy entry: {id}"));
                            }
                            if !reference.provenance.matched_seed_ids.is_empty() {
                                provenance_bits.push(format!(
                                    "matched seeds: {}",
                                    reference.provenance.matched_seed_ids.join(", ")
                                ));
                            }
                            if !reference.provenance.asset_sources.is_empty() {
                                provenance_bits.push(format!(
                                    "asset sources: {}",
                                    reference.provenance.asset_sources.join(", ")
                                ));
                            }
                            self.render_expandable_text(
                                ui,
                                "分类来源",
                                &provenance_bits.join("\n"),
                                240,
                            );
                        }

                        if ui.button("查看审计 / 来源说明").clicked() {
                            self.selected_subject_id = Some(reference.reference_id.clone());
                            self.active_tab = UiTab::Audit;
                        }
                    });
                }
            },
        );
    }

    fn render_paths_tab(&mut self, ui: &mut Ui, report: &ScanReport) {
        ui.heading("攻击路径");
        ui.label("支持按严重级别、路径类型和验证状态筛选，并联动回相关 finding。");
        ui.add_space(8.0);

        self.filter_toolbar_paths(ui, report);

        let filtered = report
            .attack_paths
            .iter()
            .filter(|path| self.path_matches_filters(report, path))
            .collect::<Vec<_>>();

        if report.attack_paths.is_empty() {
            self.empty_panel(
                ui,
                "本次没有组装出满足阈值的攻击路径。孤立 finding 仍可能需要单独审查。",
            );
            return;
        }
        if filtered.is_empty() {
            self.empty_panel(ui, "当前筛选条件下没有匹配的攻击路径。请调整筛选后再看。");
            return;
        }

        for path in filtered {
            self.attack_path_card(ui, report, path);
            ui.add_space(10.0);
        }
    }

    fn render_validation_tab(&self, ui: &mut Ui, report: &ScanReport) {
        ui.heading("运行环境判断");
        ui.label("这里说明当前环境会放大风险、限制风险，还是仍然需要人工确认。");
        ui.add_space(8.0);

        ui.columns(2, |columns| {
            Self::section_card_in(
                &mut columns[0],
                "验证与环境摘要",
                "先判断是环境阻断了风险，还是环境放大了风险。",
                |ui| {
                    self.key_value(ui, "运行环境说明", &report.runtime_manifest_summary);
                    self.key_value(ui, "验证计划", &report.validation_plan.summary);
                    self.key_value(ui, "安全验证结果", &report.guarded_validation.summary);
                    self.key_value(ui, "可能影响范围", &report.consequence_summary.summary);
                    self.key_value(
                        ui,
                        "宿主机 / 沙箱边界",
                        &report.host_vs_sandbox_split.summary,
                    );
                },
            );

            Self::section_card_in(
                &mut columns[1],
                "环境影响项",
                "查看哪些环境事实会阻断、放大或改变风险判断。",
                |ui| {
                    self.string_list_from_validated(
                        ui,
                        "路径验证状态",
                        &report
                            .path_validation_status
                            .iter()
                            .map(|item| {
                                format!(
                                    "{} | {} / {} | {}",
                                    item.path_id,
                                    pretty_debug(item.status),
                                    pretty_debug(item.guard_status),
                                    item.note
                                )
                            })
                            .collect::<Vec<_>>(),
                    );
                    self.string_list_from_validated(
                        ui,
                        "环境阻断项",
                        &report
                            .environment_blockers
                            .iter()
                            .map(|item| {
                                format!("{} | {} | {}", item.path_id, item.blocker, item.rationale)
                            })
                            .collect::<Vec<_>>(),
                    );
                    self.string_list_from_validated(
                        ui,
                        "环境放大项",
                        &report
                            .environment_amplifiers
                            .iter()
                            .map(|item| {
                                format!(
                                    "{} | {} | {}",
                                    item.path_id, item.amplifier, item.rationale
                                )
                            })
                            .collect::<Vec<_>>(),
                    );
                },
            );
        });
    }

    fn render_audit_tab(&mut self, ui: &mut Ui, report: &ScanReport) {
        ui.heading("证据与依据");
        ui.label("这里集中查看评分依据、证据来源、例外规则和原始详情。");
        ui.add_space(8.0);

        if let Some(subject_id) = self.selected_subject_id.clone() {
            Self::section_card(
                ui,
                "当前焦点",
                "你是从某个发现项、路径或外部引用跳转过来的。",
                |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(format!("当前聚焦：{subject_id}"));
                        if ui.button("清除焦点").clicked() {
                            self.selected_subject_id = None;
                        }
                    });
                },
            );
        }

        ui.columns(2, |columns| {
            Self::section_card_in(
                &mut columns[0],
                "例外规则与审计摘要",
                "确保被忽略或例外处理的内容仍然可见。",
                |ui| {
                    self.key_value(ui, "审计摘要", &report.audit_summary.summary);
                    self.key_value(
                        ui,
                        "高风险例外数量",
                        &report.audit_summary.high_risk_suppressions.to_string(),
                    );

                    let suppression_items = report
                        .suppression_matches
                        .iter()
                        .filter(|item| self.subject_filter_matches(&item.target_id))
                        .map(|item| {
                            format!(
                                "{} | {} | {} | {}",
                                item.scope,
                                item.target_id,
                                item.reason,
                                pretty_debug(item.lifecycle)
                            )
                        })
                        .collect::<Vec<_>>();
                    self.string_list_from_validated(ui, "命中的例外规则", &suppression_items);

                    let expired_items = report
                        .audit_summary
                        .expired_suppressions
                        .iter()
                        .filter(|item| self.subject_filter_matches(&item.target_id))
                        .map(|item| {
                            format!("{} | {} | {}", item.target_id, item.expires_on, item.note)
                        })
                        .collect::<Vec<_>>();
                    self.string_list_from_validated(ui, "已过期例外规则", &expired_items);
                },
            );

            Self::section_card_in(
                &mut columns[1],
                "评分依据",
                "把扣分原因、可信度变化和误报修正放到一起。",
                |ui| {
                    let score_items = report
                        .scoring_summary
                        .score_rationale
                        .iter()
                        .filter(|item| self.subject_filter_matches(&item.source))
                        .map(|item| {
                            format!("{} | {} | {}", item.source, item.delta, item.explanation)
                        })
                        .collect::<Vec<_>>();
                    self.string_list_from_validated(ui, "评分理由", &score_items);

                    let confidence_items = report
                        .confidence_factors
                        .iter()
                        .filter(|item| self.subject_filter_matches(&item.subject_id))
                        .map(|item| {
                            format!("{} | {} | {}", item.subject_id, item.delta, item.rationale)
                        })
                        .collect::<Vec<_>>();
                    self.string_list_from_validated(ui, "可信度变化", &confidence_items);

                    let mitigation_items = report
                        .false_positive_mitigations
                        .iter()
                        .filter(|item| self.subject_filter_matches(&item.subject_id))
                        .map(|item| {
                            format!("{} | {} | {}", item.subject_id, item.delta, item.rationale)
                        })
                        .collect::<Vec<_>>();
                    self.string_list_from_validated(ui, "误报修正", &mitigation_items);
                },
            );
        });

        Self::section_card(
            ui,
            "证据来源与审计记录",
            "适合审查“为什么系统相信这条结论”。",
            |ui| {
                let provenance_items = report
                    .provenance_notes
                    .iter()
                    .filter(|item| self.subject_filter_matches(&item.subject_id))
                    .map(|item| {
                        format!(
                            "{} | {} | {}",
                            item.subject_id, item.source_layer, item.note
                        )
                    })
                    .collect::<Vec<_>>();
                self.string_list_from_validated(ui, "来源说明", &provenance_items);

                let audit_items = report
                    .audit_summary
                    .records
                    .iter()
                    .map(|item| format!("{} | {}", pretty_debug(item.level), item.message))
                    .collect::<Vec<_>>();
                self.string_list_from_validated(ui, "审计记录", &audit_items);

                let validation_notes = report
                    .audit_summary
                    .validation_aware_notes
                    .iter()
                    .filter(|item| self.subject_filter_matches(&item.subject_id))
                    .map(|item| format!("{} | {}", item.subject_id, item.note))
                    .collect::<Vec<_>>();
                self.string_list_from_validated(ui, "验证相关审计说明", &validation_notes);

                if self.selected_subject_id.is_some()
                    && provenance_items.is_empty()
                    && validation_notes.is_empty()
                    && audit_items.is_empty()
                {
                    ui.label("当前焦点下没有额外的证据来源或审计记录。");
                }
            },
        );
    }

    fn render_raw_json_tab(&self, ui: &mut Ui, completed: &CompletedScan) {
        ui.heading("原始 JSON");
        ui.label("保留给高级阅读和调试使用，但不再抢占主界面地位。");
        ui.add_space(8.0);

        let mut raw_json = completed.raw_json.clone();
        ui.add(
            TextEdit::multiline(&mut raw_json)
                .font(egui::TextStyle::Monospace)
                .desired_rows(36)
                .desired_width(f32::INFINITY)
                .interactive(false),
        );
    }

    fn finding_card(&mut self, ui: &mut Ui, report: &ScanReport, finding: &Finding) {
        let accent = severity_color(finding.severity);
        let selected = self.selected_finding_id.as_deref() == Some(finding.id.as_str());
        let related_paths = related_path_ids_for_finding(report, finding);

        let response = Frame::group(ui.style())
            .fill(if selected {
                Color32::from_rgb(244, 250, 248)
            } else {
                Color32::from_rgb(255, 255, 255)
            })
            .stroke(Stroke::new(1.0, accent))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let title = finding.title_zh.as_deref().unwrap_or(&finding.title);
                    let response = ui.add(
                        egui::Label::new(
                            RichText::new(display_text_zh(title))
                                .strong()
                                .size(19.0)
                                .color(Color32::from_rgb(36, 41, 47)),
                        )
                        .sense(egui::Sense::click()),
                    );
                    if response.clicked() {
                        self.selected_finding_id = Some(finding.id.clone());
                    }
                    self.small_badge(
                        ui,
                        &format!("严重级别：{}", severity_text(finding.severity)),
                    );
                });

                if let Some(location) = &finding.location {
                    ui.label(format!(
                        "位置：{}:{}",
                        safe_target_label_zh(&location.path),
                        location.line.unwrap_or(1)
                    ));
                }

                let explanation = finding
                    .explanation_zh
                    .as_deref()
                    .unwrap_or(&finding.explanation);
                self.render_expandable_text(ui, "风险解释", explanation, 280);
                if !finding.evidence.is_empty() {
                    let evidence = finding
                        .evidence
                        .iter()
                        .take(4)
                        .map(|item| item.excerpt.clone())
                        .collect::<Vec<_>>()
                        .join("\n");
                    self.render_expandable_text(ui, "关键证据", &evidence, 260);
                }
                if !finding.analyst_notes.is_empty() {
                    self.render_expandable_text(
                        ui,
                        "证据详情",
                        &finding.analyst_notes.join("\n"),
                        260,
                    );
                }
                let mut advanced = Vec::new();
                advanced.push(format!("内部分类：{}", finding.category));
                advanced.push(format!("置信度：{}", confidence_text(finding.confidence)));
                if let Some(code) = &finding.issue_code {
                    advanced.push(format!("问题编号：{code}"));
                }
                if !finding.why_openclaw_specific.is_empty() {
                    advanced.push(format!(
                        "OpenClaw 相关性：{}",
                        display_text_zh(&finding.why_openclaw_specific)
                    ));
                }
                self.render_expandable_text(ui, "高级详情", &advanced.join("\n"), 180);
                if !finding.prerequisite_context.is_empty() {
                    self.render_expandable_text(
                        ui,
                        "成立前提",
                        &finding.prerequisite_context.join("\n"),
                        220,
                    );
                }
                if !finding.remediation.is_empty() {
                    let remediation = finding
                        .recommendation_zh
                        .as_deref()
                        .unwrap_or(&finding.remediation);
                    self.render_expandable_text(ui, "修复建议", remediation, 220);
                }

                ui.horizontal_wrapped(|ui| {
                    if !related_paths.is_empty()
                        && ui
                            .button(format!("查看相关攻击路径 ({})", related_paths.len()))
                            .clicked()
                    {
                        self.selected_path_id = Some(related_paths[0].clone());
                        self.active_tab = UiTab::Paths;
                    }
                    if ui.button("查看证据与依据").clicked() {
                        self.selected_subject_id = Some(finding.id.clone());
                        self.active_tab = UiTab::Audit;
                    }
                });
            });

        if selected {
            response.response.scroll_to_me(Some(egui::Align::Center));
        }
    }

    fn attack_path_card(&mut self, ui: &mut Ui, report: &ScanReport, path: &AttackPath) {
        let selected = self.selected_path_id.as_deref() == Some(path.path_id.as_str());
        let related_findings = related_findings_for_path(report, path);
        let validation_status = path_validation_status_label(report, &path.path_id);

        let response = Frame::group(ui.style())
            .fill(if selected {
                Color32::from_rgb(252, 246, 241)
            } else {
                Color32::from_rgb(255, 255, 255)
            })
            .stroke(Stroke::new(1.0, severity_color(path.severity)))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    let response = ui.add(
                        egui::Label::new(
                            RichText::new(display_text_zh(&path.title))
                                .strong()
                                .size(19.0),
                        )
                        .sense(egui::Sense::click()),
                    );
                    if response.clicked() {
                        self.selected_path_id = Some(path.path_id.clone());
                    }
                    self.small_badge(ui, &format!("严重级别：{}", severity_text(path.severity)));
                    self.small_badge(ui, &format!("置信度：{}", confidence_text(path.confidence)));
                    self.small_badge(ui, &format!("路径类型：{}", path.path_type));
                    self.small_badge(ui, &format!("验证状态：{validation_status}"));
                });

                self.render_expandable_text(ui, "路径解释", &path.explanation, 280);
                if !path.why_openclaw_specific.is_empty() {
                    self.render_expandable_text(
                        ui,
                        "为什么这是 OpenClaw 特有路径",
                        &path.why_openclaw_specific,
                        240,
                    );
                }
                if !path.prerequisites.is_empty() {
                    self.render_expandable_text(
                        ui,
                        "前置条件",
                        &path.prerequisites.join("\n"),
                        220,
                    );
                }
                if !path.impact.is_empty() {
                    self.render_expandable_text(ui, "潜在影响", &path.impact, 220);
                }
                if !path.steps.is_empty() {
                    let step_text = path
                        .steps
                        .iter()
                        .enumerate()
                        .map(|(index, step)| {
                            format!(
                                "{}. {} | {}",
                                index + 1,
                                pretty_debug(step.step_type),
                                step.summary
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("\n");
                    self.render_expandable_text(ui, "路径步骤", &step_text, 260);
                }

                ui.horizontal_wrapped(|ui| {
                    if !related_findings.is_empty()
                        && ui
                            .button(format!("查看相关发现项 ({})", related_findings.len()))
                            .clicked()
                    {
                        self.selected_finding_id = Some(related_findings[0].id.clone());
                        self.active_tab = UiTab::Findings;
                    }
                    if ui.button("查看来源 / 评分说明").clicked() {
                        self.selected_subject_id = Some(path.path_id.clone());
                        self.active_tab = UiTab::Audit;
                    }
                });
            });

        if selected {
            response.response.scroll_to_me(Some(egui::Align::Center));
        }
    }

    fn filter_toolbar_findings(&mut self, ui: &mut Ui, report: &ScanReport) {
        let categories = unique_categories(report);
        Frame::group(ui.style())
            .fill(Color32::from_rgb(255, 252, 248))
            .stroke(Stroke::new(1.0, Color32::from_rgb(226, 220, 212)))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("筛选").strong());
                    ComboBox::from_id_salt("finding_severity_filter")
                        .selected_text(self.finding_severity_filter.label())
                        .show_ui(ui, |ui| {
                            for filter in [
                                SeverityFilter::All,
                                SeverityFilter::Info,
                                SeverityFilter::Low,
                                SeverityFilter::Medium,
                                SeverityFilter::High,
                                SeverityFilter::Critical,
                            ] {
                                ui.selectable_value(
                                    &mut self.finding_severity_filter,
                                    filter,
                                    filter.label(),
                                );
                            }
                        });

                    ComboBox::from_id_salt("finding_confidence_filter")
                        .selected_text(self.finding_confidence_filter.label())
                        .show_ui(ui, |ui| {
                            for filter in [
                                ConfidenceFilter::All,
                                ConfidenceFilter::High,
                                ConfidenceFilter::Medium,
                                ConfidenceFilter::Low,
                                ConfidenceFilter::InferredCompound,
                            ] {
                                ui.selectable_value(
                                    &mut self.finding_confidence_filter,
                                    filter,
                                    filter.label(),
                                );
                            }
                        });

                    ComboBox::from_id_salt("finding_category_filter")
                        .selected_text(&self.finding_category_filter)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.finding_category_filter,
                                "全部分类".to_string(),
                                "全部分类",
                            );
                            for category in categories {
                                ui.selectable_value(
                                    &mut self.finding_category_filter,
                                    category.clone(),
                                    category,
                                );
                            }
                        });
                });
            });
        ui.add_space(8.0);
    }

    fn filter_toolbar_paths(&mut self, ui: &mut Ui, report: &ScanReport) {
        let path_types = unique_path_types(report);
        Frame::group(ui.style())
            .fill(Color32::from_rgb(255, 252, 248))
            .stroke(Stroke::new(1.0, Color32::from_rgb(226, 220, 212)))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new("筛选").strong());
                    ComboBox::from_id_salt("path_severity_filter")
                        .selected_text(self.path_severity_filter.label())
                        .show_ui(ui, |ui| {
                            for filter in [
                                SeverityFilter::All,
                                SeverityFilter::Info,
                                SeverityFilter::Low,
                                SeverityFilter::Medium,
                                SeverityFilter::High,
                                SeverityFilter::Critical,
                            ] {
                                ui.selectable_value(
                                    &mut self.path_severity_filter,
                                    filter,
                                    filter.label(),
                                );
                            }
                        });
                    ComboBox::from_id_salt("path_type_filter")
                        .selected_text(&self.path_type_filter)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut self.path_type_filter,
                                "全部类型".to_string(),
                                "全部类型",
                            );
                            for item in path_types {
                                ui.selectable_value(&mut self.path_type_filter, item.clone(), item);
                            }
                        });
                    ComboBox::from_id_salt("path_status_filter")
                        .selected_text(self.path_status_filter.label())
                        .show_ui(ui, |ui| {
                            for filter in [
                                PathStatusFilter::All,
                                PathStatusFilter::Validated,
                                PathStatusFilter::Blocked,
                                PathStatusFilter::Assumed,
                            ] {
                                ui.selectable_value(
                                    &mut self.path_status_filter,
                                    filter,
                                    filter.label(),
                                );
                            }
                        });
                });
            });
        ui.add_space(8.0);
    }

    fn finding_matches_filters(&self, finding: &Finding) -> bool {
        self.finding_severity_filter.matches(finding.severity)
            && self.finding_confidence_filter.matches(finding.confidence)
            && (self.finding_category_filter == "全部分类"
                || self.finding_category_filter == finding.category)
    }

    fn path_matches_filters(&self, report: &ScanReport, path: &AttackPath) -> bool {
        self.path_severity_filter.matches(path.severity)
            && (self.path_type_filter == "全部类型" || self.path_type_filter == path.path_type)
            && self
                .path_status_filter
                .matches(path_validation_status(report, &path.path_id))
    }

    fn subject_filter_matches(&self, subject_id: &str) -> bool {
        match &self.selected_subject_id {
            Some(selected) => selected == subject_id,
            None => true,
        }
    }

    fn render_expandable_text(&self, ui: &mut Ui, label: &str, text: &str, preview_limit: usize) {
        if text.trim().is_empty() {
            return;
        }
        let translated = display_text_zh(text);
        let readable = readable_text(&translated);
        let preview = truncate_text(&readable, preview_limit);
        ui.label(RichText::new(label).strong());
        ui.add(egui::Label::new(preview.as_str()).wrap());
        if preview != readable {
            egui::CollapsingHeader::new(format!("展开{label}"))
                .default_open(false)
                .show(ui, |ui| {
                    ui.add(egui::Label::new(readable.as_str()).wrap());
                });
        }
        ui.add_space(6.0);
    }

    fn section_card(ui: &mut Ui, title: &str, subtitle: &str, add_contents: impl FnOnce(&mut Ui)) {
        Self::section_card_in(ui, title, subtitle, add_contents);
    }

    fn section_card_in(
        ui: &mut Ui,
        title: &str,
        subtitle: &str,
        add_contents: impl FnOnce(&mut Ui),
    ) {
        Frame::group(ui.style())
            .fill(Color32::from_rgb(255, 252, 248))
            .stroke(Stroke::new(1.0, Color32::from_rgb(226, 220, 212)))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(title)
                        .strong()
                        .size(17.0)
                        .color(Color32::from_rgb(31, 42, 52)),
                );
                ui.label(RichText::new(subtitle).color(Color32::from_rgb(104, 113, 122)));
                ui.separator();
                add_contents(ui);
            });
    }

    fn hero_banner(
        &self,
        ui: &mut Ui,
        title: &str,
        subtitle: &str,
        fill: Color32,
        accent: Color32,
    ) {
        Frame::group(ui.style())
            .fill(fill)
            .stroke(Stroke::new(1.2, accent))
            .show(ui, |ui| {
                ui.add_space(2.0);
                ui.label(RichText::new(title).size(26.0).strong().color(accent));
                ui.label(
                    RichText::new(subtitle)
                        .size(15.0)
                        .color(Color32::from_rgb(50, 61, 72)),
                );
                ui.add_space(2.0);
            });
    }

    fn empty_state(&self, ui: &mut Ui, title: &str, subtitle: &str) {
        ui.with_layout(Layout::top_down_justified(Align::Center), |ui| {
            ui.add_space(90.0);
            Frame::group(ui.style())
                .fill(Color32::from_rgb(255, 252, 248))
                .stroke(Stroke::new(1.0, Color32::from_rgb(226, 220, 212)))
                .show(ui, |ui| {
                    ui.set_min_height(220.0);
                    ui.vertical_centered(|ui| {
                        ui.add_space(20.0);
                        ui.heading(title);
                        ui.label(subtitle);
                        ui.add_space(10.0);
                        ui.label("建议流程：选择目标 -> 开始扫描 -> 先看总览 -> 再看详细页。");
                    });
                });
        });
    }

    fn empty_panel(&self, ui: &mut Ui, text: &str) {
        Frame::group(ui.style())
            .fill(Color32::from_rgb(255, 252, 248))
            .stroke(Stroke::new(1.0, Color32::from_rgb(226, 220, 212)))
            .show(ui, |ui| {
                ui.label(text);
            });
    }

    fn stat_card(&self, ui: &mut Ui, label: &str, value: &str, accent: Color32) {
        Frame::group(ui.style())
            .fill(Color32::from_rgb(255, 255, 255))
            .stroke(Stroke::new(1.0, Color32::from_rgb(216, 226, 235)))
            .show(ui, |ui| {
                ui.set_min_width(150.0);
                ui.label(RichText::new(label).color(Color32::from_rgb(91, 104, 117)));
                ui.label(RichText::new(value).size(28.0).strong().color(accent));
            });
    }

    fn status_badge(&self, ui: &mut Ui, label: &str) {
        Frame::group(ui.style())
            .fill(Color32::from_rgb(237, 247, 246))
            .stroke(Stroke::new(1.0, Color32::from_rgb(19, 106, 94)))
            .show(ui, |ui| {
                ui.label(
                    RichText::new(label)
                        .strong()
                        .color(Color32::from_rgb(19, 106, 94)),
                );
            });
    }

    fn small_badge(&self, ui: &mut Ui, label: &str) {
        Frame::group(ui.style())
            .fill(Color32::from_rgb(243, 239, 234))
            .stroke(Stroke::new(1.0, Color32::from_rgb(226, 220, 212)))
            .show(ui, |ui| {
                ui.label(RichText::new(label).size(12.0));
            });
    }

    fn info_banner(&self, ui: &mut Ui, text: &str, fill: Color32, accent: Color32) {
        Frame::group(ui.style())
            .fill(fill)
            .stroke(Stroke::new(1.0, accent))
            .show(ui, |ui| {
                ui.label(RichText::new(text).color(accent));
            });
    }

    fn step_chip(&self, ui: &mut Ui, number: &str, text: &str) {
        Frame::group(ui.style())
            .fill(Color32::from_rgb(243, 239, 234))
            .stroke(Stroke::new(1.0, Color32::from_rgb(226, 220, 212)))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(number)
                            .strong()
                            .color(Color32::from_rgb(19, 106, 94)),
                    );
                    ui.label(text);
                });
            });
    }

    fn summary_line(&self, ui: &mut Ui, label: &str, value: &str) {
        ui.label(RichText::new(label).strong());
        let text = readable_text(&display_text_zh(value));
        ui.add(egui::Label::new(text).wrap());
        ui.add_space(4.0);
    }

    fn key_value(&self, ui: &mut Ui, label: &str, value: &str) {
        ui.label(RichText::new(label).strong());
        let text = readable_text(&display_text_zh(value));
        ui.add(egui::Label::new(text).wrap());
        ui.add_space(6.0);
    }

    fn optional_summary(&self, ui: &mut Ui, label: &str, value: Option<&str>) {
        if let Some(value) = value {
            if !value.is_empty() {
                self.summary_line(ui, label, value);
            }
        }
    }

    fn string_list(&self, ui: &mut Ui, label: &str, items: &[String]) {
        if items.is_empty() {
            return;
        }
        ui.label(RichText::new(label).strong());
        for item in items {
            let text = readable_text(&display_text_zh(item));
            ui.add(egui::Label::new(format!("• {text}")).wrap());
        }
        ui.add_space(6.0);
    }

    fn string_list_from_validated(&self, ui: &mut Ui, label: &str, items: &[String]) {
        if items.is_empty() {
            return;
        }
        ui.label(RichText::new(label).strong());
        for item in items {
            let text = readable_text(&display_text_zh(item));
            ui.add(egui::Label::new(format!("• {text}")).wrap());
        }
        ui.add_space(6.0);
    }

    fn top_status_label(&self) -> Option<String> {
        if self.scan_running {
            Some("正在扫描".to_string())
        } else {
            self.completed_scan.as_ref().map(|completed| {
                format!(
                    "{} / 分数 {} / 发现项 {}",
                    verdict_label(completed.report.verdict),
                    completed.report.score,
                    completed.report.findings.len()
                )
            })
        }
    }

    fn scan_progress_text(&self) -> String {
        match self.scan_started_at {
            Some(started) => format!(
                "正在复用既有扫描主链执行分析，已运行 {} 秒。",
                started.elapsed().as_secs()
            ),
            None => "正在复用既有扫描主链执行分析。".to_string(),
        }
    }

    fn start_scan(&mut self) {
        self.error_message = None;
        self.status_message = Some("正在启动扫描…".to_string());

        let target_path = self.target_path.trim();
        if target_path.is_empty() {
            self.error_message = Some("请先选择一个扫描目标。".to_string());
            self.status_message = None;
            return;
        }

        let request = ScanRequest {
            target_path: target_path.to_string(),
            runtime_manifest_path: optional_path(&self.runtime_manifest_path),
            suppression_path: optional_path(&self.suppression_path),
            report_save_path: optional_path(&self.report_save_path),
            policy_path: optional_path(&self.policy_config_path),
            validation_mode: self.validation_mode,
            agent_ecosystem: self.agent_ecosystem,
        };

        let (sender, receiver) = mpsc::channel();
        self.scan_running = true;
        self.scan_started_at = Some(Instant::now());
        self.scan_receiver = Some(receiver);
        self.selected_finding_id = None;
        self.selected_path_id = None;
        self.selected_subject_id = None;
        thread::spawn(move || {
            let result = scan_with_request(&request);
            let _ = sender.send(ScanWorkerMessage::Finished(result));
        });
    }

    fn export_current_report(&mut self, format: ExportFormat) {
        let Some(completed) = &self.completed_scan else {
            return;
        };

        let content = match render_report_for_export(&completed.report, format) {
            Ok(content) => content,
            Err(err) => {
                self.error_message = Some(err);
                return;
            }
        };

        let target_path = if self.report_save_path.trim().is_empty() {
            FileDialog::new()
                .set_file_name(format.default_file_name())
                .save_file()
        } else {
            let base = PathBuf::from(self.report_save_path.trim());
            Some(base.with_extension(format.extension()))
        };

        match target_path {
            Some(path) => match save_report_to_file(&path, &content) {
                Ok(()) => {
                    self.error_message = None;
                    self.status_message = Some(format!("{} 导出已完成。", format.label()));
                }
                Err(err) => {
                    self.error_message = Some(err);
                }
            },
            None => {
                self.status_message = Some("已取消导出。".to_string());
            }
        }
    }

    fn poll_scan_results(&mut self) {
        let finished = self
            .scan_receiver
            .as_ref()
            .and_then(|receiver| receiver.try_recv().ok());

        if let Some(ScanWorkerMessage::Finished(result)) = finished {
            self.scan_running = false;
            self.scan_receiver = None;
            self.scan_started_at = None;
            match result {
                Ok(completed) => {
                    self.completed_scan = Some(completed);
                    self.active_tab = UiTab::Summary;
                    self.error_message = None;
                    self.status_message = Some("扫描完成，已切换到总览页。".to_string());
                }
                Err(err) => {
                    self.error_message = Some(err);
                    self.status_message = Some("扫描失败，请检查目标路径和高级选项。".to_string());
                }
            }
        }
    }
}

fn optional_path(value: &str) -> Option<PathBuf> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(PathBuf::from(trimmed))
    }
}

fn truncate_text(text: &str, limit: usize) -> String {
    let chars = text.chars().collect::<Vec<_>>();
    if chars.len() <= limit {
        text.to_string()
    } else {
        format!("{}…", chars[..limit].iter().collect::<String>())
    }
}

fn readable_text(text: &str) -> String {
    text.split_whitespace()
        .map(|token| {
            if token.chars().count() > 48 {
                chunk_long_token(token, 24)
            } else {
                token.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn chunk_long_token(token: &str, chunk: usize) -> String {
    let mut out = String::new();
    for (index, ch) in token.chars().enumerate() {
        if index > 0 && index % chunk == 0 {
            out.push('\u{200b}');
        }
        out.push(ch);
    }
    out
}

fn severity_text(severity: FindingSeverity) -> &'static str {
    match severity {
        FindingSeverity::Info => "信息",
        FindingSeverity::Low => "低",
        FindingSeverity::Medium => "中",
        FindingSeverity::High => "高",
        FindingSeverity::Critical => "严重",
    }
}

fn confidence_text(confidence: FindingConfidence) -> &'static str {
    match confidence {
        FindingConfidence::High => "高",
        FindingConfidence::Medium => "中",
        FindingConfidence::Low => "低",
        FindingConfidence::InferredCompound => "组合推断",
    }
}

fn severity_color(severity: FindingSeverity) -> Color32 {
    match severity {
        FindingSeverity::Info => Color32::from_rgb(84, 118, 165),
        FindingSeverity::Low => Color32::from_rgb(117, 126, 137),
        FindingSeverity::Medium => Color32::from_rgb(190, 122, 21),
        FindingSeverity::High => Color32::from_rgb(189, 85, 34),
        FindingSeverity::Critical => Color32::from_rgb(169, 47, 47),
    }
}

fn verdict_bg(verdict: Verdict) -> Color32 {
    match verdict {
        Verdict::Allow => Color32::from_rgb(236, 246, 242),
        Verdict::Warn => Color32::from_rgb(252, 244, 228),
        Verdict::Block => Color32::from_rgb(252, 236, 236),
    }
}

fn verdict_fg(verdict: Verdict) -> Color32 {
    match verdict {
        Verdict::Allow => Color32::from_rgb(31, 111, 88),
        Verdict::Warn => Color32::from_rgb(166, 99, 8),
        Verdict::Block => Color32::from_rgb(171, 52, 52),
    }
}

fn unique_categories(report: &ScanReport) -> Vec<String> {
    let mut values = BTreeSet::new();
    for finding in &report.findings {
        values.insert(finding.category.clone());
    }
    values.into_iter().collect()
}

fn unique_path_types(report: &ScanReport) -> Vec<String> {
    let mut values = BTreeSet::new();
    for path in &report.attack_paths {
        values.insert(path.path_type.clone());
    }
    values.into_iter().collect()
}

fn path_validation_status(report: &ScanReport, path_id: &str) -> Option<PathValidationDisposition> {
    report
        .path_validation_status
        .iter()
        .find(|item| item.path_id == path_id)
        .map(|item| item.status)
}

fn path_validation_status_label(report: &ScanReport, path_id: &str) -> String {
    path_validation_status(report, path_id)
        .map(pretty_debug)
        .unwrap_or_else(|| "未单独标注".to_string())
}

fn related_path_ids_for_finding(report: &ScanReport, finding: &Finding) -> Vec<String> {
    let mut out = Vec::new();
    let finding_path = finding.location.as_ref().map(|item| item.path.as_str());
    let excerpt_matches = finding
        .evidence
        .iter()
        .map(|item| item.excerpt.to_lowercase())
        .collect::<Vec<_>>();

    for path in &report.attack_paths {
        let mut matched = false;
        if let Some(finding_path) = finding_path {
            if path
                .evidence_nodes
                .iter()
                .any(|node| node.location.path == finding_path)
            {
                matched = true;
            }
        }

        if !matched && !excerpt_matches.is_empty() {
            matched = excerpt_matches.iter().any(|excerpt| {
                let haystacks = std::iter::once(path.explanation.to_lowercase())
                    .chain(std::iter::once(path.impact.to_lowercase()))
                    .chain(path.prerequisites.iter().map(|item| item.to_lowercase()))
                    .chain(path.steps.iter().map(|item| item.summary.to_lowercase()))
                    .collect::<Vec<_>>();
                haystacks.iter().any(|hay| hay.contains(excerpt.trim()))
            });
        }

        if !matched {
            let title = finding.title.to_lowercase();
            let category = finding.category.to_lowercase();
            matched = path.title.to_lowercase().contains(&title)
                || path.explanation.to_lowercase().contains(&title)
                || path.explanation.to_lowercase().contains(&category)
                || path
                    .prerequisites
                    .iter()
                    .any(|item| item.to_lowercase().contains(&category));
        }

        if matched {
            out.push(path.path_id.clone());
        }
    }

    out
}

fn related_findings_for_path<'a>(report: &'a ScanReport, path: &AttackPath) -> Vec<&'a Finding> {
    report
        .findings
        .iter()
        .filter(|finding| {
            let related_paths = related_path_ids_for_finding(report, finding);
            related_paths.iter().any(|path_id| path_id == &path.path_id)
        })
        .collect()
}

fn subject_provenance_notes(report: &ScanReport, subject_id: &str) -> Vec<String> {
    report
        .provenance_notes
        .iter()
        .filter(|note| note.subject_id == subject_id)
        .map(|note| format!("{} | {}", note.source_layer, note.note))
        .collect()
}

fn subject_score_rationales(report: &ScanReport, subject_id: &str) -> Vec<String> {
    report
        .scoring_summary
        .score_rationale
        .iter()
        .filter(|item| item.source == subject_id)
        .map(|item| format!("{} | {}", item.delta, item.explanation))
        .collect()
}
