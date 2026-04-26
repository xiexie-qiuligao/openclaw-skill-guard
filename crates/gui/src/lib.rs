mod app;

use std::fs;
use std::path::{Path, PathBuf};

use openclaw_skill_guard_core::{
    scan_path_with_options, ScanReport, ValidationExecutionMode, Verdict,
};
use openclaw_skill_guard_report::{render_html, render_json, render_markdown, render_sarif};

pub use app::OpenClawGuardApp;

#[derive(Debug, Clone)]
pub struct ScanRequest {
    pub target_path: PathBuf,
    pub runtime_manifest_path: Option<PathBuf>,
    pub suppression_path: Option<PathBuf>,
    pub report_save_path: Option<PathBuf>,
    pub validation_mode: ValidationExecutionMode,
}

#[derive(Debug, Clone)]
pub struct CompletedScan {
    pub report: ScanReport,
    pub raw_json: String,
    pub saved_report_path: Option<PathBuf>,
    pub summary_text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiTab {
    Summary,
    Findings,
    Context,
    Paths,
    Validation,
    Audit,
    RawJson,
}

impl UiTab {
    pub const ALL: [UiTab; 7] = [
        UiTab::Summary,
        UiTab::Findings,
        UiTab::Context,
        UiTab::Paths,
        UiTab::Validation,
        UiTab::Audit,
        UiTab::RawJson,
    ];

    pub fn label(self) -> &'static str {
        match self {
            UiTab::Summary => "总览",
            UiTab::Findings => "发现项",
            UiTab::Context => "上下文",
            UiTab::Paths => "攻击路径",
            UiTab::Validation => "运行时验证",
            UiTab::Audit => "审计",
            UiTab::RawJson => "原始 JSON",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    Json,
    Sarif,
    Markdown,
    Html,
}

impl ExportFormat {
    pub const ALL: [ExportFormat; 4] = [
        ExportFormat::Json,
        ExportFormat::Sarif,
        ExportFormat::Markdown,
        ExportFormat::Html,
    ];

    pub fn label(self) -> &'static str {
        match self {
            ExportFormat::Json => "JSON",
            ExportFormat::Sarif => "SARIF",
            ExportFormat::Markdown => "Markdown",
            ExportFormat::Html => "HTML",
        }
    }

    pub fn extension(self) -> &'static str {
        match self {
            ExportFormat::Json => "json",
            ExportFormat::Sarif => "sarif",
            ExportFormat::Markdown => "md",
            ExportFormat::Html => "html",
        }
    }

    pub fn default_file_name(self) -> &'static str {
        match self {
            ExportFormat::Json => "openclaw-skill-guard-report.json",
            ExportFormat::Sarif => "openclaw-skill-guard-report.sarif",
            ExportFormat::Markdown => "openclaw-skill-guard-report.md",
            ExportFormat::Html => "openclaw-skill-guard-report.html",
        }
    }
}

pub fn run_gui() -> Result<(), String> {
    run_gui_with_state(None, UiTab::Summary)
}

pub fn run_gui_with_state(
    initial_scan: Option<CompletedScan>,
    initial_tab: UiTab,
) -> Result<(), String> {
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_title("OpenClaw Skill Guard")
            .with_inner_size([1440.0, 940.0])
            .with_min_inner_size([1160.0, 760.0]),
        ..Default::default()
    };

    eframe::run_native(
        "OpenClaw Skill Guard",
        options,
        Box::new(move |_cc| {
            let app = match initial_scan.clone() {
                Some(completed) => OpenClawGuardApp::with_completed_scan(completed, initial_tab),
                None => OpenClawGuardApp::default(),
            };
            Ok(Box::new(app))
        }),
    )
    .map_err(|err| err.to_string())
}

pub fn scan_with_request(request: &ScanRequest) -> Result<CompletedScan, String> {
    validate_request(request)?;

    let report = scan_path_with_options(
        &request.target_path,
        request.suppression_path.as_deref(),
        request.runtime_manifest_path.as_deref(),
        request.validation_mode,
    )
    .map_err(|err| err.to_string())?;

    let raw_json = render_report_for_export(&report, ExportFormat::Json)?;
    let saved_report_path = if let Some(path) = &request.report_save_path {
        save_report_to_file(path, &raw_json)?;
        Some(path.clone())
    } else {
        None
    };

    let summary_text = build_summary_text(&report);

    Ok(CompletedScan {
        report,
        raw_json,
        saved_report_path,
        summary_text,
    })
}

pub fn render_report_for_export(
    report: &ScanReport,
    format: ExportFormat,
) -> Result<String, String> {
    match format {
        ExportFormat::Json => render_json(report).map_err(|err| err.to_string()),
        ExportFormat::Sarif => render_sarif(report).map_err(|err| err.to_string()),
        ExportFormat::Markdown => Ok(render_markdown(report)),
        ExportFormat::Html => Ok(render_html(report)),
    }
}

pub fn load_completed_scan_from_json(path: &Path) -> Result<CompletedScan, String> {
    let raw_json = fs::read_to_string(path).map_err(|err| format!("读取报告失败：{err}"))?;
    let normalized_json = raw_json.trim_start_matches('\u{feff}');
    let report: ScanReport =
        serde_json::from_str(normalized_json).map_err(|err| format!("解析报告失败：{err}"))?;
    let summary_text = build_summary_text(&report);
    Ok(CompletedScan {
        report,
        raw_json: normalized_json.to_string(),
        saved_report_path: Some(path.to_path_buf()),
        summary_text,
    })
}

pub fn save_report_to_file(path: &Path, content: &str) -> Result<(), String> {
    fs::write(path, content).map_err(|err| format!("保存导出文件失败：{err}"))
}

pub fn build_summary_text(report: &ScanReport) -> String {
    format!(
        "目标：{}\n结论：{}\n风险分数：{}\n是否阻断：{}\n发现项：{}\n攻击路径：{}\nThreat corpus：{}\nSensitive corpus：{}\nDependency audit：{}\n外部引用：{}\nConfig / control-plane：{}\nCapability manifest：{}\nCompanion docs：{}\nSource identity：{}",
        report.target.path,
        verdict_label(report.verdict),
        report.score,
        if report.blocked { "是" } else { "否" },
        report.findings.len(),
        report.attack_paths.len(),
        report
            .context_analysis
            .threat_corpus_summary
            .as_deref()
            .unwrap_or("n/a"),
        report
            .context_analysis
            .sensitive_data_summary
            .as_deref()
            .unwrap_or("n/a"),
        report.dependency_audit_summary.summary,
        report.external_references.len(),
        report.openclaw_config_audit_summary.summary,
        report.capability_manifest.summary,
        report.companion_doc_audit_summary.summary,
        report.source_identity_summary.summary,
    )
}

pub fn pretty_debug<T: std::fmt::Debug>(value: T) -> String {
    let raw = format!("{value:?}");
    let mut out = String::new();
    let mut prev_lower = false;
    for ch in raw.chars() {
        if ch == '_' || ch == '-' {
            out.push(' ');
            prev_lower = false;
            continue;
        }
        if ch.is_uppercase() && prev_lower {
            out.push(' ');
        }
        out.push(ch);
        prev_lower = ch.is_lowercase() || ch.is_ascii_digit();
    }
    out
}

pub fn verdict_label(verdict: Verdict) -> &'static str {
    match verdict {
        Verdict::Allow => "允许",
        Verdict::Warn => "警告",
        Verdict::Block => "阻断",
    }
}

fn validate_request(request: &ScanRequest) -> Result<(), String> {
    if !request.target_path.exists() {
        return Err(format!("扫描目标不存在：{}", request.target_path.display()));
    }
    if let Some(path) = &request.runtime_manifest_path {
        if !path.exists() {
            return Err(format!("运行时 manifest 不存在：{}", path.display()));
        }
    }
    if let Some(path) = &request.suppression_path {
        if !path.exists() {
            return Err(format!("suppression 文件不存在：{}", path.display()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use openclaw_skill_guard_core::ValidationExecutionMode;

    use super::{
        load_completed_scan_from_json, render_report_for_export, scan_with_request, ExportFormat,
        ScanRequest,
    };

    fn fixture(path: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join(path)
    }

    #[test]
    fn gui_scan_pipeline_handles_benign_sample() {
        let completed = scan_with_request(&ScanRequest {
            target_path: fixture("fixtures/v1/benign/SKILL.md"),
            runtime_manifest_path: None,
            suppression_path: None,
            report_save_path: None,
            validation_mode: ValidationExecutionMode::Planned,
        })
        .unwrap();

        assert_eq!(
            completed.report.verdict,
            openclaw_skill_guard_core::Verdict::Allow
        );
        assert!(completed.raw_json.contains("\"findings\""));
    }

    #[test]
    fn gui_scan_pipeline_handles_risky_sample() {
        let completed = scan_with_request(&ScanRequest {
            target_path: fixture("fixtures/v1/prompt-risk/SKILL.md"),
            runtime_manifest_path: None,
            suppression_path: None,
            report_save_path: None,
            validation_mode: ValidationExecutionMode::Planned,
        })
        .unwrap();

        assert!(!completed.report.findings.is_empty());
        assert!(
            completed.report.verdict == openclaw_skill_guard_core::Verdict::Warn
                || completed.report.verdict == openclaw_skill_guard_core::Verdict::Block
        );
    }

    #[test]
    fn gui_scan_pipeline_can_save_canonical_json_report() {
        let output_path = fixture("target/gui-export-test.json");
        if output_path.exists() {
            let _ = fs::remove_file(&output_path);
        }

        let completed = scan_with_request(&ScanRequest {
            target_path: fixture("fixtures/v1/benign/SKILL.md"),
            runtime_manifest_path: None,
            suppression_path: None,
            report_save_path: Some(output_path.clone()),
            validation_mode: ValidationExecutionMode::Planned,
        })
        .unwrap();

        assert_eq!(completed.saved_report_path.as_ref(), Some(&output_path));
        let saved = fs::read_to_string(&output_path).unwrap();
        assert!(saved.contains("\"findings\""));

        let _ = fs::remove_file(output_path);
    }

    #[test]
    fn gui_export_renders_all_supported_formats() {
        let completed = scan_with_request(&ScanRequest {
            target_path: fixture("fixtures/v2/report-demo"),
            runtime_manifest_path: None,
            suppression_path: None,
            report_save_path: None,
            validation_mode: ValidationExecutionMode::Planned,
        })
        .unwrap();

        let json = render_report_for_export(&completed.report, ExportFormat::Json).unwrap();
        let sarif = render_report_for_export(&completed.report, ExportFormat::Sarif).unwrap();
        let markdown = render_report_for_export(&completed.report, ExportFormat::Markdown).unwrap();
        let html = render_report_for_export(&completed.report, ExportFormat::Html).unwrap();

        assert!(json.contains("\"findings\""));
        assert!(sarif.contains("\"version\": \"2.1.0\""));
        assert!(markdown.contains("## Findings"));
        assert!(html.contains("<!DOCTYPE html>"));
    }

    #[test]
    fn gui_can_load_json_report_with_utf8_bom() {
        let source = render_report_for_export(
            &scan_with_request(&ScanRequest {
                target_path: fixture("fixtures/v2/report-demo"),
                runtime_manifest_path: None,
                suppression_path: None,
                report_save_path: None,
                validation_mode: ValidationExecutionMode::Planned,
            })
            .unwrap()
            .report,
            ExportFormat::Json,
        )
        .unwrap();
        let temp_path = fixture("target/gui-bom-report.json");
        fs::write(&temp_path, format!("\u{feff}{source}")).unwrap();

        let completed = load_completed_scan_from_json(&temp_path).unwrap();

        assert!(!completed.report.findings.is_empty());
        assert!(completed.raw_json.starts_with('{'));

        let _ = fs::remove_file(temp_path);
    }
}
