use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use agent_skill_guard_core::corpus::load_builtin_corpora;
use agent_skill_guard_core::dependency_audit::analyze_dependency_audit;
use agent_skill_guard_core::install::InstallAnalysis;
use agent_skill_guard_core::scan_path;
use agent_skill_guard_core::types::{
    ExternalReferenceCategory, ExternalRiskSignal, TextArtifact,
};
use agent_skill_guard_core::url_classification::analyze_external_references;
use walkdir::WalkDir;

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/v2")
}

fn fixture_file(path: &str) -> PathBuf {
    fixture_root().join(path)
}

fn read_fixture(path: &str) -> String {
    fs::read_to_string(fixture_file(path)).unwrap()
}

fn load_text_artifacts(dir: &Path) -> Vec<TextArtifact> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file())
        .filter_map(|entry| {
            fs::read_to_string(entry.path())
                .ok()
                .map(|content| TextArtifact {
                    path: entry.path().display().to_string(),
                    content,
                })
        })
        .collect()
}

#[test]
fn threat_corpus_fixture_matches_expected_entries() {
    let corpora = load_builtin_corpora().unwrap();
    let content = read_fixture("threat-corpus/SKILL.md");
    let matched_ids: BTreeSet<String> = corpora
        .threat_patterns
        .iter()
        .filter(|entry| entry.matcher.matches_text(&content).unwrap())
        .map(|entry| entry.id.clone())
        .collect();

    assert!(matched_ids.contains("v2.threat.prompt_ignore_previous"));
    assert!(matched_ids.contains("v2.threat.prompt_skip_confirmation"));
    assert!(matched_ids.contains("v2.threat.agent_context_memory_write"));
}

#[test]
fn sensitive_data_corpus_fixture_matches_expected_entries() {
    let corpora = load_builtin_corpora().unwrap();
    let content = read_fixture("sensitive-corpus/SKILL.md");
    let matched_ids: BTreeSet<String> = corpora
        .sensitive_data_patterns
        .iter()
        .filter(|entry| entry.matcher.matches_text(&content).unwrap())
        .map(|entry| entry.id.clone())
        .collect();

    assert!(matched_ids.contains("v2.sensitive.openai_key"));
    assert!(matched_ids.contains("v2.sensitive.github_pat"));
    assert!(matched_ids.contains("v2.sensitive.private_key_material"));
    assert!(matched_ids.contains("v2.sensitive.generic_bearer_token"));
}

#[test]
fn dependency_audit_fixture_emits_explainable_findings() {
    let docs = load_text_artifacts(&fixture_file("dependency-audit"));
    let analysis = analyze_dependency_audit(
        &docs,
        &InstallAnalysis {
            install_specs: Vec::new(),
            findings: Vec::new(),
            summary: String::new(),
        },
    );
    let ids: BTreeSet<&str> = analysis
        .findings
        .iter()
        .map(|finding| finding.id.as_str())
        .collect();

    assert!(ids.contains("dependency.unpinned_requirement"));
    assert!(ids.contains("dependency.remote_source"));
    assert!(ids.contains("dependency.unpinned_vcs_source"));
    assert!(ids.contains("dependency.non_default_registry"));
    assert!(ids.contains("dependency.lockfile_gap"));
}

#[test]
fn api_classification_fixture_covers_common_categories() {
    let corpora = load_builtin_corpora().unwrap();
    let docs = load_text_artifacts(&fixture_file("api-classification"));
    let analysis = analyze_external_references(&docs, &corpora);

    assert!(analysis
        .external_references
        .iter()
        .any(|item| item.category == ExternalReferenceCategory::Documentation));
    assert!(analysis
        .external_references
        .iter()
        .any(|item| item.category == ExternalReferenceCategory::SourceRepository));
    assert!(analysis
        .external_references
        .iter()
        .any(|item| item.category == ExternalReferenceCategory::RawContent));
    assert!(analysis
        .external_references
        .iter()
        .any(|item| item.category == ExternalReferenceCategory::ApiEndpoint));
}

#[test]
fn suspicious_source_fixture_emits_reputation_signals() {
    let corpora = load_builtin_corpora().unwrap();
    let docs = load_text_artifacts(&fixture_file("suspicious-sources"));
    let analysis = analyze_external_references(&docs, &corpora);

    assert!(analysis
        .external_references
        .iter()
        .any(|item| item.risk_signals.contains(&ExternalRiskSignal::Shortlink)));
    assert!(analysis
        .external_references
        .iter()
        .any(|item| item.risk_signals.contains(&ExternalRiskSignal::PureIp)));
    assert!(analysis.external_references.iter().any(|item| item
        .risk_signals
        .contains(&ExternalRiskSignal::DynamicDnsSuffix)));
    assert!(analysis.external_references.iter().any(|item| item
        .risk_signals
        .contains(&ExternalRiskSignal::SuspiciousTld)));
}

#[test]
fn false_positive_fixture_avoids_suspicious_source_findings() {
    let corpora = load_builtin_corpora().unwrap();
    let docs = load_text_artifacts(&fixture_file("false-positive-docs"));
    let analysis = analyze_external_references(&docs, &corpora);

    assert!(analysis.external_references.len() >= 2);
    assert!(!analysis
        .findings
        .iter()
        .any(|finding| finding.id.starts_with("source.")));
}

#[test]
fn scan_report_exposes_v2_sections_for_fixture_directory() {
    let report = scan_path(&fixture_file("api-classification")).unwrap();

    assert_eq!(report.corpus_assets_used.len(), 4);
    assert!(
        report
            .dependency_audit_summary
            .summary
            .contains("No supported dependency manifests")
            || report
                .dependency_audit_summary
                .summary
                .contains("Discovered")
    );
    assert!(report.api_classification_summary.total_references >= 4);
    assert!(!report.external_references.is_empty());
    assert!(report.context_analysis.api_classification_summary.is_some());
    assert!(report.context_analysis.source_reputation_summary.is_some());
}
