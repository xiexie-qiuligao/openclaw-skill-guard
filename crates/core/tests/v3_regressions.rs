use std::path::PathBuf;

use openclaw_skill_guard_core::corpus::load_builtin_corpora;
use openclaw_skill_guard_core::{scan_path, Verdict};

fn fixture(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(path)
}

#[test]
fn v3_corpus_contains_targeted_openclaw_entries() {
    let corpora = load_builtin_corpora().unwrap();

    assert!(corpora
        .threat_patterns
        .iter()
        .any(|entry| entry.id == "v3.threat.openclaw_config_mutation"));
    assert!(corpora
        .threat_patterns
        .iter()
        .any(|entry| entry.id == "v3.threat.companion_follow_remote_instructions"));
    assert!(corpora
        .sensitive_data_patterns
        .iter()
        .any(|entry| entry.id == "v3.sensitive.openclaw_api_key_binding"));
}

#[test]
fn config_control_plane_fixture_emits_v3_findings() {
    let report = scan_path(&fixture("fixtures/v3/config-control-plane")).unwrap();

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.category == "openclaw_config.plaintext_api_key"));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.category == "openclaw_config.dangerous_env_override"));
    assert!(report
        .context_analysis
        .openclaw_config_summary
        .as_deref()
        .unwrap_or_default()
        .contains("control-plane"));
    assert!(report.openclaw_config_audit_summary.findings_count >= 2);
}

#[test]
fn capability_manifest_fixture_detects_hidden_direct_authority_and_mismatch() {
    let report = scan_path(&fixture("fixtures/v3/capability-manifest")).unwrap();

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.category == "capability.hidden_direct_authority"));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.category == "capability.permission_mismatch"));
    assert!(!report.capability_manifest.entries.is_empty());
    assert!(!report.capability_manifest.risky_combinations.is_empty());
}

#[test]
fn companion_doc_fixture_detects_indirect_instruction() {
    let report = scan_path(&fixture("fixtures/v3/companion-doc-poisoning")).unwrap();

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.category == "companion.indirect_instruction"));
    assert!(!report
        .companion_doc_audit_summary
        .companion_files_scanned
        .is_empty());
}

#[test]
fn source_identity_fixture_detects_offline_mismatch() {
    let report = scan_path(&fixture("fixtures/v3/source-identity-mismatch")).unwrap();

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.category == "source_identity.homepage_install_mismatch"));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.category == "source_identity.package_repository_mismatch"));
    assert!(report.source_identity_summary.mismatch_count >= 2);
}

#[test]
fn false_positive_docs_fixture_stays_reviewable_not_blocked() {
    let report = scan_path(&fixture("fixtures/v3/false-positive-docs")).unwrap();

    assert_ne!(report.verdict, Verdict::Block);
    assert!(report.companion_doc_audit_summary.findings_count <= 1);
}

#[test]
fn v3_sections_are_serialized_in_canonical_report() {
    let report = scan_path(&fixture("fixtures/v3/capability-manifest")).unwrap();
    let json = serde_json::to_string(&report).unwrap();

    assert!(json.contains("openclaw_config_audit_summary"));
    assert!(json.contains("capability_manifest"));
    assert!(json.contains("companion_doc_audit_summary"));
    assert!(json.contains("source_identity_summary"));
}

#[test]
fn benchmark_hidden_instruction_fixture_emits_stable_issue_code() {
    let report = scan_path(&fixture("fixtures/benchmark/hidden-instruction")).unwrap();

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.issue_code.as_deref() == Some("OCSG-HIDDEN-001")));
    assert!(!report.hidden_instruction_summary.signals.is_empty());
}

#[test]
fn benchmark_claims_vs_does_fixture_emits_review_layer() {
    let report = scan_path(&fixture("fixtures/benchmark/claims-vs-does")).unwrap();

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.issue_code.as_deref() == Some("OCSG-CLAIM-001")));
    assert!(!report.claims_review_summary.mismatches.is_empty());
    assert!(!report.claims_review_summary.review_questions.is_empty());
}

#[test]
fn benchmark_integrity_and_estate_sections_are_populated() {
    let report = scan_path(&fixture("fixtures/benchmark/integrity-estate")).unwrap();

    assert_eq!(report.integrity_snapshot.skill_file_digests.len(), 1);
    assert_eq!(
        report.integrity_snapshot.skill_file_digests[0].sha256.len(),
        64
    );
    assert!(!report.estate_inventory_summary.references.is_empty());
}

#[test]
fn benchmark_false_positive_docs_do_not_trigger_new_overlays() {
    let report = scan_path(&fixture("fixtures/benchmark/false-positive-docs")).unwrap();

    assert!(report.hidden_instruction_summary.signals.is_empty());
    assert!(report.claims_review_summary.mismatches.is_empty());
    assert!(!report.integrity_snapshot.skill_file_digests.is_empty());
}

#[test]
fn agent_ecosystem_mcp_fixture_emits_mcp_issue_codes_and_ai_bom() {
    let report = openclaw_skill_guard_core::scan_path_with_options(
        &fixture("fixtures/agent-ecosystem/mcp-dangerous"),
        None,
        None,
        openclaw_skill_guard_core::ValidationExecutionMode::Planned,
        true,
    )
    .unwrap();

    assert!(report
        .findings
        .iter()
        .any(|finding| finding.issue_code.as_deref() == Some("OCSG-MCP-001")));
    assert!(report
        .findings
        .iter()
        .any(|finding| finding.issue_code.as_deref() == Some("OCSG-MCP-002")));
    assert!(!report.agent_package_index.packages.is_empty());
    assert!(!report.ai_bom.mcp_servers.is_empty());
}

#[test]
fn agent_ecosystem_cursor_rule_indexes_without_openclaw_skill() {
    let report = openclaw_skill_guard_core::scan_path_with_options(
        &fixture("fixtures/agent-ecosystem/cursor-rule"),
        None,
        None,
        openclaw_skill_guard_core::ValidationExecutionMode::Planned,
        true,
    )
    .unwrap();

    assert!(report
        .agent_package_index
        .kind_counts
        .keys()
        .any(|kind| kind.contains("cursorrule")));
    assert!(report.findings.iter().all(|finding| {
        finding.issue_code.as_deref() != Some("OCSG-MCP-001")
            && finding.issue_code.as_deref() != Some("OCSG-MCP-002")
    }));
}

#[test]
fn benign_mcp_fixture_does_not_emit_mcp_findings() {
    let report = openclaw_skill_guard_core::scan_path_with_options(
        &fixture("fixtures/agent-ecosystem/benign-mcp"),
        None,
        None,
        openclaw_skill_guard_core::ValidationExecutionMode::Planned,
        true,
    )
    .unwrap();

    assert!(report
        .findings
        .iter()
        .all(|finding| !finding.category.starts_with("mcp.")));
    assert_eq!(report.mcp_tool_schema_summary.findings_count, 0);
}
