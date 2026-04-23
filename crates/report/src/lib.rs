use openclaw_skill_guard_core::ScanReport;
use serde_json::{json, Value};

pub fn render_json(report: &ScanReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

pub fn render_sarif(report: &ScanReport) -> Result<String, serde_json::Error> {
    let mut rule_index = std::collections::BTreeMap::<String, Value>::new();
    let mut results = Vec::<Value>::new();

    for finding in &report.findings {
        rule_index.entry(finding.id.clone()).or_insert_with(|| {
            json!({
                "id": finding.id,
                "name": finding.category,
                "shortDescription": {
                    "text": finding.title,
                },
                "properties": {
                    "category": finding.category,
                }
            })
        });

        let locations = finding
            .location
            .as_ref()
            .map(|location| {
                vec![json!({
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": location.path,
                        },
                        "region": {
                            "startLine": location.line.unwrap_or(1),
                            "startColumn": location.column.unwrap_or(1),
                        }
                    }
                })]
            })
            .unwrap_or_default();

        results.push(json!({
            "ruleId": finding.id,
            "level": sarif_level(finding.severity),
            "message": {
                "text": finding.explanation,
            },
            "locations": locations,
            "properties": {
                "severity": format!("{:?}", finding.severity).to_ascii_lowercase(),
                "confidence": format!("{:?}", finding.confidence).to_ascii_lowercase(),
                "hard_trigger": finding.hard_trigger,
                "why_openclaw_specific": finding.why_openclaw_specific,
                "suppression_status": finding.suppression_status,
            }
        }));
    }

    serde_json::to_string_pretty(&json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "openclaw-skill-guard",
                        "informationUri": "https://example.invalid/standalone-openclaw-skill-guard",
                        "rules": rule_index.into_values().collect::<Vec<_>>(),
                    }
                },
                "results": results,
            }
        ]
    }))
}

pub fn render_markdown(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str("# openclaw-skill-guard report\n\n");
    out.push_str("## Summary\n\n");
    out.push_str(&format!(
        "- Target: `{}`\n- Verdict: `{}`\n- Score: `{}`\n- Blocked: `{}`\n- Findings: `{}`\n- Attack paths: `{}`\n- External references: `{}`\n\n",
        report.target.path,
        format!("{:?}", report.verdict).to_ascii_lowercase(),
        report.score,
        if report.blocked { "yes" } else { "no" },
        report.findings.len(),
        report.attack_paths.len(),
        report.external_references.len(),
    ));

    out.push_str("## V2 Summaries\n\n");
    out.push_str(&format!(
        "- Threat corpus: {}\n- Sensitive data: {}\n- Dependency audit: {}\n- API classification: {}\n- Source reputation: {}\n\n",
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
        report.api_classification_summary.summary,
        report.source_reputation_summary.summary,
    ));

    out.push_str("## Findings\n\n");
    if report.findings.is_empty() {
        out.push_str("No findings.\n\n");
    } else {
        for finding in &report.findings {
            out.push_str(&format!(
                "### {} (`{}`)\n\n- Severity: `{}`\n- Confidence: `{}`\n- Category: `{}`\n",
                finding.title,
                finding.id,
                format!("{:?}", finding.severity).to_ascii_lowercase(),
                format!("{:?}", finding.confidence).to_ascii_lowercase(),
                finding.category,
            ));
            if let Some(location) = &finding.location {
                out.push_str(&format!("- Location: `{}`:{}\n", location.path, location.line.unwrap_or(1)));
            }
            out.push_str(&format!("\n{}\n\n", finding.explanation));
            if !finding.analyst_notes.is_empty() {
                out.push_str("Analyst notes:\n");
                for note in &finding.analyst_notes {
                    out.push_str(&format!("- {}\n", note));
                }
                out.push('\n');
            }
        }
    }

    out.push_str("## Context\n\n");
    push_optional_markdown(&mut out, "Parsing", Some(&report.context_analysis.parsing_summary));
    push_optional_markdown(
        &mut out,
        "Metadata",
        report.context_analysis.metadata_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "Install",
        report.context_analysis.install_chain_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "Prompt",
        report.context_analysis.prompt_injection_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "Threat corpus",
        report.context_analysis.threat_corpus_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "Sensitive data",
        report.context_analysis.sensitive_data_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "Dependency audit",
        report.context_analysis.dependency_audit_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "API classification",
        report.context_analysis.api_classification_summary.as_deref(),
    );
    push_optional_markdown(
        &mut out,
        "Source reputation",
        report.context_analysis.source_reputation_summary.as_deref(),
    );

    out.push_str("## Attack Paths\n\n");
    if report.attack_paths.is_empty() {
        out.push_str("No attack paths.\n\n");
    } else {
        for path in &report.attack_paths {
            out.push_str(&format!(
                "### {} (`{}`)\n\n- Severity: `{}`\n- Confidence: `{}`\n- Type: `{}`\n\n{}\n\n",
                path.title,
                path.path_id,
                format!("{:?}", path.severity).to_ascii_lowercase(),
                format!("{:?}", path.confidence).to_ascii_lowercase(),
                path.path_type,
                path.explanation
            ));
        }
    }

    out.push_str("## Validation And Consequence\n\n");
    out.push_str(&format!(
        "- Runtime manifest: {}\n- Guarded validation: {}\n- Consequence summary: {}\n- Host vs sandbox split: {}\n\n",
        report.runtime_manifest_summary,
        report.guarded_validation.summary,
        report.consequence_summary.summary,
        report.host_vs_sandbox_split.summary,
    ));

    out.push_str("## External References\n\n");
    if report.external_references.is_empty() {
        out.push_str("No external references.\n\n");
    } else {
        for reference in &report.external_references {
            out.push_str(&format!(
                "- `{}` | category `{}` | reputation `{}` | host `{}`\n",
                reference.url,
                format!("{:?}", reference.category).to_ascii_lowercase(),
                format!("{:?}", reference.reputation).to_ascii_lowercase(),
                reference.host
            ));
        }
        out.push('\n');
    }

    out.push_str("## Score And Provenance\n\n");
    for item in &report.scoring_summary.score_rationale {
        out.push_str(&format!(
            "- `{}`: {} ({})\n",
            item.source, item.explanation, item.delta
        ));
    }
    if !report.confidence_factors.is_empty() {
        out.push_str("\nConfidence factors:\n");
        for factor in &report.confidence_factors {
            out.push_str(&format!(
                "- `{}`: {} ({})\n",
                factor.subject_id, factor.rationale, factor.delta
            ));
        }
    }
    if !report.provenance_notes.is_empty() {
        out.push_str("\nProvenance notes:\n");
        for note in &report.provenance_notes {
            out.push_str(&format!(
                "- `{}`: {}\n",
                note.subject_id, note.note
            ));
        }
    }

    out
}

pub fn render_html(report: &ScanReport) -> String {
    let markdown = render_markdown(report);
    format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>openclaw-skill-guard report</title><style>body{{font-family:Segoe UI,Arial,sans-serif;max-width:1100px;margin:0 auto;padding:24px;line-height:1.5;background:#f7f7f7;color:#222}}section{{background:#fff;border:1px solid #ddd;border-radius:10px;padding:16px;margin:0 0 16px}}code{{background:#f0f0f0;padding:2px 4px;border-radius:4px}}pre{{white-space:pre-wrap;word-break:break-word}}</style></head><body><section><pre>{}</pre></section></body></html>",
        escape_html(&markdown)
    )
}

fn sarif_level(severity: openclaw_skill_guard_core::FindingSeverity) -> &'static str {
    match severity {
        openclaw_skill_guard_core::FindingSeverity::Critical
        | openclaw_skill_guard_core::FindingSeverity::High => "error",
        openclaw_skill_guard_core::FindingSeverity::Medium => "warning",
        openclaw_skill_guard_core::FindingSeverity::Low
        | openclaw_skill_guard_core::FindingSeverity::Info => "note",
    }
}

fn push_optional_markdown(out: &mut String, label: &str, value: Option<&str>) {
    if let Some(value) = value {
        if !value.is_empty() {
            out.push_str(&format!("### {}\n\n{}\n\n", label, value));
        }
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use openclaw_skill_guard_core::{
        ApiClassificationSummary, AuditSummary, ConsequenceAssessment, ConstraintEffect,
        ContextAnalysis, DependencyAuditSummary, ExternalReference, ReferenceClassificationProvenance,
        EnvironmentAmplifier, EnvironmentBlocker, ExecutionSurface, HostSandboxSplit,
        Recommendations, RootResolutionSummary, RuntimeAssumptionStatus, RuntimeFact,
        RuntimeRefinementNote, RuntimeScoreAdjustment, RuntimeSourceKind, ScanReport, ScanTarget,
        ScoringSummary, SourceReputationSummary, SuppressionLifecycle, TargetKind,
        ValidationPlan, ValidationResult, ValidationTarget, Verdict,
    };
    use serde_json::Value;

    use super::{render_html, render_json, render_markdown, render_sarif};

    #[test]
    fn json_renderer_emits_expected_top_level_fields() {
        let report = ScanReport {
            target: ScanTarget {
                path: "SKILL.md".to_string(),
                canonical_path: "SKILL.md".to_string(),
                target_kind: TargetKind::File,
            },
            scan_mode: "file".to_string(),
            files_scanned: 1,
            files_skipped: Vec::new(),
            parse_errors: Vec::new(),
            score: 100,
            verdict: Verdict::Allow,
            blocked: false,
            top_risks: Vec::new(),
            findings: Vec::new(),
            context_analysis: ContextAnalysis {
                phase: "phase5_attack_paths".to_string(),
                parsing_summary: "parsed".to_string(),
                metadata_summary: None,
                install_chain_summary: None,
                invocation_summary: None,
                tool_reachability_summary: None,
                reachable_tools: Vec::new(),
                secret_reachability_summary: None,
                reachable_secret_scopes: Vec::new(),
                precedence_summary: None,
                naming_collisions: Vec::new(),
                host_vs_sandbox_assessment: None,
                prompt_injection_summary: None,
                threat_corpus_summary: None,
                sensitive_data_summary: None,
                dependency_audit_summary: None,
                api_classification_summary: None,
                source_reputation_summary: None,
                notes: Vec::new(),
            },
            attack_paths: Vec::new(),
            path_explanations: Vec::new(),
            prompt_injection_summary: String::new(),
            consequence_summary: ConsequenceAssessment {
                execution_surface: ExecutionSurface::Uncertain,
                file_system_consequences: Vec::new(),
                credential_consequences: Vec::new(),
                network_consequences: Vec::new(),
                persistence_consequences: Vec::new(),
                environment_assumptions: Vec::new(),
                evidence_nodes: Vec::new(),
                inferred_notes: Vec::new(),
                impact_deltas: Vec::new(),
                summary: String::new(),
            },
            host_vs_sandbox_split: HostSandboxSplit {
                host_effects: Vec::new(),
                sandbox_effects: Vec::new(),
                blocked_in_sandbox: Vec::new(),
                residual_sandbox_risks: Vec::new(),
                summary: String::new(),
            },
            runtime_manifest_summary: "No runtime manifest supplied.".to_string(),
            guarded_validation: openclaw_skill_guard_core::GuardedValidationResult {
                summary: "No guarded validation facts.".to_string(),
                capability_checks: Vec::new(),
                constraint_checks: Vec::new(),
                sandbox_constraint_effects: Vec::new(),
            },
            runtime_facts: vec![RuntimeFact {
                key: "execution_environment".to_string(),
                value: "Unknown".to_string(),
                source_kind: RuntimeSourceKind::Unknown,
                confirmed: false,
            }],
            runtime_assumption_status: vec![RuntimeAssumptionStatus {
                assumption: "execution_environment".to_string(),
                state: openclaw_skill_guard_core::RuntimeAssumptionState::Unknown,
                source_kind: RuntimeSourceKind::Unknown,
                rationale: "No manifest".to_string(),
            }],
            validation_plan: ValidationPlan {
                summary: String::new(),
                hooks: Vec::new(),
            },
            validation_hooks: Vec::new(),
            validation_results: vec![ValidationResult {
                check_id: "runtime.environment".to_string(),
                target: ValidationTarget::RuntimeEnvironment,
                success: false,
                validated_constraints: Vec::new(),
                missing_constraints: Vec::new(),
                capability_checks: Vec::new(),
                constraint_checks: Vec::new(),
                sandbox_constraint_effects: Vec::new(),
                note: "No manifest".to_string(),
            }],
            path_validation_status: Vec::new(),
            runtime_refinement_notes: vec![RuntimeRefinementNote {
                subject_id: "path.example".to_string(),
                note: "Still assumed".to_string(),
            }],
            constraint_effects: vec![ConstraintEffect {
                subject_id: "path.example".to_string(),
                effect: "still_assumed".to_string(),
                rationale: "No runtime facts".to_string(),
            }],
            environment_blockers: vec![EnvironmentBlocker {
                path_id: "path.example".to_string(),
                blocker: "network_denied".to_string(),
                rationale: "Example".to_string(),
            }],
            environment_amplifiers: vec![EnvironmentAmplifier {
                path_id: "path.example".to_string(),
                amplifier: "host_home_access".to_string(),
                rationale: "Example".to_string(),
            }],
            validation_score_adjustments: vec![RuntimeScoreAdjustment {
                source: "path.example".to_string(),
                delta: 1,
                rationale: "Example".to_string(),
            }],
            corpus_assets_used: Vec::new(),
            dependency_audit_summary: DependencyAuditSummary {
                summary: "No dependency findings.".to_string(),
                manifests_discovered: Vec::new(),
                lockfile_gaps: Vec::new(),
                findings_count: 0,
                notes: Vec::new(),
            },
            api_classification_summary: ApiClassificationSummary {
                summary: "No external references.".to_string(),
                total_references: 0,
                category_counts: Default::default(),
                service_kind_counts: Default::default(),
                review_needed_count: 0,
            },
            source_reputation_summary: SourceReputationSummary {
                summary: "No reputation hints.".to_string(),
                suspicious_references: 0,
                risk_signal_counts: Default::default(),
                notes: Vec::new(),
            },
            external_references: vec![ExternalReference {
                reference_id: "ref-001".to_string(),
                url: "https://github.com/example/project".to_string(),
                host: "github.com".to_string(),
                category: openclaw_skill_guard_core::ExternalReferenceCategory::SourceRepository,
                service_kind: openclaw_skill_guard_core::ExternalServiceKind::SourceCodeHost,
                reputation: openclaw_skill_guard_core::ExternalReferenceReputation::KnownPlatform,
                risk_signals: Vec::new(),
                locations: Vec::new(),
                evidence_excerpt: "https://github.com/example/project".to_string(),
                rationale: "fixture".to_string(),
                provenance: ReferenceClassificationProvenance {
                    taxonomy_entry_id: Some("v2.api.github_repo".to_string()),
                    matched_seed_ids: Vec::new(),
                    asset_sources: vec!["api-taxonomy-v2.yaml".to_string()],
                },
            }],
            provenance_notes: Vec::new(),
            confidence_factors: Vec::new(),
            false_positive_mitigations: Vec::new(),
            scoring_summary: ScoringSummary {
                base_score: 100,
                compound_uplift: 0,
                path_uplift: 0,
                confidence_adjustment: 0,
                final_score: 100,
                score_rationale: Vec::new(),
            },
            openclaw_specific_risk_summary: String::new(),
            scope_resolution_summary: RootResolutionSummary {
                known_roots: Vec::new(),
                missing_roots: Vec::new(),
                scope_notes: Vec::new(),
                summary: String::new(),
            },
            audit_summary: AuditSummary {
                summary: String::new(),
                records: Vec::new(),
                high_risk_suppressions: 0,
                expired_suppressions: Vec::new(),
                validation_aware_notes: Vec::new(),
            },
            suppression_matches: vec![openclaw_skill_guard_core::SuppressionMatch {
                scope: "finding".to_string(),
                target_id: "example".to_string(),
                reason: "fixture".to_string(),
                note: None,
                high_risk: false,
                lifecycle: SuppressionLifecycle::Active,
            }],
            analysis_limitations: Vec::new(),
            confidence_notes: Vec::new(),
            recommendations: Recommendations {
                immediate: Vec::new(),
                short_term: Vec::new(),
                hardening: Vec::new(),
                dynamic_validation: Vec::new(),
            },
            suppressions: Vec::new(),
            scan_integrity_notes: Vec::new(),
        };

        let rendered = render_json(&report).unwrap();

        assert!(rendered.contains("\"scan_mode\""));
        assert!(rendered.contains("\"context_analysis\""));
        assert!(rendered.contains("\"recommendations\""));
        assert!(rendered.contains("\"parsing_summary\""));
        assert!(rendered.contains("\"attack_paths\""));
        assert!(rendered.contains("\"scoring_summary\""));
        assert!(rendered.contains("\"validation_plan\""));
        assert!(rendered.contains("\"consequence_summary\""));
        assert!(rendered.contains("\"runtime_manifest_summary\""));
        assert!(rendered.contains("\"validation_results\""));
        assert!(rendered.contains("\"path_validation_status\""));
        assert!(rendered.contains("\"validation_score_adjustments\""));
        assert!(rendered.contains("\"dependency_audit_summary\""));
        assert!(rendered.contains("\"external_references\""));
        assert!(rendered.contains("\"source_reputation_summary\""));
    }

    #[test]
    fn sarif_renderer_maps_findings_into_results() {
        let mut report = serde_json::from_str::<ScanReport>(
            &render_json(&ScanReport {
                target: ScanTarget {
                    path: "SKILL.md".to_string(),
                    canonical_path: "SKILL.md".to_string(),
                    target_kind: TargetKind::File,
                },
                scan_mode: "file".to_string(),
                files_scanned: 1,
                files_skipped: Vec::new(),
                parse_errors: Vec::new(),
                score: 90,
                verdict: Verdict::Warn,
                blocked: false,
                top_risks: Vec::new(),
                findings: Vec::new(),
                context_analysis: ContextAnalysis {
                    phase: "phase7_runtime_adapter".to_string(),
                    parsing_summary: "parsed".to_string(),
                    metadata_summary: None,
                    install_chain_summary: None,
                    invocation_summary: None,
                    tool_reachability_summary: None,
                    reachable_tools: Vec::new(),
                    secret_reachability_summary: None,
                    reachable_secret_scopes: Vec::new(),
                    precedence_summary: None,
                    naming_collisions: Vec::new(),
                    host_vs_sandbox_assessment: None,
                    prompt_injection_summary: None,
                    threat_corpus_summary: None,
                    sensitive_data_summary: None,
                    dependency_audit_summary: None,
                    api_classification_summary: None,
                    source_reputation_summary: None,
                    notes: Vec::new(),
                },
                attack_paths: Vec::new(),
                path_explanations: Vec::new(),
                prompt_injection_summary: String::new(),
                consequence_summary: ConsequenceAssessment {
                    execution_surface: ExecutionSurface::Uncertain,
                    file_system_consequences: Vec::new(),
                    credential_consequences: Vec::new(),
                    network_consequences: Vec::new(),
                    persistence_consequences: Vec::new(),
                    environment_assumptions: Vec::new(),
                    evidence_nodes: Vec::new(),
                    inferred_notes: Vec::new(),
                    impact_deltas: Vec::new(),
                    summary: String::new(),
                },
                host_vs_sandbox_split: HostSandboxSplit {
                    host_effects: Vec::new(),
                    sandbox_effects: Vec::new(),
                    blocked_in_sandbox: Vec::new(),
                    residual_sandbox_risks: Vec::new(),
                    summary: String::new(),
                },
                runtime_manifest_summary: "No runtime manifest supplied.".to_string(),
                guarded_validation: openclaw_skill_guard_core::GuardedValidationResult {
                    summary: String::new(),
                    capability_checks: Vec::new(),
                    constraint_checks: Vec::new(),
                    sandbox_constraint_effects: Vec::new(),
                },
                runtime_facts: Vec::new(),
                runtime_assumption_status: Vec::new(),
                validation_plan: ValidationPlan {
                    summary: String::new(),
                    hooks: Vec::new(),
                },
                validation_hooks: Vec::new(),
                validation_results: Vec::new(),
                path_validation_status: Vec::new(),
                runtime_refinement_notes: Vec::new(),
                constraint_effects: Vec::new(),
                environment_blockers: Vec::new(),
                environment_amplifiers: Vec::new(),
                validation_score_adjustments: Vec::new(),
                corpus_assets_used: Vec::new(),
                dependency_audit_summary: DependencyAuditSummary {
                    summary: String::new(),
                    manifests_discovered: Vec::new(),
                    lockfile_gaps: Vec::new(),
                    findings_count: 0,
                    notes: Vec::new(),
                },
                api_classification_summary: ApiClassificationSummary {
                    summary: String::new(),
                    total_references: 0,
                    category_counts: Default::default(),
                    service_kind_counts: Default::default(),
                    review_needed_count: 0,
                },
                source_reputation_summary: SourceReputationSummary {
                    summary: String::new(),
                    suspicious_references: 0,
                    risk_signal_counts: Default::default(),
                    notes: Vec::new(),
                },
                external_references: Vec::new(),
                provenance_notes: Vec::new(),
                confidence_factors: Vec::new(),
                false_positive_mitigations: Vec::new(),
                scoring_summary: ScoringSummary {
                    base_score: 90,
                    compound_uplift: 0,
                    path_uplift: 0,
                    confidence_adjustment: 0,
                    final_score: 90,
                    score_rationale: Vec::new(),
                },
                openclaw_specific_risk_summary: String::new(),
                scope_resolution_summary: RootResolutionSummary {
                    known_roots: Vec::new(),
                    missing_roots: Vec::new(),
                    scope_notes: Vec::new(),
                    summary: String::new(),
                },
                audit_summary: AuditSummary {
                    summary: String::new(),
                    records: Vec::new(),
                    high_risk_suppressions: 0,
                    expired_suppressions: Vec::new(),
                    validation_aware_notes: Vec::new(),
                },
                suppression_matches: Vec::new(),
                analysis_limitations: Vec::new(),
                confidence_notes: Vec::new(),
                recommendations: Recommendations {
                    immediate: Vec::new(),
                    short_term: Vec::new(),
                    hardening: Vec::new(),
                    dynamic_validation: Vec::new(),
                },
                suppressions: Vec::new(),
                scan_integrity_notes: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();

        report.findings.push(openclaw_skill_guard_core::Finding {
            id: "source.direct_ip".to_string(),
            title: "External reference uses a direct IP address".to_string(),
            category: "source.direct_ip".to_string(),
            severity: openclaw_skill_guard_core::FindingSeverity::High,
            confidence: openclaw_skill_guard_core::FindingConfidence::Medium,
            hard_trigger: false,
            evidence_kind: "text_pattern".to_string(),
            location: Some(openclaw_skill_guard_core::SkillLocation {
                path: "SKILL.md".to_string(),
                line: Some(12),
                column: Some(4),
            }),
            evidence: Vec::new(),
            explanation: "The reference targets a direct IP address.".to_string(),
            why_openclaw_specific: "fixture".to_string(),
            prerequisite_context: Vec::new(),
            analyst_notes: Vec::new(),
            remediation: "Use a stable named host.".to_string(),
            suppression_status: "not_suppressed".to_string(),
        });

        let rendered = render_sarif(&report).unwrap();
        let json: Value = serde_json::from_str(&rendered).unwrap();

        assert_eq!(json["version"], "2.1.0");
        assert_eq!(json["runs"][0]["tool"]["driver"]["name"], "openclaw-skill-guard");
        assert_eq!(json["runs"][0]["results"][0]["ruleId"], "source.direct_ip");
        assert_eq!(json["runs"][0]["results"][0]["level"], "error");
        assert_eq!(
            json["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            "SKILL.md"
        );
        assert_eq!(
            json["runs"][0]["results"][0]["properties"]["confidence"],
            "medium"
        );
    }

    #[test]
    fn markdown_and_html_renderers_cover_v2_sections() {
        let report = serde_json::from_str::<ScanReport>(
            &render_json(&ScanReport {
                target: ScanTarget {
                    path: "fixtures/v2/report-demo".to_string(),
                    canonical_path: "fixtures/v2/report-demo".to_string(),
                    target_kind: TargetKind::Workspace,
                },
                scan_mode: "workspace".to_string(),
                files_scanned: 1,
                files_skipped: Vec::new(),
                parse_errors: Vec::new(),
                score: 77,
                verdict: Verdict::Warn,
                blocked: false,
                top_risks: vec!["demo risk".to_string()],
                findings: Vec::new(),
                context_analysis: ContextAnalysis {
                    phase: "phase7_runtime_adapter".to_string(),
                    parsing_summary: "parsed".to_string(),
                    metadata_summary: Some("metadata".to_string()),
                    install_chain_summary: Some("install".to_string()),
                    invocation_summary: None,
                    tool_reachability_summary: None,
                    reachable_tools: Vec::new(),
                    secret_reachability_summary: None,
                    reachable_secret_scopes: Vec::new(),
                    precedence_summary: None,
                    naming_collisions: Vec::new(),
                    host_vs_sandbox_assessment: Some("host vs sandbox".to_string()),
                    prompt_injection_summary: Some("prompt".to_string()),
                    threat_corpus_summary: Some("threat summary".to_string()),
                    sensitive_data_summary: Some("sensitive summary".to_string()),
                    dependency_audit_summary: Some("dependency summary".to_string()),
                    api_classification_summary: Some("api summary".to_string()),
                    source_reputation_summary: Some("source summary".to_string()),
                    notes: Vec::new(),
                },
                attack_paths: Vec::new(),
                path_explanations: Vec::new(),
                prompt_injection_summary: String::new(),
                consequence_summary: ConsequenceAssessment {
                    execution_surface: ExecutionSurface::Uncertain,
                    file_system_consequences: Vec::new(),
                    credential_consequences: Vec::new(),
                    network_consequences: Vec::new(),
                    persistence_consequences: Vec::new(),
                    environment_assumptions: Vec::new(),
                    evidence_nodes: Vec::new(),
                    inferred_notes: Vec::new(),
                    impact_deltas: Vec::new(),
                    summary: "consequence summary".to_string(),
                },
                host_vs_sandbox_split: HostSandboxSplit {
                    host_effects: Vec::new(),
                    sandbox_effects: Vec::new(),
                    blocked_in_sandbox: Vec::new(),
                    residual_sandbox_risks: Vec::new(),
                    summary: "split summary".to_string(),
                },
                runtime_manifest_summary: "manifest summary".to_string(),
                guarded_validation: openclaw_skill_guard_core::GuardedValidationResult {
                    summary: "guarded validation".to_string(),
                    capability_checks: Vec::new(),
                    constraint_checks: Vec::new(),
                    sandbox_constraint_effects: Vec::new(),
                },
                runtime_facts: Vec::new(),
                runtime_assumption_status: Vec::new(),
                validation_plan: ValidationPlan {
                    summary: String::new(),
                    hooks: Vec::new(),
                },
                validation_hooks: Vec::new(),
                validation_results: Vec::new(),
                path_validation_status: Vec::new(),
                runtime_refinement_notes: Vec::new(),
                constraint_effects: Vec::new(),
                environment_blockers: Vec::new(),
                environment_amplifiers: Vec::new(),
                validation_score_adjustments: Vec::new(),
                corpus_assets_used: Vec::new(),
                dependency_audit_summary: DependencyAuditSummary {
                    summary: "dependency summary".to_string(),
                    manifests_discovered: Vec::new(),
                    lockfile_gaps: Vec::new(),
                    findings_count: 0,
                    notes: Vec::new(),
                },
                api_classification_summary: ApiClassificationSummary {
                    summary: "api summary".to_string(),
                    total_references: 1,
                    category_counts: Default::default(),
                    service_kind_counts: Default::default(),
                    review_needed_count: 0,
                },
                source_reputation_summary: SourceReputationSummary {
                    summary: "source summary".to_string(),
                    suspicious_references: 0,
                    risk_signal_counts: Default::default(),
                    notes: Vec::new(),
                },
                external_references: vec![ExternalReference {
                    reference_id: "ref-001".to_string(),
                    url: "https://github.com/example/project".to_string(),
                    host: "github.com".to_string(),
                    category: openclaw_skill_guard_core::ExternalReferenceCategory::SourceRepository,
                    service_kind: openclaw_skill_guard_core::ExternalServiceKind::SourceCodeHost,
                    reputation: openclaw_skill_guard_core::ExternalReferenceReputation::KnownPlatform,
                    risk_signals: Vec::new(),
                    locations: Vec::new(),
                    evidence_excerpt: "https://github.com/example/project".to_string(),
                    rationale: "fixture".to_string(),
                    provenance: ReferenceClassificationProvenance {
                        taxonomy_entry_id: Some("v2.api.github_repository".to_string()),
                        matched_seed_ids: Vec::new(),
                        asset_sources: vec!["api-taxonomy-v2.yaml".to_string()],
                    },
                }],
                provenance_notes: Vec::new(),
                confidence_factors: Vec::new(),
                false_positive_mitigations: Vec::new(),
                scoring_summary: ScoringSummary {
                    base_score: 90,
                    compound_uplift: 0,
                    path_uplift: 0,
                    confidence_adjustment: 0,
                    final_score: 77,
                    score_rationale: Vec::new(),
                },
                openclaw_specific_risk_summary: String::new(),
                scope_resolution_summary: RootResolutionSummary {
                    known_roots: Vec::new(),
                    missing_roots: Vec::new(),
                    scope_notes: Vec::new(),
                    summary: String::new(),
                },
                audit_summary: AuditSummary {
                    summary: String::new(),
                    records: Vec::new(),
                    high_risk_suppressions: 0,
                    expired_suppressions: Vec::new(),
                    validation_aware_notes: Vec::new(),
                },
                suppression_matches: Vec::new(),
                analysis_limitations: Vec::new(),
                confidence_notes: Vec::new(),
                recommendations: Recommendations {
                    immediate: Vec::new(),
                    short_term: Vec::new(),
                    hardening: Vec::new(),
                    dynamic_validation: Vec::new(),
                },
                suppressions: Vec::new(),
                scan_integrity_notes: Vec::new(),
            })
            .unwrap(),
        )
        .unwrap();

        let markdown = render_markdown(&report);
        let html = render_html(&report);

        assert!(markdown.contains("## V2 Summaries"));
        assert!(markdown.contains("Threat corpus"));
        assert!(markdown.contains("## External References"));
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("openclaw-skill-guard report"));
    }
}
