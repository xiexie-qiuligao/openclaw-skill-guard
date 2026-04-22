use openclaw_skill_guard_core::ScanReport;

pub fn render_json(report: &ScanReport) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(report)
}

#[cfg(test)]
mod tests {
    use openclaw_skill_guard_core::{
        AuditSummary, ConsequenceAssessment, ConstraintEffect, ContextAnalysis,
        EnvironmentBlocker, EnvironmentAmplifier, ExecutionSurface, HostSandboxSplit,
        Recommendations, RootResolutionSummary, RuntimeAssumptionStatus, RuntimeFact,
        RuntimeRefinementNote, RuntimeScoreAdjustment, RuntimeSourceKind, ScanReport, ScanTarget,
        ScoringSummary, SuppressionLifecycle, TargetKind, ValidationPlan, ValidationResult,
        ValidationTarget, Verdict,
    };

    use super::render_json;

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
    }
}
