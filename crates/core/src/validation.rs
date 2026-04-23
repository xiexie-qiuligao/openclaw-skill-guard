use crate::consequence::ConsequenceAnalysis;
use crate::install::InstallAnalysis;
use crate::precedence::PrecedenceAnalysis;
use crate::types::{
    AttackPath, Finding, ValidationHook, ValidationOutcomeExpectation, ValidationPlan,
    ValidationReason, ValidationTarget,
};

pub fn build_validation_plan(
    findings: &[Finding],
    attack_paths: &[AttackPath],
    install: &InstallAnalysis,
    precedence: &PrecedenceAnalysis,
    consequence: &ConsequenceAnalysis,
) -> ValidationPlan {
    let mut hooks = Vec::new();

    if install
        .findings
        .iter()
        .any(|finding| finding.id == "context.install.auto_remote_execution")
    {
        hooks.push(ValidationHook {
            hook_id: "validation.install.remote_execution".to_string(),
            title: "Review remote install execution chain without running it".to_string(),
            target: ValidationTarget::InstallChain,
            reason: ValidationReason::RiskConfirmation,
            expected_outcome: ValidationOutcomeExpectation::ConfirmRisk,
            guarded_check: "Inspect metadata.openclaw.install and setup commands for remote download plus execution, and verify whether checksum/pinning is absent. Do not execute the retrieved content.".to_string(),
            related_findings: vec!["context.install.auto_remote_execution".to_string()],
            related_paths: attack_paths
                .iter()
                .filter(|path| path.path_type == "download_execute")
                .map(|path| path.path_id.clone())
                .collect(),
            dangerous: false,
        });
    }

    if findings
        .iter()
        .any(|finding| finding.id == "context.invocation.tool_dispatch")
    {
        hooks.push(ValidationHook {
            hook_id: "validation.invocation.direct_dispatch".to_string(),
            title: "Confirm direct tool dispatch and least-privilege need".to_string(),
            target: ValidationTarget::ToolDispatch,
            reason: ValidationReason::FalsePositiveReduction,
            expected_outcome: ValidationOutcomeExpectation::ReduceConfidence,
            guarded_check: "Verify whether command-dispatch: tool is truly required, which command-tool is bound, and whether model-mediated invocation would still satisfy the skill use case.".to_string(),
            related_findings: vec!["context.invocation.tool_dispatch".to_string()],
            related_paths: attack_paths
                .iter()
                .filter(|path| path.path_type == "direct_privileged_action")
                .map(|path| path.path_id.clone())
                .collect(),
            dangerous: false,
        });
    }

    if matches!(
        consequence.assessment.execution_surface,
        crate::types::ExecutionSurface::Host | crate::types::ExecutionSurface::Mixed
    ) {
        hooks.push(ValidationHook {
            hook_id: "validation.runtime.host_sandbox".to_string(),
            title: "Clarify host vs sandbox runtime assumptions".to_string(),
            target: ValidationTarget::RuntimeEnvironment,
            reason: ValidationReason::EnvironmentClarification,
            expected_outcome: ValidationOutcomeExpectation::ClarifyScope,
            guarded_check: "Check whether the skill runs on host, whether network is enabled, whether write access is available, and whether secrets/configs are mounted or forwarded into the runtime.".to_string(),
            related_findings: Vec::new(),
            related_paths: attack_paths.iter().map(|path| path.path_id.clone()).take(3).collect(),
            dangerous: false,
        });
    }

    if precedence.root_resolution.missing_roots.len() > 0 {
        hooks.push(ValidationHook {
            hook_id: "validation.precedence.expand_scope".to_string(),
            title: "Expand precedence scan to missing OpenClaw roots".to_string(),
            target: ValidationTarget::PrecedenceScope,
            reason: ValidationReason::ScopeExpansion,
            expected_outcome: ValidationOutcomeExpectation::ClarifyScope,
            guarded_check: format!(
                "Scan additional OpenClaw roots to resolve precedence uncertainty: {}.",
                precedence.root_resolution.missing_roots.join(", ")
            ),
            related_findings: precedence
                .findings
                .iter()
                .map(|finding| finding.id.clone())
                .collect(),
            related_paths: attack_paths
                .iter()
                .filter(|path| path.path_type == "trust_hijack")
                .map(|path| path.path_id.clone())
                .collect(),
            dangerous: false,
        });
    }

    if attack_paths.iter().any(|path| {
        path.path_type == "instruction_secret_access"
            || path.path_type == "secret_exfiltration_potential"
    }) {
        hooks.push(ValidationHook {
            hook_id: "validation.secret.runtime_prerequisites".to_string(),
            title: "Confirm whether secret-bearing runtime prerequisites actually exist".to_string(),
            target: ValidationTarget::SecretExposure,
            reason: ValidationReason::FalsePositiveReduction,
            expected_outcome: ValidationOutcomeExpectation::ReduceConfidence,
            guarded_check: "Check whether the referenced env vars, local secret files, auth profiles, or mounted configs are present in the target runtime without reading or exporting their contents.".to_string(),
            related_findings: findings
                .iter()
                .filter(|finding| finding.category == "secret_reachability")
                .map(|finding| finding.id.clone())
                .collect(),
            related_paths: attack_paths
                .iter()
                .filter(|path| path.path_type == "instruction_secret_access" || path.path_type == "secret_exfiltration_potential")
                .map(|path| path.path_id.clone())
                .collect(),
            dangerous: false,
        });
    }

    let summary = if hooks.is_empty() {
        "No additional validation hooks were planned because the current scan did not expose unresolved high-risk prerequisites.".to_string()
    } else {
        format!(
            "Planned {} guarded validation hook(s) to confirm high-risk paths, runtime assumptions, or scan-scope limitations without executing dangerous content.",
            hooks.len()
        )
    };

    ValidationPlan { summary, hooks }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::consequence::analyze_consequences;
    use crate::install::analyze_install_chain;
    use crate::precedence::analyze_precedence;
    use crate::reachability::{analyze_secret_reachability, analyze_tool_reachability};
    use crate::skill_parse::parse_skill_file;
    use crate::types::{AttackPath, Finding, FindingConfidence, FindingSeverity, TargetKind};

    use super::build_validation_plan;

    #[test]
    fn high_risk_install_gets_validation_hook() {
        let skill = parse_skill_file(
            Path::new("demo/SKILL.md"),
            "---\nmetadata: {\"openclaw\":{\"install\":[{\"kind\":\"download\",\"url\":\"https://example.invalid/tool.zip\",\"execute\":true}]}}\n---\nBody",
            Vec::new(),
        );
        let install = analyze_install_chain(&skill);
        let tools = analyze_tool_reachability(&skill);
        let secrets = analyze_secret_reachability(&skill);
        let consequence = analyze_consequences(&[skill.clone()], &install, &tools, &secrets);
        let precedence = analyze_precedence(&[skill], TargetKind::File);

        let plan =
            build_validation_plan(&install.findings, &[], &install, &precedence, &consequence);

        assert!(plan
            .hooks
            .iter()
            .any(|hook| hook.hook_id == "validation.install.remote_execution"));
        assert!(plan.hooks.iter().all(|hook| !hook.dangerous));
    }

    #[test]
    fn incomplete_roots_produce_precedence_guidance() {
        let finding = Finding {
            id: "context.precedence.name_collision".to_string(),
            title: "collision".to_string(),
            category: "precedence".to_string(),
            severity: FindingSeverity::Medium,
            confidence: FindingConfidence::High,
            hard_trigger: false,
            evidence_kind: "precedence_collision".to_string(),
            location: None,
            evidence: Vec::new(),
            explanation: String::new(),
            why_openclaw_specific: String::new(),
            prerequisite_context: Vec::new(),
            analyst_notes: Vec::new(),
            remediation: String::new(),
            suppression_status: "not_suppressed".to_string(),
        };
        let skill = parse_skill_file(
            Path::new("demo/SKILL.md"),
            "---\nname: Demo\n---\nBody",
            Vec::new(),
        );
        let install = analyze_install_chain(&skill);
        let tools = analyze_tool_reachability(&skill);
        let secrets = analyze_secret_reachability(&skill);
        let consequence = analyze_consequences(&[skill.clone()], &install, &tools, &secrets);
        let mut precedence = analyze_precedence(&[skill], TargetKind::File);
        precedence.findings.push(finding);

        let plan = build_validation_plan(
            &precedence.findings,
            &[AttackPath {
                path_id: "path.trust_hijack".to_string(),
                path_type: "trust_hijack".to_string(),
                title: String::new(),
                steps: Vec::new(),
                edges: Vec::new(),
                severity: FindingSeverity::Medium,
                confidence: FindingConfidence::Medium,
                explanation: String::new(),
                prerequisites: Vec::new(),
                impact: String::new(),
                evidence_nodes: Vec::new(),
                inferred_nodes: Vec::new(),
                why_openclaw_specific: String::new(),
            }],
            &install,
            &precedence,
            &consequence,
        );

        assert!(plan
            .hooks
            .iter()
            .any(|hook| hook.target == crate::types::ValidationTarget::PrecedenceScope));
    }
}
