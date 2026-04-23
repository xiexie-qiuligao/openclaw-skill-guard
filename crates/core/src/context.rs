use crate::consequence::ConsequenceAnalysis;
use crate::dependency_audit::DependencyAuditAnalysis;
use crate::install::InstallAnalysis;
use crate::invocation::InvocationAnalysis;
use crate::precedence::PrecedenceAnalysis;
use crate::prompt_injection::PromptInjectionAnalysis;
use crate::reachability::{SecretReachabilityAnalysis, ToolReachabilityAnalysis};
use crate::types::{ContextAnalysis, ParsedSkill};
use crate::url_classification::UrlClassificationAnalysis;

pub fn build_context_analysis(
    skills: &[ParsedSkill],
    install: &InstallAnalysis,
    invocation: &InvocationAnalysis,
    tools: &ToolReachabilityAnalysis,
    secrets: &SecretReachabilityAnalysis,
    precedence: &PrecedenceAnalysis,
    prompt: &PromptInjectionAnalysis,
    threat_corpus_summary: &str,
    sensitive_data_summary: &str,
    dependency_audit: &DependencyAuditAnalysis,
    url_classification: &UrlClassificationAnalysis,
    consequence: &ConsequenceAnalysis,
) -> ContextAnalysis {
    let parsing_summary = if skills.is_empty() {
        "No SKILL.md file was parsed from the current scan scope.".to_string()
    } else {
        let malformed = skills
            .iter()
            .filter(|skill| skill.frontmatter.present && !skill.frontmatter.parsed)
            .count();
        format!(
            "Parsed {} skill file(s); malformed frontmatter detected in {} file(s).",
            skills.len(),
            malformed
        )
    };

    let metadata_summary = if skills.is_empty() {
        Some("No skill metadata was available in the current scan scope.".to_string())
    } else {
        let present = skills.iter().filter(|skill| skill.metadata.present).count();
        let normalized = skills
            .iter()
            .filter(|skill| skill.metadata.normalized)
            .count();
        Some(format!(
            "metadata.openclaw present in {} skill(s) and normalized successfully in {} skill(s).",
            present, normalized
        ))
    };

    ContextAnalysis {
        phase: "phase7_runtime_adapter".to_string(),
        parsing_summary,
        metadata_summary,
        install_chain_summary: Some(install.summary.clone()),
        invocation_summary: Some(invocation.summary.clone()),
        tool_reachability_summary: Some(tools.summary.clone()),
        reachable_tools: tools.reachable_tools.clone(),
        secret_reachability_summary: Some(secrets.summary.clone()),
        reachable_secret_scopes: secrets.reachable_secret_scopes.clone(),
        precedence_summary: Some(format!(
            "{} {}",
            precedence.summary, precedence.root_resolution.summary
        )),
        naming_collisions: precedence.collisions.clone(),
        host_vs_sandbox_assessment: Some(consequence.assessment.summary.clone()),
        prompt_injection_summary: Some(prompt.summary.clone()),
        threat_corpus_summary: Some(threat_corpus_summary.to_string()),
        sensitive_data_summary: Some(sensitive_data_summary.to_string()),
        dependency_audit_summary: Some(dependency_audit.summary.summary.clone()),
        api_classification_summary: Some(url_classification.api_summary.summary.clone()),
        source_reputation_summary: Some(url_classification.reputation_summary.summary.clone()),
        notes: vec![
            "Phase 7 runtime validation refines static conclusions with manifest-backed permission facts, guarded local checks, and explicit unknowns.".to_string(),
            "Precedence analysis records known roots, missing roots, and scope limitations instead of assuming global completeness.".to_string(),
            "V2 dependency, URL/API, and reputation signals are explainable overlays derived from built-in corpora and local heuristics rather than online trust services.".to_string(),
            "Threat and sensitive-data corpus analyzers are additive explainable detectors; they do not replace baseline, prompt, or reachability analysis.".to_string(),
        ],
    }
}
