use std::collections::BTreeSet;

use crate::dependency_audit::DependencyAuditAnalysis;
use crate::install::InstallAnalysis;
use crate::invocation::InvocationAnalysis;
use crate::reachability::{SecretReachabilityAnalysis, ToolReachabilityAnalysis};
use crate::types::{
    CapabilityManifestEntry, CapabilityManifestSummary, EvidenceKind, EvidenceNode,
    ExternalReference, Finding, FindingConfidence, FindingSeverity, ParsedSkill, SkillLocation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapabilityManifestAnalysis {
    pub summary: CapabilityManifestSummary,
    pub findings: Vec<Finding>,
}

pub fn build_capability_manifest(
    skills: &[ParsedSkill],
    install: &InstallAnalysis,
    invocation: &InvocationAnalysis,
    tools: &ToolReachabilityAnalysis,
    secrets: &SecretReachabilityAnalysis,
    dependency: &DependencyAuditAnalysis,
    external_references: &[ExternalReference],
) -> CapabilityManifestAnalysis {
    let mut entries = Vec::new();
    let mut risky_combinations = BTreeSet::new();
    let mut mismatch_notes = BTreeSet::new();
    let mut unknowns = BTreeSet::new();
    let mut findings = Vec::new();

    for tool in &tools.reachable_tools {
        entries.push(CapabilityManifestEntry {
            capability: tool.capability.clone(),
            status: if tool.direct {
                "declared_or_direct"
            } else {
                "inferred"
            }
            .to_string(),
            source: "tool_reachability".to_string(),
            rationale: tool.reason.clone(),
        });
    }

    for secret in &secrets.reachable_secret_scopes {
        entries.push(CapabilityManifestEntry {
            capability: format!("secret:{}", secret.target),
            status: if secret.direct {
                "declared_or_direct"
            } else {
                "inferred"
            }
            .to_string(),
            source: "secret_reachability".to_string(),
            rationale: secret.reason.clone(),
        });
    }

    for skill in skills {
        for env in &skill.metadata.requires.env {
            entries.push(CapabilityManifestEntry {
                capability: format!("env:{env}"),
                status: "required".to_string(),
                source: "metadata.openclaw.requires.env".to_string(),
                rationale: "The skill metadata declares an environment requirement.".to_string(),
            });
        }
        for config in &skill.metadata.requires.config {
            entries.push(CapabilityManifestEntry {
                capability: format!("config:{config}"),
                status: "required".to_string(),
                source: "metadata.openclaw.requires.config".to_string(),
                rationale: "The skill metadata declares a configuration requirement.".to_string(),
            });
        }
        for bin in &skill.metadata.requires.bins {
            entries.push(CapabilityManifestEntry {
                capability: format!("bin:{bin}"),
                status: "required".to_string(),
                source: "metadata.openclaw.requires.bins".to_string(),
                rationale: "The skill metadata declares a binary requirement.".to_string(),
            });
        }
        if skill.invocation_policy.disable_model_invocation
            && skill.invocation_policy.user_invocable
            && skill.invocation_policy.command_tool.is_some()
        {
            risky_combinations.insert(
                "hidden-from-model skill remains user-invocable with direct tool authority"
                    .to_string(),
            );
            findings.push(make_manifest_finding(
                "capability.hidden_direct_authority",
                "Skill is hidden from model prompt but keeps direct user-invocable tool authority",
                FindingSeverity::High,
                FindingConfidence::High,
                skill,
                "The invocation policy combines `disable-model-invocation: true`, user invocation, and direct tool dispatch. This can reduce model-visible context while preserving operator-triggered tool authority.",
                "Keep direct-dispatch skills visible in review surfaces, or remove direct tool dispatch for hidden skills.",
            ));
        }

        if narrative_claims_low_capability(&skill.body)
            && (has_high_risk_tool(tools) || !install.install_specs.is_empty())
        {
            mismatch_notes.insert(format!(
                "{}: low-capability narrative conflicts with tool or install reachability",
                skill.skill_file
            ));
            findings.push(make_manifest_finding(
                "capability.permission_mismatch",
                "Skill narrative understates inferred capability surface",
                FindingSeverity::Medium,
                FindingConfidence::Medium,
                skill,
                "The skill text claims a low-risk or read-only posture, but metadata or instructions expose stronger tool, install, or mutation capabilities.",
                "Align the stated permission narrative with actual OpenClaw metadata, tool dispatch, install, and file/network behavior.",
            ));
        }
    }

    if !install.install_specs.is_empty() {
        entries.push(CapabilityManifestEntry {
            capability: "install_chain".to_string(),
            status: "declared_or_inferred".to_string(),
            source: "install_analysis".to_string(),
            rationale: install.summary.clone(),
        });
    }
    if dependency.summary.findings_count > 0 {
        entries.push(CapabilityManifestEntry {
            capability: "dependency_pull".to_string(),
            status: "inferred".to_string(),
            source: "dependency_audit".to_string(),
            rationale: dependency.summary.summary.clone(),
        });
    }
    if !external_references.is_empty() {
        entries.push(CapabilityManifestEntry {
            capability: "network_or_external_reference".to_string(),
            status: "inferred".to_string(),
            source: "url_api_classification".to_string(),
            rationale: format!(
                "The scan extracted {} external reference(s).",
                external_references.len()
            ),
        });
    }

    if !secrets.reachable_secret_scopes.is_empty() && !external_references.is_empty() {
        risky_combinations.insert(
            "secret reachability combines with external references or egress-capable guidance"
                .to_string(),
        );
        if let Some(skill) = skills.first() {
            findings.push(make_manifest_finding(
                "capability.secret_egress_combination",
                "Capability manifest combines secret reachability with external references",
                FindingSeverity::High,
                FindingConfidence::InferredCompound,
                skill,
                "The manifest contains both secret/config reachability and external URL/API references. This does not prove exfiltration, but it materially raises OpenClaw review priority.",
                "Break the combination by removing secret reachability, removing egress guidance, or documenting why the pairing is required.",
            ));
        }
    }

    if entries.is_empty() {
        unknowns.insert(
            "No declared or inferred OpenClaw capability entries were available in this scan scope."
                .to_string(),
        );
    }
    if invocation.findings.is_empty() && tools.reachable_tools.is_empty() {
        unknowns.insert(
            "No direct invocation/tool authority was found; absence of evidence is not proof of no authority."
                .to_string(),
        );
    }

    CapabilityManifestAnalysis {
        summary: CapabilityManifestSummary {
            summary: if entries.is_empty() {
                "Capability manifest found no declared or inferred capability entries.".to_string()
            } else {
                format!(
                    "Capability manifest summarized {} capability entry or entries, {} risky combination(s), and {} mismatch note(s).",
                    entries.len(),
                    risky_combinations.len(),
                    mismatch_notes.len()
                )
            },
            entries,
            risky_combinations: risky_combinations.into_iter().collect(),
            mismatch_notes: mismatch_notes.into_iter().collect(),
            unknowns: unknowns.into_iter().collect(),
        },
        findings,
    }
}

fn narrative_claims_low_capability(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("read-only")
        || lower.contains("read only")
        || lower.contains("no network")
        || lower.contains("does not execute")
        || lower.contains("analysis only")
        || lower.contains("safe helper")
}

fn has_high_risk_tool(tools: &ToolReachabilityAnalysis) -> bool {
    tools.reachable_tools.iter().any(|tool| {
        matches!(
            tool.capability.as_str(),
            "exec" | "process" | "shell" | "write" | "edit" | "apply_patch" | "gateway" | "cron"
        )
    })
}

fn make_manifest_finding(
    id: &str,
    title: &str,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    skill: &ParsedSkill,
    explanation: &str,
    remediation: &str,
) -> Finding {
    let location = SkillLocation {
        path: skill.skill_file.clone(),
        line: Some(1),
        column: None,
    };
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        issue_code: None,
        title_zh: None,
        category: id.to_string(),
        severity,
        confidence,
        hard_trigger: false,
        evidence_kind: "capability_manifest".to_string(),
        location: Some(location.clone()),
        evidence: vec![EvidenceNode {
            kind: EvidenceKind::Inference,
            location,
            excerpt: title.to_string(),
            direct: false,
        }],
        explanation: explanation.to_string(),
        explanation_zh: None,
        why_openclaw_specific: "OpenClaw skill authority can come from metadata, invocation policy, required config/env, install actions, and companion text; the manifest makes that combined surface reviewable.".to_string(),
        prerequisite_context: vec![
            "The finding is synthesized from existing analyzers rather than a new permission system.".to_string(),
        ],
        analyst_notes: vec![
            "Review declared capabilities against actual reachability and install/source evidence.".to_string(),
        ],
        remediation: remediation.to_string(),
        recommendation_zh: None,
        suppression_status: "not_suppressed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::install::InstallAnalysis;
    use crate::invocation::InvocationAnalysis;
    use crate::reachability::{SecretReachabilityAnalysis, ToolReachabilityAnalysis};
    use crate::skill_parse::parse_skill_file;
    use crate::types::FindingConfidence;

    use super::build_capability_manifest;

    #[test]
    fn detects_low_capability_narrative_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("SKILL.md");
        let content = "This is read-only and does not execute anything.";
        fs::write(&path, content).unwrap();
        let skill = parse_skill_file(&path, content, Vec::new());
        let tools = ToolReachabilityAnalysis {
            summary: String::new(),
            reachable_tools: vec![crate::types::ToolReachability {
                capability: "exec".to_string(),
                direct: true,
                confidence: FindingConfidence::High,
                reason: "fixture".to_string(),
            }],
            findings: Vec::new(),
        };
        let analysis = build_capability_manifest(
            &[skill],
            &InstallAnalysis {
                install_specs: Vec::new(),
                findings: Vec::new(),
                summary: String::new(),
            },
            &InvocationAnalysis {
                summary: String::new(),
                findings: Vec::new(),
            },
            &tools,
            &SecretReachabilityAnalysis {
                summary: String::new(),
                reachable_secret_scopes: Vec::new(),
                findings: Vec::new(),
            },
            &crate::dependency_audit::DependencyAuditAnalysis {
                summary: Default::default(),
                findings: Vec::new(),
            },
            &[],
        );

        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "capability.permission_mismatch"));
    }
}
