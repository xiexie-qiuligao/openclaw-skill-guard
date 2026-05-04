use crate::install::InstallAnalysis;
use crate::types::{
    CapabilityManifestSummary, ClaimObservation, ClaimsReviewSummary, EvidenceKind, EvidenceNode,
    ExternalReference, Finding, FindingConfidence, FindingSeverity, OpenClawConfigAuditSummary,
    ParsedSkill, SkillLocation, SourceIdentitySummary,
};

#[derive(Debug, Clone, Default)]
pub struct ClaimsReviewAnalysis {
    pub summary: ClaimsReviewSummary,
    pub findings: Vec<Finding>,
}

pub fn analyze_claims_review(
    parsed_skills: &[ParsedSkill],
    capability_manifest: &CapabilityManifestSummary,
    install_analysis: &InstallAnalysis,
    openclaw_config: &OpenClawConfigAuditSummary,
    source_identity: &SourceIdentitySummary,
    external_references: &[ExternalReference],
) -> ClaimsReviewAnalysis {
    let mut declared_claims = Vec::new();
    let mut observed_signals = Vec::new();
    let mut mismatches = Vec::new();

    for skill in parsed_skills {
        if let Some(name) = &skill.descriptor.name {
            declared_claims.push(format!("skill name: {name}"));
        }
        if let Some(description) = &skill.descriptor.description {
            declared_claims.push(format!("description: {}", compact(description)));
            if low_risk_claim(description) {
                compare_low_risk_claim(
                    &mut mismatches,
                    description,
                    "frontmatter.description",
                    capability_manifest,
                    install_analysis,
                    openclaw_config,
                    &skill.skill_file,
                );
            }
        }
        if low_risk_claim(&skill.body) {
            compare_low_risk_claim(
                &mut mismatches,
                "body claims read-only / analysis-only behavior",
                &skill.skill_file,
                capability_manifest,
                install_analysis,
                openclaw_config,
                &skill.skill_file,
            );
        }
        if !skill.frontmatter.present {
            mismatches.push(ClaimObservation {
                claim: "No structured SKILL.md frontmatter was declared.".to_string(),
                claim_source: skill.skill_file.clone(),
                observed_signal:
                    "OpenClaw relies on structured metadata to make invocation, install, and capability intent reviewable."
                        .to_string(),
                status: "missing_or_weak_metadata".to_string(),
                review_question: "这个 skill 是否故意省略了可审查的 OpenClaw metadata？".to_string(),
            });
        }
    }

    for entry in &capability_manifest.entries {
        observed_signals.push(format!(
            "capability {} / {} from {}",
            entry.capability, entry.status, entry.source
        ));
    }
    for spec in &install_analysis.install_specs {
        observed_signals.push(format!("install source: {}", compact(&spec.raw)));
    }
    for binding in &openclaw_config.risky_bindings {
        observed_signals.push(format!("config binding: {}", compact(binding)));
    }
    for signal in &source_identity.signals {
        observed_signals.push(format!("source identity: {}", compact(&signal.summary)));
    }
    for reference in external_references.iter().take(12) {
        observed_signals.push(format!(
            "external reference: {} / {:?}",
            reference.host, reference.category
        ));
    }

    if source_identity.mismatch_count > 0 {
        mismatches.push(ClaimObservation {
            claim:
                "Skill source narrative should align with homepage, repository, and install source."
                    .to_string(),
            claim_source: "source identity summary".to_string(),
            observed_signal: source_identity.summary.clone(),
            status: "identity_mismatch".to_string(),
            review_question: "名称、主页、仓库、安装来源是否指向同一个可信主体？".to_string(),
        });
    }

    let review_questions = build_review_questions(&mismatches);
    let findings = build_findings(&mismatches);
    let summary = ClaimsReviewSummary {
        summary: if mismatches.is_empty() {
            "Declared skill claims align with observed high-level evidence.".to_string()
        } else {
            format!(
                "Detected {} claim-vs-observed mismatch item(s).",
                mismatches.len()
            )
        },
        summary_zh: if mismatches.is_empty() {
            "声明与实际证据未发现明显错位。".to_string()
        } else {
            format!("发现 {} 个“自称 vs 实际证据”错位点。", mismatches.len())
        },
        declared_claims,
        observed_signals,
        mismatches,
        review_questions,
    };

    ClaimsReviewAnalysis { summary, findings }
}

fn compare_low_risk_claim(
    mismatches: &mut Vec<ClaimObservation>,
    claim: &str,
    claim_source: &str,
    capability_manifest: &CapabilityManifestSummary,
    install_analysis: &InstallAnalysis,
    openclaw_config: &OpenClawConfigAuditSummary,
    path: &str,
) {
    let has_direct_authority = capability_manifest.entries.iter().any(|entry| {
        entry.status == "inferred"
            && matches!(
                entry.capability.as_str(),
                "exec" | "process" | "shell" | "network" | "env_config_access" | "file_write"
            )
    });
    let has_risky_install = install_analysis.install_specs.iter().any(|spec| {
        spec.auto_install
            || spec.executes_after_download
            || spec.url.is_some() && !spec.checksum_present
    });
    let has_secret_binding = !openclaw_config.risky_bindings.is_empty();

    if has_direct_authority || has_risky_install || has_secret_binding {
        let mut observed = Vec::new();
        if has_direct_authority {
            observed.push("inferred direct authority");
        }
        if has_risky_install {
            observed.push("risky install/source behavior");
        }
        if has_secret_binding {
            observed.push("config/env secret binding");
        }
        mismatches.push(ClaimObservation {
            claim: compact(claim),
            claim_source: claim_source.to_string(),
            observed_signal: observed.join(", "),
            status: "low_risk_claim_conflicts_with_authority".to_string(),
            review_question: format!("`{path}` 的低风险叙事是否和实际权限/安装/密钥证据一致？"),
        });
    }
}

fn build_findings(mismatches: &[ClaimObservation]) -> Vec<Finding> {
    mismatches
        .iter()
        .enumerate()
        .map(|(index, mismatch)| Finding {
            id: format!("claims_review.mismatch.{:03}", index + 1),
            title: "Declared skill claim does not align with observed evidence".to_string(),
            issue_code: Some("OCSG-CLAIM-001".to_string()),
            title_zh: Some("skill 自称能力与实际证据不一致".to_string()),
            category: "claims_review.mismatch".to_string(),
            severity: if mismatch.status == "missing_or_weak_metadata" {
                FindingSeverity::Low
            } else {
                FindingSeverity::Medium
            },
            confidence: FindingConfidence::Medium,
            hard_trigger: false,
            evidence_kind: "claims_vs_observed".to_string(),
            location: Some(SkillLocation {
                path: mismatch.claim_source.clone(),
                line: None,
                column: None,
            }),
            evidence: vec![EvidenceNode {
                kind: EvidenceKind::Inference,
                location: SkillLocation {
                    path: mismatch.claim_source.clone(),
                    line: None,
                    column: None,
                },
                excerpt: format!("{} => {}", mismatch.claim, mismatch.observed_signal),
                direct: false,
            }],
            explanation: format!(
                "Declared claim `{}` conflicts with observed signal `{}`.",
                mismatch.claim, mismatch.observed_signal
            ),
            explanation_zh: Some(format!(
                "声明 `{}` 与实际证据 `{}` 不一致，需要安装前复核。",
                mismatch.claim, mismatch.observed_signal
            )),
            why_openclaw_specific:
                "OpenClaw users decide whether to install a skill from human-readable claims plus structured metadata; mismatches can hide actual delegated authority."
                    .to_string(),
            prerequisite_context: vec![
                "The mismatch is derived from existing OpenClaw metadata, install, capability, config, source, or URL evidence."
                    .to_string(),
            ],
            analyst_notes: vec![
                "This layer aggregates existing evidence and does not introduce a second scoring system."
                    .to_string(),
                format!("Review question: {}", mismatch.review_question),
            ],
            remediation:
                "Align README/frontmatter claims with actual permissions, install sources, and configuration requirements."
                    .to_string(),
            recommendation_zh: Some(
                "让 README/frontmatter 声明与实际权限、安装来源、配置依赖保持一致；不一致时先人工确认。"
                    .to_string(),
            ),
            suppression_status: "active".to_string(),
        })
        .collect()
}

fn build_review_questions(mismatches: &[ClaimObservation]) -> Vec<String> {
    let mut questions: Vec<String> = mismatches
        .iter()
        .map(|mismatch| mismatch.review_question.clone())
        .collect();
    if questions.is_empty() {
        questions.push("声明、metadata、安装来源和权限证据是否仍然和预期一致？".to_string());
    }
    questions
}

fn low_risk_claim(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("read-only")
        || lower.contains("readonly")
        || lower.contains("analysis only")
        || lower.contains("does not execute")
        || lower.contains("no network")
        || text.contains("只读")
        || text.contains("仅分析")
        || text.contains("不会执行")
        || text.contains("不联网")
}

fn compact(input: &str) -> String {
    let trimmed = input.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.chars().count() > 180 {
        format!("{}...", trimmed.chars().take(180).collect::<String>())
    } else {
        trimmed
    }
}

#[cfg(test)]
mod tests {
    use super::analyze_claims_review;
    use crate::install::InstallAnalysis;
    use crate::types::{
        CapabilityManifestEntry, CapabilityManifestSummary, FrontmatterParseResult,
        InvocationDispatch, InvocationPolicy, OpenClawConfigAuditSummary, OpenClawMetadata,
        ParsedSkill, RequiresSpec, SkillDescriptor, SkillSource,
    };

    #[test]
    fn detects_low_risk_claim_conflict() {
        let skill = ParsedSkill {
            descriptor: SkillDescriptor {
                name: Some("demo".to_string()),
                description: Some("Read-only analysis helper".to_string()),
                homepage: None,
                directory_name: None,
                slug_candidates: Vec::new(),
            },
            skill_file: "SKILL.md".to_string(),
            skill_root: ".".to_string(),
            body: "This is read-only.".to_string(),
            frontmatter: FrontmatterParseResult {
                present: true,
                parsed: true,
                raw_block: None,
                fields: Default::default(),
                diagnostics: Vec::new(),
            },
            raw_metadata: None,
            invocation_policy: InvocationPolicy {
                user_invocable: true,
                disable_model_invocation: false,
                command_dispatch: InvocationDispatch::None,
                command_tool: None,
                command_arg_mode: None,
                notes: Vec::new(),
            },
            metadata: OpenClawMetadata {
                present: false,
                normalized: false,
                homepage: None,
                skill_key: None,
                primary_env: None,
                requires: RequiresSpec::default(),
                install: Vec::new(),
                notes: Vec::new(),
            },
            additional_files: Vec::new(),
            source: SkillSource::Unknown,
            notes: Vec::new(),
        };
        let capability = CapabilityManifestSummary {
            entries: vec![CapabilityManifestEntry {
                capability: "exec".to_string(),
                status: "inferred".to_string(),
                source: "tool reachability".to_string(),
                rationale: "shell tool referenced".to_string(),
            }],
            ..Default::default()
        };

        let analysis = analyze_claims_review(
            &[skill],
            &capability,
            &InstallAnalysis {
                install_specs: Vec::new(),
                findings: Vec::new(),
                summary: String::new(),
            },
            &OpenClawConfigAuditSummary::default(),
            &Default::default(),
            &[],
        );

        assert!(!analysis.summary.mismatches.is_empty());
        assert_eq!(
            analysis.findings[0].issue_code.as_deref(),
            Some("OCSG-CLAIM-001")
        );
    }
}
