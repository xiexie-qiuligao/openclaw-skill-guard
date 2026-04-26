use std::path::Path;

use crate::types::{
    EvidenceKind, EvidenceNode, Finding, FindingConfidence, FindingSeverity,
    OpenClawConfigAuditSummary, ProvenanceNote, SkillLocation, TextArtifact,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenClawConfigAuditAnalysis {
    pub summary: OpenClawConfigAuditSummary,
    pub findings: Vec<Finding>,
    pub provenance_notes: Vec<ProvenanceNote>,
}

pub fn analyze_openclaw_config(documents: &[TextArtifact]) -> OpenClawConfigAuditAnalysis {
    let mut findings = Vec::new();
    let mut config_files = Vec::new();
    let mut explicit_dependencies = Vec::new();
    let mut risky_bindings = Vec::new();
    let mut provenance_notes = Vec::new();

    for document in documents {
        if looks_like_openclaw_config(&document.path, &document.content) {
            config_files.push(document.path.clone());
        }

        for (index, line) in document.content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            let line_number = index + 1;
            if contains_skill_env_binding(trimmed) {
                explicit_dependencies
                    .push(format!("{}: skills.entries env binding", document.path));
                risky_bindings.push("skills.entries.*.env".to_string());
                findings.push(make_config_finding(
                    "openclaw_config.secret_binding",
                    "OpenClaw skill config exposes a host env binding surface",
                    FindingSeverity::Medium,
                    FindingConfidence::High,
                    document,
                    line_number,
                    trimmed,
                    "The scanned content references `skills.entries.*.env`, which can bind per-skill environment values into the OpenClaw host process for a run.",
                    "Move secrets to documented SecretRef-style configuration and review whether this skill really needs host environment access.",
                ));
            }

            if contains_api_key_binding(trimmed) {
                let plaintext_like = !trimmed.to_ascii_lowercase().contains("secretref")
                    && !trimmed.contains("${")
                    && !trimmed.contains("<");
                let severity = if plaintext_like {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                };
                explicit_dependencies
                    .push(format!("{}: skills.entries apiKey binding", document.path));
                risky_bindings.push("skills.entries.*.apiKey".to_string());
                findings.push(make_config_finding(
                    if plaintext_like {
                        "openclaw_config.plaintext_api_key"
                    } else {
                        "openclaw_config.api_key_binding"
                    },
                    if plaintext_like {
                        "OpenClaw skill config may contain a plaintext apiKey binding"
                    } else {
                        "OpenClaw skill config declares an apiKey binding"
                    },
                    severity,
                    FindingConfidence::High,
                    document,
                    line_number,
                    trimmed,
                    "The scanned content references `skills.entries.*.apiKey`. In OpenClaw this is a host-side secret injection surface, not just descriptive metadata.",
                    "Use indirection for secret material, avoid committing real values, and verify the related skill's tool and egress reachability.",
                ));
            }

            if let Some(name) = dangerous_env_name(trimmed) {
                risky_bindings.push(name.clone());
                findings.push(make_config_finding(
                    "openclaw_config.dangerous_env_override",
                    "Control-plane config references a dangerous environment override",
                    FindingSeverity::High,
                    FindingConfidence::High,
                    document,
                    line_number,
                    trimmed,
                    &format!(
                        "The content references `{name}`, an environment name that can alter OpenClaw, interpreter startup, or host control-plane behavior."
                    ),
                    "Remove this override unless it is a documented, reviewed, and narrowly scoped administrative configuration.",
                ));
            }

            if contains_extra_dirs(trimmed) {
                risky_bindings.push("skills.load.extraDirs".to_string());
                findings.push(make_config_finding(
                    "openclaw_config.extra_dir_trust_expansion",
                    "OpenClaw skill loading expands to extra directories",
                    FindingSeverity::Medium,
                    FindingConfidence::Medium,
                    document,
                    line_number,
                    trimmed,
                    "`skills.load.extraDirs` can introduce additional low-precedence skill roots; broad or unreviewed paths can change the effective skill supply chain.",
                    "Keep extra skill roots narrow, reviewed, and separate from untrusted workspace content.",
                ));
            }

            if contains_sandbox_disabled(trimmed) {
                risky_bindings.push("sandbox disabled".to_string());
                findings.push(make_config_finding(
                    "openclaw_config.sandbox_disabled",
                    "OpenClaw sandboxing appears disabled or bypassed",
                    FindingSeverity::Medium,
                    FindingConfidence::Medium,
                    document,
                    line_number,
                    trimmed,
                    "The scanned content suggests sandbox execution may be disabled. That changes OpenClaw risk from sandbox-contained to host-reachable.",
                    "Prefer sandboxed execution for untrusted skills and record any host-only exception explicitly.",
                ));
            }

            if contains_elevated_execution(trimmed) {
                risky_bindings.push("elevated execution".to_string());
                findings.push(make_config_finding(
                    "openclaw_config.elevated_execution",
                    "OpenClaw control-plane content references elevated execution",
                    FindingSeverity::High,
                    FindingConfidence::Medium,
                    document,
                    line_number,
                    trimmed,
                    "Elevated execution can bypass normal sandbox expectations and materially changes host-side consequences.",
                    "Avoid elevated execution for skill workflows unless there is a reviewed administrative requirement.",
                ));
            }

            if contains_config_mutation_instruction(trimmed) {
                findings.push(make_config_finding(
                    "openclaw_config.control_plane_mutation",
                    "Skill content instructs mutation of OpenClaw control-plane configuration",
                    FindingSeverity::High,
                    FindingConfidence::Medium,
                    document,
                    line_number,
                    trimmed,
                    "The text tells the operator or agent to edit OpenClaw config, env, trust roots, sandbox policy, or gateway/tool settings. Configuration mutation is an OpenClaw control-plane authority surface.",
                    "Separate setup documentation from runtime skill instructions and require human review for config or trust-boundary changes.",
                ));
            }
        }
    }

    config_files.sort();
    config_files.dedup();
    explicit_dependencies.sort();
    explicit_dependencies.dedup();
    risky_bindings.sort();
    risky_bindings.dedup();

    for binding in &risky_bindings {
        provenance_notes.push(ProvenanceNote {
            subject_id: format!("openclaw_config.{binding}"),
            subject_kind: "openclaw_config_signal".to_string(),
            source_layer: "local_config_or_text".to_string(),
            evidence_sources: config_files.clone(),
            inferred_sources: Vec::new(),
            recent_signal_class: "v3_control_plane_audit".to_string(),
            long_term_pattern: "OpenClaw config and host secret/control-plane surfaces".to_string(),
            note: format!("Control-plane audit observed `{binding}` in scanned local evidence."),
        });
    }

    OpenClawConfigAuditAnalysis {
        summary: OpenClawConfigAuditSummary {
            summary: if findings.is_empty() {
                "No OpenClaw config/control-plane audit findings were generated from local evidence."
                    .to_string()
            } else {
                format!(
                    "OpenClaw config/control-plane audit generated {} finding(s) from local evidence.",
                    findings.len()
                )
            },
            config_files_discovered: config_files,
            explicit_dependencies,
            risky_bindings,
            findings_count: findings.len(),
            notes: vec![
                "Config audit is local and static; it does not mutate OpenClaw configuration or execute installer paths.".to_string(),
                "Host-side env/apiKey bindings are treated as control-plane evidence because they can change skill authority without appearing in SKILL.md body text.".to_string(),
            ],
        },
        findings,
        provenance_notes,
    }
}

fn looks_like_openclaw_config(path: &str, content: &str) -> bool {
    let file_name = Path::new(path)
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    file_name == "openclaw.json"
        || file_name == "settings.json"
        || path.to_ascii_lowercase().contains(".openclaw")
        || content.contains("skills.entries")
        || content.contains("skills.load")
}

fn contains_skill_env_binding(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    (lower.contains("skills.entries") && lower.contains(".env"))
        || (lower.contains("\"env\"") && lower.contains("skills"))
}

fn contains_api_key_binding(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("apikey") || lower.contains("api_key")
}

fn dangerous_env_name(line: &str) -> Option<String> {
    let upper = line.to_ascii_uppercase();
    for name in [
        "NODE_OPTIONS",
        "OPENCLAW_",
        "MINIMAX_API_HOST",
        "PYTHONPATH",
        "BASH_ENV",
        "ENV=",
    ] {
        if upper.contains(name) {
            return Some(name.trim_end_matches('=').to_string());
        }
    }
    None
}

fn contains_extra_dirs(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("skills.load.extradirs") || lower.contains("extradirs")
}

fn contains_sandbox_disabled(line: &str) -> bool {
    let lower = line.to_ascii_lowercase().replace(' ', "");
    lower.contains("\"sandbox\":false")
        || lower.contains("sandbox.enabled=false")
        || lower.contains("disable-sandbox")
        || lower.contains("sandbox:false")
}

fn contains_elevated_execution(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("elevated")
        || lower.contains("dangerously")
        || lower.contains("force unsafe")
        || lower.contains("unsafe-install")
}

fn contains_config_mutation_instruction(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let mentions_control_plane = lower.contains("openclaw.json")
        || lower.contains("skills.entries")
        || lower.contains("skills.load")
        || lower.contains("gateway config")
        || lower.contains("sandbox policy")
        || lower.contains("trust root");
    let mutates = lower.contains("edit")
        || lower.contains("modify")
        || lower.contains("patch")
        || lower.contains("overwrite")
        || lower.contains("set ")
        || lower.contains("append");
    mentions_control_plane && mutates
}

fn make_config_finding(
    id: &str,
    title: &str,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    document: &TextArtifact,
    line: usize,
    excerpt: &str,
    explanation: &str,
    remediation: &str,
) -> Finding {
    let location = SkillLocation {
        path: document.path.clone(),
        line: Some(line),
        column: None,
    };
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        category: id.to_string(),
        severity,
        confidence,
        hard_trigger: false,
        evidence_kind: "structured_config_or_text".to_string(),
        location: Some(location.clone()),
        evidence: vec![EvidenceNode {
            kind: EvidenceKind::RuntimeContext,
            location,
            excerpt: excerpt.to_string(),
            direct: true,
        }],
        explanation: explanation.to_string(),
        why_openclaw_specific: "OpenClaw config can grant host env/API key access, alter skill loading, or change sandbox/tool authority outside the visible SKILL.md body.".to_string(),
        prerequisite_context: vec![
            "The signal came from local scanned text or config evidence.".to_string(),
            "The analyzer is static and does not execute or mutate OpenClaw configuration.".to_string(),
        ],
        analyst_notes: vec![
            "Review whether the referenced config is operational or only documentation.".to_string(),
            "If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.".to_string(),
        ],
        remediation: remediation.to_string(),
        suppression_status: "not_suppressed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::analyze_openclaw_config;
    use crate::types::TextArtifact;

    #[test]
    fn detects_host_secret_binding_and_dangerous_env() {
        let analysis = analyze_openclaw_config(&[TextArtifact {
            path: "openclaw.json".to_string(),
            content: r#"{"skills":{"entries":{"demo":{"apiKey":"fake-key","env":{"NODE_OPTIONS":"--require ./x.js"}}}}}"#.to_string(),
        }]);

        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "openclaw_config.plaintext_api_key"));
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "openclaw_config.dangerous_env_override"));
        assert!(!analysis.summary.risky_bindings.is_empty());
    }
}
