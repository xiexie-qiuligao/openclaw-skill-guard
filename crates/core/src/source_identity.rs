use std::collections::BTreeSet;

use serde_json::Value;

use crate::install::InstallAnalysis;
use crate::types::{
    EvidenceKind, EvidenceNode, ExternalReference, ExternalReferenceReputation, Finding,
    FindingConfidence, FindingSeverity, ParsedSkill, SkillLocation, SourceIdentitySignal,
    SourceIdentitySummary, TextArtifact,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceIdentityAnalysis {
    pub summary: SourceIdentitySummary,
    pub findings: Vec<Finding>,
}

pub fn analyze_source_identity(
    skills: &[ParsedSkill],
    documents: &[TextArtifact],
    install: &InstallAnalysis,
    external_references: &[ExternalReference],
) -> SourceIdentityAnalysis {
    let mut findings = Vec::new();
    let mut signals = Vec::new();
    let mut identity_surfaces = BTreeSet::new();

    for skill in skills {
        if let Some(name) = &skill.descriptor.name {
            identity_surfaces.insert(format!("skill name: {name}"));
        }
        if let Some(homepage) = skill
            .metadata
            .homepage
            .as_ref()
            .or(skill.descriptor.homepage.as_ref())
        {
            identity_surfaces.insert(format!("homepage: {homepage}"));
        }
        if let Some(skill_key) = &skill.metadata.skill_key {
            identity_surfaces.insert(format!("skillKey: {skill_key}"));
        }
    }

    let homepage_hosts = skills
        .iter()
        .filter_map(|skill| {
            skill
                .metadata
                .homepage
                .as_ref()
                .or(skill.descriptor.homepage.as_ref())
                .and_then(|url| extract_host(url))
        })
        .collect::<BTreeSet<_>>();

    let install_hosts = install
        .install_specs
        .iter()
        .filter_map(|spec| spec.url.as_ref().and_then(|url| extract_host(url)))
        .collect::<BTreeSet<_>>();

    for homepage_host in &homepage_hosts {
        for install_host in &install_hosts {
            if !hosts_are_related(homepage_host, install_host) {
                let signal = SourceIdentitySignal {
                    signal_id: "source_identity.homepage_install_mismatch".to_string(),
                    signal_kind: "homepage_install_mismatch".to_string(),
                    summary: format!(
                        "Homepage host `{homepage_host}` differs from install/download host `{install_host}`."
                    ),
                    evidence: vec![homepage_host.clone(), install_host.clone()],
                };
                signals.push(signal.clone());
                if let Some(skill) = skills.first() {
                    findings.push(make_identity_finding(
                        "source_identity.homepage_install_mismatch",
                        "Skill homepage and install source point to different identities",
                        FindingSeverity::Medium,
                        FindingConfidence::Medium,
                        &skill.skill_file,
                        1,
                        &signal.summary,
                        "The advertised homepage/source identity does not align with the host used by install metadata. This may be legitimate, but it requires review before trusting the install path.",
                        "Align homepage, repository, and installer sources, or document why the installer must pull from a different host.",
                    ));
                }
            }
        }
    }

    for document in documents {
        if let Some(repository_url) = package_repository_url(document) {
            if let Some(repo_host) = extract_host(&repository_url) {
                identity_surfaces.insert(format!("package repository: {repository_url}"));
                for homepage_host in &homepage_hosts {
                    if !hosts_are_related(homepage_host, &repo_host) {
                        let summary = format!(
                            "Package repository host `{repo_host}` differs from skill homepage host `{homepage_host}`."
                        );
                        signals.push(SourceIdentitySignal {
                            signal_id: "source_identity.package_repository_mismatch".to_string(),
                            signal_kind: "package_repository_mismatch".to_string(),
                            summary: summary.clone(),
                            evidence: vec![repository_url.clone(), homepage_host.clone()],
                        });
                        findings.push(make_identity_finding(
                            "source_identity.package_repository_mismatch",
                            "Package manifest repository differs from advertised skill identity",
                            FindingSeverity::Medium,
                            FindingConfidence::Medium,
                            &document.path,
                            1,
                            &repository_url,
                            &summary,
                            "Keep package manifests, homepage metadata, and install sources aligned so reviewers can verify provenance locally.",
                        ));
                    }
                }
            }
        }

        for (line_number, line) in document.content.lines().enumerate() {
            let trimmed = line.trim();
            if claims_official_identity(trimmed)
                && external_references.iter().any(|reference| {
                    reference.reputation == ExternalReferenceReputation::ReviewNeeded
                        || reference.reputation == ExternalReferenceReputation::Suspicious
                })
            {
                let summary = "Document claims official or trusted identity while the scan found review-needed or suspicious source references.".to_string();
                signals.push(SourceIdentitySignal {
                    signal_id: "source_identity.official_claim_weak_source".to_string(),
                    signal_kind: "official_claim_weak_source".to_string(),
                    summary: summary.clone(),
                    evidence: vec![trimmed.to_string()],
                });
                findings.push(make_identity_finding(
                    "source_identity.official_claim_weak_source",
                    "Trusted-looking identity narrative conflicts with weak source evidence",
                    FindingSeverity::Medium,
                    FindingConfidence::Medium,
                    &document.path,
                    line_number + 1,
                    trimmed,
                    &summary,
                    "Avoid official or trusted wording unless source identity is locally verifiable and aligned with install/download references.",
                ));
            }

            if let Some(script_ref) = referenced_local_script(trimmed) {
                if !documents
                    .iter()
                    .any(|candidate| path_ends_with(&candidate.path, &script_ref))
                {
                    let summary = format!(
                        "Documentation references local script `{script_ref}`, but no matching scanned file was found."
                    );
                    signals.push(SourceIdentitySignal {
                        signal_id: "source_identity.claimed_script_missing".to_string(),
                        signal_kind: "claimed_script_missing".to_string(),
                        summary: summary.clone(),
                        evidence: vec![trimmed.to_string()],
                    });
                    findings.push(make_identity_finding(
                        "source_identity.claimed_script_missing",
                        "Documentation references a local helper that is missing from the scanned package",
                        FindingSeverity::Low,
                        FindingConfidence::Medium,
                        &document.path,
                        line_number + 1,
                        trimmed,
                        &summary,
                        "Ship referenced helper scripts with the skill package or remove instructions that rely on absent local files.",
                    ));
                }
            }
        }
    }

    let notes = vec![
        "Source identity checks are offline and explainable; they do not query registries or reputation APIs.".to_string(),
        "Mismatches require review rather than proving impersonation.".to_string(),
    ];

    SourceIdentityAnalysis {
        summary: SourceIdentitySummary {
            summary: if signals.is_empty() {
                "No offline source identity mismatch signals were generated from local evidence."
                    .to_string()
            } else {
                format!(
                    "Generated {} offline source identity signal(s), including {} finding(s).",
                    signals.len(),
                    findings.len()
                )
            },
            identity_surfaces: identity_surfaces.into_iter().collect(),
            mismatch_count: signals.len(),
            signals,
            notes,
        },
        findings,
    }
}

fn package_repository_url(document: &TextArtifact) -> Option<String> {
    if !document.path.to_ascii_lowercase().ends_with("package.json") {
        return None;
    }
    let value = serde_json::from_str::<Value>(&document.content).ok()?;
    match value.get("repository") {
        Some(Value::String(url)) => Some(url.clone()),
        Some(Value::Object(object)) => object
            .get("url")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        _ => None,
    }
}

fn claims_official_identity(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("official")
        || lower.contains("verified")
        || lower.contains("trusted")
        || lower.contains("authentic")
}

fn referenced_local_script(line: &str) -> Option<String> {
    for token in line.split_whitespace() {
        let cleaned = token.trim_matches(|ch: char| {
            ch == '`' || ch == '\'' || ch == '"' || ch == ',' || ch == ')' || ch == '('
        });
        let lower = cleaned.to_ascii_lowercase();
        if (lower.starts_with("scripts/") || lower.starts_with("./scripts/"))
            && (lower.ends_with(".sh")
                || lower.ends_with(".ps1")
                || lower.ends_with(".py")
                || lower.ends_with(".js")
                || lower.ends_with(".mjs"))
        {
            return Some(cleaned.trim_start_matches("./").to_string());
        }
    }
    None
}

fn path_ends_with(path: &str, suffix: &str) -> bool {
    let normalized_path = path.replace('\\', "/").to_ascii_lowercase();
    let normalized_suffix = suffix.replace('\\', "/").to_ascii_lowercase();
    normalized_path.ends_with(&normalized_suffix)
}

fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(url)
        .trim_start_matches("git+");
    let host_port = after_scheme.split('/').next()?.split('@').next_back()?;
    let host = host_port.split(':').next()?.trim().to_ascii_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

fn hosts_are_related(left: &str, right: &str) -> bool {
    left == right
        || left.ends_with(&format!(".{right}"))
        || right.ends_with(&format!(".{left}"))
        || (left == "github.com" && right == "raw.githubusercontent.com")
        || (right == "github.com" && left == "raw.githubusercontent.com")
        || (left == "github.com" && right == "gist.githubusercontent.com")
        || (right == "github.com" && left == "gist.githubusercontent.com")
}

fn make_identity_finding(
    id: &str,
    title: &str,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    path: &str,
    line: usize,
    excerpt: &str,
    explanation: &str,
    remediation: &str,
) -> Finding {
    let location = SkillLocation {
        path: path.to_string(),
        line: Some(line),
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
        evidence_kind: "source_identity".to_string(),
        location: Some(location.clone()),
        evidence: vec![EvidenceNode {
            kind: EvidenceKind::Inference,
            location,
            excerpt: excerpt.to_string(),
            direct: false,
        }],
        explanation: explanation.to_string(),
        explanation_zh: None,
        why_openclaw_specific: "OpenClaw skills rely on local metadata, companion docs, install sources, and workspace install identity. Mismatch across those surfaces can mislead review even when no payload is executed.".to_string(),
        prerequisite_context: vec![
            "The finding is based only on local source, package, URL, and metadata evidence.".to_string(),
            "It is a review-needed mismatch, not an online reputation verdict.".to_string(),
        ],
        analyst_notes: vec![
            "Check whether the mismatch is an expected CDN/package-host split or an unexplained identity drift.".to_string(),
        ],
        remediation: remediation.to_string(),
        recommendation_zh: None,
        suppression_status: "not_suppressed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::analyze_source_identity;
    use crate::install::InstallAnalysis;
    use crate::skill_parse::parse_skill_file;
    use crate::types::{InstallKind, InstallSpec, TextArtifact};

    #[test]
    fn detects_homepage_install_mismatch() {
        let skill = parse_skill_file(
            std::path::Path::new("SKILL.md"),
            "---\nmetadata: {\"openclaw\":{\"homepage\":\"https://github.com/example/demo\"}}\n---\n",
            Vec::new(),
        );
        let analysis = analyze_source_identity(
            &[skill],
            &[TextArtifact {
                path: "SKILL.md".to_string(),
                content: String::new(),
            }],
            &InstallAnalysis {
                install_specs: vec![InstallSpec {
                    kind: InstallKind::Download,
                    source: "metadata.openclaw.install".to_string(),
                    source_path: "SKILL.md".to_string(),
                    raw: "download".to_string(),
                    package: None,
                    url: Some("https://downloads.example.invalid/tool.zip".to_string()),
                    checksum_present: false,
                    auto_install: true,
                    executes_after_download: false,
                }],
                findings: Vec::new(),
                summary: String::new(),
            },
            &[],
        );

        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "source_identity.homepage_install_mismatch"));
    }
}
