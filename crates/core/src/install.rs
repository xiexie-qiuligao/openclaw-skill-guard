use regex::Regex;

use crate::normalize::build_scan_lines;
use crate::types::{
    EvidenceKind, EvidenceNode, Finding, FindingConfidence, FindingSeverity, InstallKind,
    InstallSpec, ParsedSkill, SkillLocation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallAnalysis {
    pub install_specs: Vec<InstallSpec>,
    pub findings: Vec<Finding>,
    pub summary: String,
}

pub fn analyze_install_chain(skill: &ParsedSkill) -> InstallAnalysis {
    let mut specs = skill.metadata.install.clone();
    let mut findings = analyze_metadata_install_specs(skill, &specs);

    let manual_specs = extract_manual_install_specs(skill);
    findings.extend(analyze_manual_specs(skill, &manual_specs));
    specs.extend(manual_specs);

    let summary = if specs.is_empty() {
        "No install metadata or high-confidence manual install patterns were extracted.".to_string()
    } else {
        format!(
            "Extracted {} install signals (metadata + manual instructions) from {}.",
            specs.len(),
            skill.skill_file
        )
    };

    InstallAnalysis {
        install_specs: specs,
        findings,
        summary,
    }
}

fn analyze_metadata_install_specs(skill: &ParsedSkill, specs: &[InstallSpec]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for spec in specs {
        if spec.kind == InstallKind::Download && !spec.checksum_present {
            findings.push(make_install_finding(
                "context.install.origin_integrity",
                "Download install spec without integrity control",
                "origin_integrity_risk",
                FindingSeverity::High,
                FindingConfidence::High,
                false,
                &skill.skill_file,
                1,
                &spec.raw,
                "A download-based install spec does not declare checksum, digest, or equivalent integrity control.",
                "OpenClaw installer metadata can execute on the gateway-host path, so unauthenticated download specs are more dangerous than ordinary documentation snippets.",
                "Add checksum or digest validation and prefer pinned trusted origins.",
            ));
        }

        if spec.kind == InstallKind::Download && spec.executes_after_download {
            findings.push(make_install_finding(
                "context.install.auto_remote_execution",
                "Installer metadata can download and execute content",
                "auto_install_risk",
                FindingSeverity::Critical,
                FindingConfidence::High,
                true,
                &skill.skill_file,
                1,
                &spec.raw,
                "The install metadata represents a download step that is followed by execution.",
                "OpenClaw metadata.openclaw.install can run through installer paths instead of remaining documentation-only.",
                "Replace download-and-execute behavior with reviewed local scripts or signed artifacts.",
            ));
        }

        if matches!(
            spec.kind,
            InstallKind::Node | InstallKind::Go | InstallKind::Uv
        ) && spec.package.is_some()
        {
            findings.push(make_install_finding(
                "context.install.supply_chain",
                "Installer metadata pulls an external package dependency",
                "supply_chain_risk",
                FindingSeverity::Medium,
                FindingConfidence::Medium,
                false,
                &skill.skill_file,
                1,
                &spec.raw,
                "The install spec pulls a package-manager dependency and may rely on mutable upstream state.",
                "OpenClaw installer flows can transform package metadata into real host-side installation steps.",
                "Pin exact versions and document provenance or integrity expectations.",
            ));
        }
    }

    findings
}

fn extract_manual_install_specs(skill: &ParsedSkill) -> Vec<InstallSpec> {
    let patterns: [(InstallKind, &str); 6] = [
        (InstallKind::Brew, r"(?i)\bbrew\s+install\b"),
        (
            InstallKind::Node,
            r"(?i)\b(?:npm|pnpm|yarn|bun)\s+(?:install|add)\b",
        ),
        (InstallKind::Go, r"(?i)\bgo\s+install\b"),
        (
            InstallKind::Uv,
            r"(?i)\buv\s+(?:tool\s+install|pip\s+install)\b",
        ),
        (
            InstallKind::Download,
            r"(?i)\b(?:curl|wget|iwr|invoke-webrequest|certutil|bitsadmin)\b",
        ),
        (
            InstallKind::ManualCommand,
            r"(?i)\b(?:powershell(?:\.exe)?\b.*(?:-enc|-encodedcommand)\b|base64\b.*(?:-d|--decode)\b.*(?:\||;)\s*(?:sh|bash)\b|(?:mshta|regsvr32|rundll32)\b)",
        ),
    ];

    let lines = build_scan_lines(&skill.body);
    let mut specs = Vec::new();

    for line in lines {
        for (kind, pattern) in patterns {
            let regex = Regex::new(pattern).unwrap();
            if !regex.is_match(&line.text) {
                continue;
            }

            specs.push(InstallSpec {
                kind,
                source: "skill_body".to_string(),
                source_path: skill.skill_file.clone(),
                raw: line.text.clone(),
                package: extract_package(&line.text),
                url: extract_url(&line.text),
                checksum_present: has_integrity_marker(&line.text),
                auto_install: false,
                executes_after_download: looks_like_execute_after_download(&line.text),
            });
            break;
        }
    }

    specs
}

fn analyze_manual_specs(skill: &ParsedSkill, specs: &[InstallSpec]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for spec in specs {
        if looks_like_remote_script(&spec.raw) || spec.executes_after_download {
            findings.push(make_install_finding(
                "context.install.manual_remote_execution",
                "Manual install instruction downloads and executes remote content",
                "manual_execution_risk",
                FindingSeverity::High,
                FindingConfidence::High,
                false,
                &skill.skill_file,
                1,
                &spec.raw,
                "The skill body includes a manual command that downloads content and executes it directly.",
                "In OpenClaw skills, documentation commands are part of the operator-facing install surface and can influence real setup behavior.",
                "Replace remote execution snippets with reviewed local scripts or pinned artifacts.",
            ));
        } else if matches!(
            spec.kind,
            InstallKind::Brew | InstallKind::Node | InstallKind::Go | InstallKind::Uv
        ) && !spec.checksum_present
        {
            findings.push(make_install_finding(
                "context.install.manual_supply_chain",
                "Manual package-manager install instruction",
                "supply_chain_risk",
                FindingSeverity::Medium,
                FindingConfidence::Medium,
                false,
                &skill.skill_file,
                1,
                &spec.raw,
                "The skill body instructs operators to install external dependencies through a package manager.",
                "OpenClaw skills frequently ship setup instructions inside SKILL.md, so manual package pulls are part of the real attack surface.",
                "Pin versions and document trusted provenance for package-manager dependencies.",
            ));
        }
    }

    findings
}

fn extract_package(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|token| {
            token.contains('@')
                || token.contains('/')
                || token
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
        })
        .map(ToString::to_string)
}

fn extract_url(line: &str) -> Option<String> {
    Regex::new(r#"https?://[^\s"'`)]+"#)
        .unwrap()
        .find(line)
        .map(|match_| match_.as_str().to_string())
}

fn has_integrity_marker(line: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    lowered.contains("sha256")
        || lowered.contains("checksum")
        || lowered.contains("digest")
        || lowered.contains("--hash")
}

fn looks_like_execute_after_download(line: &str) -> bool {
    looks_like_remote_script(line)
        || Regex::new(r"(?i)\bbase64\b[^\n]*(?:-d|--decode)\b[^\n]*(?:\||;)\s*(?:sh|bash)\b")
            .unwrap()
            .is_match(line)
        || Regex::new(r"(?i)\bpowershell(?:\.exe)?\b[^\n]*(?:-enc|-encodedcommand)\b")
            .unwrap()
            .is_match(line)
}

fn looks_like_remote_script(line: &str) -> bool {
    Regex::new(r"(?i)\b(?:curl|wget)\b[^\n]*(?:\||;)\s*(?:sh|bash)\b")
        .unwrap()
        .is_match(line)
        || Regex::new(
            r"(?i)\b(?:iwr|invoke-webrequest)\b[^\n]*(?:\||;)\s*(?:iex|invoke-expression)\b",
        )
        .unwrap()
        .is_match(line)
}

fn make_install_finding(
    id: &str,
    title: &str,
    category: &str,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    hard_trigger: bool,
    path: &str,
    line: usize,
    excerpt: &str,
    explanation: &str,
    why_openclaw_specific: &str,
    remediation: &str,
) -> Finding {
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        category: category.to_string(),
        severity,
        confidence,
        hard_trigger,
        evidence_kind: "install_action".to_string(),
        location: Some(SkillLocation {
            path: path.to_string(),
            line: Some(line),
            column: None,
        }),
        evidence: vec![EvidenceNode {
            kind: EvidenceKind::InstallAction,
            location: SkillLocation {
                path: path.to_string(),
                line: Some(line),
                column: None,
            },
            excerpt: excerpt.to_string(),
            direct: true,
        }],
        explanation: explanation.to_string(),
        why_openclaw_specific: why_openclaw_specific.to_string(),
        prerequisite_context: vec!["The install signal was extracted from structured metadata or high-confidence setup instructions.".to_string()],
        analyst_notes: vec!["Install-chain analysis distinguishes metadata-driven install behavior from manual copy-paste setup guidance.".to_string()],
        remediation: remediation.to_string(),
        suppression_status: "not_suppressed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::skill_parse::parse_skill_file;

    use super::analyze_install_chain;

    #[test]
    fn extracts_metadata_install_specs_and_findings() {
        let skill = parse_skill_file(
            Path::new("demo/SKILL.md"),
            "---\nmetadata: {\"openclaw\":{\"install\":[{\"kind\":\"download\",\"url\":\"https://example.invalid/tool.zip\",\"execute\":true}]}}\n---\nBody",
            Vec::new(),
        );

        let analysis = analyze_install_chain(&skill);

        assert_eq!(analysis.install_specs.len(), 1);
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "context.install.auto_remote_execution"));
    }
}
