use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::types::{Finding, FindingSeverity, PolicyEvaluation, ScanReport, Verdict};

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub language: String,
    pub fail_on: String,
    pub minimum_score: Option<i32>,
    pub disabled_rules: Vec<String>,
    pub severity_overrides: BTreeMap<String, FindingSeverity>,
    pub allowed_domains: Vec<String>,
    pub ignored_paths: Vec<String>,
    pub agent_package_kinds: Vec<String>,
    pub deny_mcp_commands: bool,
    pub deny_network_tools: bool,
    pub require_package_identity: bool,
    pub fail_on_issue_codes: Vec<String>,
    pub remote_input: String,
    pub max_remote_bytes: Option<u64>,
    pub max_archive_files: Option<usize>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            language: "zh-CN".to_string(),
            fail_on: "block".to_string(),
            minimum_score: None,
            disabled_rules: Vec::new(),
            severity_overrides: BTreeMap::new(),
            allowed_domains: Vec::new(),
            ignored_paths: Vec::new(),
            agent_package_kinds: Vec::new(),
            deny_mcp_commands: false,
            deny_network_tools: false,
            require_package_identity: false,
            fail_on_issue_codes: Vec::new(),
            remote_input: "allow".to_string(),
            max_remote_bytes: Some(50 * 1024 * 1024),
            max_archive_files: Some(2000),
        }
    }
}

pub fn load_policy(path: Option<&Path>) -> Result<PolicyConfig, String> {
    let Some(path) = path else {
        return Ok(PolicyConfig::default());
    };
    let raw = fs::read_to_string(path).map_err(|err| format!("读取策略配置失败：{err}"))?;
    serde_yaml::from_str(&raw).map_err(|err| format!("解析策略配置失败：{err}"))
}

pub fn evaluate_policy(
    report: &ScanReport,
    policy: &PolicyConfig,
    ci_mode: bool,
) -> PolicyEvaluation {
    let mut ignored_rules = Vec::new();
    let mut ignored_findings = Vec::new();
    let mut ignored_path_matches = Vec::new();
    let mut severity_overrides_applied = Vec::new();
    let mut allowed_domain_matches = Vec::new();
    let mut effective_findings = Vec::new();
    let mut policy_notes = Vec::new();

    for finding in &report.findings {
        let issue_code = finding.issue_code.as_deref().unwrap_or(finding.id.as_str());
        let mut ignored = false;

        if policy
            .disabled_rules
            .iter()
            .any(|rule| rule == issue_code || rule == &finding.id)
        {
            ignored = true;
            ignored_rules.push(issue_code.to_string());
            ignored_findings.push(finding.id.clone());
        }

        if policy
            .fail_on_issue_codes
            .iter()
            .any(|code| code == issue_code || code == &finding.id)
        {
            policy_notes.push(format!("fail_on_issue_codes matched {issue_code}"));
        }

        if let Some(path) = finding
            .location
            .as_ref()
            .map(|location| location.path.as_str())
        {
            if let Some(pattern) = policy
                .ignored_paths
                .iter()
                .find(|pattern| !pattern.is_empty() && path.contains(pattern.as_str()))
            {
                ignored = true;
                ignored_path_matches.push(format!("{} -> {}", finding.id, pattern));
                ignored_findings.push(finding.id.clone());
            }
        }

        if is_source_or_api_finding(finding) {
            if let Some(domain) = policy
                .allowed_domains
                .iter()
                .find(|domain| finding_mentions_domain(finding, domain))
            {
                ignored = true;
                allowed_domain_matches.push(format!("{} -> {}", finding.id, domain));
                ignored_findings.push(finding.id.clone());
            }
        }

        if ignored {
            continue;
        }

        let mut effective_severity = finding.severity;
        if let Some(override_severity) = policy
            .severity_overrides
            .get(issue_code)
            .or_else(|| policy.severity_overrides.get(&finding.id))
        {
            effective_severity = *override_severity;
            severity_overrides_applied.push(format!(
                "{}: {:?} -> {:?}",
                finding.id, finding.severity, override_severity
            ));
        }
        effective_findings.push((finding, effective_severity));
    }

    ignored_rules.sort();
    ignored_rules.dedup();
    ignored_findings.sort();
    ignored_findings.dedup();
    ignored_path_matches.sort();
    ignored_path_matches.dedup();
    allowed_domain_matches.sort();
    allowed_domain_matches.dedup();

    let mut blocked = false;
    let mut reason = "Policy did not block this report.".to_string();
    let mut reason_zh = "当前策略未阻断本次报告。".to_string();

    if !policy.fail_on_issue_codes.is_empty()
        && report.findings.iter().any(|finding| {
            let issue_code = finding.issue_code.as_deref().unwrap_or(finding.id.as_str());
            policy
                .fail_on_issue_codes
                .iter()
                .any(|code| code == issue_code || code == &finding.id)
                && !ignored_findings.iter().any(|id| id == &finding.id)
        })
    {
        blocked = true;
        reason = "Policy blocks because a configured issue code is present.".to_string();
        reason_zh = "策略因命中指定 issue code 而阻断。".to_string();
    }

    if policy.deny_mcp_commands && !report.mcp_tool_schema_summary.dangerous_commands.is_empty() {
        blocked = true;
        reason = "Policy blocks dangerous MCP command surfaces.".to_string();
        reason_zh = "策略禁止危险 MCP command/env 面，本次报告存在相关证据。".to_string();
        policy_notes.push("deny_mcp_commands matched MCP dangerous command evidence".to_string());
    }

    if policy.deny_network_tools
        && report.ai_bom.tool_surfaces.iter().any(|item| {
            let lower = item.to_ascii_lowercase();
            lower.contains("network")
                || lower.contains("fetch")
                || lower.contains("web")
                || lower.contains("http")
        })
    {
        blocked = true;
        reason = "Policy blocks network-capable tool surfaces.".to_string();
        reason_zh = "策略禁止网络工具面，本次 AI BOM 中存在网络相关工具证据。".to_string();
        policy_notes.push("deny_network_tools matched AI BOM tool surface".to_string());
    }

    if policy.require_package_identity
        && report
            .agent_package_index
            .packages
            .iter()
            .any(|package| package.identity_hint.is_none())
    {
        blocked = true;
        reason = "Policy requires package identity hints.".to_string();
        reason_zh =
            "策略要求 package 具备可审查身份线索，本次存在身份不完整的 package。".to_string();
        policy_notes
            .push("require_package_identity matched package without identity hint".to_string());
    }

    if !policy.agent_package_kinds.is_empty() {
        let allowed_kinds: Vec<String> = policy
            .agent_package_kinds
            .iter()
            .map(|kind| normalize_policy_key(kind))
            .collect();
        let disallowed_packages: Vec<String> = report
            .agent_package_index
            .packages
            .iter()
            .filter(|package| {
                let package_kind = normalize_policy_key(&format!("{:?}", package.package_kind));
                !allowed_kinds.iter().any(|allowed| allowed == &package_kind)
            })
            .map(|package| format!("{} ({:?})", package.package_id, package.package_kind))
            .collect();

        if !disallowed_packages.is_empty() {
            blocked = true;
            reason = "Policy blocks disallowed agent package kinds.".to_string();
            reason_zh = "策略限制了允许的 Agent package 类型，本次扫描发现不在允许列表内的对象。"
                .to_string();
            policy_notes.push(format!(
                "agent_package_kinds rejected {}",
                disallowed_packages.join(", ")
            ));
        }
    }

    if !blocked {
        match policy.fail_on.as_str() {
            "warn" => {
                if effective_findings
                    .iter()
                    .any(|(_, severity)| *severity >= FindingSeverity::Medium)
                    || matches!(report.verdict, Verdict::Warn | Verdict::Block)
                        && effective_findings.is_empty()
                {
                    blocked = true;
                    reason = "Policy blocks warn or block effective results.".to_string();
                    reason_zh =
                        "策略设置为 warn 即阻断，未被策略忽略的结果达到警告或阻断。".to_string();
                }
            }
            "block" => {
                if effective_findings
                    .iter()
                    .any(|(_, severity)| *severity >= FindingSeverity::High)
                    || report.verdict == Verdict::Block && effective_findings.is_empty()
                {
                    blocked = true;
                    reason = "Policy blocks block-level effective results.".to_string();
                    reason_zh =
                        "策略设置为 block 阻断，未被策略忽略的结果达到阻断级别。".to_string();
                }
            }
            "score_below" => {
                if let Some(minimum) = policy.minimum_score {
                    if report.score < minimum {
                        blocked = true;
                        reason = format!("Policy blocks scores below {minimum}.");
                        reason_zh = format!(
                            "策略要求风险分数不低于 {minimum}，本次分数为 {}。",
                            report.score
                        );
                    }
                }
            }
            _ => {}
        }
    }

    PolicyEvaluation {
        policy_name: "openclaw-guard".to_string(),
        language: policy.language.clone(),
        ci_mode,
        blocked,
        reason,
        reason_zh,
        ignored_rules,
        ignored_findings,
        severity_overrides_applied,
        allowed_domain_matches,
        ignored_path_matches,
        notes: {
            let mut notes = vec![
            "Policy evaluation is applied after the canonical verifier report is built."
                .to_string(),
            "Policy ignores and severity overrides affect CI gating only; canonical findings, scoring, attack paths, and audit evidence are preserved."
                .to_string(),
            ];
            notes.extend(policy_notes);
            notes
        },
    }
}

fn is_source_or_api_finding(finding: &Finding) -> bool {
    finding.category.starts_with("source.")
        || finding.category.starts_with("api.")
        || finding.category.starts_with("dependency.")
}

fn finding_mentions_domain(finding: &Finding, domain: &str) -> bool {
    let domain = domain.to_ascii_lowercase();
    if domain.is_empty() {
        return false;
    }
    let mut haystacks = vec![
        finding.title.to_ascii_lowercase(),
        finding.explanation.to_ascii_lowercase(),
        finding.why_openclaw_specific.to_ascii_lowercase(),
        finding.remediation.to_ascii_lowercase(),
    ];
    haystacks.extend(
        finding
            .analyst_notes
            .iter()
            .map(|note| note.to_ascii_lowercase()),
    );
    haystacks.extend(
        finding
            .evidence
            .iter()
            .map(|evidence| evidence.excerpt.to_ascii_lowercase()),
    );
    haystacks.iter().any(|value| value.contains(&domain))
}

fn normalize_policy_key(input: &str) -> String {
    input
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{evaluate_policy, load_policy, PolicyConfig};

    #[test]
    fn loads_policy_config_with_ci_gating_fields() {
        let dir = tempdir().unwrap();
        let policy_path = dir.path().join(".openclaw-guard.yml");
        fs::write(
            &policy_path,
            "language: zh-CN\nfail_on: score_below\nminimum_score: 90\nremote_input: deny\nmax_remote_bytes: 1024\nmax_archive_files: 10\nagent_package_kinds:\n  - openclaw_skill\ndeny_mcp_commands: true\ndeny_network_tools: true\nrequire_package_identity: true\nfail_on_issue_codes:\n  - OCSG-MCP-002\nseverity_overrides:\n  OCSG-SOURCE-001: low\nallowed_domains:\n  - example.com\nignored_paths:\n  - docs/\n",
        )
        .unwrap();

        let policy = load_policy(Some(&policy_path)).unwrap();

        assert_eq!(policy.language, "zh-CN");
        assert_eq!(policy.fail_on, "score_below");
        assert_eq!(policy.minimum_score, Some(90));
        assert_eq!(policy.remote_input, "deny");
        assert_eq!(policy.max_remote_bytes, Some(1024));
        assert_eq!(policy.max_archive_files, Some(10));
        assert_eq!(policy.agent_package_kinds, vec!["openclaw_skill"]);
        assert!(policy.deny_mcp_commands);
        assert!(policy.deny_network_tools);
        assert!(policy.require_package_identity);
        assert_eq!(policy.fail_on_issue_codes, vec!["OCSG-MCP-002"]);
        assert_eq!(
            policy.severity_overrides.get("OCSG-SOURCE-001"),
            Some(&crate::types::FindingSeverity::Low)
        );
        assert_eq!(policy.allowed_domains, vec!["example.com"]);
        assert_eq!(policy.ignored_paths, vec!["docs/"]);
    }

    #[test]
    fn disabled_rules_affect_policy_gate_without_removing_findings() {
        let dir = tempdir().unwrap();
        let skill = dir.path().join("SKILL.md");
        fs::write(
            &skill,
            "---\nmetadata: {\"openclaw\":{\"apiKey\":\"demo-placeholder\"}}\n---\nDemo",
        )
        .unwrap();
        let report = crate::scan::scan_path(&skill).unwrap();
        assert!(report
            .findings
            .iter()
            .any(|finding| finding.issue_code.as_deref() == Some("OCSG-CONFIG-001")));

        let mut policy = PolicyConfig::default();
        policy.fail_on = "block".to_string();
        policy.disabled_rules = vec!["OCSG-CONFIG-001".to_string()];
        let evaluation = evaluate_policy(&report, &policy, true);

        assert!(!report.findings.is_empty());
        assert!(evaluation
            .ignored_rules
            .contains(&"OCSG-CONFIG-001".to_string()));
        assert!(!evaluation.blocked);
    }
}
