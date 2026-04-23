use chrono::Utc;
use std::fs;
use std::path::Path;

use serde::Deserialize;

use crate::types::{
    AttackPath, AuditLevel, AuditRecord, AuditSummary, ExpiredSuppressionNote, Finding,
    FindingSeverity, PathValidationDisposition, PathValidationStatus, SuppressionLifecycle,
    SuppressionMatch, SuppressionRecord, SuppressionRule, ValidationAwareAuditNote,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuppressionApplication {
    pub findings: Vec<Finding>,
    pub active_findings: Vec<Finding>,
    pub paths: Vec<AttackPath>,
    pub active_paths: Vec<AttackPath>,
    pub matches: Vec<SuppressionMatch>,
    pub records: Vec<SuppressionRecord>,
    pub audit_summary: AuditSummary,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum SuppressionConfig {
    RulesObject { rules: Vec<SuppressionRule> },
    RulesArray(Vec<SuppressionRule>),
}

pub fn load_suppression_rules(path: &Path) -> Result<Vec<SuppressionRule>, String> {
    let content = fs::read_to_string(path)
        .map_err(|err| format!("failed to read suppression file {}: {err}", path.display()))?;
    let parsed: SuppressionConfig =
        serde_json::from_str(&content).map_err(|err| format!("failed to parse suppression file: {err}"))?;
    let rules = match parsed {
        SuppressionConfig::RulesObject { rules } => rules,
        SuppressionConfig::RulesArray(rules) => rules,
    };
    if rules.iter().any(|rule| rule.reason.trim().is_empty()) {
        return Err("suppression rules require a non-empty reason".to_string());
    }
    Ok(rules)
}

pub fn apply_suppressions(
    findings: &[Finding],
    attack_paths: &[AttackPath],
    rules: &[SuppressionRule],
    path_statuses: &[PathValidationStatus],
) -> SuppressionApplication {
    let mut matches = Vec::new();
    let mut records = Vec::new();
    let mut audit_records = Vec::new();
    let mut expired_suppressions = Vec::new();
    let mut validation_aware_notes = Vec::new();
    let mut updated_findings = findings.to_vec();
    let updated_paths = attack_paths.to_vec();
    let today = Utc::now().format("%Y-%m-%d").to_string();

    for finding in &mut updated_findings {
        if let Some(rule) = rules.iter().find(|rule| matches_finding(rule, finding)) {
            let lifecycle = lifecycle_for_rule(rule, &today);
            finding.suppression_status = "suppressed".to_string();
            let high_risk = finding.severity >= FindingSeverity::High;
            matches.push(SuppressionMatch {
                scope: "finding".to_string(),
                target_id: finding.id.clone(),
                reason: rule.reason.clone(),
                note: rule.note.clone(),
                high_risk,
                lifecycle,
            });
            records.push(SuppressionRecord {
                scope: format!("finding:{}", finding.id),
                reason: rule.reason.clone(),
            });
            audit_records.push(AuditRecord {
                level: if high_risk { AuditLevel::HighRisk } else { AuditLevel::Info },
                message: format!("Finding `{}` was suppressed with reason: {}", finding.id, rule.reason),
                subject_id: Some(finding.id.clone()),
            });
            if lifecycle == SuppressionLifecycle::Expired {
                expired_suppressions.push(ExpiredSuppressionNote {
                    target_id: finding.id.clone(),
                    expires_on: rule.expires_on.clone().unwrap_or_default(),
                    note: "Suppression has expired and should be reviewed or removed.".to_string(),
                });
            }
        }
    }

    for path in &updated_paths {
        if let Some(rule) = rules.iter().find(|rule| matches_path(rule, path)) {
            let lifecycle = lifecycle_for_rule(rule, &today);
            let high_risk = path.severity >= FindingSeverity::High;
            let validated_high_risk = path_statuses.iter().any(|status| {
                status.path_id == path.path_id
                    && status.status == PathValidationDisposition::Validated
                    && high_risk
            });
            matches.push(SuppressionMatch {
                scope: "attack_path".to_string(),
                target_id: path.path_id.clone(),
                reason: rule.reason.clone(),
                note: rule.note.clone(),
                high_risk,
                lifecycle,
            });
            records.push(SuppressionRecord {
                scope: format!("attack_path:{}", path.path_id),
                reason: rule.reason.clone(),
            });
            audit_records.push(AuditRecord {
                level: if high_risk { AuditLevel::HighRisk } else { AuditLevel::Warning },
                message: format!("Attack path `{}` was suppressed for scoring with reason: {}", path.path_id, rule.reason),
                subject_id: Some(path.path_id.clone()),
            });
            if lifecycle == SuppressionLifecycle::Expired {
                expired_suppressions.push(ExpiredSuppressionNote {
                    target_id: path.path_id.clone(),
                    expires_on: rule.expires_on.clone().unwrap_or_default(),
                    note: "Suppression has expired and should be reviewed or removed.".to_string(),
                });
            }
            if validated_high_risk {
                validation_aware_notes.push(ValidationAwareAuditNote {
                    subject_id: path.path_id.clone(),
                    note: "A validated high-risk path was suppressed. Evidence remains in the report and this override should receive additional review.".to_string(),
                });
                audit_records.push(AuditRecord {
                    level: AuditLevel::HighRisk,
                    message: format!(
                        "Suppressed path `{}` was already runtime-validated as high risk.",
                        path.path_id
                    ),
                    subject_id: Some(path.path_id.clone()),
                });
            }
        }
    }

    let active_findings: Vec<Finding> = updated_findings
        .iter()
        .filter(|finding| finding.suppression_status != "suppressed")
        .cloned()
        .collect();
    let active_paths: Vec<AttackPath> = updated_paths
        .iter()
        .filter(|path| !matches.iter().any(|item| item.scope == "attack_path" && item.target_id == path.path_id))
        .cloned()
        .collect();

    let high_risk_suppressions = matches.iter().filter(|item| item.high_risk).count();
    let summary = if matches.is_empty() {
        "No suppression rules matched the current findings or attack paths.".to_string()
    } else {
        format!(
            "Applied {} suppression match(es); {} affected high-risk items, {} are expired, and all remain visible in audit output.",
            matches.len(), high_risk_suppressions, expired_suppressions.len()
        )
    };

    SuppressionApplication {
        findings: updated_findings,
        active_findings,
        paths: updated_paths,
        active_paths,
        matches,
        records,
        audit_summary: AuditSummary {
            summary,
            records: audit_records,
            high_risk_suppressions,
            expired_suppressions,
            validation_aware_notes,
        },
    }
}

fn lifecycle_for_rule(rule: &SuppressionRule, today: &str) -> SuppressionLifecycle {
    if rule
        .expires_on
        .as_deref()
        .map(|value| value.trim() <= today)
        .unwrap_or(false)
    {
        SuppressionLifecycle::Expired
    } else {
        SuppressionLifecycle::Active
    }
}

fn matches_finding(rule: &SuppressionRule, finding: &Finding) -> bool {
    if let Some(finding_id) = &rule.finding_id {
        if finding_id != &finding.id {
            return false;
        }
    }
    if let Some(target_contains) = &rule.target_contains {
        if !finding
            .location
            .as_ref()
            .map(|location| location.path.contains(target_contains))
            .unwrap_or(false)
        {
            return false;
        }
    }
    rule.finding_id.is_some() || rule.target_contains.is_some()
}

fn matches_path(rule: &SuppressionRule, path: &AttackPath) -> bool {
    if let Some(path_id) = &rule.path_id {
        if path_id != &path.path_id {
            return false;
        }
    }
    if let Some(target_contains) = &rule.target_contains {
        if !path
            .evidence_nodes
            .iter()
            .any(|node| node.location.path.contains(target_contains))
        {
            return false;
        }
    }
    rule.path_id.is_some() || rule.target_contains.is_some()
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::types::{
        AttackPath, Finding, FindingConfidence, FindingSeverity, PathValidationDisposition,
        PathValidationStatus, SuppressionLifecycle, SuppressionRule,
    };

    use super::{apply_suppressions, load_suppression_rules};

    fn finding() -> Finding {
        Finding {
            id: "context.invocation.tool_dispatch".to_string(),
            title: String::new(),
            category: String::new(),
            severity: FindingSeverity::High,
            confidence: FindingConfidence::High,
            hard_trigger: false,
            evidence_kind: String::new(),
            location: None,
            evidence: Vec::new(),
            explanation: String::new(),
            why_openclaw_specific: String::new(),
            prerequisite_context: Vec::new(),
            analyst_notes: Vec::new(),
            remediation: String::new(),
            suppression_status: "not_suppressed".to_string(),
        }
    }

    fn path() -> AttackPath {
        AttackPath {
            path_id: "path.direct_privileged_action".to_string(),
            path_type: String::new(),
            title: String::new(),
            steps: Vec::new(),
            edges: Vec::new(),
            severity: FindingSeverity::High,
            confidence: FindingConfidence::High,
            explanation: String::new(),
            prerequisites: Vec::new(),
            impact: String::new(),
            evidence_nodes: Vec::new(),
            inferred_nodes: Vec::new(),
            why_openclaw_specific: String::new(),
        }
    }

    #[test]
    fn suppress_by_finding_id_keeps_audit_visibility() {
        let result = apply_suppressions(
            &[finding()],
            &[],
            &[SuppressionRule {
                finding_id: Some("context.invocation.tool_dispatch".to_string()),
                path_id: None,
                target_contains: None,
                reason: "Reviewed and accepted for local admin-only workflow".to_string(),
                note: None,
                expires_on: None,
            }],
            &[],
        );

        assert_eq!(result.active_findings.len(), 0);
        assert_eq!(result.matches.len(), 1);
        assert_eq!(result.audit_summary.high_risk_suppressions, 1);
    }

    #[test]
    fn suppress_by_path_id_requires_reason_at_load_time_but_still_filters_for_scoring() {
        let result = apply_suppressions(
            &[],
            &[path()],
            &[SuppressionRule {
                finding_id: None,
                path_id: Some("path.direct_privileged_action".to_string()),
                target_contains: None,
                reason: "Validated in isolated sandbox".to_string(),
                note: Some("Temporary exception".to_string()),
                expires_on: None,
            }],
            &[PathValidationStatus {
                path_id: "path.direct_privileged_action".to_string(),
                status: PathValidationDisposition::Validated,
                guard_status: crate::types::PathGuardStatus::Supported,
                validated_constraints: Vec::new(),
                missing_constraints: Vec::new(),
                note: String::new(),
            }],
        );

        assert_eq!(result.active_paths.len(), 0);
        assert_eq!(result.matches[0].scope, "attack_path");
        assert_eq!(result.matches[0].lifecycle, SuppressionLifecycle::Active);
        assert_eq!(result.audit_summary.validation_aware_notes.len(), 1);
    }

    #[test]
    fn load_rejects_empty_reason() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("suppressions.json");
        fs::write(
            &path,
            r#"[{"finding_id":"context.invocation.tool_dispatch","reason":"   "}]"#,
        )
        .unwrap();

        let result = load_suppression_rules(&path);

        assert!(result.is_err());
    }

    #[test]
    fn expired_suppression_is_reported() {
        let result = apply_suppressions(
            &[finding()],
            &[],
            &[SuppressionRule {
                finding_id: Some("context.invocation.tool_dispatch".to_string()),
                path_id: None,
                target_contains: None,
                reason: "Old exception".to_string(),
                note: None,
                expires_on: Some("2000-01-01".to_string()),
            }],
            &[],
        );

        assert_eq!(result.matches[0].lifecycle, SuppressionLifecycle::Expired);
        assert_eq!(result.audit_summary.expired_suppressions.len(), 1);
    }
}
