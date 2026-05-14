use crate::types::{
    ExternalReference, Finding, FindingConfidence, FindingSeverity, SkillLocation, ToxicFlow,
    ToxicFlowSummary,
};

#[derive(Debug, Clone)]
pub struct ToxicFlowAnalysis {
    pub summary: ToxicFlowSummary,
    pub flows: Vec<ToxicFlow>,
    pub findings: Vec<Finding>,
}

pub fn analyze_toxic_flows(
    findings: &[Finding],
    external_references: &[ExternalReference],
) -> ToxicFlowAnalysis {
    let untrusted_sources = collect_untrusted_sources(findings, external_references);
    let sensitive_surfaces = collect_sensitive_surfaces(findings);
    let egress_or_execution = collect_egress_or_execution(findings, external_references);

    if untrusted_sources.is_empty()
        || sensitive_surfaces.is_empty()
        || egress_or_execution.is_empty()
    {
        return ToxicFlowAnalysis {
            summary: ToxicFlowSummary {
                summary: "No toxic flow combinations were detected.".to_string(),
                summary_zh: "未发现不可信输入、敏感数据与外联/执行能力同时出现的组合风险。"
                    .to_string(),
                flows_count: 0,
                notes: vec![
                    "Toxic flow analysis is local and does not execute the skill.".to_string(),
                ],
            },
            flows: Vec::new(),
            findings: Vec::new(),
        };
    }

    let related_findings = findings
        .iter()
        .filter(|finding| {
            is_untrusted_source_finding(finding)
                || is_sensitive_finding(finding)
                || is_egress_or_execution_finding(finding)
        })
        .map(|finding| finding.id.clone())
        .collect::<Vec<_>>();

    let severity = if related_findings.len() >= 3 {
        FindingSeverity::High
    } else {
        FindingSeverity::Medium
    };
    let flow = ToxicFlow {
        flow_id: "toxic-flow-001".to_string(),
        issue_code: "OCSG-FLOW-001".to_string(),
        title: "Untrusted input, sensitive data, and egress/execution form a toxic flow"
            .to_string(),
        title_zh: "不可信输入、敏感数据与外联/执行能力形成组合风险".to_string(),
        severity,
        confidence: FindingConfidence::Medium,
        untrusted_sources: untrusted_sources.clone(),
        sensitive_surfaces: sensitive_surfaces.clone(),
        egress_or_execution: egress_or_execution.clone(),
        related_findings: related_findings.clone(),
        explanation: "The scan found untrusted content or source inputs in the same scope as sensitive data access and egress or execution capability. This does not prove exfiltration, but it creates a realistic review-needed risk envelope.".to_string(),
        explanation_zh: "扫描范围内同时出现不可信输入来源、敏感数据面以及外联或执行能力。这不证明已经发生外泄，但对 OpenClaw skill 来说已经形成需要优先复核的组合风险。".to_string(),
    };

    let finding = Finding {
        id: "toxic_flow.untrusted_sensitive_egress".to_string(),
        title: flow.title.clone(),
        issue_code: Some(flow.issue_code.clone()),
        title_zh: Some(flow.title_zh.clone()),
        category: "toxic_flow.combined_risk".to_string(),
        severity,
        confidence: FindingConfidence::Medium,
        hard_trigger: false,
        evidence_kind: "toxic_flow".to_string(),
        location: Some(SkillLocation {
            path: "context".to_string(),
            line: None,
            column: None,
        }),
        evidence: Vec::new(),
        explanation: flow.explanation.clone(),
        explanation_zh: Some(flow.explanation_zh.clone()),
        why_openclaw_specific: "OpenClaw skills combine instructions, tool authority, local credentials, and external content in one operational surface.".to_string(),
        prerequisite_context: vec![
            "At least one untrusted input/source signal exists.".to_string(),
            "At least one sensitive data or credential surface exists.".to_string(),
            "At least one egress, download, install, or execution capability exists.".to_string(),
        ],
        analyst_notes: related_findings
            .iter()
            .map(|id| format!("related finding: {id}"))
            .collect(),
        remediation: "Break the flow by removing one of the three legs: untrusted input, sensitive access, or egress/execution capability.".to_string(),
        recommendation_zh: Some(
            "通过移除不可信输入、敏感数据访问或外联/执行能力中的任一环节来打断组合风险。"
                .to_string(),
        ),
        suppression_status: "not_suppressed".to_string(),
    };

    ToxicFlowAnalysis {
        summary: ToxicFlowSummary {
            summary: "Detected 1 toxic flow combination requiring review.".to_string(),
            summary_zh: "发现 1 条需要复核的组合风险链。".to_string(),
            flows_count: 1,
            notes: vec![
                "Toxic flows are evidence aggregations, not proof of exploit execution."
                    .to_string(),
            ],
        },
        flows: vec![flow],
        findings: vec![finding],
    }
}

fn collect_untrusted_sources(
    findings: &[Finding],
    external_references: &[ExternalReference],
) -> Vec<String> {
    let mut out = Vec::new();
    for finding in findings
        .iter()
        .filter(|finding| is_untrusted_source_finding(finding))
    {
        out.push(format!("{}: {}", finding.id, finding.title));
    }
    for reference in external_references {
        let reputation = format!("{:?}", reference.reputation).to_ascii_lowercase();
        if reputation.contains("suspicious") || reputation.contains("review") {
            out.push(format!("external reference: {}", reference.host));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn collect_sensitive_surfaces(findings: &[Finding]) -> Vec<String> {
    findings
        .iter()
        .filter(|finding| is_sensitive_finding(finding))
        .map(|finding| format!("{}: {}", finding.id, finding.title))
        .collect()
}

fn collect_egress_or_execution(
    findings: &[Finding],
    external_references: &[ExternalReference],
) -> Vec<String> {
    let mut out = findings
        .iter()
        .filter(|finding| is_egress_or_execution_finding(finding))
        .map(|finding| format!("{}: {}", finding.id, finding.title))
        .collect::<Vec<_>>();
    let review_references = external_references
        .iter()
        .filter(|reference| {
            let reputation = format!("{:?}", reference.reputation).to_ascii_lowercase();
            reputation.contains("suspicious") || reputation.contains("review")
        })
        .count();
    if review_references > 0 {
        out.push(format!(
            "{review_references} review-needed external reference(s)"
        ));
    }
    out.sort();
    out.dedup();
    out
}

fn is_untrusted_source_finding(finding: &Finding) -> bool {
    finding.category.starts_with("source.")
        || finding.category.starts_with("companion")
        || finding.category.contains("threat_corpus")
}

fn is_sensitive_finding(finding: &Finding) -> bool {
    finding.category.contains("secret")
        || finding.category.contains("sensitive")
        || (finding.category.starts_with("openclaw_config")
            && finding.severity >= FindingSeverity::Medium
            && finding.confidence != FindingConfidence::Low)
        || (finding.title.to_ascii_lowercase().contains("apikey")
            && finding.severity >= FindingSeverity::Medium
            && finding.confidence != FindingConfidence::Low)
}

fn is_egress_or_execution_finding(finding: &Finding) -> bool {
    finding.category.contains("tool")
        || finding.category.contains("install")
        || finding.category.starts_with("dependency.")
        || finding.title.to_ascii_lowercase().contains("download")
        || finding.title.to_ascii_lowercase().contains("exec")
        || finding.title.to_ascii_lowercase().contains("remote")
}

#[cfg(test)]
mod tests {
    use super::analyze_toxic_flows;
    use crate::types::{Finding, FindingConfidence, FindingSeverity};

    fn finding(id: &str, title: &str, category: &str) -> Finding {
        Finding {
            id: id.to_string(),
            title: title.to_string(),
            issue_code: None,
            title_zh: None,
            category: category.to_string(),
            severity: FindingSeverity::Medium,
            confidence: FindingConfidence::Medium,
            hard_trigger: false,
            evidence_kind: "test".to_string(),
            location: None,
            evidence: Vec::new(),
            explanation: String::new(),
            explanation_zh: None,
            why_openclaw_specific: String::new(),
            prerequisite_context: Vec::new(),
            analyst_notes: Vec::new(),
            remediation: String::new(),
            recommendation_zh: None,
            suppression_status: "not_suppressed".to_string(),
        }
    }

    #[test]
    fn detects_combined_untrusted_sensitive_and_egress_flow() {
        let findings = vec![
            finding("source.shortlink", "Shortlink source", "source.shortlink"),
            finding(
                "config.api_key",
                "OpenClaw skill config may contain a plaintext apiKey binding",
                "openclaw_config.secret_binding",
            ),
            finding(
                "install.remote",
                "Manual install instruction downloads remote content",
                "manual_execution_risk",
            ),
        ];

        let analysis = analyze_toxic_flows(&findings, &[]);

        assert_eq!(analysis.summary.flows_count, 1);
        assert_eq!(analysis.flows[0].issue_code, "OCSG-FLOW-001");
        assert_eq!(
            analysis.findings[0].issue_code.as_deref(),
            Some("OCSG-FLOW-001")
        );
    }

    #[test]
    fn benign_partial_evidence_does_not_create_toxic_flow() {
        let findings = vec![finding("source.docs", "Docs URL", "source.documentation")];

        let analysis = analyze_toxic_flows(&findings, &[]);

        assert_eq!(analysis.summary.flows_count, 0);
        assert!(analysis.findings.is_empty());
    }
}
