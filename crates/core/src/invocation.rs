use crate::types::{
    EvidenceKind, EvidenceNode, Finding, FindingConfidence, FindingSeverity, InvocationDispatch,
    ParsedSkill, SkillLocation,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvocationAnalysis {
    pub summary: String,
    pub findings: Vec<Finding>,
}

pub fn analyze_invocation_policy(skill: &ParsedSkill) -> InvocationAnalysis {
    let mut findings = Vec::new();
    let policy = &skill.invocation_policy;

    if policy.command_dispatch == InvocationDispatch::Tool {
        findings.push(make_finding(
            "context.invocation.tool_dispatch",
            "Skill command bypasses model reasoning with direct tool dispatch",
            FindingSeverity::High,
            FindingConfidence::High,
            false,
            skill,
            &format!(
                "command-dispatch: tool{}",
                policy
                    .command_tool
                    .as_deref()
                    .map(|tool| format!(", command-tool: {tool}"))
                    .unwrap_or_default()
            ),
            "The skill config requests direct tool dispatch instead of normal model-mediated invocation.",
            "OpenClaw supports slash-command style tool dispatch that can bypass model reasoning and approval shaping for skill execution.",
            "Require careful review of command-tool targets and prefer model-mediated invocation when possible.",
        ));
    }

    if policy.disable_model_invocation
        && policy.user_invocable
        && policy.command_dispatch == InvocationDispatch::Tool
    {
        findings.push(make_finding(
            "context.invocation.hidden_direct_tool",
            "User-invocable direct tool dispatch is hidden from model skill listing",
            FindingSeverity::High,
            FindingConfidence::High,
            false,
            skill,
            "disable-model-invocation: true + user-invocable: true + command-dispatch: tool",
            "The skill remains user-invocable while being excluded from the model-visible available-skills surface.",
            "In OpenClaw this combination increases operator deception risk because the skill can still run as a slash command while being less visible in the model prompt surface.",
            "Expose the skill to the model or remove direct tool dispatch unless there is a strong, reviewed reason not to.",
        ));
    }

    let summary = format!(
        "Invocation policy: user_invocable={}, disable_model_invocation={}, dispatch={:?}, command_tool={}.",
        policy.user_invocable,
        policy.disable_model_invocation,
        policy.command_dispatch,
        policy.command_tool.as_deref().unwrap_or("none")
    );

    InvocationAnalysis { summary, findings }
}

fn make_finding(
    id: &str,
    title: &str,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    hard_trigger: bool,
    skill: &ParsedSkill,
    excerpt: &str,
    explanation: &str,
    why_openclaw_specific: &str,
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
        category: "invocation_policy".to_string(),
        severity,
        confidence,
        hard_trigger,
        evidence_kind: "structured_metadata".to_string(),
        location: Some(location.clone()),
        evidence: vec![EvidenceNode {
            kind: EvidenceKind::StructuredMetadata,
            location,
            excerpt: excerpt.to_string(),
            direct: true,
        }],
        explanation: explanation.to_string(),
        explanation_zh: None,
        why_openclaw_specific: why_openclaw_specific.to_string(),
        prerequisite_context: vec!["The finding relies on parsed SKILL.md frontmatter and normalized invocation metadata.".to_string()],
        analyst_notes: vec!["Invocation-policy findings are specific to OpenClaw command semantics, not generic markdown content.".to_string()],
        remediation: remediation.to_string(),
        recommendation_zh: None,
        suppression_status: "not_suppressed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::skill_parse::parse_skill_file;

    use super::analyze_invocation_policy;

    #[test]
    fn command_dispatch_tool_produces_finding() {
        let skill = parse_skill_file(
            Path::new("demo/SKILL.md"),
            "---\ncommand-dispatch: tool\ncommand-tool: exec\ndisable-model-invocation: true\nuser-invocable: true\n---\nBody",
            Vec::new(),
        );
        let analysis = analyze_invocation_policy(&skill);
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "context.invocation.tool_dispatch"));
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "context.invocation.hidden_direct_tool"));
    }
}
