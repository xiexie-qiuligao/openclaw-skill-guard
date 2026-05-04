use std::collections::BTreeMap;

use regex::Regex;

use crate::types::{
    AgentPackage, AgentPackageIndexSummary, AgentPackageKind, AgentPackageSurface, ParsedSkill,
    TextArtifact,
};

pub fn build_agent_package_index(
    parsed_skills: &[ParsedSkill],
    text_artifacts: &[TextArtifact],
    include_agent_ecosystem: bool,
) -> AgentPackageIndexSummary {
    let url_re = Regex::new(r#"https?://[^\s)>\]"']+"#).expect("static URL regex is valid");
    let mut packages = Vec::new();

    for skill in parsed_skills {
        let index = packages.len() + 1;
        packages.push(AgentPackage {
            package_id: format!("agent-package-{index:03}"),
            package_kind: AgentPackageKind::OpenClawSkill,
            name: skill.descriptor.name.clone(),
            source_path: safe_path(&skill.skill_file),
            identity_hint: skill
                .metadata
                .skill_key
                .clone()
                .or_else(|| skill.descriptor.homepage.clone()),
            surface: AgentPackageSurface {
                instructions: vec![compact(&skill.body)],
                tools: skill
                    .invocation_policy
                    .command_tool
                    .clone()
                    .into_iter()
                    .collect(),
                schemas: Vec::new(),
                commands: skill
                    .metadata
                    .install
                    .iter()
                    .map(|spec| compact(&spec.raw))
                    .collect(),
                env: skill.metadata.requires.env.clone(),
                external_refs: url_re
                    .find_iter(&skill.body)
                    .map(|m| m.as_str().trim_end_matches('.').to_string())
                    .collect(),
            },
            evidence_excerpt: compact(&skill.body),
            summary: "OpenClaw SKILL.md package mapped into generic agent package index."
                .to_string(),
            summary_zh: "OpenClaw SKILL.md 已映射到通用 Agent Package 视图。".to_string(),
        });
    }

    if include_agent_ecosystem {
        for artifact in text_artifacts {
            if parsed_skills
                .iter()
                .any(|skill| skill.skill_file == artifact.path)
            {
                continue;
            }
            if let Some(kind) = classify_agent_asset(&artifact.path, &artifact.content) {
                let index = packages.len() + 1;
                packages.push(AgentPackage {
                    package_id: format!("agent-package-{index:03}"),
                    package_kind: kind,
                    name: name_from_path(&artifact.path),
                    source_path: safe_path(&artifact.path),
                    identity_hint: None,
                    surface: AgentPackageSurface {
                        instructions: collect_instruction_lines(&artifact.content),
                        tools: collect_tool_hints(&artifact.content),
                        schemas: collect_schema_hints(&artifact.content),
                        commands: collect_command_hints(&artifact.content),
                        env: collect_env_hints(&artifact.content),
                        external_refs: url_re
                            .find_iter(&artifact.content)
                            .map(|m| m.as_str().trim_end_matches('.').to_string())
                            .collect(),
                    },
                    evidence_excerpt: compact(&artifact.content),
                    summary: "Agent ecosystem asset mapped into package index.".to_string(),
                    summary_zh: "Agent 生态资产已映射到通用 package 视图。".to_string(),
                });
            }
        }
    }

    let mut kind_counts = BTreeMap::new();
    for package in &packages {
        *kind_counts
            .entry(format!("{:?}", package.package_kind).to_ascii_lowercase())
            .or_insert(0) += 1;
    }

    AgentPackageIndexSummary {
        summary: if include_agent_ecosystem {
            format!(
                "Indexed {} OpenClaw and generic agent package asset(s).",
                packages.len()
            )
        } else {
            format!(
                "Indexed {} OpenClaw package asset(s); generic agent ecosystem parsing is disabled.",
                packages.len()
            )
        },
        summary_zh: if include_agent_ecosystem {
            format!("已索引 {} 个 OpenClaw / 通用 Agent package 资产。", packages.len())
        } else {
            format!(
                "已索引 {} 个 OpenClaw package；通用 Agent 生态解析未开启。",
                packages.len()
            )
        },
        packages,
        kind_counts,
        notes: vec![
            "Agent package indexing is passive and does not execute tools, MCP servers, or install commands."
                .to_string(),
        ],
    }
}

fn classify_agent_asset(path: &str, content: &str) -> Option<AgentPackageKind> {
    let normalized = path.replace('\\', "/").to_ascii_lowercase();
    let lower = content.to_ascii_lowercase();
    if normalized.ends_with("skill.md") || normalized.contains("/skills/") {
        if normalized.contains("claude") || lower.contains("claude") {
            return Some(AgentPackageKind::ClaudeSkill);
        }
        if normalized.contains("codex") || normalized.contains(".codex") {
            return Some(AgentPackageKind::CodexSkill);
        }
        return Some(AgentPackageKind::GenericPromptPackage);
    }
    if normalized.contains(".cursor") || normalized.ends_with(".mdc") {
        Some(AgentPackageKind::CursorRule)
    } else if normalized.contains("windsurf") {
        Some(AgentPackageKind::WindsurfRule)
    } else if normalized.contains("cline") || normalized.contains(".clinerules") {
        Some(AgentPackageKind::ClineRule)
    } else if normalized.contains("mcp")
        || lower.contains("mcpservers")
        || lower.contains("\"tools\"")
        || lower.contains("inputschema")
    {
        Some(AgentPackageKind::McpConfig)
    } else if lower.contains("system prompt")
        || lower.contains("instructions")
        || lower.contains("agent")
        || lower.contains("tool")
    {
        Some(AgentPackageKind::GenericPromptPackage)
    } else {
        None
    }
}

fn collect_instruction_lines(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            lower.contains("instruction")
                || lower.contains("prompt")
                || lower.contains("system")
                || line.contains("指令")
        })
        .take(8)
        .map(compact)
        .collect()
}

fn collect_tool_hints(content: &str) -> Vec<String> {
    collect_lines(content, &["tool", "tools", "function", "server", "mcp"])
}

fn collect_schema_hints(content: &str) -> Vec<String> {
    collect_lines(
        content,
        &["schema", "inputSchema", "parameters", "description"],
    )
}

fn collect_command_hints(content: &str) -> Vec<String> {
    collect_lines(
        content,
        &["command", "args", "npx", "uvx", "python", "node", "bash"],
    )
}

fn collect_env_hints(content: &str) -> Vec<String> {
    collect_lines(content, &["env", "api_key", "apikey", "token", "secret"])
}

fn collect_lines(content: &str, needles: &[&str]) -> Vec<String> {
    content
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            needles
                .iter()
                .any(|needle| lower.contains(&needle.to_ascii_lowercase()))
        })
        .take(8)
        .map(compact)
        .collect()
}

fn name_from_path(path: &str) -> Option<String> {
    path.replace('\\', "/")
        .split('/')
        .next_back()
        .map(str::to_string)
}

fn safe_path(path: &str) -> String {
    let normalized = path.replace('\\', "/");
    if normalized.starts_with("<remote-") {
        return normalized;
    }
    let parts = normalized
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    match parts.as_slice() {
        [] => "未命名目标".to_string(),
        [one] => (*one).to_string(),
        _ => parts[parts.len().saturating_sub(2)..].join("/"),
    }
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
    use super::build_agent_package_index;
    use crate::types::{AgentPackageKind, TextArtifact};

    #[test]
    fn indexes_mcp_and_cursor_assets_when_enabled() {
        let artifacts = vec![
            TextArtifact {
                path: ".cursor/rules/demo.mdc".to_string(),
                content: "system prompt: use tool carefully".to_string(),
            },
            TextArtifact {
                path: ".config/mcp.json".to_string(),
                content: r#"{"mcpServers":{"demo":{"command":"node","tools":[]}}}"#.to_string(),
            },
        ];

        let index = build_agent_package_index(&[], &artifacts, true);

        assert!(index
            .packages
            .iter()
            .any(|pkg| pkg.package_kind == AgentPackageKind::CursorRule));
        assert!(index
            .packages
            .iter()
            .any(|pkg| pkg.package_kind == AgentPackageKind::McpConfig));
    }
}
