use sha2::{Digest, Sha256};

use crate::types::{
    EstateInventorySummary, EstateReference, IntegritySnapshot, SkillFileDigest, TextArtifact,
};

pub fn build_integrity_snapshot(text_artifacts: &[TextArtifact]) -> IntegritySnapshot {
    let mut skill_file_digests = Vec::new();
    let mut total_text_bytes = 0usize;

    for artifact in text_artifacts {
        total_text_bytes += artifact.content.len();
        if artifact.path.replace('\\', "/").ends_with("SKILL.md") {
            skill_file_digests.push(SkillFileDigest {
                path: safe_path(&artifact.path),
                sha256: sha256_hex(artifact.content.as_bytes()),
                bytes: artifact.content.len(),
            });
        }
    }

    let summary = if skill_file_digests.is_empty() {
        "No SKILL.md digest was produced for this scan scope.".to_string()
    } else {
        format!(
            "Captured {} SKILL.md digest(s) across {} text file(s).",
            skill_file_digests.len(),
            text_artifacts.len()
        )
    };
    let summary_zh = if skill_file_digests.is_empty() {
        "当前扫描范围未生成 SKILL.md 摘要。".to_string()
    } else {
        format!(
            "已记录 {} 个 SKILL.md SHA-256 摘要，覆盖 {} 个文本文件。",
            skill_file_digests.len(),
            text_artifacts.len()
        )
    };

    IntegritySnapshot {
        summary,
        summary_zh,
        skill_file_digests,
        text_file_count: text_artifacts.len(),
        total_text_bytes,
        notes: vec![
            "Integrity snapshot is local and passive; it does not monitor future remote changes."
                .to_string(),
            "Use the digest to compare reports or detect remote skill drift during manual review."
                .to_string(),
        ],
    }
}

pub fn discover_estate_references(text_artifacts: &[TextArtifact]) -> EstateInventorySummary {
    let mut references = Vec::new();
    for artifact in text_artifacts {
        let normalized = artifact.path.replace('\\', "/").to_ascii_lowercase();
        let content_lower = artifact.content.to_ascii_lowercase();
        let mut kinds = Vec::new();
        if normalized.contains("mcp") || content_lower.contains("mcpservers") {
            kinds.push("mcp_config");
        }
        if normalized.contains("openclaw") || content_lower.contains("metadata.openclaw") {
            kinds.push("openclaw_config");
        }
        if normalized.contains("claude") || content_lower.contains(".claude") {
            kinds.push("claude_skill_reference");
        }
        if normalized.contains("cursor") || content_lower.contains(".cursor") {
            kinds.push("cursor_skill_reference");
        }
        if normalized.contains("windsurf") || content_lower.contains("windsurf") {
            kinds.push("windsurf_skill_reference");
        }
        for kind in kinds {
            let index = references.len() + 1;
            references.push(EstateReference {
                reference_id: format!("estate-ref-{index:03}"),
                reference_kind: kind.to_string(),
                path: safe_path(&artifact.path),
                summary: format!("Detected local configuration reference of kind `{kind}`."),
                summary_zh: format!("检测到本地配置引用类型 `{kind}`。"),
            });
        }
    }

    EstateInventorySummary {
        summary: if references.is_empty() {
            "No local agent or MCP configuration references were detected in the scan scope."
                .to_string()
        } else {
            format!(
                "Detected {} local agent or MCP configuration reference(s) in the scan scope.",
                references.len()
            )
        },
        summary_zh: if references.is_empty() {
            "当前扫描范围未发现本地 Agent / MCP 配置引用。".to_string()
        } else {
            format!(
                "在当前扫描范围内发现 {} 个本地 Agent / MCP 配置引用。",
                references.len()
            )
        },
        references,
        notes: vec![
            "Estate discovery only inspects files already inside the selected scan scope."
                .to_string(),
            "It never starts MCP servers, connects to tools, or scans private home directories by default."
                .to_string(),
        ],
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("{digest:x}")
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

#[cfg(test)]
mod tests {
    use super::{build_integrity_snapshot, discover_estate_references};
    use crate::types::TextArtifact;

    #[test]
    fn records_skill_digest_without_executing_anything() {
        let artifacts = vec![TextArtifact {
            path: "SKILL.md".to_string(),
            content: "name: demo\n".to_string(),
        }];

        let snapshot = build_integrity_snapshot(&artifacts);

        assert_eq!(snapshot.skill_file_digests.len(), 1);
        assert_eq!(snapshot.skill_file_digests[0].sha256.len(), 64);
    }

    #[test]
    fn estate_discovery_is_scope_limited() {
        let artifacts = vec![TextArtifact {
            path: ".config/mcp.json".to_string(),
            content: r#"{"mcpServers":{"demo":{}}}"#.to_string(),
        }];

        let estate = discover_estate_references(&artifacts);

        assert_eq!(estate.references.len(), 1);
        assert_eq!(estate.references[0].reference_kind, "mcp_config");
    }
}
