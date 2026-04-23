use std::path::Path;

use crate::frontmatter::{get_field, parse_frontmatter};
use crate::metadata::normalize_metadata;
use crate::types::{ParsedSkill, SkillDescriptor, SkillSource};

pub fn parse_skill_file(path: &Path, content: &str, additional_files: Vec<String>) -> ParsedSkill {
    let frontmatter_doc = parse_frontmatter(content);
    let raw_metadata = get_field(&frontmatter_doc.frontmatter, "metadata").map(ToString::to_string);
    let normalized = normalize_metadata(&frontmatter_doc.frontmatter);
    let directory_name = path
        .parent()
        .and_then(Path::file_name)
        .map(|value| value.to_string_lossy().to_string());
    let name = get_field(&frontmatter_doc.frontmatter, "name")
        .map(ToString::to_string)
        .or_else(|| directory_name.clone());
    let description =
        get_field(&frontmatter_doc.frontmatter, "description").map(ToString::to_string);
    let homepage = get_field(&frontmatter_doc.frontmatter, "homepage")
        .map(ToString::to_string)
        .or_else(|| normalized.metadata.homepage.clone());
    let slug_candidates = build_slug_candidates(name.as_deref(), directory_name.as_deref());

    let mut notes = normalized.diagnostics;
    notes.extend(normalized.metadata.notes.iter().cloned());
    notes.extend(frontmatter_doc.frontmatter.diagnostics.iter().cloned());

    ParsedSkill {
        descriptor: SkillDescriptor {
            name,
            description,
            homepage,
            directory_name,
            slug_candidates,
        },
        skill_file: path.display().to_string(),
        skill_root: path.parent().unwrap_or(path).display().to_string(),
        body: frontmatter_doc.body,
        frontmatter: frontmatter_doc.frontmatter,
        raw_metadata,
        invocation_policy: normalized.invocation_policy,
        metadata: normalized.metadata,
        additional_files,
        source: infer_skill_source(path),
        notes,
    }
}

fn infer_skill_source(path: &Path) -> SkillSource {
    let lowered = path
        .display()
        .to_string()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if lowered.contains("/plugins/") {
        SkillSource::PluginExtraDir
    } else if lowered.contains("/bundled/") {
        SkillSource::Bundled
    } else if lowered.contains("/managed/") {
        SkillSource::Managed
    } else if lowered.contains("/extra") {
        SkillSource::ExtraDir
    } else if lowered.contains("/workspace/") || lowered.contains("/workspaces/") {
        SkillSource::Workspace
    } else if lowered.contains("/.openclaw/skills/") || lowered.contains("/personal/") {
        SkillSource::PersonalAgents
    } else if lowered.contains("/agents/") {
        SkillSource::ProjectAgents
    } else {
        SkillSource::Unknown
    }
}

fn build_slug_candidates(name: Option<&str>, directory_name: Option<&str>) -> Vec<String> {
    let mut candidates = Vec::new();
    for value in [name, directory_name] {
        if let Some(value) = value {
            let slug = value
                .chars()
                .map(|ch| {
                    if ch.is_ascii_alphanumeric() {
                        ch.to_ascii_lowercase()
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
                .trim_matches('-')
                .split('-')
                .filter(|segment| !segment.is_empty())
                .collect::<Vec<_>>()
                .join("-");
            if !slug.is_empty() && !candidates.contains(&slug) {
                candidates.push(slug);
            }
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use crate::types::SkillSource;

    use super::parse_skill_file;

    #[test]
    fn parsed_skill_contains_descriptor_and_metadata() {
        let parsed = parse_skill_file(
            Path::new("demo/SKILL.md"),
            "---\nname: Demo Skill\nmetadata: {\"openclaw\":{\"skillKey\":\"demo\"}}\n---\nBody",
            Vec::new(),
        );

        assert_eq!(parsed.descriptor.name.as_deref(), Some("Demo Skill"));
        assert_eq!(parsed.metadata.skill_key.as_deref(), Some("demo"));
        assert_eq!(
            parsed.descriptor.slug_candidates,
            vec!["demo-skill", "demo"]
        );
    }

    #[test]
    fn infers_source_from_path_segments() {
        let parsed = parse_skill_file(
            Path::new("workspace/plugins/demo/SKILL.md"),
            "---\nname: Demo\n---\nBody",
            Vec::new(),
        );

        assert_eq!(parsed.source, SkillSource::PluginExtraDir);
    }
}
