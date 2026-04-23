use serde_json::Value;

use crate::frontmatter::{get_field, parse_bool};
use crate::types::{
    InstallKind, InstallSpec, InvocationDispatch, InvocationPolicy, OpenClawMetadata, RequiresSpec,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MetadataNormalizationResult {
    pub metadata: OpenClawMetadata,
    pub invocation_policy: InvocationPolicy,
    pub diagnostics: Vec<String>,
}

pub fn normalize_metadata(
    frontmatter: &crate::types::FrontmatterParseResult,
) -> MetadataNormalizationResult {
    let mut diagnostics = Vec::new();
    let raw_metadata = get_field(frontmatter, "metadata")
        .map(str::trim)
        .filter(|value| !value.is_empty());

    let mut metadata = OpenClawMetadata {
        present: raw_metadata.is_some(),
        normalized: false,
        homepage: None,
        skill_key: None,
        primary_env: None,
        requires: RequiresSpec::default(),
        install: Vec::new(),
        notes: Vec::new(),
    };

    let invocation_policy = InvocationPolicy {
        user_invocable: parse_bool(get_field(frontmatter, "user-invocable"), true),
        disable_model_invocation: parse_bool(
            get_field(frontmatter, "disable-model-invocation"),
            false,
        ),
        command_dispatch: normalize_dispatch(get_field(frontmatter, "command-dispatch")),
        command_tool: get_field(frontmatter, "command-tool")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
        command_arg_mode: get_field(frontmatter, "command-arg-mode")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string),
        notes: Vec::new(),
    };

    if let Some(raw_metadata) = raw_metadata {
        match serde_json::from_str::<Value>(raw_metadata) {
            Ok(value) => {
                let openclaw = value.get("openclaw").unwrap_or(&Value::Null);
                if let Some(object) = openclaw.as_object() {
                    metadata.normalized = true;
                    metadata.homepage = string_at(object.get("homepage"));
                    metadata.skill_key = string_at(object.get("skillKey"));
                    metadata.primary_env = string_at(object.get("primaryEnv"));
                    metadata.requires = normalize_requires(object.get("requires"));
                    metadata.install = normalize_install(object.get("install"), &mut diagnostics);
                } else if !openclaw.is_null() {
                    diagnostics
                        .push("metadata.openclaw exists but is not a JSON object".to_string());
                }
            }
            Err(err) => diagnostics.push(format!("metadata JSON parse failed: {err}")),
        }
    }

    if metadata.homepage.is_none() {
        metadata.homepage = get_field(frontmatter, "homepage").map(ToString::to_string);
    }

    MetadataNormalizationResult {
        metadata,
        invocation_policy,
        diagnostics,
    }
}

fn normalize_dispatch(value: Option<&str>) -> InvocationDispatch {
    match value.map(|v| v.trim().to_ascii_lowercase()) {
        Some(value) if value == "tool" => InvocationDispatch::Tool,
        Some(value) if value.is_empty() => InvocationDispatch::None,
        Some(_) => InvocationDispatch::Unknown,
        None => InvocationDispatch::None,
    }
}

fn normalize_requires(value: Option<&Value>) -> RequiresSpec {
    let Some(value) = value.and_then(Value::as_object) else {
        return RequiresSpec::default();
    };

    RequiresSpec {
        bins: string_list(value.get("bins")),
        any_bins: string_list(value.get("anyBins")),
        env: string_list(value.get("env")),
        config: string_list(value.get("config")),
    }
}

fn normalize_install(value: Option<&Value>, diagnostics: &mut Vec<String>) -> Vec<InstallSpec> {
    let Some(value) = value else {
        return Vec::new();
    };

    let raw_specs: Vec<&Value> = match value {
        Value::Array(items) => items.iter().collect(),
        Value::Object(_) => vec![value],
        _ => {
            diagnostics.push("metadata.openclaw.install must be an object or array".to_string());
            return Vec::new();
        }
    };

    raw_specs
        .into_iter()
        .filter_map(|item| {
            let object = item.as_object()?;
            let kind = object
                .get("kind")
                .and_then(Value::as_str)
                .map(normalize_install_kind)
                .unwrap_or(InstallKind::Unknown);
            let raw = item.to_string();
            let package = string_at(object.get("package"))
                .or_else(|| string_at(object.get("formula")))
                .or_else(|| string_at(object.get("module")))
                .or_else(|| string_at(object.get("tool")));
            let url = string_at(object.get("url"));
            let checksum_present = object.contains_key("checksum")
                || object.contains_key("sha256")
                || object.contains_key("digest")
                || raw.to_ascii_lowercase().contains("checksum");
            let executes_after_download = object
                .get("execute")
                .and_then(Value::as_bool)
                .unwrap_or(false)
                || object.get("run").and_then(Value::as_bool).unwrap_or(false);

            Some(InstallSpec {
                kind,
                source: "metadata.openclaw.install".to_string(),
                source_path: "SKILL.md".to_string(),
                raw,
                package,
                url,
                checksum_present,
                auto_install: true,
                executes_after_download,
            })
        })
        .collect()
}

fn normalize_install_kind(value: &str) -> InstallKind {
    match value.to_ascii_lowercase().as_str() {
        "brew" => InstallKind::Brew,
        "node" | "npm" | "pnpm" | "yarn" | "bun" => InstallKind::Node,
        "go" => InstallKind::Go,
        "uv" => InstallKind::Uv,
        "download" => InstallKind::Download,
        _ => InstallKind::Unknown,
    }
}

fn string_at(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).map(ToString::to_string)
}

fn string_list(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(item)) => vec![item.to_string()],
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .map(ToString::to_string)
            .collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use crate::frontmatter::parse_frontmatter;

    use super::normalize_metadata;

    #[test]
    fn normalizes_openclaw_metadata() {
        let doc = parse_frontmatter(
            "---\nmetadata: {\"openclaw\":{\"skillKey\":\"demo\",\"primaryEnv\":\"DEMO_KEY\",\"requires\":{\"env\":[\"DEMO_KEY\"],\"config\":[\"tools.exec\"]},\"install\":[{\"kind\":\"download\",\"url\":\"https://example.invalid/tool.zip\",\"checksum\":\"sha256:abc\"}]}}\nuser-invocable: true\ncommand-dispatch: tool\ncommand-tool: exec\n---\nBody",
        );

        let normalized = normalize_metadata(&doc.frontmatter);

        assert_eq!(normalized.metadata.skill_key.as_deref(), Some("demo"));
        assert_eq!(normalized.metadata.primary_env.as_deref(), Some("DEMO_KEY"));
        assert_eq!(normalized.metadata.requires.config, vec!["tools.exec"]);
        assert_eq!(normalized.metadata.install.len(), 1);
        assert_eq!(
            normalized.invocation_policy.command_tool.as_deref(),
            Some("exec")
        );
    }
}
