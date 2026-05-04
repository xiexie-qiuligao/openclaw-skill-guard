use std::path::Path;

use serde_json::Value;

use crate::install::InstallAnalysis;
use crate::types::{
    DependencyAuditSummary, EvidenceKind, EvidenceNode, Finding, FindingConfidence,
    FindingSeverity, SkillLocation, TextArtifact,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DependencyAuditAnalysis {
    pub summary: DependencyAuditSummary,
    pub findings: Vec<Finding>,
}

pub fn analyze_dependency_audit(
    documents: &[TextArtifact],
    install: &InstallAnalysis,
) -> DependencyAuditAnalysis {
    let mut findings = Vec::new();
    let mut manifests_discovered = Vec::new();
    let mut lockfile_gaps = Vec::new();
    let mut notes = Vec::new();

    for document in documents {
        let Some(file_name) = Path::new(&document.path)
            .file_name()
            .and_then(|name| name.to_str())
        else {
            continue;
        };

        match file_name {
            "package.json" => {
                manifests_discovered.push(document.path.clone());
                findings.extend(analyze_package_json(document));
                if !has_npm_lockfile(documents, &document.path) {
                    lockfile_gaps.push(document.path.clone());
                    findings.push(make_dependency_finding(
                        "dependency.lockfile_gap",
                        "Dependency manifest is missing an adjacent npm lockfile",
                        FindingSeverity::Medium,
                        &document.path,
                        1,
                        "package.json was found without package-lock.json, npm-shrinkwrap.json, yarn.lock, or pnpm-lock.yaml alongside it.",
                        "Lockfile coverage is missing for a package-manager manifest.",
                        vec!["No supported npm lockfile was found next to this package manifest.".to_string()],
                    ));
                }
            }
            "package-lock.json" | "npm-shrinkwrap.json" => {
                manifests_discovered.push(document.path.clone());
                findings.extend(analyze_npm_lockfile(document));
            }
            "requirements.txt" => {
                manifests_discovered.push(document.path.clone());
                findings.extend(analyze_requirements_txt(document));
            }
            "pyproject.toml" => {
                manifests_discovered.push(document.path.clone());
                findings.extend(analyze_pyproject_toml(document));
            }
            "Cargo.toml" => {
                manifests_discovered.push(document.path.clone());
                findings.extend(analyze_cargo_toml(document));
                if !has_sibling_file(&document.path, documents, "Cargo.lock") {
                    lockfile_gaps.push(document.path.clone());
                    findings.push(make_dependency_finding(
                        "dependency.lockfile_gap",
                        "Cargo manifest is missing an adjacent lockfile",
                        FindingSeverity::Low,
                        &document.path,
                        1,
                        "Cargo.toml was found without a sibling Cargo.lock.",
                        "Lockfile coverage is missing for a Rust package manifest.",
                        vec!["Cargo manifests without lockfiles make dependency reproduction less explicit.".to_string()],
                    ));
                }
            }
            "Cargo.lock" | "yarn.lock" | "pnpm-lock.yaml" => {
                manifests_discovered.push(document.path.clone());
            }
            _ => {}
        }
    }

    findings.extend(analyze_install_chain_dependency_risk(install));

    manifests_discovered.sort();
    manifests_discovered.dedup();
    lockfile_gaps.sort();
    lockfile_gaps.dedup();
    if manifests_discovered.is_empty() {
        notes.push(
            "No supported dependency manifests were discovered in the current scan scope."
                .to_string(),
        );
    } else {
        notes.push(format!(
            "Dependency audit v1 scanned {} supported manifest or lockfile artifact(s).",
            manifests_discovered.len()
        ));
    }

    let summary = DependencyAuditSummary {
        summary: if manifests_discovered.is_empty() {
            "No supported dependency manifests were discovered.".to_string()
        } else if findings.is_empty() {
            format!(
                "Discovered {} dependency manifest or lockfile artifact(s) with no dependency audit findings.",
                manifests_discovered.len()
            )
        } else {
            format!(
                "Discovered {} dependency manifest or lockfile artifact(s) and generated {} dependency audit finding(s).",
                manifests_discovered.len(),
                findings.len()
            )
        },
        manifests_discovered,
        lockfile_gaps,
        findings_count: findings.len(),
        notes,
    };

    DependencyAuditAnalysis { summary, findings }
}

fn analyze_package_json(document: &TextArtifact) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(value) = serde_json::from_str::<Value>(&document.content) else {
        findings.push(make_dependency_finding(
            "dependency.remote_source",
            "package.json could not be parsed for dependency audit",
            FindingSeverity::Low,
            &document.path,
            1,
            "package.json parsing failed during dependency audit.",
            "The manifest could not be parsed, so dependency source analysis is incomplete.",
            vec![
                "Dependency audit v1 relies on manifest parsing for explainable source signals."
                    .to_string(),
            ],
        ));
        return findings;
    };

    for group in [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ] {
        if let Some(object) = value.get(group).and_then(Value::as_object) {
            for (name, spec) in object {
                if let Some(version) = spec.as_str() {
                    findings.extend(analyze_npm_spec(
                        document,
                        name,
                        version,
                        format!("package.json {group}"),
                    ));
                }
            }
        }
    }

    if let Some(registry) = value
        .get("publishConfig")
        .and_then(|item| item.get("registry"))
        .and_then(Value::as_str)
    {
        let host = extract_host(registry);
        if let Some(host) = host {
            if host != "registry.npmjs.org" && host != "registry.yarnpkg.com" {
                findings.push(make_dependency_finding(
                    "dependency.non_default_registry",
                    "package.json publishConfig points at a non-default registry",
                    FindingSeverity::Medium,
                    &document.path,
                    1,
                    registry,
                    "The manifest points package publication or resolution at a non-default npm registry.",
                    vec![format!("Detected publishConfig.registry host `{host}`.")],
                ));
            }
        }
    }

    findings
}

fn analyze_npm_lockfile(document: &TextArtifact) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(value) = serde_json::from_str::<Value>(&document.content) else {
        return findings;
    };
    let mut resolved_urls = Vec::new();
    collect_json_values_by_key(&value, "resolved", &mut resolved_urls);
    for resolved in resolved_urls {
        if let Some(host) = extract_host(&resolved) {
            if host != "registry.npmjs.org" && host != "registry.yarnpkg.com" {
                findings.push(make_dependency_finding(
                    "dependency.non_default_registry",
                    "Lockfile resolves dependencies from a non-default npm registry",
                    FindingSeverity::Medium,
                    &document.path,
                    1,
                    &resolved,
                    "The lockfile contains a dependency resolution URL outside the default npm registry hosts.",
                    vec![format!("Resolved host `{host}` came from lockfile metadata.")],
                ));
            }
        }
    }
    findings
}

fn analyze_requirements_txt(document: &TextArtifact) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (index, line) in document.content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with("--index-url") || trimmed.starts_with("--extra-index-url") {
            if let Some(url) = trimmed.split_whitespace().last() {
                if let Some(host) = extract_host(url) {
                    if host != "pypi.org" && host != "files.pythonhosted.org" {
                        findings.push(make_dependency_finding(
                            "dependency.non_default_registry",
                            "requirements.txt configures a non-default Python package index",
                            FindingSeverity::Medium,
                            &document.path,
                            index + 1,
                            trimmed,
                            "The requirements file configures a custom package index or mirror.",
                            vec![format!("Configured package index host `{host}`.")],
                        ));
                    }
                }
            }
            continue;
        }
        findings.extend(analyze_pip_spec(
            document,
            index + 1,
            trimmed,
            "requirements.txt",
        ));
    }
    findings
}

fn analyze_pyproject_toml(document: &TextArtifact) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(value) = document.content.parse::<toml::Value>() else {
        return findings;
    };

    if let Some(project) = value.get("project").and_then(toml::Value::as_table) {
        if let Some(dependencies) = project.get("dependencies").and_then(toml::Value::as_array) {
            for dependency in dependencies {
                if let Some(spec) = dependency.as_str() {
                    findings.extend(analyze_pip_spec(
                        document,
                        1,
                        spec,
                        "pyproject project.dependencies",
                    ));
                }
            }
        }
    }

    if let Some(tool) = value.get("tool").and_then(toml::Value::as_table) {
        if let Some(poetry) = tool.get("poetry").and_then(toml::Value::as_table) {
            if let Some(dependencies) = poetry.get("dependencies").and_then(toml::Value::as_table) {
                for (name, spec) in dependencies {
                    if name == "python" {
                        continue;
                    }
                    findings.extend(analyze_poetry_dependency(document, name, spec));
                }
            }
            if let Some(sources) = poetry.get("source").and_then(toml::Value::as_array) {
                for source in sources {
                    if let Some(url) = source.get("url").and_then(toml::Value::as_str) {
                        if let Some(host) = extract_host(url) {
                            if host != "pypi.org" && host != "files.pythonhosted.org" {
                                findings.push(make_dependency_finding(
                                    "dependency.non_default_registry",
                                    "pyproject.toml declares a non-default Poetry source",
                                    FindingSeverity::Medium,
                                    &document.path,
                                    1,
                                    url,
                                    "The pyproject metadata declares a non-default dependency source.",
                                    vec![format!("Poetry source host `{host}` was declared in pyproject.toml.")],
                                ));
                            }
                        }
                    }
                }
            }
        }
    }

    findings
}

fn analyze_cargo_toml(document: &TextArtifact) -> Vec<Finding> {
    let mut findings = Vec::new();
    let Ok(value) = document.content.parse::<toml::Value>() else {
        return findings;
    };
    let Some(root) = value.as_table() else {
        return findings;
    };

    for table_name in ["dependencies", "dev-dependencies", "build-dependencies"] {
        if let Some(table) = root.get(table_name).and_then(toml::Value::as_table) {
            for (name, spec) in table {
                findings.extend(analyze_cargo_dependency(document, name, spec, table_name));
            }
        }
    }

    findings
}

fn analyze_npm_spec(
    document: &TextArtifact,
    name: &str,
    spec: &str,
    source: String,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lowered = spec.trim().to_ascii_lowercase();
    if lowered == "*" || lowered == "latest" || is_weak_version_spec(&lowered) {
        findings.push(make_dependency_finding(
            "dependency.unpinned_requirement",
            "npm dependency uses a weak or floating version constraint",
            FindingSeverity::Low,
            &document.path,
            1,
            &format!("{name}: {spec}"),
            "The dependency declaration is not pinned to a specific reviewed artifact version.",
            vec![format!(
                "Found npm dependency `{name}` in {source} with spec `{spec}`."
            )],
        ));
    }

    if is_vcs_spec(&lowered) {
        let finding_id = if has_pinned_vcs_ref(&lowered) {
            "dependency.remote_source"
        } else {
            "dependency.unpinned_vcs_source"
        };
        let severity = if finding_id == "dependency.unpinned_vcs_source" {
            FindingSeverity::High
        } else {
            FindingSeverity::Medium
        };
        findings.push(make_dependency_finding(
            finding_id,
            "npm dependency resolves from a VCS source",
            severity,
            &document.path,
            1,
            &format!("{name}: {spec}"),
            "The dependency resolves from a VCS location instead of a default reviewed registry artifact.",
            vec![format!("Found npm dependency `{name}` in {source} with VCS spec `{spec}`.")],
        ));
    } else if lowered.starts_with("http://")
        || lowered.starts_with("https://")
        || lowered.starts_with("file:")
        || lowered.starts_with("github:")
    {
        findings.push(make_dependency_finding(
            "dependency.remote_source",
            "npm dependency resolves from a direct URL or alternate source",
            FindingSeverity::High,
            &document.path,
            1,
            &format!("{name}: {spec}"),
            "The dependency resolves from a direct URL, local file source, or alternate package source.",
            vec![format!("Found npm dependency `{name}` in {source} with source spec `{spec}`.")],
        ));
    }

    findings
}

fn analyze_pip_spec(
    document: &TextArtifact,
    line: usize,
    spec: &str,
    source: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let lowered = spec.to_ascii_lowercase();
    if lowered.starts_with("-e ") || is_vcs_spec(&lowered) {
        let finding_id = if has_pinned_vcs_ref(&lowered) {
            "dependency.remote_source"
        } else {
            "dependency.unpinned_vcs_source"
        };
        let severity = if finding_id == "dependency.unpinned_vcs_source" {
            FindingSeverity::High
        } else {
            FindingSeverity::Medium
        };
        findings.push(make_dependency_finding(
            finding_id,
            "Python dependency resolves from a VCS source",
            severity,
            &document.path,
            line,
            spec,
            "The dependency resolves from a VCS or editable source rather than a pinned package artifact.",
            vec![format!("Found Python dependency in {source}: `{spec}`.")],
        ));
        return findings;
    }

    if lowered.contains(" @ http://")
        || lowered.contains(" @ https://")
        || lowered.starts_with("http://")
        || lowered.starts_with("https://")
    {
        findings.push(make_dependency_finding(
            "dependency.remote_source",
            "Python dependency resolves from a direct URL",
            FindingSeverity::High,
            &document.path,
            line,
            spec,
            "The dependency resolves from a direct URL instead of a standard pinned package source.",
            vec![format!("Found Python dependency in {source}: `{spec}`.")],
        ));
        return findings;
    }

    if !is_exact_pip_pin(spec) {
        findings.push(make_dependency_finding(
            "dependency.unpinned_requirement",
            "Python dependency is not pinned exactly",
            FindingSeverity::Medium,
            &document.path,
            line,
            spec,
            "The dependency declaration allows version drift or omits an explicit reviewed version.",
            vec![format!("Found Python dependency in {source}: `{spec}`.")],
        ));
    }

    findings
}

fn analyze_poetry_dependency(
    document: &TextArtifact,
    name: &str,
    spec: &toml::Value,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    match spec {
        toml::Value::String(version) => {
            if is_weak_version_spec(&version.to_ascii_lowercase()) || version.trim() == "*" {
                findings.push(make_dependency_finding(
                    "dependency.unpinned_requirement",
                    "Poetry dependency uses a weak version constraint",
                    FindingSeverity::Medium,
                    &document.path,
                    1,
                    &format!("{name} = {version}"),
                    "The Poetry dependency declaration is not pinned to a specific reviewed version.",
                    vec![format!("Poetry dependency `{name}` uses version `{version}`.")],
                ));
            }
        }
        toml::Value::Table(table) => {
            if let Some(git) = table.get("git").and_then(toml::Value::as_str) {
                let pinned = table.contains_key("rev") || table.contains_key("tag");
                findings.push(make_dependency_finding(
                    if pinned {
                        "dependency.remote_source"
                    } else {
                        "dependency.unpinned_vcs_source"
                    },
                    "Poetry dependency resolves from VCS metadata",
                    if pinned {
                        FindingSeverity::Medium
                    } else {
                        FindingSeverity::High
                    },
                    &document.path,
                    1,
                    &format!("{name} = {git}"),
                    "The Poetry dependency is sourced from VCS metadata rather than a default reviewed package artifact.",
                    vec![format!("Poetry dependency `{name}` uses git source `{git}`.")],
                ));
            }
            if let Some(url) = table.get("url").and_then(toml::Value::as_str) {
                findings.push(make_dependency_finding(
                    "dependency.remote_source",
                    "Poetry dependency resolves from a direct URL",
                    FindingSeverity::High,
                    &document.path,
                    1,
                    &format!("{name} = {url}"),
                    "The Poetry dependency is sourced from a direct URL.",
                    vec![format!(
                        "Poetry dependency `{name}` uses direct URL `{url}`."
                    )],
                ));
            }
        }
        _ => {}
    }
    findings
}

fn analyze_cargo_dependency(
    document: &TextArtifact,
    name: &str,
    spec: &toml::Value,
    table_name: &str,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    match spec {
        toml::Value::String(version) => {
            let lowered = version.trim().to_ascii_lowercase();
            if lowered == "*" || is_weak_version_spec(&lowered) {
                findings.push(make_dependency_finding(
                    "dependency.unpinned_requirement",
                    "Cargo dependency uses a wide version constraint",
                    FindingSeverity::Low,
                    &document.path,
                    1,
                    &format!("{name} = {version}"),
                    "The Cargo dependency declaration uses a wide or floating version constraint.",
                    vec![format!(
                        "Cargo dependency `{name}` in {table_name} uses `{version}`."
                    )],
                ));
            }
        }
        toml::Value::Table(table) => {
            if let Some(version) = table.get("version").and_then(toml::Value::as_str) {
                let lowered = version.trim().to_ascii_lowercase();
                if lowered == "*" || is_weak_version_spec(&lowered) {
                    findings.push(make_dependency_finding(
                        "dependency.unpinned_requirement",
                        "Cargo dependency uses a wide version constraint",
                        FindingSeverity::Low,
                        &document.path,
                        1,
                        &format!("{name} = {version}"),
                        "The Cargo dependency declaration uses a wide or floating version constraint.",
                        vec![format!("Cargo dependency `{name}` in {table_name} uses `{version}`.")],
                    ));
                }
            }
            if let Some(git) = table.get("git").and_then(toml::Value::as_str) {
                findings.push(make_dependency_finding(
                    if table.contains_key("rev") {
                        "dependency.remote_source"
                    } else {
                        "dependency.unpinned_vcs_source"
                    },
                    "Cargo dependency resolves from a git source",
                    if table.contains_key("rev") {
                        FindingSeverity::Medium
                    } else {
                        FindingSeverity::High
                    },
                    &document.path,
                    1,
                    &format!("{name} = {git}"),
                    "The Cargo dependency is sourced from git metadata rather than a crates.io release artifact.",
                    vec![format!(
                        "Cargo dependency `{name}` in {table_name} uses git source `{git}`."
                    )],
                ));
            }
            if let Some(registry) = table.get("registry").and_then(toml::Value::as_str) {
                findings.push(make_dependency_finding(
                    "dependency.non_default_registry",
                    "Cargo dependency declares a non-default registry",
                    FindingSeverity::Medium,
                    &document.path,
                    1,
                    &format!("{name} = {registry}"),
                    "The Cargo dependency is tied to a non-default registry.",
                    vec![format!(
                        "Cargo dependency `{name}` in {table_name} uses registry `{registry}`."
                    )],
                ));
            }
            if let Some(index) = table.get("index").and_then(toml::Value::as_str) {
                findings.push(make_dependency_finding(
                    "dependency.non_default_registry",
                    "Cargo dependency declares a custom registry index",
                    FindingSeverity::Medium,
                    &document.path,
                    1,
                    &format!("{name} = {index}"),
                    "The Cargo dependency uses a custom registry index or alternate source.",
                    vec![format!(
                        "Cargo dependency `{name}` in {table_name} uses index `{index}`."
                    )],
                ));
            }
            if let Some(path) = table.get("path").and_then(toml::Value::as_str) {
                findings.push(make_dependency_finding(
                    "dependency.non_default_registry",
                    "Cargo dependency uses a local path source",
                    FindingSeverity::Medium,
                    &document.path,
                    1,
                    &format!("{name} = {path}"),
                    "The Cargo dependency resolves from a local path source instead of the default registry.",
                    vec![format!(
                        "Cargo dependency `{name}` in {table_name} uses path source `{path}`."
                    )],
                ));
            }
        }
        _ => {}
    }
    findings
}

fn analyze_install_chain_dependency_risk(install: &InstallAnalysis) -> Vec<Finding> {
    let mut findings = Vec::new();
    for spec in &install.install_specs {
        if matches!(
            spec.kind,
            crate::types::InstallKind::Node
                | crate::types::InstallKind::Go
                | crate::types::InstallKind::Uv
        ) {
            findings.push(make_dependency_finding(
                "dependency.install_chain_pull_risk",
                "Install chain pulls mutable package-manager dependencies",
                if spec.auto_install {
                    FindingSeverity::High
                } else {
                    FindingSeverity::Medium
                },
                &spec.source_path,
                1,
                &spec.raw,
                "The install chain relies on package-manager dependency retrieval as part of setup.",
                vec![format!(
                    "Install spec kind `{:?}` pulls package `{}`.",
                    spec.kind,
                    spec.package.as_deref().unwrap_or("unknown")
                )],
            ));
        }
    }
    findings
}

fn has_npm_lockfile(documents: &[TextArtifact], manifest_path: &str) -> bool {
    [
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
    ]
    .iter()
    .any(|candidate| has_sibling_file(manifest_path, documents, candidate))
}

fn has_sibling_file(manifest_path: &str, documents: &[TextArtifact], file_name: &str) -> bool {
    let Some(parent) = Path::new(manifest_path).parent() else {
        return false;
    };
    documents.iter().any(|document| {
        Path::new(&document.path).parent() == Some(parent)
            && Path::new(&document.path)
                .file_name()
                .and_then(|name| name.to_str())
                == Some(file_name)
    })
}

fn collect_json_values_by_key(value: &Value, key: &str, output: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (entry_key, entry_value) in map {
                if entry_key == key {
                    if let Some(text) = entry_value.as_str() {
                        output.push(text.to_string());
                    }
                }
                collect_json_values_by_key(entry_value, key, output);
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_json_values_by_key(item, key, output);
            }
        }
        _ => {}
    }
}

fn is_weak_version_spec(spec: &str) -> bool {
    let trimmed = spec.trim();
    trimmed.contains('^')
        || trimmed.contains('~')
        || trimmed.contains('>')
        || trimmed.contains('<')
        || trimmed.contains("||")
        || trimmed.contains(" x")
        || trimmed.ends_with(".x")
        || trimmed.contains(">=")
        || trimmed.contains("<=")
}

fn is_vcs_spec(spec: &str) -> bool {
    spec.starts_with("git+")
        || spec.starts_with("git://")
        || spec.starts_with("github:")
        || spec.starts_with("hg+")
        || spec.starts_with("svn+")
        || spec.starts_with("bzr+")
}

fn has_pinned_vcs_ref(spec: &str) -> bool {
    if let Some(fragment) = spec.split('#').nth(1) {
        return fragment.len() >= 7;
    }
    spec.contains(" rev = ") || spec.contains("@")
}

fn is_exact_pip_pin(spec: &str) -> bool {
    let trimmed = spec.trim();
    if trimmed.contains(" @ ") {
        return false;
    }
    trimmed.contains("==") && !trimmed.contains(">=") && !trimmed.contains("<=")
}

fn extract_host(url: &str) -> Option<String> {
    let trimmed = url.trim();
    let scheme_split = trimmed.find("://")?;
    let without_scheme = &trimmed[scheme_split + 3..];
    let host = without_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_end_matches(':');
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

fn make_dependency_finding(
    id: &str,
    title: &str,
    severity: FindingSeverity,
    path: &str,
    line: usize,
    excerpt: &str,
    explanation: &str,
    analyst_notes: Vec<String>,
) -> Finding {
    Finding {
        id: id.to_string(),
        title: title.to_string(),
        issue_code: None,
        title_zh: None,
        category: id.to_string(),
        severity,
        confidence: FindingConfidence::Medium,
        hard_trigger: false,
        evidence_kind: "structured_metadata".to_string(),
        location: Some(SkillLocation {
            path: path.to_string(),
            line: Some(line),
            column: None,
        }),
        evidence: vec![EvidenceNode {
            kind: EvidenceKind::StructuredMetadata,
            location: SkillLocation {
                path: path.to_string(),
                line: Some(line),
                column: None,
            },
            excerpt: excerpt.to_string(),
            direct: true,
        }],
        explanation: explanation.to_string(),
        explanation_zh: None,
        why_openclaw_specific: "Dependency retrieval and install-chain source selection can turn package metadata into real host-side setup risk inside OpenClaw skill workflows.".to_string(),
        prerequisite_context: vec!["The dependency signal was extracted from a supported manifest, lockfile, or install-chain artifact.".to_string()],
        analyst_notes,
        remediation: "Pin reviewed versions, prefer default registries, and avoid direct URL or unpinned VCS dependency sources where practical.".to_string(),
        recommendation_zh: None,
        suppression_status: "not_suppressed".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use crate::install::InstallAnalysis;
    use crate::types::{InstallKind, InstallSpec, TextArtifact};

    use super::analyze_dependency_audit;

    #[test]
    fn detects_npm_weak_pin_and_lockfile_gap() {
        let docs = vec![TextArtifact {
            path: "repo/package.json".to_string(),
            content: r#"{"dependencies":{"left-pad":"^1.3.0"}}"#.to_string(),
        }];

        let analysis = analyze_dependency_audit(
            &docs,
            &InstallAnalysis {
                install_specs: Vec::new(),
                findings: Vec::new(),
                summary: String::new(),
            },
        );

        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "dependency.unpinned_requirement"));
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "dependency.lockfile_gap"));
    }

    #[test]
    fn detects_pip_direct_url_and_custom_index() {
        let docs = vec![TextArtifact {
            path: "repo/requirements.txt".to_string(),
            content: "--index-url https://packages.example.com/simple\nmypkg @ https://packages.example.com/pkg.whl\n".to_string(),
        }];

        let analysis = analyze_dependency_audit(
            &docs,
            &InstallAnalysis {
                install_specs: Vec::new(),
                findings: Vec::new(),
                summary: String::new(),
            },
        );

        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "dependency.non_default_registry"));
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "dependency.remote_source"));
    }

    #[test]
    fn detects_cargo_git_without_rev_and_path_source() {
        let docs = vec![
            TextArtifact {
                path: "repo/Cargo.toml".to_string(),
                content: "[dependencies]\nserde = \"*\"\ncustom = { git = \"https://github.com/example/custom\" }\nlocaldep = { path = \"../localdep\" }\n".to_string(),
            },
            TextArtifact {
                path: "repo/Cargo.lock".to_string(),
                content: String::new(),
            },
        ];

        let analysis = analyze_dependency_audit(
            &docs,
            &InstallAnalysis {
                install_specs: Vec::new(),
                findings: Vec::new(),
                summary: String::new(),
            },
        );

        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "dependency.unpinned_requirement"));
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "dependency.unpinned_vcs_source"));
        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "dependency.non_default_registry"));
    }

    #[test]
    fn converts_install_chain_package_pull_into_finding() {
        let analysis = analyze_dependency_audit(
            &[],
            &InstallAnalysis {
                install_specs: vec![InstallSpec {
                    kind: InstallKind::Node,
                    source: "metadata".to_string(),
                    source_path: "repo/SKILL.md".to_string(),
                    raw: "npm install suspicious-tool".to_string(),
                    package: Some("suspicious-tool".to_string()),
                    url: None,
                    checksum_present: false,
                    auto_install: true,
                    executes_after_download: false,
                }],
                findings: Vec::new(),
                summary: String::new(),
            },
        );

        assert!(analysis
            .findings
            .iter()
            .any(|finding| finding.id == "dependency.install_chain_pull_risk"));
    }
}
