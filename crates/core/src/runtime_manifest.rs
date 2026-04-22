use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

use crate::types::{
    AvailabilityState, PermissionSurface, RuntimeEnvironment, RuntimeFact, RuntimeManifest,
    RuntimeSourceKind, WritableFileSystemScope,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeManifestLoadResult {
    pub manifest: RuntimeManifest,
    pub summary: String,
    pub runtime_facts: Vec<RuntimeFact>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Error)]
pub enum RuntimeManifestError {
    #[error("failed to read runtime manifest {path}: {message}")]
    Read { path: String, message: String },
    #[error("failed to parse runtime manifest {path}: {message}")]
    Parse { path: String, message: String },
}

#[derive(Debug, Default, Deserialize)]
struct RawRuntimeManifest {
    #[serde(default, alias = "environment", alias = "executionEnvironment")]
    execution_environment: Option<String>,
    #[serde(default, alias = "permissions")]
    permission_surface: Option<RawPermissionSurface>,
    #[serde(default, alias = "env", alias = "envVars", alias = "presentEnvVars")]
    present_env_vars: Vec<String>,
    #[serde(default, alias = "configFiles", alias = "presentConfigFiles")]
    present_config_files: Vec<String>,
    #[serde(default, alias = "authProfiles")]
    auth_profiles_present: Vec<String>,
    #[serde(default, alias = "credentialStores")]
    credential_store_proximity: Vec<String>,
    #[serde(default)]
    notes: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct RawPermissionSurface {
    #[serde(default)]
    network: Option<RawAvailability>,
    #[serde(default, alias = "writableFilesystemScope")]
    writable_scope: Option<String>,
    #[serde(default)]
    mounted_directories: Vec<String>,
    #[serde(default, alias = "mountedSecrets", alias = "mountedConfigs")]
    mounted_secrets_or_configs: Vec<String>,
    #[serde(default)]
    exec_allowed: Option<RawAvailability>,
    #[serde(default)]
    process_allowed: Option<RawAvailability>,
    #[serde(default, alias = "browser")]
    browser_available: Option<RawAvailability>,
    #[serde(default)]
    web_fetch_available: Option<RawAvailability>,
    #[serde(default)]
    web_search_available: Option<RawAvailability>,
    #[serde(default)]
    gateway_available: Option<RawAvailability>,
    #[serde(default)]
    nodes_available: Option<RawAvailability>,
    #[serde(default)]
    cron_available: Option<RawAvailability>,
    #[serde(default, alias = "rootAdmin", alias = "admin")]
    root_admin_hint: Option<RawAvailability>,
    #[serde(default)]
    user_identity_hint: Option<String>,
    #[serde(default, alias = "homeAccess")]
    home_directory_access: Option<RawAvailability>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum RawAvailability {
    Bool(bool),
    StringValue(String),
}

pub fn load_runtime_manifest(
    manifest_path: Option<&Path>,
    target_path: &Path,
    expected_env_vars: &[String],
    expected_config_files: &[String],
) -> Result<RuntimeManifestLoadResult, RuntimeManifestError> {
    let mut diagnostics = Vec::new();
    let mut runtime_facts = Vec::new();
    let mut manifest = RuntimeManifest {
        execution_environment: RuntimeEnvironment::Unknown,
        permission_surface: PermissionSurface {
            network: AvailabilityState::Unknown,
            writable_scope: WritableFileSystemScope::Unknown,
            mounted_directories: Vec::new(),
            mounted_secrets_or_configs: Vec::new(),
            exec_allowed: AvailabilityState::Unknown,
            process_allowed: AvailabilityState::Unknown,
            browser_available: AvailabilityState::Unknown,
            web_fetch_available: AvailabilityState::Unknown,
            web_search_available: AvailabilityState::Unknown,
            gateway_available: AvailabilityState::Unknown,
            nodes_available: AvailabilityState::Unknown,
            cron_available: AvailabilityState::Unknown,
            root_admin_hint: AvailabilityState::Unknown,
            user_identity_hint: None,
            home_directory_access: AvailabilityState::Unknown,
        },
        expected_env_vars: expected_env_vars.to_vec(),
        present_env_vars: Vec::new(),
        expected_config_files: expected_config_files.to_vec(),
        present_config_files: Vec::new(),
        auth_profiles_present: Vec::new(),
        credential_store_proximity: Vec::new(),
        notes: Vec::new(),
        source_kind: RuntimeSourceKind::Unknown,
    };

    if let Some(path) = manifest_path {
        let content = fs::read_to_string(path).map_err(|err| RuntimeManifestError::Read {
            path: path.display().to_string(),
            message: err.to_string(),
        })?;
        let raw = parse_manifest_content(path, &content)?;
        manifest = from_raw_manifest(raw);
        manifest.source_kind = RuntimeSourceKind::UserManifest;
        runtime_facts.extend(facts_from_manifest(&manifest));
    }

    let safe_checks = infer_safe_local_facts(target_path, &manifest.expected_env_vars, &manifest.expected_config_files);
    for fact in safe_checks {
        match fact.key.as_str() {
            "env_present" => {
                if !manifest.present_env_vars.contains(&fact.value) {
                    manifest.present_env_vars.push(fact.value.clone());
                }
            }
            "config_present" => {
                if !manifest.present_config_files.contains(&fact.value) {
                    manifest.present_config_files.push(fact.value.clone());
                }
            }
            "home_directory_present" => {
                if manifest.permission_surface.home_directory_access == AvailabilityState::Unknown {
                    manifest.permission_surface.home_directory_access = AvailabilityState::Enabled;
                }
            }
            _ => {}
        }
        runtime_facts.push(fact);
    }

    if manifest.permission_surface.mounted_directories.is_empty() {
        let parent = target_path
            .parent()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| target_path.display().to_string());
        manifest.permission_surface.mounted_directories.push(parent.clone());
        runtime_facts.push(RuntimeFact {
            key: "observed_target_root".to_string(),
            value: parent,
            source_kind: RuntimeSourceKind::InferredFromConfig,
            confirmed: true,
        });
    }

    if manifest.notes.is_empty() {
        manifest
            .notes
            .push("Runtime manifest information is partial; unknown fields remain unknown instead of being treated as absent.".to_string());
    }

    let summary = if manifest_path.is_some() {
        format!(
            "Loaded runtime manifest with environment={:?}, network={:?}, exec={:?}, writable_scope={:?}.",
            manifest.execution_environment,
            manifest.permission_surface.network,
            manifest.permission_surface.exec_allowed,
            manifest.permission_surface.writable_scope
        )
    } else {
        diagnostics.push("No runtime manifest was supplied; runtime validation will rely on safe local checks and remain partially assumed.".to_string());
        "No runtime manifest supplied; runtime refinement is based on safe local checks and unknowns remain explicit.".to_string()
    };

    Ok(RuntimeManifestLoadResult {
        manifest,
        summary,
        runtime_facts,
        diagnostics,
    })
}

fn parse_manifest_content(path: &Path, content: &str) -> Result<RawRuntimeManifest, RuntimeManifestError> {
    let extension = path
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if extension == "yaml" || extension == "yml" {
        serde_yaml::from_str(content).map_err(|err| RuntimeManifestError::Parse {
            path: path.display().to_string(),
            message: err.to_string(),
        })
    } else {
        serde_json::from_str(content)
            .or_else(|_| serde_yaml::from_str(content))
            .map_err(|err| RuntimeManifestError::Parse {
                path: path.display().to_string(),
                message: err.to_string(),
            })
    }
}

fn from_raw_manifest(raw: RawRuntimeManifest) -> RuntimeManifest {
    let permission = raw.permission_surface.unwrap_or_default();
    RuntimeManifest {
        execution_environment: normalize_environment(raw.execution_environment.as_deref()),
        permission_surface: PermissionSurface {
            network: normalize_availability(permission.network),
            writable_scope: normalize_writable_scope(permission.writable_scope.as_deref()),
            mounted_directories: permission.mounted_directories,
            mounted_secrets_or_configs: permission.mounted_secrets_or_configs,
            exec_allowed: normalize_availability(permission.exec_allowed),
            process_allowed: normalize_availability(permission.process_allowed),
            browser_available: normalize_availability(permission.browser_available),
            web_fetch_available: normalize_availability(permission.web_fetch_available),
            web_search_available: normalize_availability(permission.web_search_available),
            gateway_available: normalize_availability(permission.gateway_available),
            nodes_available: normalize_availability(permission.nodes_available),
            cron_available: normalize_availability(permission.cron_available),
            root_admin_hint: normalize_availability(permission.root_admin_hint),
            user_identity_hint: permission.user_identity_hint,
            home_directory_access: normalize_availability(permission.home_directory_access),
        },
        expected_env_vars: Vec::new(),
        present_env_vars: raw.present_env_vars,
        expected_config_files: Vec::new(),
        present_config_files: raw.present_config_files,
        auth_profiles_present: raw.auth_profiles_present,
        credential_store_proximity: raw.credential_store_proximity,
        notes: raw.notes,
        source_kind: RuntimeSourceKind::UserManifest,
    }
}

fn facts_from_manifest(manifest: &RuntimeManifest) -> Vec<RuntimeFact> {
    let mut facts = Vec::new();
    facts.push(RuntimeFact {
        key: "execution_environment".to_string(),
        value: format!("{:?}", manifest.execution_environment),
        source_kind: RuntimeSourceKind::UserManifest,
        confirmed: manifest.execution_environment != RuntimeEnvironment::Unknown,
    });
    for (key, value) in [
        ("network", manifest.permission_surface.network),
        ("exec_allowed", manifest.permission_surface.exec_allowed),
        ("process_allowed", manifest.permission_surface.process_allowed),
        ("browser_available", manifest.permission_surface.browser_available),
        ("web_fetch_available", manifest.permission_surface.web_fetch_available),
        ("gateway_available", manifest.permission_surface.gateway_available),
        ("nodes_available", manifest.permission_surface.nodes_available),
        ("cron_available", manifest.permission_surface.cron_available),
        ("home_directory_access", manifest.permission_surface.home_directory_access),
    ] {
        facts.push(RuntimeFact {
            key: key.to_string(),
            value: format!("{:?}", value),
            source_kind: RuntimeSourceKind::UserManifest,
            confirmed: value != AvailabilityState::Unknown,
        });
    }
    facts
}

fn infer_safe_local_facts(
    target_path: &Path,
    expected_env_vars: &[String],
    expected_config_files: &[String],
) -> Vec<RuntimeFact> {
    let mut facts = Vec::new();
    for var in expected_env_vars {
        if env::var_os(var).is_some() {
            facts.push(RuntimeFact {
                key: "env_present".to_string(),
                value: var.clone(),
                source_kind: RuntimeSourceKind::SafeLocalCheck,
                confirmed: true,
            });
        }
    }

    for config in expected_config_files {
        if let Some(expanded) = expand_candidate_path(target_path, config) {
            if expanded.exists() {
                facts.push(RuntimeFact {
                    key: "config_present".to_string(),
                    value: config.clone(),
                    source_kind: RuntimeSourceKind::SafeLocalCheck,
                    confirmed: true,
                });
            }
        }
    }

    if let Some(home) = user_home_dir() {
        if home.exists() {
            facts.push(RuntimeFact {
                key: "home_directory_present".to_string(),
                value: home.display().to_string(),
                source_kind: RuntimeSourceKind::SafeLocalCheck,
                confirmed: true,
            });
        }
    }

    facts
}

fn expand_candidate_path(target_path: &Path, candidate: &str) -> Option<PathBuf> {
    if candidate.starts_with("~/") || candidate.starts_with("~\\") {
        return user_home_dir().map(|home| home.join(candidate[2..].replace('\\', "/")));
    }
    let candidate_path = PathBuf::from(candidate);
    if candidate_path.is_absolute() {
        Some(candidate_path)
    } else {
        target_path.parent().map(|parent| parent.join(candidate_path))
    }
}

fn user_home_dir() -> Option<PathBuf> {
    env::var_os("USERPROFILE")
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(PathBuf::from))
}

fn normalize_environment(value: Option<&str>) -> RuntimeEnvironment {
    match value.map(|value| value.trim().to_ascii_lowercase()) {
        Some(value) if value == "host" => RuntimeEnvironment::Host,
        Some(value) if value == "sandbox" => RuntimeEnvironment::Sandbox,
        Some(value) if value == "mixed" => RuntimeEnvironment::Mixed,
        _ => RuntimeEnvironment::Unknown,
    }
}

fn normalize_availability(value: Option<RawAvailability>) -> AvailabilityState {
    match value {
        Some(RawAvailability::Bool(true)) => AvailabilityState::Enabled,
        Some(RawAvailability::Bool(false)) => AvailabilityState::Disabled,
        Some(RawAvailability::StringValue(value)) => match value.trim().to_ascii_lowercase().as_str() {
            "enabled" | "allow" | "allowed" | "true" => AvailabilityState::Enabled,
            "disabled" | "deny" | "denied" | "false" => AvailabilityState::Disabled,
            _ => AvailabilityState::Unknown,
        },
        None => AvailabilityState::Unknown,
    }
}

fn normalize_writable_scope(value: Option<&str>) -> WritableFileSystemScope {
    match value.map(|value| value.trim().to_ascii_lowercase()) {
        Some(value) if value == "read_only" || value == "readonly" => WritableFileSystemScope::ReadOnly,
        Some(value) if value == "workspace_only" || value == "workspace" => {
            WritableFileSystemScope::WorkspaceOnly
        }
        Some(value) if value == "home_directory" || value == "home" => WritableFileSystemScope::HomeDirectory,
        Some(value) if value == "user_files" || value == "user" => WritableFileSystemScope::UserFiles,
        Some(value) if value == "any" => WritableFileSystemScope::Any,
        _ => WritableFileSystemScope::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::types::{AvailabilityState, RuntimeEnvironment, WritableFileSystemScope};

    use super::load_runtime_manifest;

    #[test]
    fn parses_minimal_json_manifest() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("runtime.json");
        fs::write(
            &manifest,
            r#"{"execution_environment":"sandbox","permission_surface":{"network":"disabled","exec_allowed":false,"writable_scope":"workspace_only"}}"#,
        )
        .unwrap();

        let result = load_runtime_manifest(Some(&manifest), &manifest, &[], &[]).unwrap();

        assert_eq!(result.manifest.execution_environment, RuntimeEnvironment::Sandbox);
        assert_eq!(result.manifest.permission_surface.network, AvailabilityState::Disabled);
        assert_eq!(
            result.manifest.permission_surface.writable_scope,
            WritableFileSystemScope::WorkspaceOnly
        );
    }

    #[test]
    fn parses_partial_yaml_manifest_and_tolerates_unknown_fields() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("runtime.yaml");
        fs::write(
            &manifest,
            "execution_environment: host\nunknown_field: true\npermission_surface:\n  exec_allowed: enabled\n",
        )
        .unwrap();

        let result = load_runtime_manifest(Some(&manifest), &manifest, &[], &[]).unwrap();

        assert_eq!(result.manifest.execution_environment, RuntimeEnvironment::Host);
        assert_eq!(result.manifest.permission_surface.exec_allowed, AvailabilityState::Enabled);
    }

    #[test]
    fn invalid_manifest_reports_error() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("runtime.json");
        fs::write(&manifest, "{not-json").unwrap();

        let result = load_runtime_manifest(Some(&manifest), &manifest, &[], &[]);

        assert!(result.is_err());
    }
}
