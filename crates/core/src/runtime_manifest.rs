use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use thiserror::Error;

use crate::types::{
    AvailabilityState, CapabilitySurface, EnvironmentScope, PermissionSchema, PermissionSurface,
    PrivilegeHint, RuntimeEnvironment, RuntimeFact, RuntimeManifest, RuntimeSourceKind,
    WritableFileSystemScope,
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
    #[serde(default)]
    capability_surface: Option<RawCapabilitySurface>,
    #[serde(default)]
    environment_scope: Option<RawEnvironmentScope>,
    #[serde(default)]
    privilege_hint: Option<String>,
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
    #[serde(default)]
    direct_network: Option<RawAvailability>,
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
    #[serde(default)]
    shell_allowed: Option<RawAvailability>,
    #[serde(default)]
    child_process_allowed: Option<RawAvailability>,
    #[serde(default)]
    write_allowed: Option<RawAvailability>,
    #[serde(default)]
    edit_allowed: Option<RawAvailability>,
    #[serde(default)]
    apply_patch_allowed: Option<RawAvailability>,
    #[serde(default, alias = "browser")]
    browser_available: Option<RawAvailability>,
    #[serde(default)]
    browser_network: Option<RawAvailability>,
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
    #[serde(default, alias = "homeAccess", alias = "home_access")]
    home_directory_access: Option<RawAvailability>,
}

#[derive(Debug, Default, Deserialize)]
struct RawCapabilitySurface {
    #[serde(default)]
    exec_allowed: Option<RawAvailability>,
    #[serde(default)]
    process_allowed: Option<RawAvailability>,
    #[serde(default)]
    shell_allowed: Option<RawAvailability>,
    #[serde(default)]
    child_process_allowed: Option<RawAvailability>,
    #[serde(default)]
    write_allowed: Option<RawAvailability>,
    #[serde(default)]
    edit_allowed: Option<RawAvailability>,
    #[serde(default)]
    apply_patch_allowed: Option<RawAvailability>,
    #[serde(default)]
    direct_network: Option<RawAvailability>,
    #[serde(default)]
    browser_network: Option<RawAvailability>,
    #[serde(default, alias = "web_fetch_available")]
    web_fetch: Option<RawAvailability>,
    #[serde(default, alias = "gateway_available")]
    gateway: Option<RawAvailability>,
    #[serde(default, alias = "nodes_available")]
    nodes: Option<RawAvailability>,
    #[serde(default, alias = "cron_available")]
    cron: Option<RawAvailability>,
    #[serde(default)]
    env_available: Option<RawAvailability>,
    #[serde(default)]
    config_available: Option<RawAvailability>,
    #[serde(default)]
    auth_profiles_available: Option<RawAvailability>,
    #[serde(default)]
    local_secret_paths_available: Option<RawAvailability>,
    #[serde(default)]
    browser_store_proximity: Option<RawAvailability>,
}

#[derive(Debug, Default, Deserialize)]
struct RawEnvironmentScope {
    #[serde(default)]
    workspace_only: Option<RawAvailability>,
    #[serde(default, alias = "home_directory_access", alias = "homeAccess")]
    home_access: Option<RawAvailability>,
    #[serde(default, alias = "mounted_directories")]
    mounted_paths: Vec<String>,
    #[serde(default, alias = "mounted_secrets_or_configs", alias = "mountedSecrets")]
    mounted_secrets: Vec<String>,
    #[serde(default)]
    writable_scope: Option<String>,
    #[serde(default)]
    read_only_scope: Option<RawAvailability>,
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
            shell_allowed: AvailabilityState::Unknown,
            child_process_allowed: AvailabilityState::Unknown,
            write_allowed: AvailabilityState::Unknown,
            edit_allowed: AvailabilityState::Unknown,
            apply_patch_allowed: AvailabilityState::Unknown,
            browser_available: AvailabilityState::Unknown,
            web_fetch_available: AvailabilityState::Unknown,
            web_search_available: AvailabilityState::Unknown,
            gateway_available: AvailabilityState::Unknown,
            nodes_available: AvailabilityState::Unknown,
            cron_available: AvailabilityState::Unknown,
            direct_network: AvailabilityState::Unknown,
            browser_network: AvailabilityState::Unknown,
            root_admin_hint: AvailabilityState::Unknown,
            user_identity_hint: None,
            home_directory_access: AvailabilityState::Unknown,
        },
        permission_schema: PermissionSchema {
            schema_version: "v2".to_string(),
            capability_surface: CapabilitySurface {
                exec_allowed: AvailabilityState::Unknown,
                process_allowed: AvailabilityState::Unknown,
                shell_allowed: AvailabilityState::Unknown,
                child_process_allowed: AvailabilityState::Unknown,
                write_allowed: AvailabilityState::Unknown,
                edit_allowed: AvailabilityState::Unknown,
                apply_patch_allowed: AvailabilityState::Unknown,
                direct_network: AvailabilityState::Unknown,
                browser_network: AvailabilityState::Unknown,
                web_fetch: AvailabilityState::Unknown,
                gateway: AvailabilityState::Unknown,
                nodes: AvailabilityState::Unknown,
                cron: AvailabilityState::Unknown,
                env_available: AvailabilityState::Unknown,
                config_available: AvailabilityState::Unknown,
                auth_profiles_available: AvailabilityState::Unknown,
                local_secret_paths_available: AvailabilityState::Unknown,
                browser_store_proximity: AvailabilityState::Unknown,
            },
            environment_scope: EnvironmentScope {
                workspace_only: AvailabilityState::Unknown,
                home_access: AvailabilityState::Unknown,
                mounted_paths: Vec::new(),
                mounted_secrets: Vec::new(),
                writable_scope: WritableFileSystemScope::Unknown,
                read_only_scope: AvailabilityState::Unknown,
            },
            privilege_hint: PrivilegeHint::Unknown,
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
    let capability = raw.capability_surface.unwrap_or_default();
    let environment_scope = raw.environment_scope.unwrap_or_default();
    let writable_scope = normalize_writable_scope(
        permission
            .writable_scope
            .as_deref()
            .or(environment_scope.writable_scope.as_deref()),
    );
    let mounted_directories = if !environment_scope.mounted_paths.is_empty() {
        environment_scope.mounted_paths
    } else {
        permission.mounted_directories
    };
    let mounted_secrets_or_configs = if !environment_scope.mounted_secrets.is_empty() {
        environment_scope.mounted_secrets
    } else {
        permission.mounted_secrets_or_configs
    };
    let exec_allowed = first_known([
        normalize_availability(capability.exec_allowed),
        normalize_availability(permission.exec_allowed),
    ]);
    let process_allowed = first_known([
        normalize_availability(capability.process_allowed),
        normalize_availability(permission.process_allowed),
    ]);
    let shell_allowed = first_known([
        normalize_availability(capability.shell_allowed),
        normalize_availability(permission.shell_allowed),
        exec_allowed,
    ]);
    let child_process_allowed = first_known([
        normalize_availability(capability.child_process_allowed),
        normalize_availability(permission.child_process_allowed),
        process_allowed,
    ]);
    let browser_available = normalize_availability(permission.browser_available);
    let web_fetch_available = first_known([
        normalize_availability(capability.web_fetch),
        normalize_availability(permission.web_fetch_available),
    ]);
    let gateway_available = first_known([
        normalize_availability(capability.gateway),
        normalize_availability(permission.gateway_available),
    ]);
    let nodes_available = first_known([
        normalize_availability(capability.nodes),
        normalize_availability(permission.nodes_available),
    ]);
    let cron_available = first_known([
        normalize_availability(capability.cron),
        normalize_availability(permission.cron_available),
    ]);
    let direct_network = first_known([
        normalize_availability(capability.direct_network),
        normalize_availability(permission.direct_network),
        normalize_availability(permission.network.clone()),
    ]);
    let browser_network = first_known([
        normalize_availability(capability.browser_network),
        normalize_availability(permission.browser_network),
        browser_available,
    ]);
    let home_directory_access = first_known([
        normalize_availability(permission.home_directory_access),
        normalize_availability(environment_scope.home_access),
    ]);
    let write_allowed = first_known([
        normalize_availability(capability.write_allowed),
        normalize_availability(permission.write_allowed),
    ]);
    let edit_allowed = first_known([
        normalize_availability(capability.edit_allowed),
        normalize_availability(permission.edit_allowed),
    ]);
    let apply_patch_allowed = first_known([
        normalize_availability(capability.apply_patch_allowed),
        normalize_availability(permission.apply_patch_allowed),
    ]);
    let network = normalize_availability(permission.network);
    let web_search_available = normalize_availability(permission.web_search_available);
    let root_admin_hint = normalize_availability(permission.root_admin_hint);
    let privilege_hint = normalize_privilege_hint(
        raw.privilege_hint.as_deref(),
        root_admin_hint,
        permission.user_identity_hint.as_deref(),
        normalize_environment(raw.execution_environment.as_deref()),
    );

    let present_env_vars = raw.present_env_vars;
    let present_config_files = raw.present_config_files;
    let auth_profiles_present = raw.auth_profiles_present;
    let credential_store_proximity = raw.credential_store_proximity;

    let permission_surface = PermissionSurface {
        network,
        writable_scope,
        mounted_directories: mounted_directories.clone(),
        mounted_secrets_or_configs: mounted_secrets_or_configs.clone(),
        exec_allowed,
        process_allowed,
        shell_allowed,
        child_process_allowed,
        write_allowed,
        edit_allowed,
        apply_patch_allowed,
        browser_available,
        web_fetch_available,
        web_search_available,
        gateway_available,
        nodes_available,
        cron_available,
        direct_network,
        browser_network,
        root_admin_hint,
        user_identity_hint: permission.user_identity_hint,
        home_directory_access,
    };

    let permission_schema = PermissionSchema {
        schema_version: "v2".to_string(),
        capability_surface: CapabilitySurface {
            exec_allowed,
            process_allowed,
            shell_allowed,
            child_process_allowed,
            write_allowed,
            edit_allowed,
            apply_patch_allowed,
            direct_network,
            browser_network,
            web_fetch: web_fetch_available,
            gateway: gateway_available,
            nodes: nodes_available,
            cron: cron_available,
            env_available: first_known([
                normalize_availability(capability.env_available),
                availability_from_non_empty(&present_env_vars),
            ]),
            config_available: first_known([
                normalize_availability(capability.config_available),
                availability_from_non_empty(&present_config_files),
            ]),
            auth_profiles_available: first_known([
                normalize_availability(capability.auth_profiles_available),
                availability_from_non_empty(&auth_profiles_present),
            ]),
            local_secret_paths_available: first_known([
                normalize_availability(capability.local_secret_paths_available),
                home_directory_access,
                availability_from_non_empty(&mounted_secrets_or_configs),
            ]),
            browser_store_proximity: first_known([
                normalize_availability(capability.browser_store_proximity),
                availability_from_non_empty(&credential_store_proximity),
            ]),
        },
        environment_scope: EnvironmentScope {
            workspace_only: first_known([
                normalize_availability(environment_scope.workspace_only),
                match writable_scope {
                    WritableFileSystemScope::WorkspaceOnly => AvailabilityState::Enabled,
                    WritableFileSystemScope::Unknown => AvailabilityState::Unknown,
                    _ => AvailabilityState::Disabled,
                },
            ]),
            home_access: home_directory_access,
            mounted_paths: mounted_directories.clone(),
            mounted_secrets: mounted_secrets_or_configs.clone(),
            writable_scope,
            read_only_scope: first_known([
                normalize_availability(environment_scope.read_only_scope),
                match writable_scope {
                    WritableFileSystemScope::ReadOnly => AvailabilityState::Enabled,
                    WritableFileSystemScope::Unknown => AvailabilityState::Unknown,
                    _ => AvailabilityState::Disabled,
                },
            ]),
        },
        privilege_hint,
    };

    let execution_environment = normalize_environment(raw.execution_environment.as_deref());
    RuntimeManifest {
        execution_environment,
        permission_surface,
        permission_schema,
        expected_env_vars: Vec::new(),
        present_env_vars,
        expected_config_files: Vec::new(),
        present_config_files,
        auth_profiles_present,
        credential_store_proximity,
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
        ("shell_allowed", manifest.permission_surface.shell_allowed),
        ("child_process_allowed", manifest.permission_surface.child_process_allowed),
        ("write_allowed", manifest.permission_surface.write_allowed),
        ("edit_allowed", manifest.permission_surface.edit_allowed),
        ("apply_patch_allowed", manifest.permission_surface.apply_patch_allowed),
        ("direct_network", manifest.permission_surface.direct_network),
        ("browser_network", manifest.permission_surface.browser_network),
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

fn normalize_privilege_hint(
    value: Option<&str>,
    root_admin_hint: AvailabilityState,
    user_identity_hint: Option<&str>,
    environment: RuntimeEnvironment,
) -> PrivilegeHint {
    if matches!(root_admin_hint, AvailabilityState::Enabled) {
        return PrivilegeHint::RootAdmin;
    }
    if let Some(value) = value.map(|value| value.trim().to_ascii_lowercase()) {
        return match value.as_str() {
            "root" | "admin" | "administrator" => PrivilegeHint::RootAdmin,
            "standard_user" | "standard user" | "user" => PrivilegeHint::StandardUser,
            "sandbox_restricted" | "sandbox restricted" | "restricted" => {
                PrivilegeHint::SandboxRestricted
            }
            _ => PrivilegeHint::Unknown,
        };
    }
    if matches!(environment, RuntimeEnvironment::Sandbox) {
        return PrivilegeHint::SandboxRestricted;
    }
    if let Some(identity) = user_identity_hint {
        if !identity.trim().is_empty() {
            return PrivilegeHint::StandardUser;
        }
    }
    PrivilegeHint::Unknown
}

fn availability_from_non_empty(items: &[String]) -> AvailabilityState {
    if items.is_empty() {
        AvailabilityState::Unknown
    } else {
        AvailabilityState::Enabled
    }
}

fn first_known<const N: usize>(values: [AvailabilityState; N]) -> AvailabilityState {
    values
        .into_iter()
        .find(|value| *value != AvailabilityState::Unknown)
        .unwrap_or(AvailabilityState::Unknown)
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::types::{AvailabilityState, PrivilegeHint, RuntimeEnvironment, WritableFileSystemScope};

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
    fn schema_v2_fields_and_unknowns_are_supported() {
        let dir = tempdir().unwrap();
        let manifest = dir.path().join("runtime.yaml");
        fs::write(
            &manifest,
            "execution_environment: sandbox\ncapability_surface:\n  shell_allowed: false\n  child_process_allowed: unknown\n  direct_network: false\nenvironment_scope:\n  workspace_only: true\n  read_only_scope: false\nprivilege_hint: sandbox_restricted\n",
        )
        .unwrap();

        let result = load_runtime_manifest(Some(&manifest), &manifest, &[], &[]).unwrap();

        assert_eq!(result.manifest.permission_surface.shell_allowed, AvailabilityState::Disabled);
        assert_eq!(
            result.manifest.permission_surface.child_process_allowed,
            AvailabilityState::Unknown
        );
        assert_eq!(result.manifest.permission_schema.privilege_hint, PrivilegeHint::SandboxRestricted);
        assert_eq!(
            result.manifest.permission_schema.environment_scope.workspace_only,
            AvailabilityState::Enabled
        );
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
