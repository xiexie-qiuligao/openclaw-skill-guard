use crate::types::{
    AvailabilityState, CapabilityCheck, ConstraintCheck, GuardedValidationResult, PathGuardStatus,
    PathValidationDisposition, PathValidationStatus, PrivilegeHint, RuntimeAssumptionState,
    RuntimeManifest, SandboxConstraintEffect,
};

pub fn build_guarded_validation_result(
    manifest: &RuntimeManifest,
    path_statuses: &[PathValidationStatus],
) -> GuardedValidationResult {
    let capability_checks = build_capability_checks(manifest);
    let constraint_checks = build_constraint_checks(manifest);
    let sandbox_constraint_effects = build_sandbox_constraint_effects(path_statuses);

    let summary = format!(
        "Guarded validation evaluated {} capability checks, {} environment/secret constraint checks, and {} path-level sandbox effects without executing untrusted content.",
        capability_checks.len(),
        constraint_checks.len(),
        sandbox_constraint_effects.len()
    );

    GuardedValidationResult {
        summary,
        capability_checks,
        constraint_checks,
        sandbox_constraint_effects,
    }
}

pub fn infer_guard_status(status: PathValidationDisposition) -> PathGuardStatus {
    match status {
        PathValidationDisposition::Validated => PathGuardStatus::Supported,
        PathValidationDisposition::PartiallyValidated => PathGuardStatus::Narrowed,
        PathValidationDisposition::BlockedByEnvironment => PathGuardStatus::Blocked,
        PathValidationDisposition::ScopeIncomplete | PathValidationDisposition::StillAssumed => {
            PathGuardStatus::Assumed
        }
    }
}

fn build_capability_checks(manifest: &RuntimeManifest) -> Vec<CapabilityCheck> {
    let surface = &manifest.permission_schema.capability_surface;
    vec![
        capability_check(
            "exec_or_process",
            first_known([surface.exec_allowed, surface.process_allowed]),
            "Execution-capable tool surfaces decide whether command-dispatch and execution paths can be supported.",
        ),
        capability_check(
            "shell_or_child_process",
            first_known([surface.shell_allowed, surface.child_process_allowed]),
            "Shell and child-process availability refine whether wrapper-style execution chains remain realistic.",
        ),
        capability_check(
            "write_edit_apply_patch",
            first_known([surface.write_allowed, surface.edit_allowed, surface.apply_patch_allowed]),
            "Mutation-capable surfaces refine whether file-changing paths remain feasible.",
        ),
        capability_check(
            "browser_or_web_fetch",
            first_known([surface.browser_network, surface.web_fetch]),
            "Browser and fetch surfaces refine instruction-following and remote-content mediated paths.",
        ),
        capability_check(
            "gateway_nodes_cron",
            first_known([surface.gateway, surface.nodes, surface.cron]),
            "Gateway, nodes, and cron surfaces amplify delegated or persistent outward actions.",
        ),
        capability_check(
            "direct_network",
            surface.direct_network,
            "Direct network availability refines install-chain and exfiltration-style paths.",
        ),
    ]
}

fn build_constraint_checks(manifest: &RuntimeManifest) -> Vec<ConstraintCheck> {
    let scope = &manifest.permission_schema.environment_scope;
    let surface = &manifest.permission_schema.capability_surface;
    let mut checks = vec![
        constraint_check(
            "workspace_only_scope",
            map_availability(scope.workspace_only),
            "Workspace-only scope narrows filesystem consequence and mutation range.",
        ),
        constraint_check(
            "home_access",
            map_availability(scope.home_access),
            "Home-directory access amplifies local secret and persistence consequences.",
        ),
        constraint_check(
            "read_only_scope",
            map_availability(scope.read_only_scope),
            "Read-only scope can block mutation-oriented attack paths.",
        ),
        constraint_check(
            "env_available",
            map_availability(surface.env_available),
            "Env availability confirms only the presence of env-backed prerequisites, not their contents.",
        ),
        constraint_check(
            "config_available",
            map_availability(surface.config_available),
            "Config availability confirms config-backed prerequisites without reading sensitive data.",
        ),
        constraint_check(
            "auth_profiles_available",
            map_availability(surface.auth_profiles_available),
            "Auth-profile presence refines whether agent or gateway credential context is reachable.",
        ),
        constraint_check(
            "local_secret_paths_available",
            map_availability(surface.local_secret_paths_available),
            "Local secret path availability refines whether home-directory secret paths remain reachable.",
        ),
    ];

    checks.push(ConstraintCheck {
        name: "privilege_hint".to_string(),
        status: match manifest.permission_schema.privilege_hint {
            PrivilegeHint::Unknown => RuntimeAssumptionState::Unknown,
            PrivilegeHint::SandboxRestricted => RuntimeAssumptionState::Blocked,
            PrivilegeHint::RootAdmin | PrivilegeHint::StandardUser => RuntimeAssumptionState::Validated,
        },
        rationale: "Privilege hints refine whether runtime consequences are amplified, standard, or sandbox-restricted."
            .to_string(),
    });

    checks
}

fn build_sandbox_constraint_effects(
    path_statuses: &[PathValidationStatus],
) -> Vec<SandboxConstraintEffect> {
    path_statuses
        .iter()
        .map(|status| {
            let effect = match status.guard_status {
                PathGuardStatus::Supported => "supported",
                PathGuardStatus::Narrowed => "narrowed",
                PathGuardStatus::Blocked => "blocked",
                PathGuardStatus::Assumed => "assumed",
                PathGuardStatus::Amplified => "amplified",
            };
            SandboxConstraintEffect {
                name: status.path_id.clone(),
                effect: effect.to_string(),
                rationale: status.note.clone(),
            }
        })
        .collect()
}

fn capability_check(name: &str, available: AvailabilityState, rationale: &str) -> CapabilityCheck {
    CapabilityCheck {
        name: name.to_string(),
        available,
        rationale: rationale.to_string(),
    }
}

fn constraint_check(name: &str, status: RuntimeAssumptionState, rationale: &str) -> ConstraintCheck {
    ConstraintCheck {
        name: name.to_string(),
        status,
        rationale: rationale.to_string(),
    }
}

fn map_availability(state: AvailabilityState) -> RuntimeAssumptionState {
    match state {
        AvailabilityState::Enabled => RuntimeAssumptionState::Validated,
        AvailabilityState::Disabled => RuntimeAssumptionState::Blocked,
        AvailabilityState::Unknown => RuntimeAssumptionState::Unknown,
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
    use crate::types::{
        AvailabilityState, CapabilitySurface, EnvironmentScope, GuardedValidationResult,
        PathValidationDisposition, PathValidationStatus, PermissionSchema, PermissionSurface,
        PrivilegeHint, RuntimeEnvironment, RuntimeManifest, RuntimeSourceKind,
        WritableFileSystemScope,
    };

    use super::build_guarded_validation_result;

    fn demo_manifest() -> RuntimeManifest {
        RuntimeManifest {
            execution_environment: RuntimeEnvironment::Sandbox,
            permission_surface: PermissionSurface {
                network: AvailabilityState::Disabled,
                writable_scope: WritableFileSystemScope::WorkspaceOnly,
                mounted_directories: vec!["./workspace".to_string()],
                mounted_secrets_or_configs: vec![],
                exec_allowed: AvailabilityState::Disabled,
                process_allowed: AvailabilityState::Disabled,
                shell_allowed: AvailabilityState::Disabled,
                child_process_allowed: AvailabilityState::Disabled,
                write_allowed: AvailabilityState::Enabled,
                edit_allowed: AvailabilityState::Enabled,
                apply_patch_allowed: AvailabilityState::Enabled,
                browser_available: AvailabilityState::Unknown,
                web_fetch_available: AvailabilityState::Unknown,
                web_search_available: AvailabilityState::Unknown,
                gateway_available: AvailabilityState::Unknown,
                nodes_available: AvailabilityState::Unknown,
                cron_available: AvailabilityState::Unknown,
                direct_network: AvailabilityState::Disabled,
                browser_network: AvailabilityState::Unknown,
                root_admin_hint: AvailabilityState::Disabled,
                user_identity_hint: Some("sandbox-user".to_string()),
                home_directory_access: AvailabilityState::Disabled,
            },
            permission_schema: PermissionSchema {
                schema_version: "v2".to_string(),
                capability_surface: CapabilitySurface {
                    exec_allowed: AvailabilityState::Disabled,
                    process_allowed: AvailabilityState::Disabled,
                    shell_allowed: AvailabilityState::Disabled,
                    child_process_allowed: AvailabilityState::Disabled,
                    write_allowed: AvailabilityState::Enabled,
                    edit_allowed: AvailabilityState::Enabled,
                    apply_patch_allowed: AvailabilityState::Enabled,
                    direct_network: AvailabilityState::Disabled,
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
                    workspace_only: AvailabilityState::Enabled,
                    home_access: AvailabilityState::Disabled,
                    mounted_paths: vec!["./workspace".to_string()],
                    mounted_secrets: vec![],
                    writable_scope: WritableFileSystemScope::WorkspaceOnly,
                    read_only_scope: AvailabilityState::Disabled,
                },
                privilege_hint: PrivilegeHint::SandboxRestricted,
            },
            expected_env_vars: Vec::new(),
            present_env_vars: Vec::new(),
            expected_config_files: Vec::new(),
            present_config_files: Vec::new(),
            auth_profiles_present: Vec::new(),
            credential_store_proximity: Vec::new(),
            notes: Vec::new(),
            source_kind: RuntimeSourceKind::UserManifest,
        }
    }

    #[test]
    fn builds_guarded_summary_and_checks() {
        let manifest = demo_manifest();
        let paths = vec![PathValidationStatus {
            path_id: "path.demo".to_string(),
            status: PathValidationDisposition::BlockedByEnvironment,
            guard_status: super::infer_guard_status(PathValidationDisposition::BlockedByEnvironment),
            validated_constraints: Vec::new(),
            missing_constraints: Vec::new(),
            note: "A required runtime constraint is explicitly blocked in the current environment.".to_string(),
        }];

        let result: GuardedValidationResult = build_guarded_validation_result(&manifest, &paths);

        assert!(result.summary.contains("capability checks"));
        assert!(result
            .capability_checks
            .iter()
            .any(|check| check.name == "exec_or_process"));
        assert!(result
            .constraint_checks
            .iter()
            .any(|check| check.name == "workspace_only_scope"));
        assert!(result
            .sandbox_constraint_effects
            .iter()
            .any(|effect| effect.effect == "blocked"));
    }
}
