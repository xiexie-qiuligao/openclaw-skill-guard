use crate::precedence::PrecedenceAnalysis;
use crate::runtime_manifest::RuntimeManifestLoadResult;
use crate::types::{
    AttackPath, AvailabilityState, CapabilityCheck, ConsequenceAssessment, ConstraintCheck,
    ConstraintEffect, CredentialConsequenceKind, EnvironmentAmplifier, EnvironmentBlocker,
    FileSystemConsequenceKind, GuardedValidationResult, HostSandboxSplit, MissingConstraint,
    NetworkConsequenceKind, PathGuardStatus, PathValidationDisposition, PathValidationStatus,
    PermissionSurface, RuntimeAssumptionState, RuntimeAssumptionStatus, RuntimeEnvironment,
    RuntimeFact, RuntimeRefinementNote, RuntimeScoreAdjustment, SandboxConstraintEffect,
    ValidatedConstraint, ValidationCheck, ValidationExecutionMode, ValidationPlan,
    ValidationResult, ValidationTarget, WritableFileSystemScope,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeValidationAnalysis {
    pub runtime_manifest_summary: String,
    pub guarded_validation: GuardedValidationResult,
    pub runtime_facts: Vec<RuntimeFact>,
    pub runtime_assumption_status: Vec<RuntimeAssumptionStatus>,
    pub validation_results: Vec<ValidationResult>,
    pub path_validation_status: Vec<PathValidationStatus>,
    pub runtime_refinement_notes: Vec<RuntimeRefinementNote>,
    pub constraint_effects: Vec<ConstraintEffect>,
    pub environment_blockers: Vec<EnvironmentBlocker>,
    pub environment_amplifiers: Vec<EnvironmentAmplifier>,
    pub validation_score_adjustments: Vec<RuntimeScoreAdjustment>,
    pub refined_consequence: ConsequenceAssessment,
    pub refined_split: HostSandboxSplit,
    pub confidence_notes: Vec<String>,
}

pub fn perform_runtime_validation(
    manifest_load: &RuntimeManifestLoadResult,
    validation_plan: &ValidationPlan,
    attack_paths: &[AttackPath],
    consequence: &ConsequenceAssessment,
    split: &HostSandboxSplit,
    precedence: &PrecedenceAnalysis,
    mode: ValidationExecutionMode,
) -> RuntimeValidationAnalysis {
    let assumption_status = build_assumption_status(manifest_load, precedence);
    let validation_results =
        execute_validation_checks(validation_plan, manifest_load, precedence, mode);
    let path_validation_status = build_path_validation_status(
        attack_paths,
        &manifest_load.manifest.permission_surface,
        manifest_load,
        precedence,
    );
    let (
        constraint_effects,
        environment_blockers,
        environment_amplifiers,
        runtime_refinement_notes,
    ) = build_refinement_outputs(&path_validation_status);
    let validation_score_adjustments = build_runtime_score_adjustments(&path_validation_status);
    let refined_consequence = refine_consequence(
        consequence,
        &manifest_load.manifest.permission_surface,
        manifest_load,
    );
    let refined_split = refine_split(
        split,
        &manifest_load.manifest.permission_surface,
        manifest_load,
    );
    let guarded_validation = build_guarded_validation_result(
        &manifest_load.manifest.permission_surface,
        &assumption_status,
        &path_validation_status,
    );

    RuntimeValidationAnalysis {
        runtime_manifest_summary: manifest_load.summary.clone(),
        guarded_validation,
        runtime_facts: manifest_load.runtime_facts.clone(),
        runtime_assumption_status: assumption_status,
        validation_results,
        path_validation_status,
        runtime_refinement_notes,
        constraint_effects,
        environment_blockers,
        environment_amplifiers,
        validation_score_adjustments,
        refined_consequence,
        refined_split,
        confidence_notes: vec![
            "Runtime validation only uses manifest ingestion and guarded local checks; it does not execute install chains or untrusted code.".to_string(),
            "Validated runtime facts can strengthen, narrow, or block an attack path without erasing the underlying static evidence.".to_string(),
        ],
    }
}

fn build_assumption_status(
    manifest_load: &RuntimeManifestLoadResult,
    precedence: &PrecedenceAnalysis,
) -> Vec<RuntimeAssumptionStatus> {
    let manifest = &manifest_load.manifest;
    let mut statuses = Vec::new();
    statuses.push(RuntimeAssumptionStatus {
        assumption: "execution_environment".to_string(),
        state: match manifest.execution_environment {
            RuntimeEnvironment::Unknown => RuntimeAssumptionState::Unknown,
            _ => RuntimeAssumptionState::Validated,
        },
        source_kind: manifest.source_kind,
        rationale:
            "Execution environment can come directly from a runtime manifest or remain unknown."
                .to_string(),
    });
    for (assumption, state) in [
        ("network", manifest.permission_surface.network),
        ("exec_allowed", manifest.permission_surface.exec_allowed),
        (
            "process_allowed",
            manifest.permission_surface.process_allowed,
        ),
        (
            "home_directory_access",
            manifest.permission_surface.home_directory_access,
        ),
    ] {
        statuses.push(RuntimeAssumptionStatus {
            assumption: assumption.to_string(),
            state: map_availability_state(state),
            source_kind: manifest.source_kind,
            rationale:
                "Permission surfaces refine whether a path is validated, blocked, or still assumed."
                    .to_string(),
        });
    }
    for env_var in &manifest.expected_env_vars {
        statuses.push(RuntimeAssumptionStatus {
            assumption: format!("env:{env_var}"),
            state: if manifest.present_env_vars.contains(env_var) {
                RuntimeAssumptionState::Validated
            } else {
                RuntimeAssumptionState::Missing
            },
            source_kind: if manifest.present_env_vars.contains(env_var) {
                crate::types::RuntimeSourceKind::SafeLocalCheck
            } else {
                manifest.source_kind
            },
            rationale:
                "Expected env-backed secret presence can be validated without reading the value."
                    .to_string(),
        });
    }
    for file in &manifest.expected_config_files {
        statuses.push(RuntimeAssumptionStatus {
            assumption: format!("config:{file}"),
            state: if manifest.present_config_files.contains(file) {
                RuntimeAssumptionState::Validated
            } else {
                RuntimeAssumptionState::Missing
            },
            source_kind: if manifest.present_config_files.contains(file) {
                crate::types::RuntimeSourceKind::SafeLocalCheck
            } else {
                manifest.source_kind
            },
            rationale: "Expected config-backed secret presence can be checked via existence-only safe local checks.".to_string(),
        });
    }
    if !precedence.root_resolution.missing_roots.is_empty() {
        statuses.push(RuntimeAssumptionStatus {
            assumption: "precedence_scope_complete".to_string(),
            state: RuntimeAssumptionState::Missing,
            source_kind: crate::types::RuntimeSourceKind::InferredFromConfig,
            rationale: "Missing roots keep global precedence conclusions incomplete.".to_string(),
        });
    }
    statuses
}

fn execute_validation_checks(
    plan: &ValidationPlan,
    manifest_load: &RuntimeManifestLoadResult,
    precedence: &PrecedenceAnalysis,
    mode: ValidationExecutionMode,
) -> Vec<ValidationResult> {
    let checks: Vec<ValidationCheck> = plan
        .hooks
        .iter()
        .map(|hook| ValidationCheck {
            check_id: hook.hook_id.clone(),
            title: hook.title.clone(),
            target: hook.target,
            mode,
            guarded_check: hook.guarded_check.clone(),
        })
        .collect();

    checks
        .into_iter()
        .map(|check| match check.target {
            ValidationTarget::InstallChain => ValidationResult {
                check_id: check.check_id,
                target: check.target,
                success: manifest_load.manifest.permission_surface.network != AvailabilityState::Unknown,
                validated_constraints: if manifest_load.manifest.permission_surface.network
                    != AvailabilityState::Unknown
                {
                    vec![ValidatedConstraint {
                        name: "network_state_known".to_string(),
                        evidence: format!("{:?}", manifest_load.manifest.permission_surface.network),
                    }]
                } else {
                    Vec::new()
                },
                missing_constraints: if manifest_load.manifest.permission_surface.network
                    == AvailabilityState::Unknown
                {
                    vec![MissingConstraint {
                        name: "network_state".to_string(),
                        rationale: "Install and remote execution paths remain partly assumed until network availability is known.".to_string(),
                    }]
                } else {
                    Vec::new()
                },
                capability_checks: capability_checks_from_permissions(
                    &manifest_load.manifest.permission_surface,
                ),
                constraint_checks: Vec::new(),
                sandbox_constraint_effects: sandbox_constraint_effects_from_permissions(
                    &manifest_load.manifest.permission_surface,
                ),
                note: "Install-chain validation is non-executing and only confirms prerequisite surfaces.".to_string(),
            },
            ValidationTarget::ToolDispatch | ValidationTarget::InvocationPolicy => ValidationResult {
                check_id: check.check_id,
                target: check.target,
                success: manifest_load.manifest.permission_surface.exec_allowed != AvailabilityState::Unknown
                    || manifest_load.manifest.permission_surface.process_allowed != AvailabilityState::Unknown
                    || manifest_load.manifest.permission_surface.gateway_available != AvailabilityState::Unknown,
                validated_constraints: collect_permission_constraints(&manifest_load.manifest.permission_surface),
                missing_constraints: if manifest_load.manifest.permission_surface.exec_allowed
                    == AvailabilityState::Unknown
                    && manifest_load.manifest.permission_surface.process_allowed
                        == AvailabilityState::Unknown
                    && manifest_load.manifest.permission_surface.gateway_available
                        == AvailabilityState::Unknown
                {
                    vec![MissingConstraint {
                        name: "tool_permission_surface".to_string(),
                        rationale: "Direct dispatch risk remains partially assumed without runtime permission facts.".to_string(),
                    }]
                } else {
                    Vec::new()
                },
                capability_checks: capability_checks_from_permissions(
                    &manifest_load.manifest.permission_surface,
                ),
                constraint_checks: Vec::new(),
                sandbox_constraint_effects: sandbox_constraint_effects_from_permissions(
                    &manifest_load.manifest.permission_surface,
                ),
                note: "Tool-dispatch validation checks permission surfaces only; it does not invoke the tool.".to_string(),
            },
            ValidationTarget::RuntimeEnvironment => ValidationResult {
                check_id: check.check_id,
                target: check.target,
                success: manifest_load.manifest.execution_environment != RuntimeEnvironment::Unknown,
                validated_constraints: if manifest_load.manifest.execution_environment
                    != RuntimeEnvironment::Unknown
                {
                    vec![ValidatedConstraint {
                        name: "execution_environment".to_string(),
                        evidence: format!("{:?}", manifest_load.manifest.execution_environment),
                    }]
                } else {
                    Vec::new()
                },
                missing_constraints: if manifest_load.manifest.execution_environment
                    == RuntimeEnvironment::Unknown
                {
                    vec![MissingConstraint {
                        name: "execution_environment".to_string(),
                        rationale: "Host vs sandbox impact remains assumed until runtime environment is declared or inferred.".to_string(),
                    }]
                } else {
                    Vec::new()
                },
                capability_checks: capability_checks_from_permissions(
                    &manifest_load.manifest.permission_surface,
                ),
                constraint_checks: constraint_checks_from_assumptions(&build_assumption_status(
                    manifest_load,
                    precedence,
                )),
                sandbox_constraint_effects: sandbox_constraint_effects_from_permissions(
                    &manifest_load.manifest.permission_surface,
                ),
                note: "Runtime environment validation refines host-vs-sandbox consequence splits.".to_string(),
            },
            ValidationTarget::PrecedenceScope => ValidationResult {
                check_id: check.check_id,
                target: check.target,
                success: precedence.root_resolution.missing_roots.is_empty(),
                validated_constraints: if precedence.root_resolution.missing_roots.is_empty() {
                    vec![ValidatedConstraint {
                        name: "precedence_scope_complete".to_string(),
                        evidence: "all expected roots present".to_string(),
                    }]
                } else {
                    Vec::new()
                },
                missing_constraints: precedence
                    .root_resolution
                    .missing_roots
                    .iter()
                    .map(|root| MissingConstraint {
                        name: format!("missing_root:{root}"),
                        rationale: "Additional roots are needed for stronger precedence conclusions.".to_string(),
                    })
                    .collect(),
                capability_checks: Vec::new(),
                constraint_checks: constraint_checks_from_assumptions(&build_assumption_status(
                    manifest_load,
                    precedence,
                )),
                sandbox_constraint_effects: Vec::new(),
                note: "Precedence validation can only clarify scope; it does not invent missing roots.".to_string(),
            },
            ValidationTarget::AttackPath | ValidationTarget::SecretExposure => ValidationResult {
                check_id: check.check_id,
                target: check.target,
                success: !manifest_load.manifest.present_env_vars.is_empty()
                    || !manifest_load.manifest.present_config_files.is_empty()
                    || manifest_load.manifest.permission_surface.home_directory_access
                        != AvailabilityState::Unknown,
                validated_constraints: collect_secret_constraints(manifest_load),
                missing_constraints: if manifest_load.manifest.present_env_vars.is_empty()
                    && manifest_load.manifest.present_config_files.is_empty()
                    && manifest_load.manifest.permission_surface.home_directory_access
                        == AvailabilityState::Unknown
                {
                    vec![MissingConstraint {
                        name: "secret_prerequisites".to_string(),
                        rationale: "Secret-bearing prerequisites remain unconfirmed until env/config/home access is clarified.".to_string(),
                    }]
                } else {
                    Vec::new()
                },
                capability_checks: capability_checks_from_permissions(
                    &manifest_load.manifest.permission_surface,
                ),
                constraint_checks: constraint_checks_from_assumptions(&build_assumption_status(
                    manifest_load,
                    precedence,
                )),
                sandbox_constraint_effects: sandbox_constraint_effects_from_permissions(
                    &manifest_load.manifest.permission_surface,
                ),
                note: "Secret validation checks presence and access scope only, not secret contents.".to_string(),
            },
        })
        .collect()
}

fn build_path_validation_status(
    attack_paths: &[AttackPath],
    permissions: &PermissionSurface,
    manifest_load: &RuntimeManifestLoadResult,
    precedence: &PrecedenceAnalysis,
) -> Vec<PathValidationStatus> {
    attack_paths
        .iter()
        .map(|path| match path.path_type.as_str() {
            "download_execute" | "install_remote_script_execution" => {
                let mut validated = Vec::new();
                let mut missing = Vec::new();
                let mut blocked = false;
                collect_constraint(
                    "network",
                    permissions.network,
                    &mut validated,
                    &mut missing,
                    &mut blocked,
                );
                collect_exec_constraint(permissions, &mut validated, &mut missing, &mut blocked);
                finalize_path_status(path, validated, missing, blocked, manifest_load.manifest.source_kind != crate::types::RuntimeSourceKind::Unknown)
            }
            "instruction_tool_execution" | "direct_privileged_action" => {
                let mut validated = Vec::new();
                let mut missing = Vec::new();
                let mut blocked = false;
                collect_exec_constraint(permissions, &mut validated, &mut missing, &mut blocked);
                if permissions.writable_scope != WritableFileSystemScope::ReadOnly
                    && permissions.writable_scope != WritableFileSystemScope::Unknown
                {
                    validated.push(ValidatedConstraint {
                        name: "writable_scope".to_string(),
                        evidence: format!("{:?}", permissions.writable_scope),
                    });
                } else if permissions.writable_scope == WritableFileSystemScope::ReadOnly {
                    blocked = true;
                    missing.push(MissingConstraint {
                        name: "writable_scope".to_string(),
                        rationale: "Read-only scope blocks mutation-style execution paths.".to_string(),
                    });
                }
                finalize_path_status(path, validated, missing, blocked, manifest_load.manifest.source_kind != crate::types::RuntimeSourceKind::Unknown)
            }
            "instruction_secret_access" => {
                let mut validated = Vec::new();
                let mut missing = Vec::new();
                let mut blocked = false;
                collect_secret_presence(manifest_load, permissions, &mut validated, &mut missing, &mut blocked);
                finalize_path_status(path, validated, missing, blocked, manifest_load.manifest.source_kind != crate::types::RuntimeSourceKind::Unknown)
            }
            "secret_exfiltration_potential" | "delegated_misuse" => {
                let mut validated = Vec::new();
                let mut missing = Vec::new();
                let mut blocked = false;
                collect_secret_presence(manifest_load, permissions, &mut validated, &mut missing, &mut blocked);
                collect_egress_constraint(permissions, &mut validated, &mut missing, &mut blocked);
                finalize_path_status(path, validated, missing, blocked, manifest_load.manifest.source_kind != crate::types::RuntimeSourceKind::Unknown)
            }
            "trust_hijack" => {
                let status = if precedence.root_resolution.missing_roots.is_empty() {
                    PathValidationDisposition::Validated
                } else {
                    PathValidationDisposition::ScopeIncomplete
                };
                PathValidationStatus {
                    path_id: path.path_id.clone(),
                    status,
                    guard_status: guard_status_for_disposition(status),
                    validated_constraints: if status == PathValidationDisposition::Validated {
                        vec![ValidatedConstraint {
                            name: "precedence_scope_complete".to_string(),
                            evidence: "all expected roots scanned".to_string(),
                        }]
                    } else {
                        Vec::new()
                    },
                    missing_constraints: precedence
                        .root_resolution
                        .missing_roots
                        .iter()
                        .map(|root| MissingConstraint {
                            name: format!("missing_root:{root}"),
                            rationale: "The collision may resolve differently once the missing root is scanned.".to_string(),
                        })
                        .collect(),
                    note: "Trust-hijack confidence depends on how complete the precedence scope is.".to_string(),
                }
            }
            _ => PathValidationStatus {
                path_id: path.path_id.clone(),
                status: if manifest_load.manifest.source_kind == crate::types::RuntimeSourceKind::Unknown {
                    PathValidationDisposition::StillAssumed
                } else {
                    PathValidationDisposition::PartiallyValidated
                },
                guard_status: if manifest_load.manifest.source_kind
                    == crate::types::RuntimeSourceKind::Unknown
                {
                    PathGuardStatus::Assumed
                } else {
                    PathGuardStatus::Narrowed
                },
                validated_constraints: Vec::new(),
                missing_constraints: Vec::new(),
                note: "No specialized runtime refinement rule exists for this path type yet.".to_string(),
            },
        })
        .collect()
}

fn build_refinement_outputs(
    statuses: &[PathValidationStatus],
) -> (
    Vec<ConstraintEffect>,
    Vec<EnvironmentBlocker>,
    Vec<EnvironmentAmplifier>,
    Vec<RuntimeRefinementNote>,
) {
    let mut effects = Vec::new();
    let mut blockers = Vec::new();
    let mut amplifiers = Vec::new();
    let mut notes = Vec::new();

    for status in statuses {
        match status.status {
            PathValidationDisposition::Validated => {
                amplifiers.push(EnvironmentAmplifier {
                    path_id: status.path_id.clone(),
                    amplifier: "runtime_constraints_confirmed".to_string(),
                    rationale:
                        "Required runtime surfaces were confirmed, so the path is more credible."
                            .to_string(),
                });
                effects.push(ConstraintEffect {
                    subject_id: status.path_id.clone(),
                    effect: "runtime_confirmed".to_string(),
                    rationale: "Validated runtime constraints strengthen this path beyond pure static assumption.".to_string(),
                });
            }
            PathValidationDisposition::BlockedByEnvironment => {
                blockers.push(EnvironmentBlocker {
                    path_id: status.path_id.clone(),
                    blocker: "runtime_permission_denied".to_string(),
                    rationale: "A required runtime surface is explicitly disabled or unavailable."
                        .to_string(),
                });
                effects.push(ConstraintEffect {
                    subject_id: status.path_id.clone(),
                    effect: "runtime_blocked".to_string(),
                    rationale:
                        "The path remains in the report but is narrowed by the current environment."
                            .to_string(),
                });
            }
            PathValidationDisposition::ScopeIncomplete => {
                effects.push(ConstraintEffect {
                    subject_id: status.path_id.clone(),
                    effect: "scope_incomplete".to_string(),
                    rationale: "The path depends on additional scope or root information that is not yet present.".to_string(),
                });
            }
            PathValidationDisposition::PartiallyValidated
            | PathValidationDisposition::StillAssumed => {}
        }
        notes.push(RuntimeRefinementNote {
            subject_id: status.path_id.clone(),
            note: status.note.clone(),
        });
    }

    (effects, blockers, amplifiers, notes)
}

fn build_runtime_score_adjustments(
    statuses: &[PathValidationStatus],
) -> Vec<RuntimeScoreAdjustment> {
    statuses
        .iter()
        .map(|status| match status.status {
            PathValidationDisposition::Validated => RuntimeScoreAdjustment {
                source: status.path_id.clone(),
                delta: -4,
                rationale: "Runtime facts confirmed required constraints, so the path receives additional risk uplift.".to_string(),
            },
            PathValidationDisposition::PartiallyValidated => RuntimeScoreAdjustment {
                source: status.path_id.clone(),
                delta: -1,
                rationale: "Some runtime constraints were validated, which slightly increases confidence in the path.".to_string(),
            },
            PathValidationDisposition::BlockedByEnvironment => RuntimeScoreAdjustment {
                source: status.path_id.clone(),
                delta: 6,
                rationale: "Runtime facts blocked required constraints, so the path uplift is reduced without removing the evidence.".to_string(),
            },
            PathValidationDisposition::ScopeIncomplete => RuntimeScoreAdjustment {
                source: status.path_id.clone(),
                delta: 3,
                rationale: "Scope incompleteness lowers confidence in the path until additional roots or runtime facts are supplied.".to_string(),
            },
            PathValidationDisposition::StillAssumed => RuntimeScoreAdjustment {
                source: status.path_id.clone(),
                delta: 1,
                rationale: "No runtime facts confirmed this path, so it remains primarily assumption-driven.".to_string(),
            },
        })
        .collect()
}

fn refine_consequence(
    base: &ConsequenceAssessment,
    permissions: &PermissionSurface,
    manifest_load: &RuntimeManifestLoadResult,
) -> ConsequenceAssessment {
    let mut refined = base.clone();
    if permissions.network == AvailabilityState::Disabled {
        refined.network_consequences = vec![NetworkConsequenceKind::NoMeaningfulEgress];
        refined
            .inferred_notes
            .push("Runtime manifest disabled meaningful egress, so network-dependent consequences are narrowed.".to_string());
    } else if permissions.network == AvailabilityState::Enabled
        && permissions.home_directory_access == AvailabilityState::Enabled
        && !permissions.mounted_secrets_or_configs.is_empty()
    {
        refined
            .credential_consequences
            .push(CredentialConsequenceKind::ConfigBackedSecrets);
        refined
            .inferred_notes
            .push("Host/home access plus mounted secrets increased confidence in credential-bearing consequences.".to_string());
    }

    match permissions.writable_scope {
        WritableFileSystemScope::WorkspaceOnly => {
            refined.file_system_consequences = vec![FileSystemConsequenceKind::WorkspaceOnlyScope];
            refined
                .inferred_notes
                .push("Writable scope is limited to the workspace, so file-system consequence is narrowed.".to_string());
        }
        WritableFileSystemScope::ReadOnly => {
            refined.inferred_notes.push(
                "Read-only writable scope reduces mutation-oriented consequences.".to_string(),
            );
        }
        _ => {}
    }

    if manifest_load.manifest.execution_environment == RuntimeEnvironment::Host
        && permissions.home_directory_access == AvailabilityState::Enabled
    {
        if !refined
            .file_system_consequences
            .contains(&FileSystemConsequenceKind::HomeDirectoryArtifacts)
        {
            refined
                .file_system_consequences
                .push(FileSystemConsequenceKind::HomeDirectoryArtifacts);
        }
    }

    refined.summary = format!(
        "{} Runtime refinement applied with environment={:?}, network={:?}, writable_scope={:?}.",
        base.summary,
        manifest_load.manifest.execution_environment,
        permissions.network,
        permissions.writable_scope
    );
    refined
}

fn refine_split(
    base: &HostSandboxSplit,
    permissions: &PermissionSurface,
    manifest_load: &RuntimeManifestLoadResult,
) -> HostSandboxSplit {
    let mut refined = base.clone();
    if permissions.network == AvailabilityState::Disabled {
        refined
            .blocked_in_sandbox
            .push("Network-disabled runtime blocks egress-dependent sandbox paths.".to_string());
    }
    if manifest_load.manifest.execution_environment == RuntimeEnvironment::Host
        && permissions.home_directory_access == AvailabilityState::Enabled
    {
        refined.host_effects.push(
            "Runtime manifest confirms host execution with home-directory access.".to_string(),
        );
    }
    if permissions.writable_scope == WritableFileSystemScope::WorkspaceOnly {
        refined.sandbox_effects.push(
            "Workspace-only writable scope narrows file mutation to the project boundary."
                .to_string(),
        );
    }
    refined.summary = "Phase 7 runtime validation refined host-vs-sandbox split using manifest-backed permission and environment facts.".to_string();
    refined
}

fn collect_constraint(
    name: &str,
    state: AvailabilityState,
    validated: &mut Vec<ValidatedConstraint>,
    missing: &mut Vec<MissingConstraint>,
    blocked: &mut bool,
) {
    match state {
        AvailabilityState::Enabled => validated.push(ValidatedConstraint {
            name: name.to_string(),
            evidence: "enabled".to_string(),
        }),
        AvailabilityState::Disabled => {
            *blocked = true;
            missing.push(MissingConstraint {
                name: name.to_string(),
                rationale: format!("{name} is explicitly disabled in the runtime manifest."),
            });
        }
        AvailabilityState::Unknown => missing.push(MissingConstraint {
            name: name.to_string(),
            rationale: format!("{name} remains unknown in the current runtime manifest."),
        }),
    }
}

fn collect_exec_constraint(
    permissions: &PermissionSurface,
    validated: &mut Vec<ValidatedConstraint>,
    missing: &mut Vec<MissingConstraint>,
    blocked: &mut bool,
) {
    if permissions.exec_allowed == AvailabilityState::Enabled
        || permissions.process_allowed == AvailabilityState::Enabled
    {
        validated.push(ValidatedConstraint {
            name: "exec_or_process".to_string(),
            evidence: format!(
                "exec={:?}, process={:?}",
                permissions.exec_allowed, permissions.process_allowed
            ),
        });
    } else if permissions.exec_allowed == AvailabilityState::Disabled
        && permissions.process_allowed == AvailabilityState::Disabled
    {
        *blocked = true;
        missing.push(MissingConstraint {
            name: "exec_or_process".to_string(),
            rationale: "Both exec and process are explicitly disabled.".to_string(),
        });
    } else {
        missing.push(MissingConstraint {
            name: "exec_or_process".to_string(),
            rationale: "Exec/process capability remains unknown.".to_string(),
        });
    }
}

fn collect_egress_constraint(
    permissions: &PermissionSurface,
    validated: &mut Vec<ValidatedConstraint>,
    missing: &mut Vec<MissingConstraint>,
    blocked: &mut bool,
) {
    if permissions.network == AvailabilityState::Disabled {
        *blocked = true;
        missing.push(MissingConstraint {
            name: "network".to_string(),
            rationale: "Network is explicitly disabled.".to_string(),
        });
        return;
    }
    if permissions.browser_available == AvailabilityState::Enabled
        || permissions.web_fetch_available == AvailabilityState::Enabled
        || permissions.gateway_available == AvailabilityState::Enabled
        || permissions.nodes_available == AvailabilityState::Enabled
        || permissions.exec_allowed == AvailabilityState::Enabled
        || permissions.process_allowed == AvailabilityState::Enabled
    {
        validated.push(ValidatedConstraint {
            name: "egress_surface".to_string(),
            evidence: "at least one outward-capable surface is enabled".to_string(),
        });
    } else {
        missing.push(MissingConstraint {
            name: "egress_surface".to_string(),
            rationale: "No outward-capable surface was confirmed.".to_string(),
        });
    }
}

fn collect_secret_presence(
    manifest_load: &RuntimeManifestLoadResult,
    permissions: &PermissionSurface,
    validated: &mut Vec<ValidatedConstraint>,
    missing: &mut Vec<MissingConstraint>,
    blocked: &mut bool,
) {
    if !manifest_load.manifest.present_env_vars.is_empty()
        || !manifest_load.manifest.present_config_files.is_empty()
    {
        validated.push(ValidatedConstraint {
            name: "secret_or_config_presence".to_string(),
            evidence: "runtime manifest or safe local checks confirmed env/config presence"
                .to_string(),
        });
        return;
    }

    if permissions.home_directory_access == AvailabilityState::Enabled
        || !manifest_load.manifest.auth_profiles_present.is_empty()
    {
        validated.push(ValidatedConstraint {
            name: "secret_access_surface".to_string(),
            evidence: "home-directory or auth-profile access is available".to_string(),
        });
    } else if permissions.home_directory_access == AvailabilityState::Disabled {
        *blocked = true;
        missing.push(MissingConstraint {
            name: "secret_access_surface".to_string(),
            rationale: "Home-directory access is explicitly disabled and no env/config presence was confirmed.".to_string(),
        });
    } else {
        missing.push(MissingConstraint {
            name: "secret_access_surface".to_string(),
            rationale: "Secret-bearing runtime prerequisites remain unknown.".to_string(),
        });
    }
}

fn finalize_path_status(
    path: &AttackPath,
    validated: Vec<ValidatedConstraint>,
    missing: Vec<MissingConstraint>,
    blocked: bool,
    has_manifest: bool,
) -> PathValidationStatus {
    let status = if blocked {
        PathValidationDisposition::BlockedByEnvironment
    } else if !validated.is_empty() && missing.is_empty() {
        PathValidationDisposition::Validated
    } else if !validated.is_empty() {
        PathValidationDisposition::PartiallyValidated
    } else if has_manifest {
        PathValidationDisposition::ScopeIncomplete
    } else {
        PathValidationDisposition::StillAssumed
    };
    PathValidationStatus {
        path_id: path.path_id.clone(),
        status,
        guard_status: guard_status_for_disposition(status),
        validated_constraints: validated,
        missing_constraints: missing,
        note: match status {
            PathValidationDisposition::Validated => {
                "Runtime facts confirmed the key prerequisites for this path.".to_string()
            }
            PathValidationDisposition::PartiallyValidated => {
                "Runtime facts confirmed some but not all prerequisites for this path.".to_string()
            }
            PathValidationDisposition::BlockedByEnvironment => {
                "A required runtime constraint is explicitly blocked in the current environment."
                    .to_string()
            }
            PathValidationDisposition::ScopeIncomplete => {
                "A runtime manifest exists, but it does not fully cover this path's prerequisites."
                    .to_string()
            }
            PathValidationDisposition::StillAssumed => {
                "No runtime manifest confirmed this path, so it remains a static assumption."
                    .to_string()
            }
        },
    }
}

fn build_guarded_validation_result(
    permissions: &PermissionSurface,
    assumption_status: &[RuntimeAssumptionStatus],
    statuses: &[PathValidationStatus],
) -> GuardedValidationResult {
    GuardedValidationResult {
        summary: format!(
            "Guarded validation collected {} capability check(s), {} assumption check(s), and refined {} attack path(s) without executing untrusted code.",
            capability_checks_from_permissions(permissions).len(),
            assumption_status.len(),
            statuses.len()
        ),
        capability_checks: capability_checks_from_permissions(permissions),
        constraint_checks: constraint_checks_from_assumptions(assumption_status),
        sandbox_constraint_effects: sandbox_constraint_effects_from_permissions(permissions),
    }
}

fn capability_checks_from_permissions(
    permissions: &PermissionSurface,
) -> Vec<CapabilityCheck> {
    [
        ("network", permissions.network),
        ("exec_allowed", permissions.exec_allowed),
        ("process_allowed", permissions.process_allowed),
        ("browser_available", permissions.browser_available),
        ("web_fetch_available", permissions.web_fetch_available),
        ("gateway_available", permissions.gateway_available),
        ("nodes_available", permissions.nodes_available),
        ("home_directory_access", permissions.home_directory_access),
    ]
    .into_iter()
    .map(|(name, available)| CapabilityCheck {
        name: name.to_string(),
        available,
        rationale:
            "Guarded validation records runtime-exposed capabilities without invoking untrusted actions."
                .to_string(),
    })
    .collect()
}

fn constraint_checks_from_assumptions(
    assumptions: &[RuntimeAssumptionStatus],
) -> Vec<ConstraintCheck> {
    assumptions
        .iter()
        .map(|assumption| ConstraintCheck {
            name: assumption.assumption.clone(),
            status: assumption.state,
            rationale: assumption.rationale.clone(),
        })
        .collect()
}

fn sandbox_constraint_effects_from_permissions(
    permissions: &PermissionSurface,
) -> Vec<SandboxConstraintEffect> {
    let mut effects = Vec::new();
    if permissions.network == AvailabilityState::Disabled {
        effects.push(SandboxConstraintEffect {
            name: "network".to_string(),
            effect: "blocks_network_dependent_paths".to_string(),
            rationale: "Disabled network narrows or blocks egress-dependent paths.".to_string(),
        });
    }
    if permissions.writable_scope == WritableFileSystemScope::WorkspaceOnly {
        effects.push(SandboxConstraintEffect {
            name: "writable_scope".to_string(),
            effect: "narrows_mutation_scope_to_workspace".to_string(),
            rationale: "Workspace-only writes reduce host-wide mutation impact.".to_string(),
        });
    } else if permissions.writable_scope == WritableFileSystemScope::ReadOnly {
        effects.push(SandboxConstraintEffect {
            name: "writable_scope".to_string(),
            effect: "blocks_mutation_paths".to_string(),
            rationale: "Read-only scope blocks mutation-oriented paths.".to_string(),
        });
    }
    effects
}

fn guard_status_for_disposition(status: PathValidationDisposition) -> PathGuardStatus {
    match status {
        PathValidationDisposition::Validated => PathGuardStatus::Supported,
        PathValidationDisposition::PartiallyValidated
        | PathValidationDisposition::ScopeIncomplete => PathGuardStatus::Narrowed,
        PathValidationDisposition::BlockedByEnvironment => PathGuardStatus::Blocked,
        PathValidationDisposition::StillAssumed => PathGuardStatus::Assumed,
    }
}

fn map_availability_state(state: AvailabilityState) -> RuntimeAssumptionState {
    match state {
        AvailabilityState::Enabled => RuntimeAssumptionState::Validated,
        AvailabilityState::Disabled => RuntimeAssumptionState::Blocked,
        AvailabilityState::Unknown => RuntimeAssumptionState::Unknown,
    }
}

fn collect_permission_constraints(permissions: &PermissionSurface) -> Vec<ValidatedConstraint> {
    let mut constraints = Vec::new();
    for (name, state) in [
        ("exec_allowed", permissions.exec_allowed),
        ("process_allowed", permissions.process_allowed),
        ("gateway_available", permissions.gateway_available),
        ("browser_available", permissions.browser_available),
    ] {
        if state != AvailabilityState::Unknown {
            constraints.push(ValidatedConstraint {
                name: name.to_string(),
                evidence: format!("{:?}", state),
            });
        }
    }
    constraints
}

fn collect_secret_constraints(
    manifest_load: &RuntimeManifestLoadResult,
) -> Vec<ValidatedConstraint> {
    let mut constraints = Vec::new();
    for env_var in &manifest_load.manifest.present_env_vars {
        constraints.push(ValidatedConstraint {
            name: format!("env:{env_var}"),
            evidence: "present".to_string(),
        });
    }
    for config in &manifest_load.manifest.present_config_files {
        constraints.push(ValidatedConstraint {
            name: format!("config:{config}"),
            evidence: "present".to_string(),
        });
    }
    constraints
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use crate::attack_paths::build_attack_paths;
    use crate::compound_rules::evaluate_compound_rules;
    use crate::consequence::analyze_consequences;
    use crate::install::analyze_install_chain;
    use crate::instruction::extract_instruction_segments;
    use crate::invocation::analyze_invocation_policy;
    use crate::precedence::analyze_precedence;
    use crate::prompt_injection::analyze_instruction_segments;
    use crate::reachability::{analyze_secret_reachability, analyze_tool_reachability};
    use crate::runtime_manifest::load_runtime_manifest;
    use crate::skill_parse::parse_skill_file;
    use crate::types::{
        PathValidationDisposition, TargetKind, ValidationExecutionMode, ValidationPlan,
    };
    use crate::validation::build_validation_plan;

    use super::perform_runtime_validation;

    #[test]
    fn exec_denied_blocks_execution_path() {
        let dir = tempdir().unwrap();
        let manifest_path = dir.path().join("runtime.json");
        fs::write(
            &manifest_path,
            r#"{"execution_environment":"sandbox","permission_surface":{"network":true,"exec_allowed":false,"process_allowed":false}}"#,
        )
        .unwrap();
        let skill = parse_skill_file(
            dir.path().join("SKILL.md").as_path(),
            "---\ncommand-dispatch: tool\ncommand-tool: exec\n---\nUse exec.",
            Vec::new(),
        );
        let instructions = extract_instruction_segments(&skill);
        let prompt = analyze_instruction_segments(&instructions.segments);
        let install = analyze_install_chain(&skill);
        let invocation = analyze_invocation_policy(&skill);
        let tools = analyze_tool_reachability(&skill);
        let secrets = analyze_secret_reachability(&skill);
        let precedence = analyze_precedence(&[skill.clone()], TargetKind::File);
        let compounds = evaluate_compound_rules(
            &[skill.clone()],
            &instructions,
            &prompt,
            &install,
            &invocation,
            &tools,
            &secrets,
            &precedence,
        );
        let attack_paths = build_attack_paths(
            &[skill.clone()],
            &prompt,
            &install,
            &invocation,
            &tools,
            &secrets,
            &precedence,
            &compounds,
        );
        let consequence = analyze_consequences(&[skill], &install, &tools, &secrets);
        let manifest =
            load_runtime_manifest(Some(&manifest_path), &manifest_path, &[], &[]).unwrap();
        let plan = build_validation_plan(
            &[],
            &attack_paths.paths,
            &install,
            &precedence,
            &consequence,
        );

        let result = perform_runtime_validation(
            &manifest,
            &plan,
            &attack_paths.paths,
            &consequence.assessment,
            &consequence.split,
            &precedence,
            ValidationExecutionMode::Guarded,
        );

        assert!(result
            .path_validation_status
            .iter()
            .any(|status| status.status == PathValidationDisposition::BlockedByEnvironment));
    }

    #[test]
    fn no_manifest_keeps_path_assumed() {
        let dir = tempdir().unwrap();
        let skill = parse_skill_file(
            dir.path().join("SKILL.md").as_path(),
            "---\ncommand-dispatch: tool\ncommand-tool: exec\n---\nUse exec.",
            Vec::new(),
        );
        let instructions = extract_instruction_segments(&skill);
        let prompt = analyze_instruction_segments(&instructions.segments);
        let install = analyze_install_chain(&skill);
        let invocation = analyze_invocation_policy(&skill);
        let tools = analyze_tool_reachability(&skill);
        let secrets = analyze_secret_reachability(&skill);
        let precedence = analyze_precedence(&[skill.clone()], TargetKind::File);
        let compounds = evaluate_compound_rules(
            &[skill.clone()],
            &instructions,
            &prompt,
            &install,
            &invocation,
            &tools,
            &secrets,
            &precedence,
        );
        let attack_paths = build_attack_paths(
            &[skill.clone()],
            &prompt,
            &install,
            &invocation,
            &tools,
            &secrets,
            &precedence,
            &compounds,
        );
        let consequence = analyze_consequences(&[skill], &install, &tools, &secrets);
        let manifest = load_runtime_manifest(None, dir.path(), &[], &[]).unwrap();

        let result = perform_runtime_validation(
            &manifest,
            &ValidationPlan {
                summary: String::new(),
                hooks: Vec::new(),
            },
            &attack_paths.paths,
            &consequence.assessment,
            &consequence.split,
            &precedence,
            ValidationExecutionMode::Planned,
        );

        assert!(result
            .path_validation_status
            .iter()
            .any(|status| status.status == PathValidationDisposition::StillAssumed));
        assert!(result
            .runtime_assumption_status
            .iter()
            .any(|status| status.assumption == "execution_environment"
                && status.state != crate::types::RuntimeAssumptionState::Validated));
    }
}
