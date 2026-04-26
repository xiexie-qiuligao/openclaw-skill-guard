use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetKind {
    File,
    SkillDir,
    SkillsRoot,
    Workspace,
    OpenClawHome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillSource {
    Workspace,
    ProjectAgents,
    PersonalAgents,
    Managed,
    Bundled,
    ExtraDir,
    PluginExtraDir,
    ClawHubWorkspaceInstall,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingConfidence {
    High,
    Medium,
    Low,
    InferredCompound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Warn,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    TextPattern,
    StructuredMetadata,
    InstallAction,
    ToolDispatch,
    SecretReference,
    PrecedenceCollision,
    RuntimeContext,
    ParseDiagnostic,
    Instruction,
    PromptInjectionSignal,
    CompoundRule,
    Inference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackPathNodeKind {
    Instruction,
    UntrustedContent,
    PromptInjection,
    DirectToolDispatch,
    ToolUse,
    SecretAccess,
    Execution,
    ConfigMutation,
    NetworkEgress,
    InstallExecution,
    PrecedenceHijack,
    Persistence,
    HostPrivilege,
    SandboxResidualRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionType {
    BenignInstruction,
    SuspiciousInstruction,
    HighRiskInstruction,
    InstallStep,
    ToolDirective,
    SecretDirective,
    ExternalInstruction,
    PolicyBypass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionRisk {
    Benign,
    Suspicious,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionSource {
    BodyText,
    InstallSection,
    CodeFence,
    CodeFenceContext,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptSignalKind {
    ModelBypass,
    ApprovalBypass,
    IndirectInstruction,
    ToolCoercion,
    SensitiveDataCoercion,
    PolicyBypass,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionSurface {
    Host,
    Sandbox,
    Mixed,
    Uncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileSystemConsequenceKind {
    LocalUserFiles,
    HomeDirectoryArtifacts,
    WorkspaceOnlyScope,
    MountedSecretsOrConfigs,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialConsequenceKind {
    EnvironmentSecrets,
    ConfigBackedSecrets,
    LocalSecretFiles,
    AuthProfileExposure,
    BrowserCredentialProximity,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkConsequenceKind {
    NoMeaningfulEgress,
    BrowserWebFetch,
    ExecProcess,
    GatewayNodesCron,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceConsequenceKind {
    None,
    LocalScriptDrop,
    ShellProfileModificationHint,
    ScheduledTaskOrCronHint,
    StartupPersistenceHint,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEnvironment {
    Host,
    Sandbox,
    Mixed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AvailabilityState {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WritableFileSystemScope {
    ReadOnly,
    WorkspaceOnly,
    HomeDirectory,
    UserFiles,
    Any,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegeHint {
    RootAdmin,
    StandardUser,
    SandboxRestricted,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeSourceKind {
    UserManifest,
    InferredFromConfig,
    SafeLocalCheck,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeAssumptionState {
    Validated,
    Missing,
    Blocked,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationTarget {
    InstallChain,
    InvocationPolicy,
    RuntimeEnvironment,
    PrecedenceScope,
    AttackPath,
    SecretExposure,
    ToolDispatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationReason {
    RiskConfirmation,
    FalsePositiveReduction,
    ScopeExpansion,
    EnvironmentClarification,
    IntegrityCheck,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationOutcomeExpectation {
    ConfirmRisk,
    ReduceConfidence,
    ClarifyScope,
    ConfirmMitigation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationExecutionMode {
    Planned,
    Guarded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollisionConfidence {
    ConfirmedWithinScannedRoots,
    PossibleScopeLimited,
    Unresolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLevel {
    Info,
    Warning,
    HighRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathValidationDisposition {
    Validated,
    PartiallyValidated,
    BlockedByEnvironment,
    ScopeIncomplete,
    StillAssumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathGuardStatus {
    Supported,
    Narrowed,
    Blocked,
    Assumed,
    Amplified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SuppressionLifecycle {
    Active,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusSourceKind {
    FirstParty,
    AdaptedReference,
    InternalSeed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalReferenceCategory {
    SourceRepository,
    Documentation,
    RawContent,
    ApiEndpoint,
    AuthEndpoint,
    PackageRegistry,
    ObjectStorage,
    FileDownload,
    Shortlink,
    DynamicDns,
    DirectIp,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalServiceKind {
    SourceCodeHost,
    PackageEcosystem,
    CloudPlatform,
    AiService,
    GeneralApi,
    ContentDelivery,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalReferenceReputation {
    TrustedInfrastructure,
    KnownPlatform,
    ReviewNeeded,
    Suspicious,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalRiskSignal {
    Shortlink,
    RawDownloadHost,
    RawDownloadPath,
    PureIp,
    DynamicDnsSuffix,
    SuspiciousTld,
    NonHttps,
    DirectFileDownload,
    KnownSuspiciousSeed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanTarget {
    pub path: String,
    pub canonical_path: String,
    pub target_kind: TargetKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillLocation {
    pub path: String,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSpan {
    pub start_line: usize,
    pub end_line: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedSkill {
    pub descriptor: SkillDescriptor,
    pub skill_file: String,
    pub skill_root: String,
    pub body: String,
    pub frontmatter: FrontmatterParseResult,
    pub raw_metadata: Option<String>,
    pub invocation_policy: InvocationPolicy,
    pub metadata: OpenClawMetadata,
    pub additional_files: Vec<String>,
    pub source: SkillSource,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontmatterParseResult {
    pub present: bool,
    pub parsed: bool,
    pub raw_block: Option<String>,
    pub fields: BTreeMap<String, String>,
    pub diagnostics: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkillDescriptor {
    pub name: Option<String>,
    pub description: Option<String>,
    pub homepage: Option<String>,
    pub directory_name: Option<String>,
    pub slug_candidates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RequiresSpec {
    pub bins: Vec<String>,
    pub any_bins: Vec<String>,
    pub env: Vec<String>,
    pub config: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallKind {
    Brew,
    Node,
    Go,
    Uv,
    Download,
    ManualCommand,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenClawMetadata {
    pub present: bool,
    pub normalized: bool,
    pub homepage: Option<String>,
    pub skill_key: Option<String>,
    pub primary_env: Option<String>,
    pub requires: RequiresSpec,
    pub install: Vec<InstallSpec>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallSpec {
    pub kind: InstallKind,
    pub source: String,
    pub source_path: String,
    pub raw: String,
    pub package: Option<String>,
    pub url: Option<String>,
    pub checksum_present: bool,
    pub auto_install: bool,
    pub executes_after_download: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationDispatch {
    None,
    Tool,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationPolicy {
    pub user_invocable: bool,
    pub disable_model_invocation: bool,
    pub command_dispatch: InvocationDispatch,
    pub command_tool: Option<String>,
    pub command_arg_mode: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallAction {
    pub source_path: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolReachability {
    pub capability: String,
    pub direct: bool,
    pub confidence: FindingConfidence,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretReachability {
    pub secret_kind: String,
    pub target: String,
    pub direct: bool,
    pub confidence: FindingConfidence,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrecedenceCollision {
    pub skill_name: String,
    pub collision_kind: String,
    pub winning_source: SkillSource,
    pub losing_source: SkillSource,
    pub paths: Vec<String>,
    pub limited_by_scope: bool,
    pub confidence: CollisionConfidence,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceNode {
    pub kind: EvidenceKind,
    pub location: SkillLocation,
    pub excerpt: String,
    pub direct: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstructionSegment {
    pub id: String,
    pub instruction_type: InstructionType,
    pub risk: InstructionRisk,
    pub source: InstructionSource,
    pub location: SkillLocation,
    pub span: SourceSpan,
    pub normalized_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptInjectionSignal {
    pub signal_id: String,
    pub kind: PromptSignalKind,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub segment_id: String,
    pub summary: String,
    pub evidence: Vec<EvidenceNode>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackNode {
    pub step_type: AttackPathNodeKind,
    pub summary: String,
    pub evidence: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackEdge {
    pub from: usize,
    pub to: usize,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttackPath {
    pub path_id: String,
    pub path_type: String,
    pub title: String,
    pub steps: Vec<AttackNode>,
    pub edges: Vec<AttackEdge>,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub explanation: String,
    pub prerequisites: Vec<String>,
    pub impact: String,
    pub evidence_nodes: Vec<EvidenceNode>,
    pub inferred_nodes: Vec<String>,
    pub why_openclaw_specific: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
    pub hard_trigger: bool,
    pub evidence_kind: String,
    pub location: Option<SkillLocation>,
    pub evidence: Vec<EvidenceNode>,
    pub explanation: String,
    pub why_openclaw_specific: String,
    pub prerequisite_context: Vec<String>,
    pub analyst_notes: Vec<String>,
    pub remediation: String,
    pub suppression_status: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionRecord {
    pub scope: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSurface {
    pub network: AvailabilityState,
    pub writable_scope: WritableFileSystemScope,
    pub mounted_directories: Vec<String>,
    pub mounted_secrets_or_configs: Vec<String>,
    pub exec_allowed: AvailabilityState,
    pub process_allowed: AvailabilityState,
    pub shell_allowed: AvailabilityState,
    pub child_process_allowed: AvailabilityState,
    pub write_allowed: AvailabilityState,
    pub edit_allowed: AvailabilityState,
    pub apply_patch_allowed: AvailabilityState,
    pub browser_available: AvailabilityState,
    pub web_fetch_available: AvailabilityState,
    pub web_search_available: AvailabilityState,
    pub gateway_available: AvailabilityState,
    pub nodes_available: AvailabilityState,
    pub cron_available: AvailabilityState,
    pub direct_network: AvailabilityState,
    pub browser_network: AvailabilityState,
    pub root_admin_hint: AvailabilityState,
    pub user_identity_hint: Option<String>,
    pub home_directory_access: AvailabilityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentScope {
    pub workspace_only: AvailabilityState,
    pub home_access: AvailabilityState,
    pub mounted_paths: Vec<String>,
    pub mounted_secrets: Vec<String>,
    pub writable_scope: WritableFileSystemScope,
    pub read_only_scope: AvailabilityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySurface {
    pub exec_allowed: AvailabilityState,
    pub process_allowed: AvailabilityState,
    pub shell_allowed: AvailabilityState,
    pub child_process_allowed: AvailabilityState,
    pub write_allowed: AvailabilityState,
    pub edit_allowed: AvailabilityState,
    pub apply_patch_allowed: AvailabilityState,
    pub direct_network: AvailabilityState,
    pub browser_network: AvailabilityState,
    pub web_fetch: AvailabilityState,
    pub gateway: AvailabilityState,
    pub nodes: AvailabilityState,
    pub cron: AvailabilityState,
    pub env_available: AvailabilityState,
    pub config_available: AvailabilityState,
    pub auth_profiles_available: AvailabilityState,
    pub local_secret_paths_available: AvailabilityState,
    pub browser_store_proximity: AvailabilityState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSchema {
    pub schema_version: String,
    pub capability_surface: CapabilitySurface,
    pub environment_scope: EnvironmentScope,
    pub privilege_hint: PrivilegeHint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeFact {
    pub key: String,
    pub value: String,
    pub source_kind: RuntimeSourceKind,
    pub confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeAssumptionStatus {
    pub assumption: String,
    pub state: RuntimeAssumptionState,
    pub source_kind: RuntimeSourceKind,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeManifest {
    pub execution_environment: RuntimeEnvironment,
    pub permission_surface: PermissionSurface,
    pub permission_schema: PermissionSchema,
    pub expected_env_vars: Vec<String>,
    pub present_env_vars: Vec<String>,
    pub expected_config_files: Vec<String>,
    pub present_config_files: Vec<String>,
    pub auth_profiles_present: Vec<String>,
    pub credential_store_proximity: Vec<String>,
    pub notes: Vec<String>,
    pub source_kind: RuntimeSourceKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentAssumption {
    pub environment: RuntimeEnvironment,
    pub assumption: String,
    pub satisfied: Option<bool>,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpactDelta {
    pub environment: RuntimeEnvironment,
    pub delta: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsequenceAssessment {
    pub execution_surface: ExecutionSurface,
    pub file_system_consequences: Vec<FileSystemConsequenceKind>,
    pub credential_consequences: Vec<CredentialConsequenceKind>,
    pub network_consequences: Vec<NetworkConsequenceKind>,
    pub persistence_consequences: Vec<PersistenceConsequenceKind>,
    pub environment_assumptions: Vec<EnvironmentAssumption>,
    pub evidence_nodes: Vec<EvidenceNode>,
    pub inferred_notes: Vec<String>,
    pub impact_deltas: Vec<ImpactDelta>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostSandboxSplit {
    pub host_effects: Vec<String>,
    pub sandbox_effects: Vec<String>,
    pub blocked_in_sandbox: Vec<String>,
    pub residual_sandbox_risks: Vec<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationHook {
    pub hook_id: String,
    pub title: String,
    pub target: ValidationTarget,
    pub reason: ValidationReason,
    pub expected_outcome: ValidationOutcomeExpectation,
    pub guarded_check: String,
    pub related_findings: Vec<String>,
    pub related_paths: Vec<String>,
    pub dangerous: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationCheck {
    pub check_id: String,
    pub title: String,
    pub target: ValidationTarget,
    pub mode: ValidationExecutionMode,
    pub guarded_check: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatedConstraint {
    pub name: String,
    pub evidence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingConstraint {
    pub name: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationResult {
    pub check_id: String,
    pub target: ValidationTarget,
    pub success: bool,
    pub validated_constraints: Vec<ValidatedConstraint>,
    pub missing_constraints: Vec<MissingConstraint>,
    pub capability_checks: Vec<CapabilityCheck>,
    pub constraint_checks: Vec<ConstraintCheck>,
    pub sandbox_constraint_effects: Vec<SandboxConstraintEffect>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationPlan {
    pub summary: String,
    pub hooks: Vec<ValidationHook>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvenanceNote {
    pub subject_id: String,
    pub subject_kind: String,
    pub source_layer: String,
    pub evidence_sources: Vec<String>,
    pub inferred_sources: Vec<String>,
    pub recent_signal_class: String,
    pub long_term_pattern: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfidenceFactor {
    pub subject_id: String,
    pub factor: String,
    pub delta: i32,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FalsePositiveMitigation {
    pub subject_id: String,
    pub mitigation_kind: String,
    pub delta: i32,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRefinementNote {
    pub subject_id: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintEffect {
    pub subject_id: String,
    pub effect: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentBlocker {
    pub path_id: String,
    pub blocker: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentAmplifier {
    pub path_id: String,
    pub amplifier: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathValidationStatus {
    pub path_id: String,
    pub status: PathValidationDisposition,
    pub guard_status: PathGuardStatus,
    pub validated_constraints: Vec<ValidatedConstraint>,
    pub missing_constraints: Vec<MissingConstraint>,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityCheck {
    pub name: String,
    pub available: AvailabilityState,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConstraintCheck {
    pub name: String,
    pub status: RuntimeAssumptionState,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxConstraintEffect {
    pub name: String,
    pub effect: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardedValidationResult {
    pub summary: String,
    pub capability_checks: Vec<CapabilityCheck>,
    pub constraint_checks: Vec<ConstraintCheck>,
    pub sandbox_constraint_effects: Vec<SandboxConstraintEffect>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeScoreAdjustment {
    pub source: String,
    pub delta: i32,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRecord {
    pub level: AuditLevel,
    pub message: String,
    pub subject_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSummary {
    pub summary: String,
    pub records: Vec<AuditRecord>,
    pub high_risk_suppressions: usize,
    pub expired_suppressions: Vec<ExpiredSuppressionNote>,
    pub validation_aware_notes: Vec<ValidationAwareAuditNote>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionRule {
    pub finding_id: Option<String>,
    pub path_id: Option<String>,
    pub target_contains: Option<String>,
    pub reason: String,
    pub note: Option<String>,
    pub expires_on: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionMatch {
    pub scope: String,
    pub target_id: String,
    pub reason: String,
    pub note: Option<String>,
    pub high_risk: bool,
    pub lifecycle: SuppressionLifecycle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExpiredSuppressionNote {
    pub target_id: String,
    pub expires_on: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationAwareAuditNote {
    pub subject_id: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrecedenceScope {
    pub source: SkillSource,
    pub path: String,
    pub present: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeLimitationNote {
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootResolutionSummary {
    pub known_roots: Vec<PrecedenceScope>,
    pub missing_roots: Vec<String>,
    pub scope_notes: Vec<ScopeLimitationNote>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileSkip {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseError {
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextArtifact {
    pub path: String,
    pub content: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanIntegrityNote {
    pub kind: String,
    pub message: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompoundRuleHit {
    pub rule_id: String,
    pub title: String,
    pub summary: String,
    pub severity: FindingSeverity,
    pub confidence: FindingConfidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreRationaleItem {
    pub source: String,
    pub delta: i32,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoringSummary {
    pub base_score: i32,
    pub compound_uplift: i32,
    pub path_uplift: i32,
    pub confidence_adjustment: i32,
    pub final_score: i32,
    pub score_rationale: Vec<ScoreRationaleItem>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusProvenance {
    pub source_name: String,
    pub source_kind: CorpusSourceKind,
    pub source_ref: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusAssetUsage {
    pub asset_name: String,
    pub entry_count: usize,
    pub source_refs: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceClassificationProvenance {
    pub taxonomy_entry_id: Option<String>,
    pub matched_seed_ids: Vec<String>,
    pub asset_sources: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalReference {
    pub reference_id: String,
    pub url: String,
    pub host: String,
    pub category: ExternalReferenceCategory,
    pub service_kind: ExternalServiceKind,
    pub reputation: ExternalReferenceReputation,
    pub risk_signals: Vec<ExternalRiskSignal>,
    pub locations: Vec<SkillLocation>,
    pub evidence_excerpt: String,
    pub rationale: String,
    pub provenance: ReferenceClassificationProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct DependencyAuditSummary {
    pub summary: String,
    pub manifests_discovered: Vec<String>,
    pub lockfile_gaps: Vec<String>,
    pub findings_count: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiClassificationSummary {
    pub summary: String,
    pub total_references: usize,
    pub category_counts: BTreeMap<String, usize>,
    pub service_kind_counts: BTreeMap<String, usize>,
    pub review_needed_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceReputationSummary {
    pub summary: String,
    pub suspicious_references: usize,
    pub risk_signal_counts: BTreeMap<String, usize>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct OpenClawConfigAuditSummary {
    pub summary: String,
    pub config_files_discovered: Vec<String>,
    pub explicit_dependencies: Vec<String>,
    pub risky_bindings: Vec<String>,
    pub findings_count: usize,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityManifestEntry {
    pub capability: String,
    pub status: String,
    pub source: String,
    pub rationale: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CapabilityManifestSummary {
    pub summary: String,
    pub entries: Vec<CapabilityManifestEntry>,
    pub risky_combinations: Vec<String>,
    pub mismatch_notes: Vec<String>,
    pub unknowns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CompanionDocAuditSummary {
    pub summary: String,
    pub companion_files_scanned: Vec<String>,
    pub poisoning_signals: Vec<String>,
    pub findings_count: usize,
    pub false_positive_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceIdentitySignal {
    pub signal_id: String,
    pub signal_kind: String,
    pub summary: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SourceIdentitySummary {
    pub summary: String,
    pub identity_surfaces: Vec<String>,
    pub mismatch_count: usize,
    pub signals: Vec<SourceIdentitySignal>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextAnalysis {
    pub phase: String,
    pub parsing_summary: String,
    pub metadata_summary: Option<String>,
    pub install_chain_summary: Option<String>,
    pub invocation_summary: Option<String>,
    pub tool_reachability_summary: Option<String>,
    pub reachable_tools: Vec<ToolReachability>,
    pub secret_reachability_summary: Option<String>,
    pub reachable_secret_scopes: Vec<SecretReachability>,
    pub precedence_summary: Option<String>,
    pub naming_collisions: Vec<PrecedenceCollision>,
    pub host_vs_sandbox_assessment: Option<String>,
    pub prompt_injection_summary: Option<String>,
    pub threat_corpus_summary: Option<String>,
    pub sensitive_data_summary: Option<String>,
    pub dependency_audit_summary: Option<String>,
    pub api_classification_summary: Option<String>,
    pub source_reputation_summary: Option<String>,
    pub openclaw_config_summary: Option<String>,
    pub capability_manifest_summary: Option<String>,
    pub companion_doc_audit_summary: Option<String>,
    pub source_identity_summary: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recommendations {
    pub immediate: Vec<String>,
    pub short_term: Vec<String>,
    pub hardening: Vec<String>,
    pub dynamic_validation: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: ScanTarget,
    pub scan_mode: String,
    pub files_scanned: usize,
    pub files_skipped: Vec<FileSkip>,
    pub parse_errors: Vec<ParseError>,
    pub score: i32,
    pub verdict: Verdict,
    pub blocked: bool,
    pub top_risks: Vec<String>,
    pub findings: Vec<Finding>,
    pub context_analysis: ContextAnalysis,
    pub attack_paths: Vec<AttackPath>,
    pub path_explanations: Vec<String>,
    pub prompt_injection_summary: String,
    pub consequence_summary: ConsequenceAssessment,
    pub host_vs_sandbox_split: HostSandboxSplit,
    pub runtime_manifest_summary: String,
    pub guarded_validation: GuardedValidationResult,
    pub runtime_facts: Vec<RuntimeFact>,
    pub runtime_assumption_status: Vec<RuntimeAssumptionStatus>,
    pub validation_plan: ValidationPlan,
    pub validation_hooks: Vec<ValidationHook>,
    pub validation_results: Vec<ValidationResult>,
    pub path_validation_status: Vec<PathValidationStatus>,
    pub runtime_refinement_notes: Vec<RuntimeRefinementNote>,
    pub constraint_effects: Vec<ConstraintEffect>,
    pub environment_blockers: Vec<EnvironmentBlocker>,
    pub environment_amplifiers: Vec<EnvironmentAmplifier>,
    pub validation_score_adjustments: Vec<RuntimeScoreAdjustment>,
    pub corpus_assets_used: Vec<CorpusAssetUsage>,
    pub dependency_audit_summary: DependencyAuditSummary,
    pub api_classification_summary: ApiClassificationSummary,
    pub source_reputation_summary: SourceReputationSummary,
    pub external_references: Vec<ExternalReference>,
    #[serde(default)]
    pub openclaw_config_audit_summary: OpenClawConfigAuditSummary,
    #[serde(default)]
    pub capability_manifest: CapabilityManifestSummary,
    #[serde(default)]
    pub companion_doc_audit_summary: CompanionDocAuditSummary,
    #[serde(default)]
    pub source_identity_summary: SourceIdentitySummary,
    pub provenance_notes: Vec<ProvenanceNote>,
    pub confidence_factors: Vec<ConfidenceFactor>,
    pub false_positive_mitigations: Vec<FalsePositiveMitigation>,
    pub scoring_summary: ScoringSummary,
    pub openclaw_specific_risk_summary: String,
    pub scope_resolution_summary: RootResolutionSummary,
    pub audit_summary: AuditSummary,
    pub suppression_matches: Vec<SuppressionMatch>,
    pub analysis_limitations: Vec<String>,
    pub confidence_notes: Vec<String>,
    pub recommendations: Recommendations,
    pub suppressions: Vec<SuppressionRecord>,
    pub scan_integrity_notes: Vec<ScanIntegrityNote>,
}
