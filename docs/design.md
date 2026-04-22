# Design

This document is the authoritative Phase 2 implementation spec for the standalone OpenClaw-aware skill verifier. It assumes Phase 1 reverse-engineering and runtime-signal collection are complete and does not repeat that work except where it affects inheritance, rewrites, or new design.

## Product shape

The v1 product is **CLI-first**:

- primary deliverables:
  - scan engine
  - CLI
  - JSON report
  - terminal summary
  - Markdown report
  - HTML report
- explicitly deferred:
  - GUI workflow
  - dynamic execution
  - reputation or signing backends

The scanner is not a generic Markdown lint tool. It is a layered OpenClaw-aware verifier that answers whether a skill can form a realistic attack path in current OpenClaw runtime conditions.

## Architecture

### Workspace layout

The intended repository layout is:

- `crates/core`
  - parsing
  - baseline scanning
  - OpenClaw-aware context modeling
  - rule execution
  - graph composition
  - scoring
  - suppression handling
- `crates/cli`
  - target discovery
  - CLI argument parsing
  - exit codes
  - terminal summary output
  - orchestration of core + report
- `crates/report`
  - JSON serialization contracts
  - Markdown rendering
  - HTML rendering
  - shared report-format helpers
- `crates/research-locks`
  - non-production crate that locks Phase 1 assumptions and Phase 2 design deliverables

Support roots:

- `schemas`
- `fixtures`
- `examples`
- `tests`
- `research`
- `docs`

### Dependency direction

Dependency direction is fixed:

- `cli -> core + report`
- `report -> core` types only
- `core` has no dependency on CLI or any UI surface
- `research-locks` remains isolated from production crates

This keeps the scan engine embeddable, the report contract stable, and the CLI thin enough to later support a GUI wrapper without reworking the analysis model.

## Core data model

The following concepts are stable and must be introduced early in Phase 3:

### Target and location model

- `ScanTarget`
  - the resolved logical thing being scanned
  - includes user-supplied path, canonical path, target mode, and optional OpenClaw context root
- `TargetKind`
  - `file`
  - `skill_dir`
  - `skills_root`
  - `workspace`
  - `openclaw_home`
- `SkillLocation`
  - concrete path plus source classification, relative location, and containment diagnostics
- `SkillSource`
  - `workspace`
  - `project_agents`
  - `personal_agents`
  - `managed`
  - `bundled`
  - `extra_dir`
  - `plugin_extra_dir`
  - `clawhub_workspace_install`
  - `unknown`

### Parse and metadata model

- `ParsedSkill`
  - top-level skill representation after file discovery and parse attempts
  - contains frontmatter result, body segments, auxiliary files, install-chain references, and local diagnostics
- `FrontmatterParseResult`
  - parsed keys
  - raw frontmatter block
  - malformed-field diagnostics
  - compatibility notes for single-line OpenClaw expectations
- `OpenClawMetadata`
  - normalized `metadata.openclaw` model with fields:
    - `homepage`
    - `skill_key`
    - `primary_env`
    - `os`
    - `requires`
    - `install`
    - `always`
    - `emoji`
    - invocation fields surfaced alongside metadata analysis:
      - `user_invocable`
      - `disable_model_invocation`
      - `command_dispatch`
      - `command_tool`
      - `command_arg_mode`
- `InstallAction`
  - normalized install or setup step extracted from metadata, helper scripts, or manual docs

### Context and risk model

- `InstructionSegment`
  - extracted prompt- or behavior-shaping instruction unit from SKILL body text, install guidance, or code fences
- `PromptInjectionSignal`
  - normalized signal for policy bypass, indirect instruction, tool coercion, or sensitive-data coercion
- `ToolReachability`
  - reachability assessment for:
    - `exec`
    - `browser`
    - `web_fetch`
    - `web_search`
    - `read`
    - `write`
    - `edit`
    - `apply_patch`
    - `process`
    - `gateway`
    - `cron`
    - `nodes`
  - each capability must carry:
    - evidence nodes
    - confidence
    - whether access is direct, induced, or inferred
- `SecretReachability`
  - secret categories and target paths, plus evidence for direct read, induced read, or env injection exposure
- `PrecedenceCollision`
  - same-name collision data across OpenClaw source layers, including who wins, who loses, and the trust implication

### Finding and graph model

- `EvidenceNode`
  - atomic proof unit
  - contains source file, location, excerpt, normalized signal kind, and directness
- `EvidenceKind`
  - `text_pattern`
  - `structured_metadata`
  - `install_action`
  - `tool_dispatch`
  - `secret_reference`
  - `precedence_collision`
  - `runtime_context`
  - `parse_diagnostic`
  - `inference`
- `AttackPath`
  - narrative chain assembled from evidence and inference nodes
  - carries prerequisites, impact summary, and score escalation metadata
  - must preserve path type, evidence-backed steps, inferred connectors, and OpenClaw-specific explanation
- `AttackPathNodeKind`
  - `untrusted_content`
  - `prompt_injection`
  - `direct_tool_dispatch`
  - `tool_use`
  - `secret_access`
  - `config_mutation`
  - `network_egress`
  - `install_execution`
  - `precedence_hijack`
  - `host_privilege`
  - `sandbox_residual_risk`
- `Finding`
  - individual explainable issue with category, severity, confidence, evidence, and remediation
- `FindingSeverity`
  - `info`
  - `low`
  - `medium`
  - `high`
  - `critical`
- `FindingConfidence`
  - `high`
  - `medium`
  - `low`
  - `inferred_compound`
- `Verdict`
  - `allow`
  - `warn`
  - `block`
- `SuppressionRecord`
  - rule-scoped or path-scoped suppression with justification and audit metadata
- `ScanReport`
  - canonical report contract shared by JSON, Markdown, HTML, and terminal summary

### Evidence vs inference

The model must distinguish facts from reasoning:

- evidence fields store directly observed content, metadata, config shape, or path collisions
- inference fields store graph edges, prerequisites, and risk escalation logic

A `Finding` may contain both, but the report must always tell the operator which statements are evidenced and which are inferred.

## Scan pipeline

The scanner is a 9-layer pipeline. Each layer emits explicit outputs and diagnostics so later layers can compose on top without re-reading raw files.

### 1. Target resolution and file inventory

Inputs:

- user path
- requested scan mode
- optional OpenClaw home root

Outputs:

- `ScanTarget`
- discovered files
- discovered skill candidates
- skipped files and reasons
- scan-integrity diagnostics for broken traversal, unreadable files, or boundary escapes

Failure handling:

- unreadable files are reportable
- root-not-found and target-type mismatch are fatal
- partial inventory is allowed but must degrade scan integrity

### 2. File and text normalization

Inputs:

- file inventory
- raw bytes

Outputs:

- normalized text units
- encoding diagnostics
- line mapping table for excerpts and evidence coordinates

Inherited baseline behavior:

- UTF-16 handling
- line continuation normalization
- file skip accounting

Failure handling:

- unsupported or undecodable text becomes a reportable parse/integrity diagnostic
- content is never silently dropped

### 3. Frontmatter and metadata parsing

Inputs:

- normalized `SKILL.md`
- candidate metadata-bearing companion files where relevant

Outputs:

- `FrontmatterParseResult`
- `OpenClawMetadata`
- invocation-policy summary
- malformed or evasive metadata findings

Failure handling:

- malformed frontmatter is reportable, not fatal by default
- integrity failures become fatal only when they prevent trustworthy interpretation of invocation, metadata, or source identity

### 4. Install, setup, and dependency chain extraction

Inputs:

- metadata install entries
- helper scripts
- README or docs command snippets
- referenced URLs and package manager actions

Outputs:

- normalized `InstallAction` list
- origin/authenticity assessment
- install-mode classification:
  - auto-install
  - manual copy-paste
  - supply-chain dependency
  - installer-path asymmetry

Failure handling:

- missing helpers or unparseable commands generate findings, not fatal errors

### 5. OpenClaw runtime-context enrichment

Inputs:

- parsed skill
- target layout
- OpenClaw source precedence rules from Phase 1

Outputs:

- source classification
- precedence map
- host-vs-sandbox assessment
- tool reachability
- secret reachability
- runtime eligibility notes

Failure handling:

- unknown source or incomplete workspace context degrades confidence but does not stop the scan

### 6. Prompt-injection and indirect-instruction analysis

Inputs:

- skill text
- docs/examples/comments
- external reference list
- tool and secret reachability context
- extracted instruction segments

Outputs:

- instruction segment inventory
- direct prompt-injection findings
- indirect instruction findings
- tool-poisoning and doc-poisoning findings
- role-boundary spoofing markers

Failure handling:

- uncertain cases are allowed but must be low-confidence unless supported by contextual or graph evidence

### 7. Precedence, shadowing, and hijack analysis

Inputs:

- discovered skills
- canonical names
- source classification
- homepage/display-name metadata

Outputs:

- `PrecedenceCollision` records
- disguised-trusted-skill findings
- override-risk summary

Failure handling:

- incomplete multi-root visibility reduces collision confidence but still reports local collisions

### 8. Toxic-flow and attack-path composition

Inputs:

- findings from prior layers
- evidence nodes
- reachability models
- precedence collisions

Outputs:

- `AttackPath` list
- path completeness and prerequisite analysis
- compounded-risk escalations
- score-rationale inputs that preserve which links are evidence-backed vs inferred

Failure handling:

- graph composition is never fatal
- absence of paths does not suppress underlying findings

### 9. Scoring, verdict, and report rendering

Inputs:

- findings
- attack paths
- suppressions
- scan integrity diagnostics

Outputs:

- final `ScanReport`
- overall score
- `Verdict`
- terminal summary
- JSON, Markdown, and HTML renderable forms

Failure handling:

- JSON serialization failure is fatal
- Markdown and HTML rendering failure must not block JSON output

## Rule system

### Rule classes

Rules are split into four classes:

1. baseline inherited pattern rules
2. structured metadata rules
3. heuristic contextual rules
4. compound graph rules

The inherited regex engine remains valuable, but it becomes only one subsystem of the verifier.

### Baseline inherited pattern rules

These are the ported or adapted descendants of `agent-skills-guard` pattern scanning:

- destructive shell primitives
- reverse-shell style patterns
- encoded or obfuscated command execution markers
- raw credential or private-key exposure markers
- suspicious install snippets

They use a reusable `PatternRule`-style subsystem with:

- regex prefiltering
- extension-aware application
- normalized line matching
- hard-trigger support

### Structured metadata rules

These rules run on parsed frontmatter and normalized metadata:

- malformed frontmatter and evasive formatting
- risky `command-dispatch: tool`
- deceptive invocation policy combinations
- risky `requires.config` capability hints
- secret-bearing metadata such as `primaryEnv`, `requires.env`, or `skillKey`/entry mapping concerns
- install entries with missing authenticity controls

### Heuristic contextual rules

These rules inspect intent and surrounding context:

- quoted command example vs imperative operator instruction
- docs mention vs actual setup step
- localhost/RPC/node-control legitimate patterns vs exfiltration pressure
- references to external pages or downloaded docs as instruction carriers
- host-only path dependence in an otherwise sandbox-friendly skill

### Compound graph rules

These rules operate over the assembled graph:

- untrusted content -> tool use -> secret access -> egress
- install metadata -> remote download -> execution -> host compromise
- same-name override -> direct tool dispatch -> secret exposure
- hidden-from-model slash command -> dangerous direct tool -> host-side action

### Rule signal provenance

Each OpenClaw-aware rule must carry a `RuleSignalSource` record with:

- `phase1_fact`
  - which confirmed runtime fact from Phase 1 justified the rule
- `recent_signal`
  - which official recent release, advisory, or issue contributed the signal
- `long_term_pattern`
  - the generalized risk pattern the rule represents

This is the mechanism that prevents the verifier from turning into a patchwork of issue-specific regexes. The rule binds to a durable pattern, not to one issue number.

## Scoring and verdict

### Scoring model

Scoring is two-step:

1. finding-level scoring
   - severity
   - confidence
   - directness
   - scan-integrity effect
2. attack-path escalation
   - path completeness
   - prerequisite satisfaction
   - host vs sandbox consequence
   - control-plane compromise potential

The final score is not a sum of rule hits. It is a synthesis of individual findings plus compounded path risk.

Phase 5 locks the score breakdown into:

- `base_score`
- `compound_uplift`
- `path_uplift`
- `confidence_adjustment`
- `final_score`
- `score_rationale`

### Verdict policy

Verdicts are:

- `allow`
- `warn`
- `block`

`block` is reserved for:

- high-confidence direct execution, secret-exfiltration, or install-compromise primitives
- compound paths that reach secret or control-plane compromise with enough prerequisites already satisfied
- parse or boundary evasion that makes the scan untrustworthy

`warn` is used when:

- risk is credible but partially inferred
- risk depends on operator behavior not directly forced by the skill
- reachability exists but egress or secret access is not yet complete

`allow` is used when:

- findings are low-severity or documentation-only
- no serious attack path is complete
- scan integrity remains trustworthy

### Host vs sandbox weighting

The verdict engine must score host and sandbox separately:

- host-access findings receive higher weight where secrets, config mutation, or installer execution are host-bound
- sandbox findings still matter when:
  - elevated exec can bypass the sandbox
  - mirrored skill content remains available
  - gateway remains on host
  - the flow can still produce egress or operator deception

## False-positive control

### Confidence model

Use:

- `high`
- `medium`
- `low`
- `inferred_compound`

Confidence applies to each finding and to each attack path.

### Downgrade rules

The engine must actively downgrade or avoid escalation for:

- quoted example commands without imperative framing
- educational mention of dangerous strings
- legitimate localhost/RPC/node-control docs that do not pair with exfiltration or hostile delegation
- dependency-install docs that stop short of remote execution pressure
- generic mentions of `exec`, `subprocess`, or `child_process` without risky flow context

### Suppression model

Support:

- rule-scoped suppression
- path-scoped suppression

Requirements:

- justification required
- suppression reason is preserved in the report
- suppressed findings remain visible unless a hide flag is explicitly added in a later phase
- suppressions cannot remove scan-integrity notes

This keeps the scanner credible while still usable in real repos with known-benign patterns.

## Report design

`ScanReport` is the source-of-truth contract. All renderers consume it.

### Top-level fields

Lock these top-level fields:

- `target`
- `scan_mode`
- `files_scanned`
- `files_skipped`
- `parse_errors`
- `score`
- `verdict`
- `blocked`
- `top_risks`
- `findings`
- `context_analysis`
- `attack_paths`
- `path_explanations`
- `prompt_injection_summary`
- `scoring_summary`
- `openclaw_specific_risk_summary`
- `analysis_limitations`
- `confidence_notes`
- `recommendations`
- `suppressions`
- `scan_integrity_notes`

### Section expectations

#### Summary

- target
- scan mode
- score
- verdict
- blocked
- top risks
- inventory totals

#### Findings

Each finding includes:

- id
- title
- category
- severity
- confidence
- location
- evidence
- explanation
- why this is OpenClaw-specific
- remediation
- suppression status

#### Context analysis

Must include:

- metadata summary
- install-chain summary
- tool reachability
- secret reachability
- precedence/shadowing summary
- host vs sandbox assessment

#### Attack paths

Each path includes:

- path id
- narrative
- nodes
- prerequisites
- impact
- evidence links

#### Recommendations

Split into:

- immediate
- short-term
- hardening
- suppression guidance
- dynamic-validation suggestions

### Output formats

- JSON is canonical
- Markdown is a readable analyst report
- HTML is a styled view of the same report
- terminal output is a concise summary with key verdict and top findings

## Extension points

The v1 design must leave explicit insertion points for:

- provenance and reputation feeds
- signature, checksum, or pinning verification
- SBOM / AI-BOM enrichment
- dynamic validation or sandbox replay
- external allowlist or suppression feeds

These extensions plug into `core` analyzers or `report` enrichers. They must not change the canonical report shape unexpectedly.

## Known limitations

Static analysis will not fully determine:

- whether a remote URL is currently malicious
- whether a package owner or registry account is compromised
- whether a secret is populated at runtime
- whether a browser or node has ambient authority outside the inspected workspace
- whether an operator will manually follow a copy-paste step
- whether current deployment settings expose a dangerous tool path not visible from local scan inputs

The report must therefore surface uncertainty honestly and point to future dynamic hooks where a static result is insufficient.

## Decisions absorbed from recent OpenClaw signals

The design absorbs recent official OpenClaw signals as long-term principles:

- runtime env is part of the attack surface, not just configuration
- delegated config mutation is a control-plane risk
- prompt injection is a flow problem, not a phrase problem
- precedence and trust-root changes matter as much as raw payload text
- false-positive lessons must be encoded as downgrade rules, not tribal knowledge

This is why the design is not a patch set for a few recent issues. The rule model binds every new rule to:

- a confirmed Phase 1 runtime fact
- an official recent signal
- a generalized long-term risk pattern

That abstraction layer is the defense against version-specific fragility.

## Phase 6 refinement

Phase 6 keeps the static verifier as the primary decision engine, then layers on four trust-building systems:

- typed host-vs-sandbox consequence modeling
- guarded validation hooks for high-risk paths
- provenance and false-positive shaping
- auditable suppression instead of silent ignores

The key design choice is that dynamic validation remains a planning surface, not an execution engine. High-risk paths gain:

- runtime assumptions
- host/sandbox impact split
- recommended follow-up checks
- explicit scope limitations
- auditable suppressions when local policy accepts the risk

This follows the same long-term pattern approach used in earlier phases:

- recent prompt/runtime hardening signals become provenance and confidence wording
- install-path and scanner-boundary lessons become guarded validation hooks
- delegated tool authority lessons become host/sandbox consequence rules
- false-positive lessons become confidence factors and mitigation records rather than hidden score hacks

## Phase 7 refinement

Phase 7 upgrades the validation layer from a plan-only surface into a controlled runtime adapter.

The key additions are:

- runtime manifest and permission ingestion
- guarded validation execution modes
- runtime-backed consequence refinement
- attack-path status refinement:
  - `validated`
  - `partially_validated`
  - `blocked_by_environment`
  - `scope_incomplete`
  - `still_assumed`
- runtime-aware score adjustments
- validation-aware suppression lifecycle and audit notes

This still avoids dangerous execution. The adapter may:

- parse user-supplied JSON or YAML manifests
- perform safe local presence checks for expected env vars and config files
- refine whether a path is blocked, amplified, or still hypothetical

It may not:

- execute install chains
- run shell or PowerShell
- fetch unknown remote payloads
- verify risk by replaying untrusted behavior

The long-term design principle remains the same as earlier phases: OpenClaw release notes and security guidance are absorbed as durable validation families such as permission surfaces, delegated tool authority, installer asymmetry, scope completion, and runtime hardening, rather than as brittle patches tied to a single version string.
