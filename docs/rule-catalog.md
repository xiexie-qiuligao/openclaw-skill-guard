# Rule Catalog

This catalog tracks the currently implemented rule families for the standalone OpenClaw-aware skill verifier. It is intentionally organized by long-term risk pattern instead of by one-off upstream issue numbers.

## Baseline inherited pattern rules

These are the inherited Phase 3 descendants of `agent-skills-guard` style pattern scanning. They remain valuable because direct execution, obfuscation, destructive commands, and inline credential material are still dangerous inside real OpenClaw environments.

### `baseline.curl_pipe_shell`

- Category: `execution`
- Trigger: remote download piped into `sh` or `bash`
- Severity: `critical`
- Confidence: `high`
- Hard trigger: yes
- Long-term pattern: download-to-shell execution
- False-positive notes: kept narrow to direct retrieval-plus-shell chains

### `baseline.invoke_expression_download`

- Category: `execution`
- Trigger: PowerShell `iwr` or similar download executed through `iex` / `Invoke-Expression`
- Severity: `critical`
- Confidence: `high`
- Hard trigger: yes
- Long-term pattern: downloaded content evaluated directly

### `baseline.powershell_encoded_command`

- Category: `obfuscation`
- Trigger: PowerShell encoded-command usage
- Severity: `high`
- Confidence: `high`
- Hard trigger: no
- Long-term pattern: opaque or review-resistant execution

### `baseline.rm_rf_root`

- Category: `destructive`
- Trigger: recursive force delete against root path
- Severity: `critical`
- Confidence: `high`
- Hard trigger: yes
- Long-term pattern: destructive filesystem primitive

### `baseline.reverse_shell`

- Category: `execution`
- Trigger: reverse-shell style command patterns
- Severity: `critical`
- Confidence: `high`
- Hard trigger: yes
- Long-term pattern: remote shell establishment

### `baseline.private_key_material`

- Category: `credential_exposure`
- Trigger: inline private-key material
- Severity: `critical`
- Confidence: `high`
- Hard trigger: yes
- Long-term pattern: direct credential exposure

### `baseline.certutil_decode_exec`

- Category: `execution`
- Trigger: `certutil` used as decode or download primitive
- Severity: `high`
- Confidence: `medium`
- Hard trigger: no
- Long-term pattern: LOLBin-assisted execution chain

### `baseline.lolbin_proxy_execution`

- Category: `execution`
- Trigger: `mshta`, `regsvr32`, or `rundll32`
- Severity: `high`
- Confidence: `medium`
- Hard trigger: no
- Long-term pattern: Windows proxy execution

### `baseline.base64_pipe_shell`

- Category: `obfuscation`
- Trigger: base64 decode piped into shell
- Severity: `high`
- Confidence: `high`
- Hard trigger: yes
- Long-term pattern: opaque decode-and-execute

## Structured OpenClaw-aware rules

These rules rely on parsed metadata, install extraction, or context analyzers rather than raw regex matches.

### Parsing and metadata integrity

#### `context.parsing.malformed_frontmatter`

- Category: `parsing`
- Trigger: SKILL frontmatter exists but fails structured parsing
- Severity: `medium`
- Confidence: `high`
- Long-term pattern: metadata integrity failure that can hide runtime semantics
- OpenClaw-specific reason: invocation, install, and capability semantics live in frontmatter

### Install-chain rules

#### `context.install.origin_integrity`

- Category: `origin_integrity_risk`
- Trigger: download-based install spec without checksum or equivalent integrity marker
- Severity: `high`
- Confidence: `high`
- Long-term pattern: remote installer without authenticity control
- Signals absorbed: installer-path asymmetry, authenticity hardening, and scan-boundary lessons from recent OpenClaw fixes

#### `context.install.auto_remote_execution`

- Category: `auto_install_risk`
- Trigger: metadata install step downloads content and executes it
- Severity: `critical`
- Confidence: `high`
- Hard trigger: yes
- Long-term pattern: install-time remote execution

#### `context.install.supply_chain`

- Category: `supply_chain_risk`
- Trigger: package-manager install in metadata install flow
- Severity: `medium`
- Confidence: `medium`
- Long-term pattern: mutable upstream dependency during install

#### `context.install.manual_remote_execution`

- Category: `manual_execution_risk`
- Trigger: SKILL body manual setup command downloads and executes remote content
- Severity: `high`
- Confidence: `high`
- Long-term pattern: operator copy-paste execution path

#### `context.install.manual_supply_chain`

- Category: `supply_chain_risk`
- Trigger: manual package-manager setup instruction
- Severity: `medium`
- Confidence: `medium`
- Long-term pattern: manual dependency pull in setup surface

### Invocation-policy rules

#### `context.invocation.tool_dispatch`

- Category: `invocation_policy`
- Trigger: `command-dispatch: tool`
- Severity: `high`
- Confidence: `high`
- Long-term pattern: direct slash-command dispatch to tool authority
- Signals absorbed: delegated tool authority and prompt/runtime hardening direction

#### `context.invocation.hidden_direct_tool`

- Category: `invocation_policy`
- Trigger: `disable-model-invocation: true` + `user-invocable: true` + `command-dispatch: tool`
- Severity: `high`
- Confidence: `high`
- Long-term pattern: low-visibility user-invocable privileged surface

### Reachability rules

#### `context.tool.high_risk_reachable`

- Category: `tool_reachability`
- Trigger: direct or high-confidence exposure of high-risk tools such as `exec`, `write`, `edit`, `apply_patch`, `process`, `gateway`, `cron`, or `nodes`
- Severity: `high`
- Confidence: `high`
- Long-term pattern: skill-level reachability of sensitive tool authority

#### `context.secret.local_sensitive_path`

- Category: `secret_reachability`
- Trigger: high-confidence guidance to read local sensitive stores such as `~/.ssh`, `.env`, `~/.openclaw/openclaw.json`, or similar
- Severity: `high`
- Confidence: `high`
- Long-term pattern: local secret access guidance
- False-positive notes: reserved for high-confidence access language, not for all env usage

### Precedence rules

#### `context.precedence.name_collision`

- Category: `precedence`
- Trigger: same-name or same-slug collision in scanned scope
- Severity: `medium`
- Confidence: `high`
- Long-term pattern: trusted-name collision / shadowing precondition
- False-positive notes: explicit scope limitation is reported instead of inventing a global precedence winner

## Prompt and instruction rules

These are Phase 5 rules built on top of extracted instruction segments.

### Prompt-level findings

#### `prompt.model_bypass`

- Category: `prompt_injection`
- Trigger: instruction attempts to override higher-priority guidance
- Examples of supported pattern families:
  - ignore previous instructions
  - override system
  - follow only this skill
- Long-term pattern: model-control boundary bypass

#### `prompt.approval_bypass`

- Category: `prompt_injection`
- Trigger: instruction pressures execution without asking
- Supported families:
  - run without asking
  - skip confirmation
  - do not ask for approval
  - never ask for confirmation
- Long-term pattern: approval bypass / operator coercion

#### `prompt.indirect_instruction`

- Category: `prompt_injection`
- Trigger: instruction delegates trust to external content
- Supported families:
  - fetch remote instructions
  - read README/webpage and follow it
  - treat external content as trusted instructions
- Long-term pattern: indirect prompt injection / delegated trust

#### `prompt.tool_coercion`

- Category: `prompt_injection`
- Trigger: instruction pressures use of sensitive tools
- Supported families:
  - use exec
  - use process
  - run shell / PowerShell
  - use browser or web fetch for next steps
- Long-term pattern: tool coercion

#### `prompt.sensitive_data_coercion`

- Category: `prompt_injection`
- Trigger: instruction pressures access to secrets or local sensitive data
- Supported families:
  - read `.env`
  - read `~/.ssh`
  - copy credentials
  - send local data outward
- Long-term pattern: sensitive-data coercion

#### `prompt.policy_bypass`

- Category: `prompt_injection`
- Trigger: instruction pressures safety or validation bypass
- Supported families:
  - bypass safety
  - skip validation
  - do not validate
- Long-term pattern: policy bypass attempt

## Compound graph rules

These are the first matcher-based path/compound escalation rules. They deliberately encode durable patterns rather than issue-specific string patches.

### `compound.dispatch_risky_tool`

- Trigger: `command-dispatch: tool` plus reachable `exec`/`process`/`write`/`apply_patch`
- Effect: high-risk uplift
- Long-term pattern: direct privileged tool dispatch

### `compound.hidden_user_invocation`

- Trigger: `disable-model-invocation: true` plus `user-invocable: true`
- Effect: medium-risk uplift
- Long-term pattern: low-visibility command surface

### `compound.remote_install_no_integrity`

- Trigger: remote install without checksum or digest
- Effect: high-risk uplift
- Long-term pattern: weak-origin install chain

### `compound.instruction_tool_coercion`

- Trigger: prompt signal plus reachable exec/process/browser/web_fetch
- Effect: high-risk uplift
- Long-term pattern: instruction-guided tool misuse

### `compound.instruction_secret_coercion`

- Trigger: prompt signal plus secret reachability
- Effect: high-risk uplift
- Long-term pattern: instruction-guided secret access

### `compound.secret_exfil_potential`

- Trigger: secret reachability plus outward-capable or state-moving tools
- Effect: high-risk uplift
- Long-term pattern: exfiltration potential

### `compound.precedence_hijack_uplift`

- Trigger: precedence collision plus risky invocation or install behavior
- Effect: medium-risk uplift
- Long-term pattern: trust hijack via naming collision

### `compound.multi_surface_uplift`

- Trigger: multiple independent high-risk surfaces in one scan scope
- Effect: high-risk uplift
- Long-term pattern: combined risk envelope larger than isolated findings

## How recent OpenClaw signals are absorbed

The implemented rules deliberately absorb recent OpenClaw signals as durable constraints:

- prompt/runtime hardening changes -> model/approval/policy bypass rule families
- delegated tool authority guidance -> direct dispatch and tool-coercion families
- install-path and installer-boundary fixes -> install-chain and origin-integrity families
- scanner false-positive lessons -> conservative wording, scope-limited precedence, and high-confidence secret finding thresholds
- boundary and trust-root clarifications -> precedence collision and scan-integrity reporting

This keeps the verifier from becoming a dead-patch rule machine that only recognizes the last few issue titles.

## Phase 6 runtime and audit layers

Phase 6 adds trust-building layers that do not replace static scanning:

### Consequence model

- Long-term pattern: host-vs-sandbox impact splits matter as much as the existence of a path
- Signals absorbed:
  - runtime hardening and delegated tool authority guidance
  - scanner-boundary clarification around host files, mounted secrets, and gateway-style outward surfaces
- Implementation style:
  - typed consequence dimensions
  - environment assumptions
  - host/sandbox impact deltas
- Why this is not a patch:
  - the model does not assume a single OpenClaw version or exact runtime shape
  - it records assumptions and residual risks explicitly

### Validation hooks

- Long-term pattern: static high-risk paths should produce safe follow-up checks instead of forcing blind trust or unsafe execution
- Signals absorbed:
  - install-path asymmetry
  - precedence scope incompleteness
  - delegated tool authority
  - host-vs-sandbox uncertainty
- Implementation style:
  - guarded, non-executing validation plans
  - explicit reasons and expected outcomes
- Why this is not a patch:
  - hooks are keyed to risk families like install execution, scope expansion, and runtime clarification, not to issue strings

### Provenance and false-positive shaping

- Long-term pattern: confidence must depend on evidence quality, scope completeness, and benign-example context
- Signals absorbed:
  - false-positive lessons from scanner hardening
  - prompt/runtime wording guidance
  - scope limitation reporting expectations
- Implementation style:
  - provenance notes
  - confidence factors
  - false-positive mitigation records
- Why this is not a patch:
  - the system explains confidence movement instead of silently encoding version-specific exceptions

### Suppression and audit

- Long-term pattern: accepted risk should remain visible and reviewable
- Signals absorbed:
  - break-glass style operator workflows
  - need for explicit audit visibility around high-risk overrides
- Implementation style:
  - minimal-scope suppression by finding or path
  - reason required
  - high-risk suppressions stay visible in audit output
- Why this is not a patch:
  - suppression is not bound to any single rule family and does not erase evidence

## Phase 7 runtime validation and refinement layers

Phase 7 does not add a new pile of payload regexes. It adds controlled validation and refinement families that convert runtime guidance into typed evidence.

### Runtime manifest and permission ingestion

- Long-term pattern: runtime permissions and environment facts determine whether a static path is amplified, blocked, or still assumed
- Signals absorbed:
  - official runtime/config guidance
  - delegated tool authority and shared tool surface guidance
  - scope limitation and install-path clarification
- Implementation style:
  - permissive runtime manifest parsing
  - permission-surface modeling
  - safe local checks for env/config presence
- Why this is not a patch:
  - the manifest loader accepts partial JSON or YAML and tolerates unknown fields
  - the model captures durable capability families rather than one release's exact field layout

### Controlled validation adapter

- Long-term pattern: high-risk static paths should be refined by safe runtime checks instead of unsafe execution or blind trust
- Signals absorbed:
  - install-path split
  - delegated tool authority
  - host-vs-sandbox runtime hardening
  - scope limitation reporting
- Implementation style:
  - guarded validation results
  - path validation status
  - runtime score adjustments
- Why this is not a patch:
  - checks are tied to permission families, prerequisite presence, and scope completeness, not to issue strings

### Validation-aware suppression lifecycle

- Long-term pattern: accepted risk remains reviewable, especially when runtime facts already confirm danger
- Signals absorbed:
  - operator override workflows
  - review friction around high-risk suppressions
- Implementation style:
  - suppression lifecycle
  - expired suppression notes
  - validation-aware audit notes
- Why this is not a patch:
  - audit refinement depends on risk state and validation status, not on any single rule or version-specific special case
