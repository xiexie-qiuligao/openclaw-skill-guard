# OpenClaw Current Signals

This document captures the current OpenClaw runtime facts and the recent official security signals that should shape the new verifier. The intent is to extract durable patterns, not to hardcode one-off patches.

## Evidence Labels

- Confirmed fact: directly backed by current OpenClaw source, docs, changelog, appcast, or official GitHub issue/advisory pages
- Inference: reasoned from multiple confirmed facts
- Hypothesis: worth keeping in mind, but not yet strong enough to drive a hard rule

## Version Baseline

As of **2026-04-22**:

- Confirmed fact: the shipped appcast stable feed in `research/openclaw-main/appcast.xml` advertises **2026.4.20**, published on **2026-04-21**.
- Confirmed fact: the current repository `CHANGELOG.md` already contains a **2026.4.21** section.
- Inference: for Phase 1 design, `2026.4.20` should be treated as the latest confirmed release artifact, while `2026.4.21` is a repo-main signal worth absorbing as near-term direction but not yet assumed to be universally deployed.

This distinction matters because the verifier should model durable runtime patterns, not overfit to an unreleased or partially deployed tree state.

## Current Skill Runtime Facts

### Skill sources and precedence

Confirmed from `docs/tools/skills.md` and `src/agents/skills/workspace.ts`:

- OpenClaw loads skills from multiple sources:
  - `skills.load.extraDirs`
  - bundled skills
  - `~/.openclaw/skills`
  - `~/.agents/skills`
  - `<workspace>/.agents/skills`
  - `<workspace>/skills`
- Merge precedence is:
  - extra
  - bundled
  - managed
  - personal agent skills
  - project agent skills
  - workspace skills
- Final conflict precedence is:
  - `<workspace>/skills`
  - `<workspace>/.agents/skills`
  - `~/.agents/skills`
  - `~/.openclaw/skills`
  - bundled
  - `skills.load.extraDirs`
- Plugin skill directories are folded into the same low-precedence path as `skills.load.extraDirs`.

Design implication:

- The verifier must treat same-name collisions as a first-class risk.
- Risk is not only “is this SKILL.md suspicious?” but also “what trusted thing can this skill overshadow?”

### Path containment and symlink boundaries

Confirmed from `src/agents/skills/workspace.ts`:

- Skill discovery uses `resolveContainedSkillPath`.
- Escapes are surfaced through `warnEscapedSkillPath`.
- Bundled skill roots get special reasons such as bundled symlink/root escape cases.

Design implication:

- The verifier should test and report discovery-boundary evasions even if current OpenClaw rejects them, because those are high-value regression points.

### Frontmatter and metadata semantics

Confirmed from `docs/tools/skills.md`, `src/agents/skills/frontmatter.ts`, and `src/agents/skills/types.ts`:

- Frontmatter is parsed structurally via `parseFrontmatterBlock`, not with a one-off regex.
- The embedded agent parser supports **single-line frontmatter keys only**.
- `metadata` is expected to be a **single-line JSON object**.
- `metadata.openclaw` currently maps to fields including:
  - `homepage`
  - `skillKey`
  - `primaryEnv`
  - `os`
  - `requires.bins`
  - `requires.anyBins`
  - `requires.env`
  - `requires.config`
  - `install`
  - `always`
  - `emoji`

Design implication:

- The verifier should parse both the intended structure and common evasive/malformed variants.
- Parse failure is itself security-relevant and should never be silent.

### Invocation policy and direct tool dispatch

Confirmed from `docs/tools/skills.md`, `src/agents/skills/frontmatter.ts`, and `src/agents/skills/command-specs.ts`:

- `user-invocable` defaults to `true`.
- `disable-model-invocation` defaults to `false`.
- `command-dispatch: tool` bypasses model reasoning and directly dispatches to the named tool in `command-tool`.
- Unknown or missing `command-tool` does not execute; the dispatch is ignored with a diagnostic log.
- `command-arg-mode` currently accepts `raw`; unknown modes fall back to raw.
- `disable-model-invocation: true` sets `includeInAvailableSkillsPrompt` to false, meaning the skill can remain user-invocable while being hidden from the model’s available-skills prompt.

Design implication:

- A skill can reduce model visibility while preserving user-triggerable direct tool authority.
- `disable-model-invocation: true` is not a safety signal by itself. In combination with `user-invocable: true` and dangerous `command-dispatch`, it can increase operator deception risk.

### Eligibility and secret injection

Confirmed from `src/agents/skills/config.ts`, `src/agents/skills/env-overrides.ts`, `src/agents/skills/runtime-config.ts`, `docs/tools/skills.md`, and `docs/tools/skills-config.md`:

- `shouldIncludeSkill` evaluates runtime eligibility against OS, binary presence, env, config, and remote-node availability.
- `skills.entries.<skillKey>.env` and `skills.entries.<skillKey>.apiKey` are resolved into environment overrides for the **host process** for that agent turn.
- `primaryEnv` binds `apiKey` convenience values to a concrete environment variable name.
- OpenClaw blocks dangerous host env override keys via `isDangerousHostEnvVarName` and `isDangerousHostEnvOverrideVarName`.
- Runtime config handling distinguishes raw secret refs that remain unresolved in snapshots.

Design implication:

- Secret reachability is not hypothetical. It is a declared feature path.
- The verifier must distinguish:
  - a skill that requires a secret
  - a skill that can access a secret on host
  - a skill that pairs secret access with egress or delegated tool authority

### Install-chain asymmetry

Confirmed from `docs/tools/skills.md`, `docs/gateway/protocol.md`, and `src/agents/skills-install.ts`:

- `skills.install` has two distinct modes:
  - ClawHub mode installs a skill folder into the workspace
  - gateway installer mode runs a declared `metadata.openclaw.install` action on the gateway host
- Gateway-backed dependency installs run the built-in dangerous-code scanner before installer metadata execution.
- `openclaw skills install <slug>` is explicitly different: it downloads a ClawHub skill folder into the workspace and **does not** use the installer-metadata path above.
- OpenClaw warns when install metadata is triggered from a non-bundled source.

Design implication:

- The verifier must model both:
  - what the skill content asks the agent to do
  - what the installer metadata path can execute automatically
- The two install paths have different trust and scan boundaries. That asymmetry is itself a risk signal.

### Host vs sandbox boundaries

Confirmed from `docs/gateway/sandboxing.md`, `docs/tools/skills.md`, and `docs/tools/skills-config.md`:

- Sandboxing is optional. If disabled, tools run on the host.
- The gateway itself stays on the host even when tool execution is sandboxed.
- Elevated exec bypasses sandboxing.
- Skill binaries needed by sandboxed sessions must also exist inside the sandbox.
- Package installs inside the sandbox need network egress, writable root, and root user privileges.
- `skills.entries.*.env` and `apiKey` apply to **host** runs, not the sandbox.
- OpenClaw mirrors eligible skills into sandbox workspaces for some modes so `SKILL.md` remains available even with restricted workspace mounts.

Design implication:

- The verifier must score host and sandbox paths separately.
- “Sandboxed” does not mean “no risk”; it changes which assets are reachable and which prerequisites remain.

## Recent Official Security Signals

| Date | Source | Confirmed fact | Durable pattern | Verifier design implication |
| --- | --- | --- | --- | --- |
| 2026-04-21 | [GHSA-mj59-h3q9-ghfh](https://github.com/openclaw/openclaw/security/advisories/GHSA-mj59-h3q9-ghfh) and `2026.4.20` notes | OpenClaw blocked interpreter-startup env keys like `NODE_OPTIONS` for MCP stdio servers | workspace-controlled env can mutate execution semantics without changing visible skill content | Secret/env reachability logic must treat runtime env control as an attack surface, not just explicit shell snippets |
| 2026-04-21 | [GHSA-hxvm-xjvf-93f3](https://github.com/openclaw/openclaw/security/advisories/GHSA-hxvm-xjvf-93f3) and `2026.4.20` notes | Untrusted workspace `.env` inputs were hardened: `OPENCLAW_*` blocked, `MINIMAX_API_HOST` blocked | dotenv is part of the control plane, not “just configuration” | Treat workspace env references and install instructions that redirect through env as trust-boundary violations, not harmless config |
| 2026-04-21 | `2026.4.20` release notes / appcast item `#69377` | Gateway tool config mutation guard was extended to stop model-driven rewrites of trusted paths and dangerous per-agent overrides | delegated tool authority can rewrite future trust boundaries | Rules should model control-plane mutation attempts generically, not only one issue id |
| 2026-04-21 | `2026.4.21` changelog | Wrapped external content now strips special-token literals from user-provided external content | tokenizer-layer prompt injection is a real runtime concern | Prompt-injection detection should include role-boundary spoofing and wrapped-content poisoning, not only “ignore previous instructions” text |
| 2026-04-21 | `2026.4.21` changelog | Skill Workshop plugin quarantines unsafe proposals before workspace skill writes | generated skills are now an expected ingestion source | Workspace skill provenance and newly-written same-name skills deserve higher review priority |
| 2026-04-21 | `2026.4.20` changelog item `#67253` | OpenClaw fixed false-positive “missing secret” style alerts for env-backed and unresolved SecretRefs | naive missing-secret warnings are noisy | Our verifier should separate confirmed missing secret, unresolved secret ref, and intentionally externalized auth state |
| 2026-04-21 | `2026.4.20` changelog item `#58909` | `--dangerously-force-unsafe-install` no longer silently falls back after scan failures | break-glass paths must be auditable and non-magical | Suppression and overrides in the new verifier must be explicit, narrow, and recorded |
| 2026-04-21 | `2026.4.20` changelog item `#67401` | unknown-tool loop guard was enabled by default because it had no false-positive surface | some guards can be strict if grounded in objective state | High-confidence rules should prefer invariant conditions like direct tool dispatch plus concrete dangerous tool names |
| 2026-03-01 | [Issue #30448](https://github.com/openclaw/openclaw/issues/30448) | Prompt injection can combine memory compaction and tool calls to exfiltrate secrets | prompt injection becomes higher severity when it couples with tool authority and state summarization | Attack-path scoring must combine untrusted text, secret reachability, and egress, not score them independently |

## Signals We Should Absorb as Long-Term Principles

### Principle 1: Treat configuration mutation as an execution primitive

Confirmed signal sources:

- `OPENCLAW_*` workspace env hardening
- `MINIMAX_API_HOST` block
- gateway `config.patch` / `config.apply` guard expansion
- MCP `NODE_OPTIONS` / interpreter-startup env hardening

Verifier consequence:

- Flag skills that encourage editing config, env, or trust roots in ways that expand future tool authority, alter endpoints, or relax sandbox boundaries.

### Principle 2: Model prompt-injection as a flow, not a phrase match

Confirmed signal sources:

- external-content special-token stripping
- prompt-injection issue #30448

Verifier consequence:

- Detect:
  - wrapped-content poisoning
  - role-boundary spoofing
  - “read this URL/file and obey it” patterns
  - escalation from poisoned content to tool use, secret read, or egress

### Principle 3: Preserve scanner credibility by encoding false-positive lessons

Confirmed signal sources:

- false-positive “missing secret” fixes
- no-false-positive unknown-tool guard rationale
- explicit dangerous-install fallback hardening

Verifier consequence:

- Classify findings as:
  - directly evidenced
  - heuristic
  - inferred compound risk
- Require stronger evidence before blocking documentation-only cases.

### Principle 4: Keep install-path and discovery-path asymmetries visible

Confirmed signal sources:

- `skills.install` vs `openclaw skills install <slug>` split
- multi-source precedence
- sandbox skill mirroring and contained-path enforcement

Verifier consequence:

- Every report should summarize:
  - how the skill could arrive
  - what it can shadow
  - whether install metadata runs automatically
  - whether runtime execution differs on host vs sandbox

## Hypotheses Worth Testing in Phase 3-4

- Workspace-generated or workshop-generated skills may become a practical same-name shadowing vector even when the content itself looks “helpful”.
- Some seemingly benign config requirements in `requires.config` may act as capability beacons for already-enabled high-risk tools, and should raise risk only when combined with other evidence.
- Sandboxed skills that still require host-side secrets may produce a misleading “safe” impression unless reports explicitly call out the split control plane.

