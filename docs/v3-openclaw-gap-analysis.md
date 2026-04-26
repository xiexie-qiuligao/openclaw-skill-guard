# V3 OpenClaw Gap Analysis

Date: 2026-04-24

This document maps current scanner coverage against OpenClaw's real skill risk surface. It is intentionally OpenClaw-specific: the project should not regress into a generic script scanner.

## OpenClaw Risk Surface

OpenClaw skills are not isolated Markdown files. According to the current OpenClaw Skills documentation, OpenClaw loads AgentSkills-compatible folders, applies source precedence, filters by environment/config/binary presence, supports direct slash-command tool dispatch, injects per-skill env/API key values for host runs, and can install skills from public registries into high-precedence workspace locations.

The highest-value risk surfaces are:

1. skill metadata and `metadata.openclaw`
2. `skills.entries.*.env`, `skills.entries.*.apiKey`, and `primaryEnv`
3. system prompt exposure and skill list injection
4. delegated tool authority through `command-dispatch: tool`
5. install path and workspace precedence
6. host-vs-sandbox split
7. prompt injection and indirect instruction poisoning
8. companion docs, external URLs, and source repositories
9. dependency and installer supply chain
10. registry/source identity and ecosystem trust

## Coverage Map

| OpenClaw risk surface | Current coverage | Gap level | Notes |
| --- | --- | --- | --- |
| SKILL.md structure | Covered | Low | Frontmatter and parser diagnostics are visible. |
| `metadata.openclaw` install/requirements | Covered | Low-medium | Good parser and install-chain analysis; v3 should deepen config interactions. |
| `primaryEnv` and declared env needs | Covered | Low-medium | Secret reachability is strong, but config-backed host injection should be summarized more clearly. |
| `skills.entries.*.env/apiKey` host injection | Partially covered | High | Needs first-class OpenClaw config audit when scanning workspace and config context. |
| Per-agent skill allowlists | Partially covered | Medium-high | Current report can reason about skills, but does not fully audit config allowlist exposure. |
| Source precedence and shadowing | Covered | Low | One of the strongest current areas. |
| Workspace install as high-precedence source | Covered | Low-medium | Precedence is covered; registry install identity and source mismatch need more depth. |
| Gateway-backed install metadata | Covered | Medium | Install-chain analysis exists; v3 should improve unsafe installer selection, download target, and config-control-plane narrative. |
| Direct tool dispatch | Covered | Low | Invocation analyzer models this well. |
| Raw argument direct dispatch | Partially covered | Medium | Needs clearer capability manifest and risk narrative for raw argument authority. |
| Hidden-from-model but user-invocable skills | Covered | Low-medium | Existing invocation analysis sees this; v3 should expose it better in capability summary. |
| Host vs sandbox split | Covered | Low | Consequence model and runtime validation are mature. |
| Elevated exec / sandbox escape hatches | Partially covered | Medium-high | Known as a concept, but config-level audit should become first-class. |
| Remote macOS/Linux nodes | Partially covered | Medium-high | Current runtime model does not deeply inspect remote-node eligibility or node-host execution split. |
| Prompt injection phrases | Covered | Low | Prompt/instruction analyzer is strong. |
| Indirect instruction flow | Partially covered | Medium | Needs better companion-document and untrusted external reference labeling. |
| Special-token/role-boundary spoofing | Partially covered | Medium | Corpus can detect some patterns; v3 should add targeted OpenClaw examples. |
| Tool plus secret plus egress attack chains | Covered | Low | Attack-path reasoning is strong. |
| Dependency pull risk | Covered | Medium | Good npm/pip/Cargo v1, not full vulnerability intelligence. |
| URL/API/source classification | Covered | Medium | Good local classification; not remote verification. |
| Registry/source identity mismatch | Partially covered | High | Needs offline mismatch signals based on target evidence. |
| ClawHub/mirror/marketplace trust | Partially covered | High | Should remain offline and explainable; do not build a crawler. |
| Privacy/data-use compliance | Partially covered | High | Current signals help, but compliance is not a full data-flow/privacy engine. |
| Generated skill/workshop provenance | Weakly covered | High | OpenClaw now has generated skill ingestion signals; v3 should add fixtures and patterns. |

## Most Important OpenClaw Scanning Dimensions

### Priority 1: Control-plane and config authority

This is the most important v3 gap. OpenClaw docs state that `skills.entries.*.env` and `apiKey` can be applied to `process.env` for an agent run, and the Skills Config docs distinguish host env injection from sandbox env behavior. A scanner that only reads skill text misses a real authority path.

V3 should detect and summarize:

1. per-skill env/API key injection
2. plaintext secret values in skill config
3. dangerous or interpreter-startup env names
4. broad `skills.load.extraDirs`
5. unrestricted skill allowlists
6. sandbox disabled or elevated escape hatches
7. config mutation instructions inside skills

### Priority 2: Capability manifest

Users need a concise answer to "what can this skill do if trusted?" Existing analyzers already compute much of this. V3 should synthesize:

1. tool authority
2. command dispatch mode
3. env/config/API key requirements
4. install actions
5. dependency pull risks
6. external endpoints
7. source/precedence position
8. host/sandbox consequence

This should be a canonical report section derived from existing analyzers.

### Priority 3: Indirect instruction and companion-document poisoning

OpenClaw skills can include companion files and external references that guide usage, install, or tool behavior. V3 should better distinguish:

1. authoritative skill instructions
2. companion docs that ask the model/user to obey external text
3. examples that are inert
4. instructions that fetch and follow remote content
5. role-boundary spoofing or hidden instruction markers

This is not an online fetcher. It is local analysis of content already present or referenced by the target.

### Priority 4: Source identity and registry mismatch

The ecosystem risk is not only whether content is suspicious; it is whether the content is what the user thinks it is. V3 should add offline checks for:

1. homepage/repository/install URL mismatch
2. package registry source differing from advertised source
3. same-name or typosquatting hints
4. missing bundled implementation despite instructions claiming local scripts
5. stale or unpinned source declarations

### Priority 5: Targeted corpus expansion

The corpus should be expanded only for the above OpenClaw-specific risks:

1. config/env control-plane mutation
2. model-hidden direct tool authority
3. generated skill write/shadow instructions
4. installer download and remote execution combinations
5. obfuscated prompts and special-token/role-boundary poisoning

## Strong Current Coverage

### Attack-path composition

The project is strongest when risks compose:

1. prompt injection plus tool authority
2. install action plus remote download
3. secret reachability plus egress
4. workspace precedence plus familiar skill name
5. host execution plus sandbox assumption mismatch

This should remain the v3 scoring foundation.

### Host-vs-sandbox consequence

OpenClaw sandboxing is optional, the gateway remains on the host, and elevated tools can bypass sandboxing. The project already models host/sandbox consequences better than generic scanners.

### Suppression and audit

Explicit suppression is important because OpenClaw skills often contain examples, docs, and intentionally scary security text. The current audit layer should stay primary.

## Partial or Weak Coverage That v3 Should Address

### Config audit

V3 should add an analyzer for OpenClaw config/control-plane evidence. It should parse local config-like inputs when present and report:

1. host-injected secrets
2. plaintext secrets
3. suspicious env names
4. broad skill loading paths
5. unrestricted allowlists
6. sandbox/elevated settings
7. installer preferences that alter package manager risk

### Capability manifest

V3 should add a stable section such as `capability_manifest` or `openclaw_capability_summary`, not a separate protocol. This section should make GUI and Markdown output easier to read.

### Companion-doc poisoning

V3 should add a small analyzer that tags companion files and local docs as untrusted or secondary-authority sources when they contain tool-use, install, or instruction-hierarchy manipulation.

### Source identity mismatch

V3 should add local evidence checks, not online reputation:

1. `homepage` says one domain, install URL pulls another
2. package manifest repository differs from skill homepage
3. README claims scripts exist but package does not include them
4. raw download URL does not match source repository host

## Explicit Non-goals

V3 should not:

1. execute install scripts
2. fetch remote docs and follow their instructions
3. query live ClawHub, GitHub, VirusTotal, or advisory services by default
4. build a full CVE platform
5. replace attack-path scoring with an additive checklist
6. treat registry trust scores as final truth
7. certify skills as safe

## Sources

1. [OpenClaw Skills documentation](https://docs.openclaw.ai/tools/skills)
2. [OpenClaw Skills Config documentation](https://docs.openclaw.ai/tools/skills-config)
3. [OpenClaw Sandboxing documentation](https://docs.openclaw.ai/gateway/sandboxing)
4. Existing project docs: `docs/openclaw-current-signals.md`, `docs/openclaw-threat-model.md`
