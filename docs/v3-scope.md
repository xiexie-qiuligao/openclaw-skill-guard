# V3 Scope

Date: 2026-04-24

V3 is a focused OpenClaw-aware hardening release. It should deepen the verifier's understanding of OpenClaw configuration, capability authority, companion-document poisoning, and source identity without replacing the v2 architecture.

## V3 Objective

V3 should answer a sharper question:

> Given this skill and its local evidence, what OpenClaw authority can it obtain, what control-plane assumptions does it rely on, and where can that authority combine with install, prompt, source, or secret evidence into real risk?

V3 is not a new scanner family. It is an incremental hardening layer over the existing Rust core, canonical report, GUI, CLI, attack paths, consequence, validation, and suppression/audit model.

## Final V3 Scope

### 1. OpenClaw config/control-plane audit

Add a first-class analyzer for local OpenClaw config/control-plane evidence when present.

It should cover:

1. `skills.entries.*.env`
2. `skills.entries.*.apiKey`
3. plaintext secret values versus SecretRef-like indirection
4. `metadata.openclaw.primaryEnv` linkage
5. broad `skills.load.extraDirs`
6. per-agent skill allowlists and unrestricted skill exposure
7. sandbox mode signals
8. elevated execution escape hatches
9. dangerous env/control-plane names such as interpreter startup and OpenClaw control variables
10. instructions that attempt to mutate OpenClaw config, trust roots, sandbox policy, or gateway/tool configuration

This analyzer should remain static and local. It must not mutate config or execute tools.

### 2. Capability/permission manifest

Add a synthesized report section derived from existing analyzers:

1. tools reachable
2. direct command dispatch and raw argument mode
3. env/API key/config requirements
4. install actions
5. dependencies and package ecosystems
6. external references and service categories
7. source/precedence identity
8. host/sandbox consequence summary
9. hidden-from-model but user-invocable status

This should be a canonical report extension and GUI/Markdown readable summary, not a second protocol.

### 3. Companion-document and indirect instruction audit

Add a focused analyzer for local companion files and referenced instruction surfaces:

1. README/example/setup files that instruct the model or user to obey external content
2. companion docs that contain prompt-injection or role-boundary spoofing
3. documentation-only examples that should be downgraded
4. external URL instructions that ask the agent to fetch and follow remote text
5. generated-skill or workshop-style instructions that write skills into high-precedence locations

This should use existing text artifacts and URL classification. It should not fetch remote pages.

### 4. Offline source identity and mismatch signals

Add local, explainable checks for evidence already present in the target:

1. homepage/repository/install URL mismatch
2. package manifest repository mismatch
3. claimed local scripts missing from package
4. raw download from a host unrelated to advertised source
5. same-name or typosquatting hints where local evidence exists
6. registry/source ambiguity that should require review

This is not online reputation and not a live registry crawler.

### 5. Targeted v3 corpus and fixtures

Add small, high-value assets and fixtures only for v3's new analyzers:

1. control-plane env/config mutation
2. hidden direct tool authority
3. generated-skill write/shadow
4. package/content mismatch
5. obfuscated role-boundary and instruction poisoning
6. benign documentation examples for false-positive regression

### 6. Minimal report/GUI/CLI integration

Expose the new sections in:

1. canonical JSON
2. Markdown/HTML derived reports
3. GUI summary/detail panels
4. CLI JSON and existing derived output paths

No GUI redesign is in scope.

## Explicitly Out of Scope

V3 must not:

1. replace the Rust core
2. replace attack-path or compound scoring
3. replace consequence or guarded validation
4. execute install scripts or skill payloads
5. fetch external URLs and follow remote instructions
6. query live ClawHub/GitHub/VirusTotal/advisory services by default
7. build a full CVE/transitive dependency platform
8. build an online threat-intelligence service
9. use LLM/cloud verdicts as hard truth
10. turn the GUI into a marketplace manager
11. create a plugin system for arbitrary analyzers
12. certify skills as safe

## Deferred Beyond V3

These are useful but should not enter the v3 final scope:

1. live registry identity verification
2. full dependency graph and CVE correlation
3. optional online reputation providers
4. behavior sandbox replay
5. enterprise policy language
6. continuous monitoring daemon
7. marketplace install/update/uninstall workflows
8. LLM-assisted second-pass review
9. full privacy compliance engine
10. multi-user/team collaboration workflows

## Second-round Implementation Slice

V3 round 2 should implement only these core pieces:

1. `openclaw_config_audit` analyzer
2. `capability_manifest` canonical report section
3. `companion_instruction_audit` analyzer
4. offline source identity/mismatch analyzer
5. small v3 corpus additions and inert fixtures
6. schema/report/GUI/CLI minimal display wiring
7. tests for the above plus existing regression preservation

Everything else should be rejected as scope creep.

## Acceptance Criteria

V3 is done when:

1. OpenClaw config/control-plane evidence is visible and explainable.
2. Every scanned skill can produce a concise capability/permission summary.
3. Companion-document and indirect instruction risks are easier to see.
4. Source identity mismatches are flagged from local evidence.
5. New findings explain what evidence triggered them and why they matter in OpenClaw.
6. Reports and GUI expose the new sections without changing the canonical report principle.
7. Existing attack-path, consequence, validation, suppression, GUI, CLI, and derived output behavior remains stable.
8. Regression fixtures cover both true-positive and false-positive v3 examples.

## Boundary Statement

V3 remains a verifier/guard. It improves evidence quality and OpenClaw-specific coverage, but it does not certify safety. A clean scan means no known local evidence triggered current rules; it does not mean the skill, source, dependency graph, or remote behavior is risk-free.
