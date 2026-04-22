# Progress

## Phase 1

Date: 2026-04-22

### Completed

- Pulled `agent-skills-guard` source into `research/agent-skills-guard-main`.
- Pulled current OpenClaw source/docs into `research/openclaw-main`.
- Mapped the upstream `agent-skills-guard` security code path:
  - scanner
  - rules
  - report model
  - install gating
  - frontend consumption
- Established the current OpenClaw baseline for:
  - skill discovery sources
  - precedence
  - frontmatter/metadata semantics
  - command dispatch
  - installer path split
  - host-vs-sandbox behavior
  - secret injection path
- Wrote Phase 1 documents:
  - `docs/reverse-engineering.md`
  - `docs/openclaw-current-signals.md`
  - `docs/openclaw-threat-model.md`
- Added a Rust workspace plus `research-locks` tests so critical upstream evidence markers are checked automatically.

### Blockers and workarounds

- Direct git clone was unreliable in this environment, so upstreams were pulled as source archives and unpacked under `research/`.
- `rg.exe` was not executable in the current shell context, so evidence extraction used PowerShell `Select-String` instead.
- The repo changelog is ahead of the stable appcast feed. We treated `2026.4.20` as latest confirmed shipped release and `2026.4.21` as a near-term source signal.

### Verification

- Installed Rust via `winget` (`Rustlang.Rustup`) and confirmed:
  - `cargo 1.95.0`
  - `rustc 1.95.0`
- Executed `cargo test` successfully at the repository root.
- Result: `2` Phase 1 research-lock tests passed.
- Earlier Python smoke validation is now superseded by the real Rust test run, but remains useful as a quick independent cross-check.

### Outputs

- Research fixtures:
  - `research/agent-skills-guard-main`
  - `research/openclaw-main`
  - `research/phase1-source-locks.json`
- Phase 1 docs:
  - `docs/reverse-engineering.md`
  - `docs/openclaw-current-signals.md`
  - `docs/openclaw-threat-model.md`
- Tests:
  - `crates/research-locks/tests/phase1_source_locks.rs`

### Next up

- Phase 2 architecture documents:
  - `docs/design.md`
  - `docs/comparison.md`
  - `docs/refactor-plan.md`
- Convert Phase 1 findings into a reusable verifier architecture:
  - structured metadata parser
  - OpenClaw runtime-context model
  - precedence/shadowing engine
  - install-chain analyzer
  - toxic-flow graph and score model

## Phase 2

Date: 2026-04-22

### Completed

- Created `docs/design.md` as the Phase 3/4 implementation spec.
- Created `docs/comparison.md` as the inherit/wrap/rewrite/add decision log.
- Created `docs/refactor-plan.md` as the phase-by-phase execution sheet.
- Added minimal design-lock scaffolding:
  - `schemas/report.schema.json`
  - `crates/core/src/types.rs`
  - placeholder directories for `crates/cli`, `crates/report`, `fixtures`, `examples`, and `tests`

### Key design decisions

- v1 is CLI-first.
- JSON is the source-of-truth report format.
- The scanner is a layered 9-stage pipeline rather than a single regex pass.
- Scoring is compound and attack-path aware rather than rule-hit additive.
- False-positive control is explainability-first and suppression-aware.

### Outputs

- New docs:
  - `docs/design.md`
  - `docs/comparison.md`
  - `docs/refactor-plan.md`
- New scaffolding:
  - `schemas/report.schema.json`
  - `crates/core/src/types.rs`
  - `crates/cli/src/.gitkeep`
  - `crates/report/src/.gitkeep`
  - `fixtures/.gitkeep`
  - `examples/.gitkeep`
  - `tests/.gitkeep`

### Next up

- Phase 3 kickoff sequence:
  1. add `core`, `cli`, and `report` crate manifests plus workspace membership
  2. implement stable shared types in `core`
  3. port inherited normalization and file inventory
  4. port inherited pattern-rule execution and hard-trigger handling
  5. add minimal CLI scan support for single file and directory with JSON output
  6. port inherited inert fixtures and make CI pass

## Phase 3

Date: 2026-04-22

### Completed

- Expanded the workspace to include `crates/core`, `crates/cli`, and `crates/report`.
- Replaced the Phase 2 type skeleton with serialized core report and finding types.
- Implemented baseline file discovery and recursive traversal.
- Implemented baseline text reading plus line-ending and continuation normalization.
- Ported 9 stable baseline rules for direct execution, obfuscation, destructive commands, Windows LOLBins, and private-key exposure.
- Implemented baseline finding generation, hard-trigger handling, simplified scoring, and verdict mapping.
- Implemented minimal CLI support for `scan <path> --format json`.
- Implemented JSON rendering through the report crate.

### Verification

- Executed `cargo test` successfully at the repository root.
- Current result:
  - `1` CLI integration test passed
  - `8` core tests passed
  - `1` report test passed
  - `3` research-lock tests passed

### Intentional simplifications versus `design.md`

- No `metadata.openclaw` parsing yet.
- No secret/tool reachability yet.
- No precedence or shadowing analysis yet.
- No prompt-injection or indirect-instruction analysis yet.
- No attack-path graph composition yet.
- `context_analysis`, `attack_paths`, and suppression output are present only as Phase 3 placeholders so the JSON contract is stable before Phase 4 fills them in.

### Next up

- Phase 4 should start with:
  1. structured frontmatter parsing
  2. `metadata.openclaw` normalization
  3. install-chain extraction
  4. tool and secret reachability scaffolding

## Phase 4

Date: 2026-04-22

### Completed

- Added structured SKILL.md frontmatter parsing.
- Added `metadata.openclaw` normalization and invocation-policy extraction.
- Added first-pass install-chain extraction from both metadata and SKILL body instructions.
- Added first-pass invocation-policy, tool-reachability, secret-reachability, and precedence analyzers.
- Replaced placeholder `context_analysis` output with populated structured summaries.
- Kept Phase 3 baseline scanner behavior intact and layered the new context analyzers on top.

### Verification

- Executed `cargo test` successfully at the repository root.
- Current result:
  - `1` CLI integration test passed
  - `18` core tests passed
  - `1` report test passed
  - `3` research-lock tests passed

### Intentional scope control

- Prompt injection and indirect instruction remain limited.
- Attack-path graphing remains a placeholder.
- Host-vs-sandbox analysis remains summary-level only.
- Suppression remains report-shape-only and is not yet a full audit system.
- Precedence analysis is conservative and definitive only within the scanned scope.

### Next up

- The next phase should prioritize:
  1. prompt injection and indirect instruction analysis
  2. first real attack-path composition
  3. richer host-vs-sandbox consequence modeling

## Phase 5

Date: 2026-04-22

### Completed

- Added a dedicated instruction extraction layer for SKILL body text, install guidance, and code fences.
- Added a first formal prompt-injection and indirect-instruction analyzer.
- Added first-pass attack-path structures and a builder that combines prompt, install, invocation, reachability, and precedence signals.
- Added compound graph rules and upgraded scoring to be path-aware and compound-aware.
- Populated `attack_paths`, `prompt_injection_summary`, `scoring_summary`, and related explanation fields in the canonical `ScanReport`.
- Extended the JSON schema and renderer to include the richer Phase 5 reporting surface.
- Added `docs/rule-catalog.md` and updated `docs/design.md` to lock the new instruction/path/scoring/report contract.

### Verification

- Executed root `cargo test` successfully with the local Rust toolchain at `C:\Users\29345\.cargo\bin\cargo.exe`.
- Current result:
  - `1` CLI integration test passed
  - `26` core tests passed
  - `1` report test passed
  - `3` research-lock tests passed
- Total: `31` tests green.

### Intentional scope control

- Prompt analysis is pattern- and context-based, not a full NLP or LLM classifier.
- Attack-path composition is intentionally a first-pass model rather than a full global graph engine.
- Multi-root global precedence and host-vs-sandbox consequence simulation remain limited.
- Suppression remains report-shape-compatible but is not yet a full audited workflow.
- Dynamic validation, reputation, signing, SBOM, and runtime sandbox replay remain deferred.

### Next up

- Phase 6 should start with:
  1. richer prompt-injection false-positive controls and provenance tracking
  2. deeper host-vs-sandbox consequence modeling
  3. dynamic validation hooks for high-risk attack paths

## Phase 6

Date: 2026-04-22

### Completed

- Strengthened host-vs-sandbox consequence modeling into typed execution, file-system, credential, egress, persistence, assumption, and impact-delta structures.
- Added guarded dynamic validation hooks and validation planning for install chains, direct dispatch, runtime assumptions, secret prerequisites, and missing precedence roots.
- Added provenance notes, confidence factors, and false-positive mitigation records that refine confidence without hiding evidence.
- Added first-pass suppression and audit workflow with reason-required suppression rules, high-risk audit visibility, and CLI integration via `--suppressions`.
- Expanded precedence analysis to track known roots, missing roots, and collision confidence instead of only local scope notes.
- Extended `ScanReport` and schema with validation, consequence, provenance, audit, suppression-match, and scope-resolution sections.

### Verification

- Executed root `cargo test` successfully with the local Rust toolchain at `C:\Users\29345\.cargo\bin\cargo.exe`.
- Current result:
  - `2` CLI integration tests passed
  - `37` core tests passed
  - `1` report test passed
  - `3` research-lock tests passed
- Total: `43` tests green.

### Intentional scope control

- Dynamic validation remains planning-oriented and does not execute dangerous payloads.
- Host-vs-sandbox modeling is richer, but still not a full runtime simulator.
- Multi-root precedence is improved, but it still reports missing roots rather than inventing a full global truth.
- Suppression is formalized, but full expiration policy and enterprise audit workflows remain future work.
- Reputation, signing, SBOM, AI-BOM, and external online feeds remain deferred.

### Next up

- The next phase should prioritize:
  1. dynamic or sandbox-backed validation adapters for selected high-risk paths
  2. stronger host-vs-sandbox assumption checking against real runtime manifests
  3. provenance-aware report renderers and richer operator review workflows

## Phase 7

Date: 2026-04-22

### Completed

- Added runtime manifest ingestion with permissive JSON/YAML parsing, safe local checks, and typed permission surfaces.
- Added a controlled validation adapter that upgrades validation hooks into guarded runtime-backed checks.
- Refined consequence, attack-path status, score adjustments, and confidence wording using runtime facts.
- Added suppression lifecycle and validation-aware audit notes.
- Extended CLI with runtime manifest input and validation mode selection.
- Extended the canonical report schema and JSON output with runtime validation sections.
- Updated validation, consequence, suppression, and design docs for the runtime-adapter phase.

### Verification

- Root `cargo test` was rerun after the Phase 7 integration work.
- Current result:
  - `3` CLI integration tests passed
  - `44` core tests passed
  - `1` report test passed
  - `3` research-lock tests passed
- Total: `51` tests green.

### Intentional scope control

- Runtime validation remains guarded and non-executing.
- The adapter confirms permissions, prerequisites, and scope; it does not run installs or payloads.
- Multi-root precedence is improved through scope resolution, but still does not claim complete global truth.
- Signing, SBOM, AI-BOM, remote attestation, and full dynamic sandbox replay remain deferred.

### Next up

- The next phase should prioritize:
  1. sandbox-backed validation adapters for selected high-risk paths
  2. richer runtime manifest ingestion from real OpenClaw permission/runtime surfaces
  3. deeper false-positive shaping for delegated local workflows such as localhost, RPC, and child-process control

## V1 Release Prep

Date: 2026-04-22

### Completed

- Added a top-level release-ready README.
- Polished CLI help text and option descriptions without changing the v1 interface shape.
- Added inert demo fixtures and generated example JSON reports.
- Added reporting and release-ready docs to lock the public contract and self-check results.
- Revalidated canonical JSON output, runtime-refinement examples, and suppression/audit examples.

### Release posture

- v1 is CLI-first.
- JSON remains the canonical public contract.
- The repository now includes runnable demos, release-facing documentation, and a release-ready self-check.

### Current recommendation

- The project is suitable for a v1 release candidate tag if you want to freeze the current CLI-first scope and document the remaining non-blocking limitations as post-v1 work.
