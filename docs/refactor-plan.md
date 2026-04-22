# Refactor Plan

This document is the build sheet for Phase 3, Phase 4, and Phase 5. It is intentionally decision-complete so implementation can start without reopening architecture questions.

## Overall strategy

Expand the current workspace into the target structure while preserving the existing research assets:

- production crates:
  - `crates/core`
  - `crates/cli`
  - `crates/report`
- support crate:
  - `crates/research-locks`
- support roots:
  - `schemas`
  - `fixtures`
  - `examples`
  - `tests`

Guiding strategy:

- Phase 3 establishes baseline scanner parity and stable shared types.
- Phase 4 adds OpenClaw-aware analysis on top of a known-good baseline.
- Phase 5 focuses on report polish, CLI completeness, and Windows packaging.

`research-locks` stays separate at least through the end of Phase 4 so research and design assertions stay independent from product implementation.

## Phase 3

### Goal

Reach baseline scanner parity with the inherited mature capabilities from `agent-skills-guard`, but inside the new crate architecture and report contract.

### Task packages

#### Package P3-1: workspace expansion and stable shared types

Work:

- add `core`, `cli`, and `report` crate manifests
- add shared types in `core`
- add canonical `ScanReport` structure
- update workspace membership

Done definition:

- workspace builds
- shared public types exist
- `cargo test` passes with the existing research-lock crate still enabled

#### Package P3-2: baseline file inventory and normalization

Work:

- implement file inventory
- implement skip accounting
- implement encoding support
- port line continuation normalization

Done definition:

- baseline inventory returns files scanned, files skipped, and parse/integrity diagnostics
- UTF-16 and continuation normalization fixtures pass

#### Package P3-3: baseline rule engine

Work:

- port inherited pattern rules into `core::baseline::rules`
- implement regex prefiltering
- implement hard-trigger handling
- preserve severity and confidence wiring

Done definition:

- inherited dangerous-pattern regressions pass
- rule execution produces structured `Finding` values

#### Package P3-4: minimal JSON reporting

Work:

- serialize `ScanReport`
- map baseline findings into summary, findings, and scan-integrity sections
- expose a minimal CLI scan command

Done definition:

- CLI can scan at least a single file and a single directory
- JSON report shape matches the Phase 2 design contract

#### Package P3-5: inherited regression suite

Work:

- port relevant inert fixtures from the upstream project
- lock expected hits and false-positive cases

Done definition:

- baseline regressions prove inherited capability parity
- CI can fail on rule drift

### Phase 3 kickoff order

The first implementation commits should happen in this exact order:

1. workspace expansion and crate manifests
2. shared report and type module
3. inherited normalization and traversal
4. inherited rules and severity/confidence wiring
5. minimal CLI scan command for file/dir JSON output
6. baseline regression fixtures and CI pass

## Phase 4

### Goal

Add OpenClaw-aware analysis and upgrade the baseline scanner into a runtime-context verifier.

### Task packages

#### Package P4-1: frontmatter and metadata parser

Work:

- implement structured frontmatter parsing
- normalize `metadata.openclaw`
- parse invocation-policy fields
- emit parse diagnostics

Done definition:

- malformed frontmatter is reported, not skipped
- metadata and invocation policy are available as typed outputs

#### Package P4-2: install-chain analyzer

Work:

- normalize `metadata.openclaw.install`
- extract helper-script and docs install steps
- classify auto-install vs manual copy-paste
- add authenticity-control checks

Done definition:

- install-chain summary is present in the report
- auto-install and manual docs are scored differently

#### Package P4-3: runtime-context analyzer

Work:

- compute `SkillSource`
- compute precedence and collisions
- compute host-vs-sandbox assessment
- compute tool and secret reachability

Done definition:

- report includes context-analysis sections for source, precedence, tool reachability, secret reachability, and host/sandbox split

#### Package P4-4: prompt-injection and indirect-instruction analyzer

Work:

- implement strong prompt-injection rules
- add heuristic indirect-instruction analysis
- add tool-poisoning and doc-poisoning analysis

Done definition:

- explainable prompt-injection findings are emitted with evidence and prerequisites

#### Package P4-5: attack-path composer and verdict upgrade

Work:

- build attack paths from prior findings
- score path completeness
- upgrade overall score and verdict logic

Done definition:

- compound path summaries appear in reports
- verdict uses both direct findings and path escalation

## Phase 5

### Goal

Turn the analyzer into a usable standalone product.

### Task packages

#### Package P5-1: CLI completeness

Work:

- support target modes:
  - `scan file`
  - `scan skill-dir`
  - `scan skills-root`
  - `scan workspace`
  - optional `scan openclaw-home`
- finalize exit codes
- finalize terminal summary UX

Done definition:

- CLI covers all v1 target modes
- exit codes map cleanly to `allow`, `warn`, `block`, and fatal errors

#### Package P5-2: report renderers

Work:

- Markdown renderer
- HTML renderer
- shared formatting helpers

Done definition:

- JSON, Markdown, and HTML render from one `ScanReport`
- example outputs exist under `examples`

#### Package P5-3: packaging and examples

Work:

- document Windows EXE packaging flow
- add packaging/build verification steps
- publish inert fixtures and sample reports

Done definition:

- Windows packaging path is documented and exercised
- example report paths are stable

## Test plan

The implementation must create and maintain the following test buckets:

### Baseline inherited regressions

- inherited regex detections still work after the port
- hard-trigger behavior remains intact
- UTF-16 and continuation normalization stay covered
- partial scan and skipped file accounting remain visible

### OpenClaw-aware parser and context tests

- malformed frontmatter is reported, not skipped
- `command-dispatch: tool` plus dangerous `command-tool` escalates risk
- `disable-model-invocation: true` plus `user-invocable: true` is treated as a visibility/deception signal, not a standalone block
- `primaryEnv`, `apiKey`, and `requires.env` feed secret reachability
- `metadata.openclaw.install` with remote download and no authenticity control escalates install risk

### False-positive regressions

- manual copy-paste shell snippets in docs score lower than auto-install metadata
- benign localhost/RPC control docs do not block
- legitimate subprocess or node-control documentation does not over-trigger
- recent official OpenClaw false-positive lessons remain covered

### Path and platform tests

- Windows path handling
- macOS and Linux path variants
- symlink handling
- nested directory traversal
- large directories
- weird encodings

### Attack-path regressions

- same-name workspace skill shadowing a trusted bundled skill is reported
- sandbox-only residual risk differs from host-path risk
- untrusted text -> tool use -> secret read -> network egress produces an attack path

Fixture policy:

- inert fixtures only
- no directly weaponizable payloads

## Risks

Major implementation risks:

- copied-rule drift from the upstream project
- overly aggressive compound scoring that inflates block verdicts
- parse brittleness around single-line OpenClaw metadata rules
- source precedence complexity across multiple workspace and home roots
- overfitting to a few recent OpenClaw fixes instead of modeling the underlying trust boundary

## Rollback and containment strategy

If an advanced analyzer is unstable:

- baseline scanning must remain runnable independently
- unstable OpenClaw-aware analyzers may degrade to warning-only
- report output must preserve scan-integrity notes and analyzer failure notes
- no unstable analyzer may suppress a direct high-confidence baseline hard trigger

Containment strategy by layer:

- baseline inventory and pattern rules are the minimum reliable core
- OpenClaw-aware analyzers attach additional findings and context without becoming a single point of failure
- report rendering failure must not block JSON output

## Phase 3 start order

Phase 3 should begin with the following exact sequence:

1. add `core`, `cli`, and `report` crate manifests and workspace membership
2. implement stable shared types in `core`
3. port inherited normalization and file inventory
4. port inherited pattern-rule execution and hard-trigger handling
5. add minimal CLI scan support for single file and directory with JSON output
6. port inherited inert fixtures and make CI pass

## Definition of “Phase 3 ready”

Phase 3 is unblocked when:

- there are no unresolved architecture questions about crate boundaries
- stable report fields are locked
- the inheritance/wrap/rewrite decisions are documented
- the kickoff order is explicit
- target directories and minimal skeleton files exist so implementation can begin without reshaping the repository

