# Release-Ready Self-Check

Date: 2026-04-23

## Scope

This document captures the `v1.0.0-rc1` release-readiness pass for Standalone OpenClaw Skill Guard. It is intentionally focused on publication readiness for a CLI-first verifier release, not on opening a new feature phase.

## Product posture confirmed

- project positioning is consistent as an OpenClaw-aware skill verifier
- primary delivery is a Rust CLI, with a documented Windows EXE path
- canonical output remains the v1 JSON report
- runtime refinement remains guarded, non-executing, and evidence-preserving
- the tool is presented as a verifier, not an exploit runner

## Checks performed

### 1. Root tests

- Command:
  - `cargo test`
- Result:
  - passed

### 2. CLI help and common usage

- Verified:
  - top-level help
  - `scan --help`
  - canonical JSON output mode
  - suppression file option
  - runtime manifest option
  - validation mode option
  - Windows release EXE invocation
- Result:
  - help text is consistent and usable for v1 demos and release documentation

### 3. Demo commands

Verified demo commands from [demo-commands.md](../examples/demo-commands.md):

- benign sample
- high-risk sample
- install-risk sample
- prompt-risk sample
- precedence-shadowing sample
- runtime-refinement sample
- suppression-audit sample

All commands produced JSON output successfully.

### 3.1 Smoke scan review

- Reviewed representative samples across:
  - benign
  - obvious high-risk
  - install-risk
  - prompt-risk
  - precedence or shadowing hint
  - runtime refinement
  - suppression or audit
- Result:
  - one release-facing false positive was found in the benign sample
  - it was fixed before release by suppressing clearly negated indirect, tool, and secret directives in the prompt analyzer
  - no remaining publication blocker was found in the smoke-scan pass

### 3.2 Windows EXE delivery

- Verified:
  - `cargo build --release`
  - `target\release\openclaw-skill-guard.exe`
  - benign sample via EXE
  - risky sample via EXE
- Result:
  - Windows EXE delivery path is working for the current release candidate

### 4. Canonical report output

Checked that example outputs include the expected v1 sections:

- `findings`
- `context_analysis`
- `attack_paths`
- `scoring_summary`
- `consequence_summary`
- runtime validation fields
- guarded validation fields
- suppression and audit fields
- `analysis_limitations`

### 5. Schema and output consistency

- `report.schema.json` matches the current runtime-validation-era `ScanReport`
- renderer test passes
- example outputs deserialize as valid JSON and contain the expected top-level fields

### 6. Docs consistency

Reviewed and updated release-facing wording in:

- [README.md](../README.md)
- [README.zh-CN.md](../README.zh-CN.md)
- [CHANGELOG.md](../CHANGELOG.md)
- [packaging.md](./packaging.md)
- [github-release-kit.md](./github-release-kit.md)
- release-facing technical references:
  - [runtime-manifest.md](./runtime-manifest.md)
  - [validation-adapter.md](./validation-adapter.md)
  - [reporting.md](./reporting.md)

## Current blockers

No release-text blocker or release-validation blocker was found during this pass.

## Known non-blocking limits

- runtime validation is guarded and non-executing
- precedence truth remains scope-dependent rather than globally complete
- reputation, signing, SBOM, and AI-BOM are not part of `v1.0.0-rc1`
- no GUI release surface is being shipped in this release candidate

## Recommendation

The repository is in deliverable shape for a Windows-friendly `v1.0.0-rc1` CLI release and the publication copy is ready for direct GitHub use.
