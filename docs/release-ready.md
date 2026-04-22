# Release-Ready Self-Check

Date: 2026-04-22

## Scope

This document captures the v1 release-candidate self-check. It is intentionally focused on release readiness, not on starting a new feature phase.

## Checks performed

### 1. Root tests

- Command:
  - `C:\Users\29345\.cargo\bin\cargo.exe test`
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
- Result:
  - help text is consistent and usable for v1 demos

### 3. Demo commands

Verified demo commands from [demo-commands.md](D:/漏扫skill/standalone-openclaw-skill-guard/examples/demo-commands.md):

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
  - precedence/shadowing hint
  - runtime refinement
  - suppression/audit
- Result:
  - one release-facing false positive was found in the benign sample
  - it was fixed before release by suppressing clearly negated indirect/tool/secret directives in the prompt analyzer
  - no remaining release blocker was found in the smoke-scan pass

### 4. Canonical report output

Checked that example outputs include the expected v1 sections:

- `findings`
- `context_analysis`
- `attack_paths`
- `scoring_summary`
- `consequence_summary`
- runtime validation fields
- suppression and audit fields
- `analysis_limitations`

### 5. Schema and output consistency

- `report.schema.json` was updated to match the current runtime-validation-era `ScanReport`
- renderer test passes
- example outputs deserialize as valid JSON and contain the expected top-level fields

### 6. Docs consistency

Reviewed and updated:

- [README.md](D:/漏扫skill/standalone-openclaw-skill-guard/README.md)
- [design.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/design.md)
- [rule-catalog.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/rule-catalog.md)
- [validation-hooks.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/validation-hooks.md)
- [runtime-consequences.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/runtime-consequences.md)
- [suppression-audit.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/suppression-audit.md)
- [runtime-manifest.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/runtime-manifest.md)
- [validation-adapter.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/validation-adapter.md)
- [reporting.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/reporting.md)

## Current blockers

No release blocker was found during this pass.

## Known non-blocking limits

- runtime validation is guarded and non-executing
- global precedence truth remains scope-dependent
- reputation, signing, SBOM, and AI-BOM are not part of v1
- no GUI release surface is being shipped in this v1 candidate

## Recommendation

The repository is in release-candidate shape for a v1 CLI-first release.
