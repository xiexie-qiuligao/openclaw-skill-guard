# Release-Ready Self-Check

Date: 2026-04-24

## Scope

This document captures the final release-readiness pass for `openclaw-skill-guard` as a Windows-friendly deliverable with both GUI and CLI entry points. The goal of this pass is final packaging, validation, and submission readiness.

## Final product shape

- GUI is the primary product surface for target selection, scan execution, result review, and export.
- CLI remains available for automation, pipelines, and advanced-user workflows.
- Both surfaces reuse the same core scanning and reporting logic.
- JSON remains the canonical report contract.
- SARIF, Markdown, and HTML remain derived exports from the same `ScanReport`.
- v3 adds OpenClaw-specific config/control-plane, capability manifest, companion-document, and source-identity coverage without changing the verifier boundary.

## Checks performed

### 1. Root tests

- Command:
  - `cargo test`
- Result:
  - passed

### 2. GUI product path

- Verified:
  - GUI crate tests
  - GUI startup smoke validation
  - benign sample scan through the GUI pipeline
  - risky sample scan through the GUI pipeline
  - GUI export coverage for JSON, SARIF, Markdown, and HTML
- Result:
  - GUI delivery path is ready for Windows handoff

### 3. CLI executable path

- Verified:
  - release build for CLI binary
  - release executable naming and path
  - minimal CLI invocation
- Result:
  - CLI delivery path is ready for automation and Windows handoff

### 4. GUI executable path

- Verified:
  - release build for GUI binary
  - release executable naming and path
  - minimal GUI startup
- Result:
  - GUI delivery path is ready as the primary desktop entry point

### 5. Report contract and UX consistency

- Verified:
  - CLI still emits canonical JSON output
  - GUI exposes summary, findings, context, paths, validation, audit, and raw JSON views
  - GUI exposes v3 config/control-plane, capability, companion-doc, and source-identity summaries in the result reading flow
  - GUI can export JSON, SARIF, Markdown, and HTML from the same report pipeline
  - canonical JSON, SARIF, Markdown, and HTML example reports include the current v3 report sections
- Result:
  - CLI and GUI remain consistent with the same report contract

### 6. Documentation consistency

Reviewed and updated:

- [README.md](../README.md)
- [README.zh-CN.md](../README.zh-CN.md)
- [packaging.md](./packaging.md)
- [CHANGELOG.md](../CHANGELOG.md)
- [demo-commands.md](../examples/demo-commands.md)

### 7. Showcase materials

Prepared:

- GUI screenshots under [docs/gui-screenshots/](./gui-screenshots/)
- sanitized example reports under [examples/reports/](../examples/reports/)

## Current blockers

No release blocker was found during this final pass.

## Known intentional limits

- the GUI remains a product surface over the existing verifier core, not a second analysis engine
- runtime validation remains guarded and non-executing
- the canonical public contract remains the JSON report
- no online service layer, exploit execution, or plugin marketplace workflow is included in this release
- v3 source identity and reputation signals are offline, explainable hints rather than an online trust oracle

## Recommendation

`openclaw-skill-guard` is ready for final submission as a Windows-friendly release with:

- a desktop GUI as the main product surface
- a CLI EXE for automation and advanced workflows
- a canonical JSON report contract with derived export formats
- OpenClaw-aware v3 coverage for control-plane config, capability mismatch, companion-doc poisoning, and source identity mismatch
- consistent docs, screenshots, and packaging guidance
- root-level tests in passing state
