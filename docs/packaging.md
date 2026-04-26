# Packaging Notes

`openclaw-skill-guard` ships with two Windows-friendly executables:

- GUI EXE
  - primary desktop product surface
  - `target\release\openclaw-skill-guard-gui.exe`
- CLI EXE
  - automation and advanced-user entry point
  - `target\release\openclaw-skill-guard.exe`

Both executables front the same verifier core and the same canonical report pipeline.
The v3 release keeps that contract intact while adding OpenClaw-specific config/control-plane, capability, companion-document, and source-identity review.

## Build both executables

```powershell
cargo build --release -p openclaw-skill-guard-cli -p openclaw-skill-guard-gui
```

## GUI EXE usage

Launch the desktop app:

```powershell
.\target\release\openclaw-skill-guard-gui.exe
```

Minimal startup smoke validation:

```powershell
.\target\release\openclaw-skill-guard-gui.exe --smoke-test
```

Best for:

- day-to-day desktop review
- guided target selection and scan execution
- overview-first result reading
- findings, paths, validation, and audit review
- exporting JSON, SARIF, Markdown, and HTML from the GUI

## CLI EXE usage

Show help:

```powershell
.\target\release\openclaw-skill-guard.exe --help
```

Scan a benign sample:

```powershell
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v1\benign\SKILL.md --format json
```

Best for:

- automation
- CI or review pipelines
- direct canonical JSON consumption
- scripted validation workflows
- reproducible export generation

## Files worth shipping

- `openclaw-skill-guard-gui.exe`
- `openclaw-skill-guard.exe`
- `README.md`
- `README.zh-CN.md`
- `CHANGELOG.md`
- `schemas/report.schema.json`
- `docs/packaging.md`
- `docs/release-ready.md`
- optional demo and support materials:
  - `examples/`
  - `fixtures/`
  - `docs/reporting.md`
  - `docs/runtime-manifest.md`
  - `docs/validation-adapter.md`
  - `docs/gui-screenshots/`

## Packaging intent

The release bundle should remain:

- clear about GUI as the primary product entry point
- explicit about CLI as the auxiliary automation surface
- safe to hand over without local-only artifacts
- complete enough to explain the canonical JSON report contract
- explicit about the v3 OpenClaw-specific summaries included in that report contract
- Windows-friendly for both desktop and terminal usage

## What this package is not

- not an exploit runner
- not a dynamic malware sandbox
- not an online reputation service
- not a second report protocol

JSON remains the canonical report contract. SARIF, Markdown, and HTML remain derived outputs from the same `ScanReport`.
The v3-specific sections are `openclaw_config_audit_summary`, `capability_manifest`, `companion_doc_audit_summary`, and `source_identity_summary`.
