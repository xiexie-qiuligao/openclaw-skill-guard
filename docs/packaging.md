# Packaging Notes

Standalone OpenClaw Skill Guard ships as a CLI-first Rust application. For Windows users, the primary release artifact is:

```text
target\release\openclaw-skill-guard.exe
```

The packaging goal is simple: deliver a usable verifier binary together with enough documentation to explain the JSON report contract, the guarded runtime-validation model, and the current release limits.

## Build the release executable

```powershell
cargo build --release
```

## Minimal Windows EXE usage

```powershell
.\target\release\openclaw-skill-guard.exe --help
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v1\benign\SKILL.md --format json
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v1\prompt-risk\SKILL.md --format json
```

## Core runtime flags

- `scan <path>`
- `--format json`
- `--runtime-manifest <file>`
- `--validation-mode planned|guarded`
- `--suppressions <file>`

## Files worth shipping with a release

- `openclaw-skill-guard.exe`
- `README.md`
- `README.zh-CN.md`
- `LICENSE`
- `CHANGELOG.md`
- `schemas/report.schema.json`
- `docs/packaging.md`
- `docs/release-ready.md`
- `docs/github-release-kit.md`
- optional demo and support materials:
  - `examples/`
  - `fixtures/`
  - `docs/reporting.md`
  - `docs/runtime-manifest.md`
  - `docs/validation-adapter.md`

## Files not worth shipping in a release bundle

- `target/debug/`
- incremental build caches
- editor-specific metadata
- local logs or temporary output
- private or local-only scan output generated outside the repository

## Packaging posture

The release bundle should remain:

- small enough to hand over easily
- complete enough to explain the verifier posture and report contract
- safe enough that no local machine paths, usernames, or private runtime traces leak into shipped artifacts

## What this release bundle is not

- not a GUI package
- not a dynamic malware sandbox
- not an exploit execution environment
- not a promise of globally complete runtime truth

The artifact is a `v1.0.0-rc1` release-candidate verifier bundle for CLI use, JSON reporting, and Windows-friendly distribution.
