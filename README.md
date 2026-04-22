# Standalone OpenClaw Skill Guard

Standalone OpenClaw Skill Guard is a Windows-friendly, Rust-based **OpenClaw-aware skill verifier**. It is designed to scan `SKILL.md`, skill directories, skills roots, and broader workspaces, then explain whether a skill can form a realistic attack path in current OpenClaw runtime conditions.

This is **not** a generic markdown linter and **not** a pure regex scanner. It combines:

- baseline dangerous-pattern scanning
- structured `SKILL.md` and `metadata.openclaw` parsing
- install / invocation / reachability / precedence analysis
- instruction and prompt-risk analysis
- attack-path and compound scoring
- host-vs-sandbox consequence modeling
- runtime-manifest-aware guarded validation
- provenance, confidence, false-positive shaping
- suppression and audit reporting

## Why this is OpenClaw-aware

The verifier reasons about OpenClaw-specific semantics that a generic scanner would miss:

- `metadata.openclaw`
- `command-dispatch` and direct tool authority
- `disable-model-invocation` and `user-invocable`
- install-path versus installer-path asymmetry
- tool reachability and secret reachability
- precedence, shadowing, and trusted-name collisions
- runtime permission and environment constraints

In practice, the tool answers a stronger question than "does this file contain something suspicious?" It asks: **can this skill plausibly turn into a real attack chain inside OpenClaw?**

## Core capabilities

- Baseline scanning
  - stable dangerous-pattern rules inherited from the original upstream research baseline
- Structured context
  - frontmatter parsing
  - `metadata.openclaw` normalization
  - invocation-policy analysis
- Install / invocation / reachability / precedence
  - install-chain extraction
  - tool reachability
  - secret reachability
  - precedence and shadowing analysis
- Prompt / instruction analysis
  - instruction extraction
  - prompt injection
  - indirect instruction
  - tool and secret coercion
- Attack path and scoring
  - toxic-flow paths
  - compound risk rules
  - path-aware scoring and verdicts
- Consequence and validation
  - host-vs-sandbox consequence modeling
  - guarded validation hooks
  - runtime manifest ingestion
  - controlled runtime refinement
- Suppression and audit
  - minimal-scope suppression
  - audit visibility
  - suppression lifecycle
  - validation-aware audit notes

## Quick start

### Build

```powershell
cd D:\漏扫skill\standalone-openclaw-skill-guard
C:\Users\29345\.cargo\bin\cargo.exe build
```

### Show CLI help

```powershell
C:\Users\29345\.cargo\bin\cargo.exe run -p openclaw-skill-guard-cli -- --help
```

### Scan a single `SKILL.md`

```powershell
C:\Users\29345\.cargo\bin\cargo.exe run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\prompt-risk\SKILL.md --format json
```

### Scan a skill directory

```powershell
C:\Users\29345\.cargo\bin\cargo.exe run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\install-risk --format json
```

### Use a runtime manifest

```powershell
C:\Users\29345\.cargo\bin\cargo.exe run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\runtime-refinement\SKILL.md --format json --runtime-manifest .\fixtures\v1\runtime-refinement\runtime-sandbox.json --validation-mode guarded
```

### Use a suppression file

```powershell
C:\Users\29345\.cargo\bin\cargo.exe run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\suppression-audit\SKILL.md --format json --suppressions .\fixtures\v1\suppression-audit\suppressions.json
```

## Canonical output

`JSON` is the canonical v1 report format.

The main report sections are:

- `findings`
  - individual explainable issues with evidence and remediation
- `context_analysis`
  - structured OpenClaw context such as metadata, install chain, invocation, reachability, precedence, and prompt summaries
- `attack_paths`
  - realistic risk chains assembled from findings and context
- `scoring_summary`
  - base score, compound uplift, path uplift, confidence adjustment, final score
- `consequence_summary`
  - host vs sandbox impact model
- `validation_*`
  - validation plan, runtime facts, validation results, path validation status, runtime score adjustments
- `provenance_notes` and `confidence_notes`
  - why the scanner believes something, and where uncertainty remains
- `suppression_matches` and `audit_summary`
  - accepted exceptions without hiding evidence
- `analysis_limitations`
  - explicit scope or runtime gaps

More detail is in [report.schema.json](D:/漏扫skill/standalone-openclaw-skill-guard/schemas/report.schema.json) and [validation-adapter.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/validation-adapter.md).

## Demo assets

Release-candidate demo assets are included under:

- [fixtures/v1](D:/漏扫skill/standalone-openclaw-skill-guard/fixtures/v1)
- [examples/demo-commands.md](D:/漏扫skill/standalone-openclaw-skill-guard/examples/demo-commands.md)
- [examples/demo-samples.md](D:/漏扫skill/standalone-openclaw-skill-guard/examples/demo-samples.md)
- [examples/reports](D:/漏扫skill/standalone-openclaw-skill-guard/examples/reports)

These samples are inert and intended for demonstration, testing, and review only.

## Current limits

This v1 intentionally distinguishes between:

- static conclusions
  - what the repository content, metadata, and attack-path logic indicate
- runtime refinement
  - what a supplied runtime manifest or safe local checks can confirm, narrow, or block
- scope limitations
  - what remains incomplete because not all roots, runtime facts, or environment surfaces are visible

v1 deliberately does **not** do the following:

- execute install chains or payloads
- run arbitrary shell, PowerShell, or `child_process`
- fetch unknown remote content for validation
- provide a full global precedence truth graph
- integrate online reputation feeds
- implement signing, SBOM, or AI-BOM verification
- act as an exploit runner or dynamic malware sandbox

## Safety statement

This project is a **verifier**, not an exploit runner.

- It does not intentionally execute dangerous payloads.
- Runtime validation is guarded and controlled.
- The runtime adapter only performs manifest ingestion, safe local presence checks, scope validation, and consequence refinement.
- High-risk findings remain evidence-driven and auditable.

## Current v1 status

The project is now in release-candidate shape:

- core scanner is implemented
- CLI is stable for v1 usage
- schema and public report contract are documented
- examples and demo reports are included
- tests pass at the repository root

Release materials:

- [CHANGELOG.md](D:/漏扫skill/standalone-openclaw-skill-guard/CHANGELOG.md)
- [LICENSE](D:/漏扫skill/standalone-openclaw-skill-guard/LICENSE)
- [release-ready.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/release-ready.md)
- [smoke-scan-summary.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/smoke-scan-summary.md)

See [progress.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/progress.md) for the implementation trail and [design.md](D:/漏扫skill/standalone-openclaw-skill-guard/docs/design.md) for the final architecture record.
