# Standalone OpenClaw Skill Guard

[中文说明](./README.zh-CN.md)

**OpenClaw-aware skill verifier for CLI-first security review.**
**面向 OpenClaw Skill 生态的命令行安全验证器。**

Standalone OpenClaw Skill Guard is a Windows-friendly, Rust-based verifier that inspects `SKILL.md`, skill directories, skills roots, and broader workspaces. It is built for one concrete question: **can this skill plausibly become a real attack path under OpenClaw runtime conditions, and what evidence supports that conclusion?**

Unlike a generic scanner, it does not stop at keyword hits or markdown linting. It combines structured OpenClaw context, attack-path reasoning, consequence modeling, and guarded runtime validation so operators can judge whether a finding is realistically reachable, policy-relevant, and worth acting on.

OpenClaw-aware matters here because real risk is shaped by runtime semantics: `metadata.openclaw`, invocation policy, install-path asymmetry, tool and secret reachability, precedence and shadowing, permission boundaries, and sandbox constraints. This project exists to verify those runtime-shaped risks without turning the tool into an exploit runner.

## At a glance

- Purpose
  - verify whether an OpenClaw skill can form a realistic attack chain
- Positioning
  - CLI-first verifier, not a generic scanner and not a dynamic exploit harness
- Canonical output
  - JSON report with structured findings, context, attack paths, scoring, and audit notes
- Runtime awareness
  - uses guarded runtime validation and optional runtime manifests to refine reachability and consequence
- Delivery
  - Rust CLI with a documented Windows EXE release path

## Why this project exists

OpenClaw skills can look harmless in isolation yet become risky once install flow, invocation rules, tool authority, precedence behavior, and runtime permissions are considered together. A plain scanner can tell you that something suspicious appears in a file. This verifier aims to answer the more operational question: **does the repository content, plus visible OpenClaw context, support a believable attack path that should block release or require review?**

## Why it is not a generic scanner

The verifier reasons about OpenClaw-specific semantics that generic markdown or regex-driven tooling usually misses:

- `metadata.openclaw`
- `command-dispatch` and direct tool authority
- `disable-model-invocation` and `user-invocable`
- install-path versus installer-path asymmetry
- tool reachability and secret reachability
- precedence, shadowing, and trusted-name collisions
- runtime permission and environment constraints

It is designed to preserve technical credibility:

- CLI-first workflow
- canonical JSON report contract
- structured context extraction
- attack-path and compound-risk reasoning
- guarded runtime validation
- verifier posture rather than payload execution

## Core capabilities

- Baseline scanning
  - stable dangerous-pattern rules inherited from the original research baseline
- Structured OpenClaw context
  - `SKILL.md` frontmatter parsing
  - `metadata.openclaw` normalization
  - invocation-policy analysis
- Install, reachability, and precedence analysis
  - install-chain extraction
  - tool reachability
  - secret reachability
  - precedence and shadowing analysis
- Instruction and prompt-risk analysis
  - instruction extraction
  - prompt injection
  - indirect instruction
  - tool and secret coercion
- Attack-path reasoning
  - toxic-flow paths
  - compound risk rules
  - path-aware scoring and verdicts
- Runtime-aware refinement
  - host-vs-sandbox consequence modeling
  - runtime manifest ingestion
  - guarded validation hooks
  - sandbox-backed guarded validator checks
  - controlled runtime refinement
- Auditability
  - provenance notes
  - confidence shaping
  - suppression matching
  - audit reporting

## Quick start

### Build

```powershell
cargo build
```

### Build a Windows EXE

```powershell
cargo build --release
```

The release executable is:

```text
target\release\openclaw-skill-guard.exe
```

### Show CLI help

```powershell
cargo run -p openclaw-skill-guard-cli -- --help
```

### Scan a single `SKILL.md`

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\prompt-risk\SKILL.md --format json
```

### Scan a skill directory

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\install-risk --format json
```

### Use a runtime manifest

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\runtime-refinement\SKILL.md --format json --runtime-manifest .\fixtures\v1\runtime-refinement\runtime-sandbox.json --validation-mode guarded
```

### Use a suppression file

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\suppression-audit\SKILL.md --format json --suppressions .\fixtures\v1\suppression-audit\suppressions.json
```

### Run the Windows EXE directly

```powershell
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v1\benign\SKILL.md --format json
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v1\prompt-risk\SKILL.md --format json
```

## How to read the report

`JSON` is the canonical v1 report format.

The main report sections are:

- `findings`
  - explainable issues with evidence, severity, and remediation direction
- `context_analysis`
  - structured OpenClaw context such as metadata, install chain, invocation, reachability, precedence, and prompt summaries
- `attack_paths`
  - realistic risk chains assembled from findings and context
- `scoring_summary`
  - base score, compound uplift, path uplift, confidence adjustment, and final score
- `consequence_summary`
  - host-vs-sandbox consequence model
- `validation_*`
  - validation plan, runtime facts, validation results, path validation status, and runtime score adjustments
- `guarded_validation`
  - sandbox-backed capability and constraint checks used to refine path status without executing untrusted content
- `provenance_notes` and `confidence_notes`
  - why the verifier believes something, and where uncertainty remains
- `suppression_matches` and `audit_summary`
  - accepted exceptions without hiding evidence
- `analysis_limitations`
  - explicit scope or runtime gaps

More detail is in [report.schema.json](./schemas/report.schema.json), [runtime-manifest.md](./docs/runtime-manifest.md), [validation-adapter.md](./docs/validation-adapter.md), and [reporting.md](./docs/reporting.md).

## Windows EXE packaging

For release packaging details, see [packaging.md](./docs/packaging.md). The short version is:

- build with `cargo build --release`
- ship `target\release\openclaw-skill-guard.exe`
- keep `README.md`, `README.zh-CN.md`, `CHANGELOG.md`, `schemas/`, and key `docs/` files with the release if you want a self-explanatory handoff
- optionally include `examples/` and `fixtures/` for demos
- do not ship local build caches, debug artifacts, or editor-generated files

## Demo assets

Release-candidate demo assets are included under:

- [fixtures/v1](./fixtures/v1)
- [examples/demo-commands.md](./examples/demo-commands.md)
- [examples/demo-samples.md](./examples/demo-samples.md)
- [examples/reports](./examples/reports)

These samples are inert and intended for demonstration, testing, and review only.

## False-positive handling

The verifier does not rely on raw keyword matching alone. It also carries:

- provenance notes for where a conclusion came from
- confidence shaping for direct evidence versus inferred context
- guarded runtime refinement for capability and scope checks
- false-positive handling for localhost or RPC workflows, quoted examples, benign `child_process` references, and legitimate install guidance
- suppression and audit output when an operator intentionally narrows a result

## Current limits

This release intentionally distinguishes between:

- static conclusions
  - what the repository content, metadata, and attack-path logic indicate
- runtime refinement
  - what a supplied runtime manifest or safe local checks can confirm, narrow, or block
- guarded validation
  - what the sandbox-backed capability and scope checker can safely confirm without running untrusted content
- scope limitations
  - what remains incomplete because not all roots, runtime facts, or environment surfaces are visible

The current release deliberately does **not** do the following:

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
- The runtime adapter performs manifest ingestion, safe local presence checks, scope validation, and consequence refinement.
- High-risk findings remain evidence-driven and auditable.

## Release candidate status

The repository is in release-candidate shape for `v1.0.0-rc1`, a CLI-first Windows-friendly v1 delivery:

- core verifier is implemented
- CLI is stable for v1 usage
- schema and public report contract are documented
- examples and demo reports are included
- Windows release build and EXE entrypoint are documented
- root-level tests are green

Release-facing materials:

- [CHANGELOG.md](./CHANGELOG.md)
- [LICENSE](./LICENSE)
- [packaging.md](./docs/packaging.md)
- [release-ready.md](./docs/release-ready.md)
- [github-release-kit.md](./docs/github-release-kit.md)
- [smoke-scan-summary.md](./docs/smoke-scan-summary.md)

See [progress.md](./docs/progress.md) for the implementation trail and [design.md](./docs/design.md) for the final architecture record.
