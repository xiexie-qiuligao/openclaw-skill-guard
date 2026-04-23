# openclaw-skill-guard

[中文说明](./README.zh-CN.md)

**面向 OpenClaw Skills 的安全验证器。**

`openclaw-skill-guard` 是一个面向 Windows 交付的 Rust verifier，用于在发布或审查前扫描 `SKILL.md`、skill 目录、skills 根目录或更大工作区。它不是通用漏洞扫描器，也不是 exploit runner；它的目标是基于可见证据回答一个更实际的问题：这个 skill 在 OpenClaw 语境下是否可能形成真实攻击路径，以及结论背后的证据是什么。

**OpenClaw-aware verifier for security review of OpenClaw Skills.**

`openclaw-skill-guard` is a Windows-friendly Rust project for verifying OpenClaw Skills before release or review. It scans `SKILL.md`, skill directories, skills roots, and broader workspaces to answer a practical question: under visible OpenClaw runtime conditions, can a skill plausibly become a real attack path, and what evidence supports that conclusion?

This project is not a generic scanner and not an exploit runner. It combines baseline scanning, structured context analysis, frontmatter and `metadata.openclaw` parsing, install-chain and invocation-policy analysis, tool and secret reachability, precedence and shadowing analysis, prompt and instruction analysis, attack-path reasoning, compound scoring, host-vs-sandbox consequence modeling, guarded runtime validation, and suppression with audit visibility.

## Delivery surfaces

`openclaw-skill-guard` now ships with two Windows-friendly entry points:

- GUI
  - the primary desktop product surface for target selection, scan execution, result review, and JSON export
- CLI
  - the automation and advanced-user entry point for pipelines and canonical output

The canonical public output remains the JSON report. The GUI does not replace the verifier logic; it reuses the same core scanning and report pipeline as the CLI.

## What it does

- baseline dangerous-pattern scanning
- structured OpenClaw context extraction
- frontmatter parsing
- `metadata.openclaw` normalization and parsing
- install-chain analysis
- dependency audit
- invocation-policy analysis
- tool reachability
- secret reachability
- URL and API classification
- source and domain reputation hints
- precedence and shadowing analysis
- prompt and instruction analysis
- attack-path reasoning
- compound scoring
- host-vs-sandbox consequence modeling
- guarded runtime validation
- suppression and audit support

## Quick start

### Build both release executables

```powershell
cargo build --release -p openclaw-skill-guard-cli -p openclaw-skill-guard-gui
```

### Windows executables

```text
target\release\openclaw-skill-guard.exe
target\release\openclaw-skill-guard-gui.exe
```

### CLI usage

Show help:

```powershell
cargo run -p openclaw-skill-guard-cli -- --help
```

Scan a benign sample:

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\benign\SKILL.md --format json
```

Scan a risky sample:

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\prompt-risk\SKILL.md --format json
```

Export derived SARIF from the canonical report pipeline:

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v2\suspicious-sources\SKILL.md --format sarif
```

Use runtime validation inputs:

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v1\runtime-refinement\SKILL.md --format json --runtime-manifest .\fixtures\v1\runtime-refinement\runtime-sandbox.json --validation-mode guarded
```

Run the release CLI EXE directly:

```powershell
.\target\release\openclaw-skill-guard.exe scan .\fixtures\v1\benign\SKILL.md --format json
```

### GUI usage

Run the GUI from Cargo:

```powershell
cargo run -p openclaw-skill-guard-gui
```

Run the release GUI EXE directly:

```powershell
.\target\release\openclaw-skill-guard-gui.exe
```

Minimal GUI workflow:

1. Choose a `SKILL.md` file or a directory.
2. Start the scan from the main action area.
3. Expand advanced options only if you need runtime manifest, suppression, or guarded validation inputs.
4. Review the Overview page first for verdict, score, key risks, environment conclusions, and v2 summaries.
5. Drill into Findings, Paths, Context, Validation, Audit, and Raw JSON as needed.
6. Save the canonical JSON report.

## GUI product shape

The GUI is now shaped as the primary product surface instead of a thin CLI configuration shell. It supports:

- Chinese-first desktop flow
- target selection for a single `SKILL.md`, skill directory, skills root, or workspace
- a simplified main scan path with collapsible advanced options
- scan execution without freezing the whole window
- an overview-first results home with verdict, score, key risks, and environment conclusions
- findings, context, attack path, validation, audit, and raw JSON views
- lightweight in-page filtering for findings and attack paths
- basic cross-linking between findings, paths, and provenance-oriented audit notes
- clear display of v2 summaries for threat corpus, sensitive corpus, dependency audit, API classification, and source reputation
- JSON, SARIF, Markdown, and HTML export from the same canonical report pipeline

It does not introduce a second analysis engine or a different report contract.

## GUI screenshots

Representative GUI screenshots are included under `docs/gui-screenshots/`:

- `gui-home-empty.png`
- `gui-overview-demo.png`
- `gui-validation-demo.png`

## Canonical output

JSON is the canonical v2 report format. SARIF, Markdown, and HTML are available as derived exports from the same `ScanReport`.

Key sections include:

- `findings`
- `context_analysis`
- `attack_paths`
- `corpus_assets_used`
- `dependency_audit_summary`
- `api_classification_summary`
- `source_reputation_summary`
- `external_references`
- `scoring_summary`
- `consequence_summary`
- `validation_*`
- `guarded_validation`
- `provenance_notes` and `confidence_notes`
- `suppression_matches` and `audit_summary`
- `analysis_limitations`

More detail is available in:

- [report.schema.json](./schemas/report.schema.json)
- [reporting.md](./docs/reporting.md)
- [runtime-manifest.md](./docs/runtime-manifest.md)
- [validation-adapter.md](./docs/validation-adapter.md)
- [examples/reports/README.md](./examples/reports/README.md)

Example derived reports for the inert v2 demo fixture are included under:

- `examples/reports/v2-report-demo.json`
- `examples/reports/v2-report-demo.sarif`
- `examples/reports/v2-report-demo.md`
- `examples/reports/v2-report-demo.html`

## Packaging and release docs

- [packaging.md](./docs/packaging.md)
- [release-ready.md](./docs/release-ready.md)
- [CHANGELOG.md](./CHANGELOG.md)
- [examples/demo-commands.md](./examples/demo-commands.md)

## Safety boundary

`openclaw-skill-guard` is a verifier, not an exploit runner.

- It does not intentionally execute dangerous payloads.
- Runtime validation is guarded and non-executing.
- The CLI and GUI both use the same evidence-driven scanning core.
- Suppression handling remains auditable rather than hiding risk silently.

## Current release position

The project is in final deliverable shape for a Windows-friendly release with both CLI and GUI entry points:

- desktop GUI as the main product surface
- CLI retained for automation and advanced workflows
- canonical JSON report contract
- Windows EXE delivery path for both executables
- root-level tests in place
