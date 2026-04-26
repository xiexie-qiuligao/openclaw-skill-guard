# openclaw-skill-guard

[中文说明](./README.zh-CN.md)

## 中文介绍

**面向 OpenClaw Skills 的安全验证器。**

`openclaw-skill-guard` 是一个面向 Windows 交付的 Rust verifier，用于在发布或审查前扫描 `SKILL.md`、skill 目录、skills 根目录或更大的工作区。它不是通用漏洞扫描器，也不是 exploit runner；它的目标是基于可见证据回答一个更实际的问题：这个 skill 在 OpenClaw 语境下是否可能形成真实攻击路径，以及结论背后的证据是什么。

GUI 是主要产品入口，适合日常审查、结果阅读和报告导出。CLI 保留为自动化、流水线和高级用户入口。两者复用同一条 Rust core 扫描链和同一份 canonical report。

v3 继续保持 verifier / guard 边界，只补 OpenClaw 本体特性相关缺口：config / control-plane audit、capability / permission manifest、companion-document 间接指令审计，以及离线 source identity / mismatch signals。

## English Summary

**OpenClaw-aware verifier for security review of OpenClaw Skills.**

`openclaw-skill-guard` is a Windows-friendly Rust project for verifying OpenClaw Skills before release or review. It scans `SKILL.md`, skill directories, skills roots, and broader workspaces to answer a practical question: under visible OpenClaw runtime conditions, can a skill plausibly become a real attack path, and what evidence supports that conclusion?

The GUI is the primary desktop product surface for target selection, scan execution, result review, and export. The CLI remains the automation and advanced-user entry point. Both surfaces reuse the same core scanner and canonical report pipeline.

The v3 layer stays inside the same verifier boundary and adds OpenClaw-specific coverage for config/control-plane audit, capability manifest summaries, companion-document indirect-instruction review, and offline source-identity mismatch signals.

## Current Capabilities

- baseline dangerous-pattern scanning
- structured OpenClaw context extraction
- frontmatter and `metadata.openclaw` parsing
- install-chain analysis
- dependency audit
- invocation-policy analysis
- tool and secret reachability
- URL / API classification
- source and domain reputation hints
- OpenClaw config / control-plane audit
- capability / permission manifest
- companion-document / indirect-instruction audit
- offline source identity / mismatch signals
- prompt / instruction analysis
- corpus-backed threat and sensitive analyzers
- attack-path reasoning and compound scoring
- host-vs-sandbox consequence modeling
- guarded runtime validation
- suppression and audit support
- canonical JSON report
- SARIF / Markdown / HTML derived outputs

## Quick Start

Build both release executables:

```powershell
cargo build --release -p openclaw-skill-guard-cli -p openclaw-skill-guard-gui
```

Windows executables:

```text
target\release\openclaw-skill-guard-gui.exe
target\release\openclaw-skill-guard.exe
```

Run the GUI:

```powershell
cargo run -p openclaw-skill-guard-gui
```

Run the release GUI EXE:

```powershell
.\target\release\openclaw-skill-guard-gui.exe
```

Run a CLI scan:

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v2\report-demo --format json
```

Export derived formats:

```powershell
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v2\report-demo --format sarif
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v2\report-demo --format markdown
cargo run -p openclaw-skill-guard-cli -- scan .\fixtures\v2\report-demo --format html
```

## GUI Product Shape

The GUI is now shaped as the primary product surface instead of a thin CLI configuration shell. It supports:

- Chinese-first desktop flow
- target selection for a single `SKILL.md`, skill directory, skills root, or workspace
- a simplified main scan path with collapsible advanced options
- overview-first results with verdict, score, key risks, and environment conclusions
- Findings, Paths, Context, Validation, Audit, and Raw JSON views
- lightweight filtering for findings, paths, and external references
- basic cross-linking between findings, paths, and provenance-oriented audit notes
- readable v2 / v3 summaries for corpus, dependency, API/source, config/control-plane, capability, companion-doc, and source-identity signals
- JSON, SARIF, Markdown, and HTML export from the same canonical report pipeline

Representative GUI screenshots are included under `docs/gui-screenshots/`:

- `gui-home-empty.png`
- `gui-overview-demo.png`
- `gui-validation-demo.png`

## Canonical Report

JSON is the canonical report format. SARIF, Markdown, and HTML are derived exports from the same `ScanReport`, not a second report protocol.

Key sections include:

- `findings`
- `context_analysis`
- `attack_paths`
- `corpus_assets_used`
- `dependency_audit_summary`
- `api_classification_summary`
- `source_reputation_summary`
- `external_references`
- `openclaw_config_audit_summary`
- `capability_manifest`
- `companion_doc_audit_summary`
- `source_identity_summary`
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

Example v2 and v3 reports are included under `examples/reports/`, including canonical JSON, SARIF, Markdown, and HTML variants.

## Packaging And Release Docs

- [packaging.md](./docs/packaging.md)
- [release-ready.md](./docs/release-ready.md)
- [CHANGELOG.md](./CHANGELOG.md)
- [demo-commands.md](./examples/demo-commands.md)

## Safety Boundary

`openclaw-skill-guard` is a verifier, not an exploit runner.

- It does not intentionally execute dangerous payloads.
- Runtime validation is guarded and non-executing.
- Local reputation and source-identity signals are explainable hints, not an online trust oracle.
- The CLI and GUI both use the same evidence-driven scanning core.
- Suppression handling remains auditable rather than hiding risk silently.

## Current Release Position

The project is in final deliverable shape for a Windows-friendly release with:

- desktop GUI as the main product surface
- CLI retained for automation and advanced workflows
- canonical JSON report contract with SARIF / Markdown / HTML derived exports
- Windows EXE delivery path for both executables
- v3 OpenClaw-specific config, capability, companion-doc, and source-identity coverage
- root-level tests in place
