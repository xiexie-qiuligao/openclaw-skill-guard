# Changelog

## v2.0.0 - 2026-04-23

Final deliverable release for `openclaw-skill-guard`, shipped as a Windows-friendly OpenClaw-aware verifier with a primary desktop GUI and an auxiliary CLI for automation.

### Included in this release

- baseline dangerous-pattern scanner
- structured `SKILL.md` and `metadata.openclaw` parsing
- install-chain, invocation-policy, tool-reachability, secret-reachability, and precedence analysis
- prompt and instruction analysis
- attack-path construction and compound scoring
- host-vs-sandbox consequence modeling
- runtime manifest ingestion and guarded runtime refinement
- provenance, confidence, and false-positive shaping
- suppression and audit workflow
- corpus-backed threat analyzer
- corpus-backed sensitive analyzer
- dependency audit
- URL and API classification
- source and domain reputation hints
- canonical JSON report schema
- SARIF, Markdown, and HTML derived outputs
- overview-first Chinese GUI product surface with deep result reading
- Windows GUI EXE and CLI EXE delivery path
- inert fixtures, example reports, and GUI showcase materials

### GUI delivery highlights

- Chinese-first desktop workflow
- overview-first result homepage
- findings, paths, context, validation, audit, and raw JSON views
- finding/path/provenance linkage
- lightweight result filtering
- external reference and dependency drill-down reading
- in-GUI export for JSON, SARIF, Markdown, and HTML

### Current limits

- runtime validation is guarded and non-executing
- local reputation hints are explainable but not an online truth source
- no exploit execution, dynamic malware sandboxing, or online CVE service
- JSON remains the canonical contract; derived formats are convenience outputs

### Final positioning

- GUI is the primary user-facing product surface
- CLI remains the automation and advanced-user entry point
- both executables reuse the same verifier core
- the project stays within verifier / guard boundaries rather than becoming an exploit runner
