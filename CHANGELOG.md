# Changelog

## v3.0.0 - 2026-04-24

Final v3 deliverable release for `openclaw-skill-guard`, keeping the same verifier core while adding OpenClaw-specific control-plane, capability, companion-document, and source-identity coverage.

### Added in v3

- OpenClaw config / control-plane audit for `skills.entries.*.env`, `apiKey`, risky env binding, `extraDirs`, sandbox-disabled, elevated/unsafe, and config-mutation signals
- capability / permission manifest with declared, inferred, required, risky-combination, incomplete, and mismatch narratives
- companion-document / indirect-instruction audit for README, docs, examples, setup, and walkthrough files distributed with a skill
- offline source identity mismatch signals across homepage, repository, install source, package metadata, and officialness narratives
- targeted inert v3 fixtures and regression coverage for config, capability, companion-doc, source-identity, and false-positive cases
- canonical report sections for `openclaw_config_audit_summary`, `capability_manifest`, `companion_doc_audit_summary`, and `source_identity_summary`
- GUI reading polish for v3 summaries and details without changing the product layout
- Markdown and HTML report rendering now surfaces v3 OpenClaw summaries and details derived from the canonical report

### Final positioning

- GUI remains the primary desktop product surface
- CLI remains the automation and advanced-user entry point
- JSON remains the canonical report contract; SARIF, Markdown, and HTML remain derived outputs
- runtime validation remains guarded and non-executing
- no online reputation platform, cloud judgment service, exploit runner, or dynamic malware sandbox is included

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
