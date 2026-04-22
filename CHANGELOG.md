# Changelog

## v1.0.0-rc1 - 2026-04-22

First release candidate for the standalone OpenClaw-aware skill verifier.

### Included in this release

- baseline dangerous-pattern scanner
- structured `SKILL.md` and `metadata.openclaw` parsing
- install-chain, invocation-policy, tool-reachability, secret-reachability, and precedence analysis
- instruction extraction and first-pass prompt injection / indirect instruction analysis
- attack-path construction and compound scoring
- host-vs-sandbox consequence modeling
- runtime manifest ingestion and guarded runtime refinement
- provenance, confidence, false-positive shaping
- suppression and audit workflow
- canonical JSON report schema
- demo fixtures and example reports

### Current limits

- runtime validation is guarded and non-executing
- precedence remains scope-aware rather than globally omniscient
- no reputation, signing, SBOM, or AI-BOM integration
- CLI-first release; no GUI release surface in rc1

### Near-term follow-up candidates

- sandbox-backed validation adapters
- richer OpenClaw runtime permission ingestion
- deeper false-positive shaping for delegated local workflows
