# Changelog

## v1.0.0-rc1 - 2026-04-23

First release candidate for Standalone OpenClaw Skill Guard, a CLI-first OpenClaw-aware skill verifier with canonical JSON reporting and guarded runtime validation.

### Included in this release

- baseline dangerous-pattern scanning for OpenClaw skill review
- structured `SKILL.md` and `metadata.openclaw` parsing
- install-chain, invocation-policy, tool-reachability, secret-reachability, and precedence analysis
- instruction extraction and prompt injection or indirect instruction analysis
- attack-path construction, compound scoring, and consequence modeling
- runtime manifest ingestion and guarded runtime refinement
- sandbox-backed guarded validator checks for capability presence, environment scope, and path prerequisites
- provenance notes, confidence shaping, false-positive handling, suppression matching, and audit output
- canonical JSON report schema for CLI and release workflows
- demo fixtures, example reports, and Windows EXE delivery path

### Release posture

- CLI-first delivery for v1
- canonical JSON as the public report contract
- verifier posture rather than payload execution
- guarded runtime validation to refine reachability and consequence without running untrusted content

### Current limits

- runtime validation is guarded and non-executing
- precedence remains scope-aware rather than globally omniscient
- reputation, signing, SBOM, and AI-BOM integration are out of scope for rc1
- no GUI release surface is shipped in this release candidate

### Notes

- release-facing copy and GitHub publication materials are prepared under `README*` and `docs/github-release-kit.md`
- root-level `cargo test` passed for the current release candidate
