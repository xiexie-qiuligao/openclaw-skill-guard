# Reporting

This document describes the canonical JSON report contract.

## Canonical contract

The canonical output is:

- [report.schema.json](../schemas/report.schema.json)

JSON is the source-of-truth contract. SARIF is now supported as a derived export and must remain mapped from the same `ScanReport`.

## Stable sections

These top-level sections are treated as stable for v1:

- `target`
- `scan_mode`
- `files_scanned`
- `files_skipped`
- `parse_errors`
- `score`
- `verdict`
- `blocked`
- `top_risks`
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
- `validation_plan`
- `validation_results`
- `audit_summary`
- `analysis_limitations`
- `recommendations`

## Scope-dependent or optional sections

These sections are still part of the contract, but their contents depend on scan scope or runtime inputs:

- `runtime_manifest_summary`
- `runtime_facts`
- `runtime_assumption_status`
- `path_validation_status`
- `runtime_refinement_notes`
- `constraint_effects`
- `environment_blockers`
- `environment_amplifiers`
- `validation_score_adjustments`
- `scope_resolution_summary`
- `suppression_matches`
- `confidence_notes`

## Intended semantics

- `findings`
  - atomic issues with direct evidence and remediation
- `context_analysis`
  - structured OpenClaw-aware summary
- `attack_paths`
  - chained risk narratives with evidence and inference
- `scoring_summary`
  - why the verdict moved
- `consequence_summary`
  - host/sandbox impact model
- `validation_*`
  - guarded runtime refinement outputs
- `corpus_assets_used`
  - which built-in v2 corpora contributed structured knowledge assets to the scan
- `dependency_audit_summary`
  - manifest discovery, lockfile gaps, and explainable dependency-source risk signals
- `api_classification_summary`, `source_reputation_summary`, and `external_references`
  - structured URL/API classification, local reputation hints, and extracted external reference narratives
- `provenance_notes` and `confidence_factors`
  - why the verifier trusts or discounts a conclusion
- `suppression_matches` and `audit_summary`
  - accepted exceptions without silent disappearance

## Derived formats

- `json`
  - canonical report contract and source of truth
- `sarif`
  - derived finding export for security tooling integrations
  - first version maps findings, severity, confidence, rule ids, messages, and file locations
  - it does not currently serialize attack-path graphs, runtime validation internals, or suppression audit history in full detail
- `markdown`
  - human-readable summary export derived from the same `ScanReport`
  - emphasizes summary, findings, context, validation/consequence, external references, and score/provenance
- `html`
  - minimal browser-friendly rendering of the derived Markdown view
  - keeps the canonical contract in JSON rather than introducing a second schema

## Example reports

The repository includes inert v2 demo reports under `examples/reports/`:

- `v2-report-demo.json`
- `v2-report-demo.sarif`
- `v2-report-demo.md`
- `v2-report-demo.html`

These files are intended to show the current v2 shape of:

- corpus-backed findings
- dependency/source/API summaries
- canonical JSON to SARIF derivation
- minimal Markdown and HTML delivery outputs

## Experimental posture

The following areas should be treated as evolving within the stable outer contract:

- exact wording of `summary` fields
- `analysis_limitations` phrasing
- `confidence_notes` phrasing
- runtime refinement notes for newly supported manifest families

The goal for v1 is contract stability, not frozen narrative prose.
