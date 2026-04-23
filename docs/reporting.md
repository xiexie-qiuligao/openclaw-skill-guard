# Reporting

This document describes the v1 public report contract.

## Canonical contract

The canonical v1 output is:

- [report.schema.json](../schemas/report.schema.json)

JSON is the source-of-truth contract. Markdown and HTML renderers may be added later, but they should be derived from the same `ScanReport`.

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
- `provenance_notes` and `confidence_factors`
  - why the verifier trusts or discounts a conclusion
- `suppression_matches` and `audit_summary`
  - accepted exceptions without silent disappearance

## Experimental posture

The following areas should be treated as evolving within the stable outer contract:

- exact wording of `summary` fields
- `analysis_limitations` phrasing
- `confidence_notes` phrasing
- runtime refinement notes for newly supported manifest families

The goal for v1 is contract stability, not frozen narrative prose.
