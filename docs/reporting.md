# Reporting

This document describes the canonical JSON report contract.

## Canonical contract

The canonical output is:

- [report.schema.json](../schemas/report.schema.json)

JSON is the source-of-truth contract. SARIF, Markdown, and HTML are derived exports and must remain mapped from the same `ScanReport`. Human-facing narrative fields are Chinese-first where available; machine-readable keys stay stable.

## Stable sections

These top-level sections are treated as stable for v1:

- `target`
- `input_origin`
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
- `openclaw_config_audit_summary`
- `capability_manifest`
- `companion_doc_audit_summary`
- `source_identity_summary`
- `toxic_flow_summary`
- `toxic_flows`
- `hidden_instruction_summary`
- `claims_review_summary`
- `integrity_snapshot`
- `estate_inventory_summary`
- `agent_package_index`
- `mcp_tool_schema_summary`
- `ai_bom`
- `policy_evaluation`
- `summary_zh`
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

- `target`
  - canonical scan target descriptor after local or remote input resolution
- `input_origin`
  - original local path or HTTPS skill link, parsed input kind, source host, resolved scan target, and resolver warnings
- `findings`
  - atomic issues with direct evidence and remediation; may include stable `issue_code`, `title_zh`, `explanation_zh`, and `recommendation_zh`
- `hidden_instruction_summary`
  - static hidden-instruction, Trojan Source, deceptive-link, encoded-instruction, and tool/schema poisoning signals
- `claims_review_summary`
  - product-facing comparison of declared skill claims, observed evidence, mismatches, and review questions
- `integrity_snapshot`
  - passive SHA-256 and file-count summary for comparing reports and detecting remote skill drift
- `estate_inventory_summary`
  - scope-limited local OpenClaw/Claude/Cursor/Windsurf/MCP configuration references; does not start or connect to services
- `agent_package_index`
  - generic Agent Skill / Tool / MCP / prompt package index; enabled for non-OpenClaw ecosystem parsing
- `mcp_tool_schema_summary`
  - static MCP command/env/tool/schema review result; never starts MCP servers
- `ai_bom`
  - AI bill of materials covering packages, tool surfaces, MCP servers, commands, env/config, external services, dependencies, identity, digests, and review questions
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
- `openclaw_config_audit_summary`
  - OpenClaw config/control-plane findings such as skill env/API key bindings, dangerous env names, broad extraDirs, sandbox/elevated hints, and config mutation guidance
- `capability_manifest`
  - synthesized declared/inferred/required capability view derived from existing analyzers, not a second permission system
- `companion_doc_audit_summary`
  - companion README/docs/examples audit for indirect instructions, approval bypass wording, maintenance execution lures, and narrative mismatch
- `source_identity_summary`
  - offline source identity and mismatch signals across homepage, repository, install/download, package metadata, and local documentation claims
- `toxic_flow_summary` and `toxic_flows`
  - evidence aggregation for combinations of untrusted input/source, sensitive data surface, and egress/execution capability; this is a review-needed signal, not proof of exfiltration
- `policy_evaluation`
  - local `.openclaw-guard.yml` / CI gate result, including language, fail reason, ignored rules, and policy notes
- `summary_zh`
  - Chinese human-readable report summary for GUI, CLI, Markdown, and HTML surfaces
- `provenance_notes` and `confidence_factors`
  - why the verifier trusts or discounts a conclusion
- `suppression_matches` and `audit_summary`
  - accepted exceptions without silent disappearance

## Derived formats

- `json`
  - canonical report contract and source of truth
- `sarif`
  - derived finding export for security tooling integrations
  - maps findings, severity, confidence, issue-code-first rule ids, messages, and file locations
  - `message.text` is Chinese-first by default while `properties.english_message` retains the original explanation when available
  - it does not currently serialize attack-path graphs, runtime validation internals, or suppression audit history in full detail
- `markdown`
  - human-readable summary export derived from the same `ScanReport`
  - Chinese-first human-readable export that emphasizes summary, findings, context, validation/consequence, external references, v3 OpenClaw summaries, toxic flows, and score/provenance
  - includes v3 OpenClaw config/control-plane, capability, companion-document, and source-identity detail blocks when present
- `html`
  - Chinese-first browser-friendly rendering of the derived Markdown view
  - keeps the canonical contract in JSON rather than introducing a second schema
  - preserves the same canonical-report-derived v3 content rather than introducing a separate report protocol

## Experimental posture

The following areas should be treated as evolving within the stable outer contract:

- exact wording of `summary` fields
- `analysis_limitations` phrasing
- `confidence_notes` phrasing
- runtime refinement notes for newly supported manifest families

The goal for v1 is contract stability, not frozen narrative prose.
