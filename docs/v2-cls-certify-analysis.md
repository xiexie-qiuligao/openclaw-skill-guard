# V2 `cls-certify` Analysis

Date: 2026-04-23

Reference repository: [CatREFuse/cls-certify](https://github.com/CatREFuse/cls-certify)

## Purpose

This document treats `cls-certify` as a high-value reference source for v2 planning, not as a replacement architecture. The goal is to identify which ideas, assets, and output patterns are worth absorbing into `openclaw-skill-guard` without discarding the current verifier core.

## Snapshot Observed

The public repository snapshot reviewed in this round exposes four main layers:

1. Orchestration and product docs
   - `SKILL.md`
   - `README.md`
   - `TEAM-STRUCTURE.md`
   - `V2-UPGRADE-GUIDE.md`
2. Tool layer
   - `tools/threat-scan.sh`
   - `tools/secret-scan.sh`
   - `tools/entropy-detect.sh`
   - `tools/dep-audit.sh`
   - `tools/url-audit.sh`
   - `tools/github-repo-check.sh`
   - `tools/score-calc.sh`
   - `tools/skill-classify.sh`
   - `tools/threat-verify.sh`
3. Reference asset layer
   - `references/threat-patterns.md`
   - `references/sensitive-data-patterns.md`
   - `references/api-classification.md`
   - `references/structured-report-template.md`
   - `references/report-data-protocol.md`
   - `references/known-malicious-patterns.md`
   - `references/cve-sources.md`
   - `references/gdpr-checklist.md`
4. Presentation layer
   - `render.sh`
   - `templates/report-template.html`
   - `templates/sample-report.html`

## Capability Breakdown

### 1. Six-dimension model

`cls-certify` publicly frames its analysis around six dimensions:

1. Static code analysis
2. Dynamic behavior analysis
3. Dependency audit
4. Network traffic analysis
5. Privacy/compliance checks
6. Source reputation and threat intelligence

This is useful as a coverage map. It is not, by itself, an architecture.

### 2. Tool layer analysis

The shell tools are the operational core of `cls-certify`.

#### `threat-scan.sh`

- Large regex-driven candidate scanner.
- Covers code execution, injection, AI safety, prompt poisoning, privilege escalation, exfiltration, dynamic download, conditional trigger, and agent-context manipulation patterns.
- Strong value: category taxonomy, pattern inventory breadth, context-before/context-after capture.
- Limitation: rule logic is tightly embedded in Bash arrays and regex strings, making provenance management, testing, and reuse harder.

#### `secret-scan.sh` and `entropy-detect.sh`

- Focus on secret-like material and high-entropy strings.
- Strong value: sensitive data corpus thinking, exclusions, entropy thresholds.
- Limitation: generic secret scanning is noisy unless tied to context, provenance, and current verifier reachability reasoning.

#### `dep-audit.sh`

- Parses multiple dependency manifests.
- Detects typosquatting-like names and suspicious keywords.
- Strong value: dependency surface inclusion, cross-ecosystem ambition, simple supply-chain risk hooks.
- Limitation: does not yet match the richer dependency graph and CVE claims in product docs; it is more heuristic than authoritative.

#### `url-audit.sh`

- Extracts URLs, classifies domains into 14 categories, adds reputation flags, and emits structured JSON.
- Strong value: API taxonomy seed, domain-risk signal design, context capture around URLs.
- Limitation: current implementation is signature-heavy and domain-list-heavy; it should be treated as seed data, not final detection logic.

#### `github-repo-check.sh`

- Uses GitHub metadata to assign T1/T2/T3 trust levels and a simple credibility score.
- Strong value: source credibility as an explicit input to reporting.
- Limitation: hard-coded whitelist and simplistic score heuristics are too brittle for direct adoption.

#### `score-calc.sh`

- Aggregates tool JSON outputs into a final grade with deductions, caps, and forced downgrades.
- Strong value: explicit scoring explainability and tool-level deduction accounting.
- Limitation: additive deduction logic is materially weaker than this project's existing finding-plus-attack-path model.

#### `skill-classify.sh`

- Assigns `T-MD`, `T-LITE`, `T-REF`, `T-HEAVY`, `T-FULL`, `T-QUICK`.
- Strong value: scan-budget control, scope-aware strategy selection, idea of lighter paths for documentation-only targets.
- Limitation: it is oriented around a shell pipeline and should not replace the current target-resolution model directly.

#### `threat-verify.sh`

- Turns scanner candidates into a second-pass review prompt.
- Strong value: explicit false-positive review stage and candidate-to-validated separation.
- Limitation: prompt-centric workflow is useful conceptually, but the current verifier already has structured confidence, validation, and suppression surfaces that should remain primary.

### 3. Reference asset layer analysis

This is the highest-value part of `cls-certify`.

#### `threat-patterns.md`

- Publicly claims a broad threat corpus and exposes categories aligned with modern agent/tool abuse.
- Strongest lessons:
  - treat prompt/tool abuse as a first-class threat family
  - classify by long-lived attack pattern, not one-off incidents
  - include agent-context/config manipulation families

#### `sensitive-data-patterns.md`

- Useful seed corpus for API keys, credentials, private keys, JWTs, config secrets, and PII-like patterns.
- Strongest lessons:
  - secret detection should be corpus-driven
  - context and exclusion rules matter as much as raw regexes
  - data classes should be typed, not just "secret or not"

#### `api-classification.md`

- Provides 14 API/domain categories and basic risk narratives.
- Strongest lessons:
  - URL analysis is more useful when normalized into service classes
  - outbound endpoints need provider/reputation/risk context, not only "network present"

#### `structured-report-template.md` and `report-data-protocol.md`

- Show a serious attempt at stable machine-readable and human-readable reporting contracts.
- Strongest lessons:
  - schema-driven report design is worth formalizing early
  - HTML/Markdown/SARIF should derive from one canonical structured report
  - risk findings, API inventory, and score rationale should all be serializable

#### `known-malicious-patterns.md`

- Small but useful seed for regression fixtures and correlation rules.
- Strongest lessons:
  - maintain concrete malicious combinations, not only isolated signatures
  - record behavior combinations that should escalate confidence

#### `cve-sources.md`

- Not an implementation by itself, but a concise integration seed list.
- Strongest lessons:
  - dependency audit should separate "data source strategy" from "match engine"
  - authoritative sources matter more than generic heuristics

#### `gdpr-checklist.md`

- Lightweight checklist rather than a full privacy engine.
- Strongest lessons:
  - privacy review benefits from a stable checklist layer
  - "data collection beyond stated function" can be modeled as a structured review output

### 4. Report layer analysis

`cls-certify` is notably report-oriented.

Observed design choices:

- output planning is a first-class concern, not an afterthought
- JSON, Markdown, HTML, and SARIF are treated as meaningful public surfaces
- the report protocol separates:
  - metadata
  - grade/score
  - findings
  - API inventory
  - compliance view
  - recommendations

High-value lesson:

- this aligns well with the existing `ScanReport` direction in this repository and can be absorbed by expanding the current canonical schema rather than inventing a second report model

### 5. Scoring layer analysis

`cls-certify` scoring is understandable but comparatively shallow:

- base score starts at 100
- tool outputs apply fixed deductions
- certain hits force `D` or cap at `C`
- repository trust can apply bonus/penalty

Good lessons:

- explain every score movement
- keep downgrade reasons explicit
- separate score from narrative evaluation

Do not copy directly:

- the current project already has a better model:
  - finding severity/confidence
  - attack-path uplift
  - host-vs-sandbox consequences
  - runtime validation refinement
  - audited suppression

## What `cls-certify` Gets Right

1. Treats rules and taxonomies as reusable assets.
2. Makes output structure explicit.
3. Recognizes that URL/API classification and dependency audit are real security signal sources.
4. Exposes a useful false-positive review concept.
5. Separates threat pattern libraries from report presentation templates.

## Where `cls-certify` Is Weaker Than The Current Project

1. Core logic is script-first rather than typed-engine-first.
2. Scoring is mostly additive rather than attack-path-aware.
3. Dynamic behavior language is stronger than the visible implementation evidence.
4. Runtime validation and consequence modeling are much less mature than the current verifier.
5. The public architecture is oriented toward workflow orchestration, not a stable embeddable core.

## Four-way Disposition

### A. Directly Reusable

These are appropriate to reuse as data seeds or reference material with provenance cleanup.

1. API/domain category seed list from `references/api-classification.md`
2. GDPR checklist items from `references/gdpr-checklist.md`
3. CVE source inventory from `references/cve-sources.md`
4. Known malicious behavior examples as regression-fixture seeds
5. Report section ideas:
   - external API inventory
   - risk summary by severity
   - structured recommendations

### B. Reusable After Adaptation

These are the highest-value fusion targets.

1. Threat-pattern corpus concept
   - re-encode as typed Rust corpus data, not Bash arrays
2. Sensitive-data corpus concept
   - add exclusions, context windows, and data classes
3. API/URL classification concept
   - attach provider class, risk tier, and evidence provenance
4. Dependency audit concept
   - implement as analyzer module with authoritative source adapters
5. Report protocol concept
   - map into the existing `ScanReport` and `schemas/report.schema.json`
6. Candidate-versus-validated distinction
   - absorb into confidence/provenance/validation workflow rather than prompt-only review
7. Skill classification idea
   - adapt into scan-budget and target-shaping logic inside the current pipeline

### C. Useful To Study, But Not To Fuse Directly

1. Team-of-teams narrative in `TEAM-STRUCTURE.md`
   - useful for work decomposition, not for product architecture
2. Prompt-based second-pass verification flow
   - useful as review philosophy, not as the main runtime mechanism
3. Markdown frontmatter plus body protocol for HTML rendering
   - useful reporting inspiration, but the current project should keep JSON/schema as canonical
4. Hard-coded trust tiers T1/T2/T3
   - useful to think about source reputation, but too coarse for direct product semantics
5. Batch-mode and natural-language orchestration ideas
   - product-surface ideas, not v2 round-one implementation priorities

### D. Explicitly Not Adopted

1. Replacing the Rust verifier core with shell-script orchestration
2. Copying large Bash scanners into production logic
3. Downgrading current attack-path scoring to additive score buckets
4. Converting guarded validation into an exploit runner or unsafe sandbox executor
5. Tight coupling to Claude-specific paths and interaction primitives
6. Hard-coded publisher whitelists as trust truth
7. Documentation habits that expose local machine paths or environment details

## Engineering Hygiene And Release Hygiene Issues To Avoid

### Confirmed issue

`V2-UPGRADE-GUIDE.md` exposes a local machine path:

- a developer-machine absolute path pointing to a downloaded working copy

This is a release-hygiene failure and should not be inherited.

### Additional issues to avoid

1. Duplicating the same taxonomy in scripts, README, and templates without a single typed source of truth
2. Letting product claims outrun visible implementation evidence
3. Depending on Bash, `jq`, `gh`, `find`, and OS-specific behavior in core analysis logic
4. Embedding scoring policy directly into per-tool scripts instead of a central typed engine
5. Tying output shape to one renderer protocol instead of a canonical schema

## V2 Takeaways For This Project

The best interpretation of `cls-certify` is:

- not "a different scanner to copy"
- but "a rich asset and reporting reference set"

The most valuable lift for v2 is therefore:

1. corpus expansion
2. dependency/source/network/privacy analyzers
3. richer structured outputs
4. provenance-aware false-positive control

The least valuable lift is:

1. script-first orchestration
2. additive scoring replacement
3. heavy product-surface imitation
