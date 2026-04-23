# V2 Fusion Plan

Date: 2026-04-23

## Goal

Build v2 by absorbing the best `cls-certify` assets into the existing verifier, without rewriting the current architecture or weakening its guard-oriented design.

## Current Project Baseline

This repository already has the following v1 capabilities in production shape:

1. CLI and GUI delivery surfaces
2. baseline dangerous-pattern scanner
3. structured OpenClaw context extraction
4. frontmatter and metadata parsing
5. prompt and instruction analysis
6. attack-path reasoning
7. compound scoring
8. host-vs-sandbox consequence modeling
9. guarded runtime validation
10. suppression and audit workflow
11. Windows EXE delivery
12. canonical JSON report contract

This means v2 must add missing breadth, not rebuild core reasoning.

## Capability Mapping

| `cls-certify` area | Current project status | V2 action |
|---|---|---|
| Static threat pattern breadth | Present, but narrower and OpenClaw-specific | Expand through corpus-driven rule assets |
| Sensitive data pattern library | Partial via baseline/private-key and secret reachability | Add typed sensitive-data corpus |
| Dependency audit | Largely missing as first-class analyzer | Add new dependency audit module |
| URL/API classification | Partial through outward-capable tools and network consequences | Add network endpoint taxonomy and domain-risk signals |
| Privacy/compliance checks | Partial via secret/consequence/runtime reasoning | Add explicit privacy data-flow and checklist lens |
| Source reputation | Partial via provenance notes | Add repository/domain/source credibility analyzer |
| Structured report templates | Strong JSON schema already exists | Extend current schema rather than replace it |
| HTML/SARIF output posture | JSON-first; GUI can export JSON | Add derived report renderers from canonical report |
| Candidate/verified distinction | Already has confidence, validation, and suppression concepts | Refine those instead of adding a separate prompt-only layer |
| Additive grade calculator | Inferior to current attack-path scoring | Do not replace existing scoring model |

## What We Already Have And Should Not Rebuild

These are already stronger than the equivalent `cls-certify` concepts and should remain authoritative:

1. attack-path composition
2. compound uplift scoring
3. host-vs-sandbox consequence model
4. guarded runtime validation
5. audited suppression lifecycle
6. typed core/report separation
7. CLI plus GUI reuse of the same engine

## Highest-value V2 Increments

### 1. Reference asset layer upgrade

Add corpus-driven assets that become reusable inputs to analyzers.

Target asset families:

1. threat patterns corpus
2. sensitive data patterns corpus
3. API and URL classification corpus
4. known malicious behavior seed corpus
5. provenance metadata for every imported or adapted rule family

Why it matters:

- this raises coverage without changing product shape
- it lets the verifier scale by data plus typed analyzers
- it creates a base for false-positive regression and provenance tracking

### 2. Dependency and source audit

Add first-class analyzers for:

1. manifest discovery
2. dependency normalization
3. vulnerability-source adapter strategy
4. suspicious package naming signals
5. repo/domain/source credibility signals

Why it matters:

- this is one of the clearest real gaps between v1 and the `cls-certify` reference set
- it provides meaningful supply-chain coverage without requiring unsafe execution

### 3. Report-layer expansion

Preserve canonical JSON, but add derived outputs:

1. Markdown analyst report
2. SARIF export
3. HTML report

Key rule:

- one canonical `ScanReport`
- no parallel report model
- renderers consume the same typed output

### 4. False-positive control and rule provenance

Add:

1. corpus provenance metadata
2. rationale for downgraded or excluded matches
3. regression fixtures for benign and borderline patterns
4. source-of-truth mapping from rule family to corpus item

Why it matters:

- broader corpus coverage without stronger FP control would hurt product trust

### 5. Classification and explanation refinement

Add richer explanation, not a new scoring philosophy.

Potential additions:

1. risk-source classification
2. finding family tags
3. API/provider class in report output
4. dependency-source risk notes
5. clearer score rationale for new audit families

## Proposed V2 Additions

### New data assets

Recommended additions:

1. `crates/core/data/threat-corpus-v2.yaml`
2. `crates/core/data/sensitive-data-corpus-v2.yaml`
3. `crates/core/data/api-taxonomy-v2.yaml`
4. `crates/core/data/reputation-seeds-v2.yaml`
5. `fixtures/v2/` regression corpus for:
   - benign docs/examples
   - dependency typosquatting cases
   - suspicious URL/domain cases
   - privacy overreach cases
   - malicious behavior combinations

### New core analyzers

Recommended additions:

1. `dependency_audit`
2. `network_taxonomy`
3. `origin_reputation`
4. `privacy_review`
5. `corpus` or `rule_assets` loader

These should feed the existing scan pipeline and report types, not create a second mini-pipeline.

### New report outputs

Recommended additions in `crates/report`:

1. Markdown renderer
2. SARIF renderer
3. HTML renderer

All should render from the existing canonical report plus any v2 schema extensions.

## Architecture Constraints

These are non-negotiable for v2:

1. `core` remains the only analysis source of truth
2. `report` remains a pure rendering and serialization layer
3. GUI stays a thin consumer of scan results
4. no shell tools inside production core
5. no dangerous runtime execution
6. no rewrite of attack-path, consequence, or suppression systems

## Recommended Delivery Sequence

### Phase V2-1: Asset and schema foundation

Deliver:

1. corpus formats and provenance fields
2. schema extensions for new finding families and endpoint/dependency sections
3. regression-fixture layout

Why first:

- later analyzers and renderers need stable inputs and stable output contracts

### Phase V2-2: Dependency plus source/network analyzers

Deliver:

1. dependency manifest discovery
2. basic suspicious dependency heuristics
3. CVE source adapter scaffolding
4. URL/API taxonomy classification
5. domain/repo/source credibility signals

Why second:

- this is the biggest functional gap and the most direct lift from `cls-certify`

### Phase V2-3: Privacy and sensitive-data expansion

Deliver:

1. typed sensitive-data corpus matching
2. privacy-oriented data class tagging
3. basic compliance checklist outputs

Why third:

- it depends on network and dependency visibility to explain data use more credibly

### Phase V2-4: Output expansion

Deliver:

1. Markdown renderer
2. SARIF renderer
3. HTML renderer

Why fourth:

- renderer work is lower-risk once the v2 report fields are stable

### Phase V2-5: FP hardening and explanation refinement

Deliver:

1. benign regression corpus
2. downgraders and exclusions for new families
3. score/explanation polish for added analyzers

Why fifth:

- avoids locking in noisy defaults too early

## Priority Decision

If v2 needs a deliberately narrow implementation core, the best priority order is:

1. corpus foundation
2. dependency audit
3. URL/API plus source reputation
4. SARIF and Markdown output
5. privacy/compliance overlay

## Second-round Implementation Recommendation

The second round should implement only the highest-signal core:

1. typed corpus asset loading
2. dependency audit analyzer
3. URL/API classification plus domain-risk analyzer
4. report schema extension for new outputs and evidence sections
5. SARIF renderer
6. small v2 regression fixtures

This keeps v2 advancing on real missing coverage while preserving the current verifier identity.

## Readiness Assessment

The repository is ready to enter v2 implementation because:

1. the v1 architecture is already stable
2. the missing areas are now clearly isolated
3. `cls-certify` provides usable reference assets without forcing architectural change
4. the recommended first implementation slice is additive rather than disruptive

The project is not ready for an uncontrolled "full six-dimension rewrite", and should not attempt one.
