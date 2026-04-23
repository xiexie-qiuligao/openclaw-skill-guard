# V2 Scope

Date: 2026-04-23

## V2 Definition

V2 is an additive upgrade to the current verifier. It expands coverage with corpus-driven assets, dependency/source/network/privacy signals, and richer report outputs while preserving:

1. the current Rust core
2. the current attack-path reasoning model
3. the current guarded validation boundary
4. the current CLI/GUI shared-engine design

## In Scope

### 1. Corpus-driven asset upgrade

Add and maintain:

1. threat-pattern corpus
2. sensitive-data corpus
3. API/URL classification corpus
4. malicious-pattern seed corpus
5. provenance metadata for imported/adapted rules

### 2. New analyzer coverage

Add:

1. dependency audit
2. repository/source credibility
3. domain and URL risk signals
4. privacy-oriented data-use review

### 3. Output expansion

Add derived output formats from the canonical report:

1. Markdown
2. SARIF
3. HTML

### 4. False-positive and regression infrastructure

Add:

1. benign/borderline regression corpus
2. rule provenance
3. corpus-driven downgrade and exclusion support

### 5. Explanation quality

Improve:

1. finding family labeling
2. score rationale for new analyzers
3. endpoint/dependency/source explanations

## Explicitly Out Of Scope

### 1. No architecture rewrite

Do not:

1. replace the current scan pipeline
2. replace the current report core with a separate `cls-certify`-style protocol
3. rebuild the product around shell tools

### 2. No dangerous runtime expansion

Do not:

1. turn runtime validation into exploit execution
2. run untrusted installs or payloads
3. build a sandbox replay engine in this v2 cycle

### 3. No large GUI program

Do not:

1. start a new UI architecture
2. treat HTML output as a GUI replacement
3. build new release packaging work unrelated to v2 analysis coverage

### 4. No broad live-intel platform

Do not:

1. build a full threat-intel service
2. depend on unstable or closed external feeds as core functionality
3. promise real-time malicious-domain verdicts beyond clearly bounded signals

### 5. No score-model regression

Do not:

1. replace attack-path scoring with tool-by-tool additive deductions
2. reduce consequence modeling to a simple grade table
3. remove suppression/audit visibility

## Guardrails Against Scope Creep

Every v2 task should pass all of these checks:

1. Does it extend the current verifier instead of replacing it?
2. Does it improve coverage or explainability in a measurable way?
3. Can it be represented in the canonical report?
4. Can it be tested with local fixtures or stable inputs?
5. Does it preserve the verifier/guard safety boundary?

If any answer is no, it should be deferred.

## V2 Acceptance Criteria

V2 is successful when the repository can demonstrate:

1. corpus-backed rule assets with provenance
2. first-class dependency/source/network/privacy increments
3. stable canonical report extensions
4. at least one machine-consumable new format beyond JSON
5. regression coverage for new rule families
6. no loss of current v1 capabilities

## What V2 Is Not

V2 is not:

1. a port of `cls-certify`
2. a generic multi-language malware scanner
3. an exploit runner
4. a separate compliance product
5. a release-polish project

## Recommended Narrow Implementation Slice

If execution must stay tight, v2 should first deliver only:

1. corpus assets
2. dependency audit
3. URL/API and source-risk analysis
4. SARIF plus Markdown output
5. regression fixtures for the above

That slice is large enough to justify v2 and small enough to stay under control.
