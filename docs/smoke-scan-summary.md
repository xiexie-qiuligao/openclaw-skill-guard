# Smoke Scan Summary

Date: 2026-04-22

This is a release-prep sampling pass, not a new benchmark phase. All samples below are inert and were scanned through the CLI.

## Samples and outcomes

### `benign`

- Scan target: [fixtures/v1/benign/SKILL.md](../fixtures/v1/benign/SKILL.md)
- Expected conclusion: allow
- Actual conclusion: allow
- Notes:
  - one obvious false positive was found during release prep
  - `Do not fetch remote instructions.` was initially misread as indirect instruction pressure
  - fixed before release by ignoring clearly negated indirect/tool/secret directives
- Issue level: fixed before release

### `high-risk`

- Scan target: [fixtures/v1/high-risk/SKILL.md](../fixtures/v1/high-risk/SKILL.md)
- Expected conclusion: block
- Actual conclusion: block
- Notes:
  - baseline hard-trigger behavior and direct dispatch findings behaved as expected
- Issue level: none

### `install-risk`

- Scan target: [fixtures/v1/install-risk](../fixtures/v1/install-risk)
- Expected conclusion: block or strong warn
- Actual conclusion: block
- Notes:
  - install extraction, origin-integrity findings, and install-path attack path behaved as expected
- Issue level: none

### `prompt-risk`

- Scan target: [fixtures/v1/prompt-risk/SKILL.md](../fixtures/v1/prompt-risk/SKILL.md)
- Expected conclusion: block
- Actual conclusion: block
- Notes:
  - model bypass, approval bypass, secret coercion, and attack-path composition behaved as expected
- Issue level: none

### `precedence-shadowing`

- Scan target: [fixtures/v1/precedence-shadowing](../fixtures/v1/precedence-shadowing)
- Expected conclusion: local collision warning with elevated risk due to direct dispatch
- Actual conclusion: block
- Notes:
  - result is acceptable for the included demo because the collision is paired with risky dispatch and tool exposure
  - no obvious false positive was found
- Issue level: can defer refinement

### `runtime-refinement`

- Scan target: [fixtures/v1/runtime-refinement/SKILL.md](../fixtures/v1/runtime-refinement/SKILL.md)
- Expected conclusion: risky path remains visible, but runtime manifest should narrow or block parts of it
- Actual conclusion: block with runtime blockers recorded
- Notes:
  - runtime manifest fields were ingested correctly
  - `validation_results`, `path_validation_status`, and `environment_blockers` behaved as expected
- Issue level: none

### `suppression-audit`

- Scan target: [fixtures/v1/suppression-audit/SKILL.md](../fixtures/v1/suppression-audit/SKILL.md)
- Expected conclusion: evidence remains visible, suppression and audit sections populated
- Actual conclusion: block with visible suppression and audit output
- Notes:
  - suppression correctly affects scoring visibility without hiding evidence
- Issue level: none

## Summary

- Blockers found: 1
- Blockers fixed: 1
- Remaining should-fix-before-release issues: 0
- Remaining can-defer items:
  - precedence sample severity calibration in broader real-world corpora

## Overall release judgment

The sampling pass did not find a remaining release blocker after the negated-instruction false positive was fixed.
