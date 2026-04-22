# Reverse Engineering

This document locks down the confirmed `agent-skills-guard` behavior that Phase 2+ may reuse, wrap, or replace. The goal is not to mirror its README. The goal is to trace the actual skill-security path through code, types, tests, and UI consumption.

## Scope

- Upstream target: `research/agent-skills-guard-main`
- Focus: skill security validation only
- Evidence style:
  - Confirmed fact: directly visible in code, tests, or shipped UI types
  - Inference: likely behavior inferred from the call graph and surrounding code
  - Open question: not yet proven from source alone

## Confirmed Facts

### Core module map

| Path | Evidence | Role |
| --- | --- | --- |
| `src-tauri/src/security/mod.rs` | module exports `SecurityRules`, `ScanOptions`, `SecurityScanner`, `SecurityChecker` | security subsystem entry surface |
| `src-tauri/src/security/scanner.rs` | `ScanOptions` at line 66, `scan_directory_with_options` at 616, `scan_file` at 901, `calculate_score_weighted` at 983 | recursive scan engine, content normalization, score calculation |
| `src-tauri/src/security/rules.rs` | `PatternRule` at 37, `PATTERN_RULES` at 83, `HARD_TRIGGER_RULES` at 1204, `quick_match_into` at 1232 | regex rule catalog and fast prefilter |
| `src-tauri/src/models/security.rs` | `SecurityReport` at 5, `SecurityLevel` at 20, `SecurityIssue` at 67 | report schema consumed by Tauri and UI |
| `src-tauri/src/commands/security.rs` | Tauri command layer | scans exposed to frontend |
| `src-tauri/src/services/skill_manager.rs` | `enforce_installable_report` at 112, `prepare_skill_installation` at 405, `confirm_skill_installation` at 596 | install/update guardrail path |
| `src/types/security.ts` | `partial_scan` and `skipped_files` fields | frontend type mirror |
| `src/components/ui/SkillSecurityDialog.tsx` and `src/components/SecurityDetailDialog.tsx` | dialog rendering | report explanation surface |

### Report model

Confirmed from `src-tauri/src/models/security.rs`:

- `SecurityReport` includes `score`, `level`, `issues`, `recommendations`, `blocked`, `hard_trigger_issues`, `scanned_files`, `partial_scan`, and `skipped_files`.
- `SecurityLevel` is score-banded:
  - `Safe`: 90-100
  - `Low`: 70-89
  - `Medium`: 50-69
  - `High`: 30-49
  - `Critical`: 0-29
- `SecurityIssue` carries severity, category, description, line number, snippet, and file path.

### Rule model

Confirmed from `src-tauri/src/security/rules.rs`:

- The engine is fundamentally regex-rule driven.
- `PatternRule` fields include:
  - `id`
  - `name`
  - `pattern`
  - `severity`
  - `category`
  - `weight`
  - `description`
  - `hard_trigger`
  - `confidence`
  - `remediation`
  - `cwe_id`
- `HARD_TRIGGER_RULES` is derived from rules where `hard_trigger == true`.
- `quick_match_into` uses a shared `RegexSet` as a coarse prefilter before detailed per-rule matching.

### Scanner mechanics

Confirmed from `src-tauri/src/security/scanner.rs`:

- `ScanOptions` currently has one explicit policy bit: `skip_readme: bool`.
- `build_scan_lines` normalizes multi-line shell and script constructs before regex matching. Confirmed cases include:
  - backslash line continuation
  - PowerShell backtick continuation
  - JavaScript-style string concatenation with `+`
- `collect_matches_for_content` deduplicates matches by rule id, line number, and normalized text.
- Extension-aware filtering is applied for many source files, but `SKILL.md` is scanned fully rather than by language-extension subsets.
- UTF-16 detection/decoding is implemented. This matters for Windows-centric fixtures and for evasion-by-encoding tests.
- Directory scanning uses `WalkDir` with `follow_links(false)`.
- Scan truncation and skipped content are surfaced explicitly through `partial_scan` and `skipped_files`, not silently dropped.

### Install/update enforcement

Confirmed call chain:

1. Frontend starts installation flow from `src/components/MarketplacePage.tsx`.
2. Tauri command layer routes into skill-management functions.
3. `skill_manager.rs::prepare_skill_installation` performs a scan.
4. That scan frequently uses `ScanOptions { skip_readme: true }`.
5. `enforce_installable_report` blocks if:
   - `report.blocked` is true
   - hard-trigger issues exist
   - `partial_scan` is true and `allow_partial_scan` is false
6. `confirm_skill_installation` reuses the same enforcement posture before final install.

This is the most important upstream product behavior: the scanner is not only an informational lint pass. It is tied into an install gate.

### Frontmatter handling limitation

Confirmed from `src-tauri/src/services/skill_manager.rs:1032-1057`:

- `parse_frontmatter` is a shallow parser.
- It only looks for literal line prefixes:
  - `name:`
  - `description:`
- It does not implement structured YAML or a semantic `metadata.openclaw` model.

This is the biggest reason Phase 1 cannot simply inherit the original parser logic for OpenClaw-aware analysis.

## Call Chain

The security validation path is:

```text
MarketplacePage.tsx
  -> prepare_skill_installation(...)
    -> SecurityScanner::scan_directory_with_options(..., ScanOptions { skip_readme: true })
      -> regex prefilter (RegexSet)
      -> normalized line construction
      -> rule matching
      -> weighted score calculation
    -> enforce_installable_report(...)
      -> block install on hard trigger / blocked / partial_scan policy
  -> confirm_skill_installation(...)
```

The informational scan path is similar, but exposed through Tauri commands in `src-tauri/src/commands/security.rs` and rendered via `SkillSecurityDialog` / `SecurityDetailDialog`.

## Test Evidence

Confirmed from `scanner.rs` tests:

- Reverse-shell patterns are detected.
- Destructive shell variants such as reordered `rm -rf /` forms are covered.
- `curl|bash` remains detectable across continued lines and concatenated strings.
- Mentions are distinguished from actual execution intent in some cases.
- Secrets and private-key style material are detected.
- Nested directory traversal is covered.
- `SKILL.md` receives full scanning.
- UTF-16LE input is decoded and scanned.
- PowerShell encoded commands and backtick continuations are covered.
- Windows persistence patterns are covered.
- Symlink handling has explicit tests and blocking behavior on supported platforms.

These tests are good baseline inheritance candidates. They are not sufficient for OpenClaw runtime-context analysis.

## UI Consumption

Confirmed from `src/types/security.ts` and the dialogs:

- The UI expects:
  - blocked vs non-blocked status
  - score and level
  - grouped issues
  - partial-scan warnings
  - skipped file surfacing
- This means upstream already values explainability, but it explains individual findings rather than attack-path composition.

## OpenClaw Gap Analysis

The current upstream engine is useful, but it is not OpenClaw-aware.

Confirmed gaps:

- No semantic parse of `metadata.openclaw`.
- No model of skill source provenance:
  - workspace
  - project agent
  - personal agent
  - managed
  - bundled
  - extraDirs
  - plugin-provided skills
- No precedence or shadowing analysis.
- No host-vs-sandbox execution model.
- No secrets-reachability model tied to `skills.entries.*.env` / `apiKey`.
- No `command-dispatch: tool` or direct tool-dispatch risk model.
- No installer-path asymmetry model for `skills.install` vs `openclaw skills install <slug>`.
- No toxic-flow graphing that combines prompt injection, tool reachability, local secret reachability, and egress reachability into one attack path.

## Reuse Assessment

### Direct reuse candidates

- File walking and skip accounting ideas
- UTF-16 handling
- Line continuation normalization
- Regex prefilter strategy
- Weighted issue scoring primitives
- Existing baseline fixture ideas

### Wrap-before-reuse candidates

- Report serialization concepts
- Hard-trigger semantics
- Recommendation generation style
- UI-style explainability patterns

### Rewrite candidates

- Frontmatter and metadata parsing
- Install-chain analysis
- Runtime-context model
- Precedence/shadowing detection
- Secrets/tool/egress reachability
- OpenClaw-specific scoring
- Attack-path composition

## Inference

- The upstream team intentionally optimized for installation-time screening of skill bundles, not for full environment-aware risk reasoning.
- The `skip_readme: true` default in installation paths likely exists to reduce noisy document-only hits during install, but that same choice would miss OpenClaw-relevant manual execution instructions and prompt-injection carriers if copied unchanged.

## Open Questions

- How much of upstream's recommendation text is templated vs hand-tuned per rule category?
- Whether its Tauri/UI layer carries additional suppression state beyond what is visible in the shared report types.
- Whether some marketplace flows pass additional scan options not yet covered in the paths inspected so far.

