# Comparison

This document records the inheritance, wrapping, rewrites, and net-new capabilities that distinguish the standalone OpenClaw-aware verifier from `agent-skills-guard`.

## Original engine summary

`agent-skills-guard` already solves several hard baseline problems well:

- recursive file scanning over skill directories
- content normalization before matching
- regex prefiltering for performance
- weighted issue scoring
- hard-trigger blocking
- install-time enforcement
- partial-scan and skipped-file surfacing

Those strengths are valuable and should be preserved where they remain architecture-compatible.

## Direct inheritance

The following capabilities should be inherited or ported with minimal semantic change:

| Capability | Why it should be inherited | Phase 3 handling |
| --- | --- | --- |
| Line continuation normalization | Already proven against shell, PowerShell, and concatenated script forms | Port into `core::baseline::normalize` |
| UTF-16 handling | Important for Windows-centric skills and evasion resistance | Port into `core::baseline::text` |
| File traversal and skip accounting | Already surfaces partial scan and skipped files | Port into `core::baseline::inventory` |
| Baseline dangerous-pattern rules | Mature starting set for shell, secrets, and execution primitives | Port selectively into `core::baseline::rules` |
| Hard-trigger concept | Useful for obvious direct execution or credential exposure primitives | Preserve in rule engine |
| Install-blocking mindset | Product behavior should stay enforcement-oriented, not purely informational | Preserve in verdict model |

## Wrap and rework

The following concepts are worth preserving in spirit but need wrapping before reuse:

| Capability | Upstream shape | New verifier approach |
| --- | --- | --- |
| Pattern-rule schema | Flat regex rule records | Wrap in a richer rule model that includes signal provenance and OpenClaw-aware metadata |
| Score weighting | Weighted deductions | Keep weighted thinking, but feed a two-step scoring system with graph escalation |
| Recommendation generation | Finding-level remediation text | Reuse the style, but split recommendations by immediate, hardening, suppression, and dynamic-validation buckets |
| Report explanation style | Explainable issue cards and install blocking | Preserve explainability, but expand to include attack-path narratives and evidence vs inference separation |

## Full rewrites

The following areas must be rewritten rather than ported:

| Capability | Why rewrite is required |
| --- | --- |
| Frontmatter parser | Upstream only extracts `name` and `description` from literal prefixes |
| `metadata.openclaw` model | No upstream semantic understanding of OpenClaw metadata |
| Precedence modeling | Upstream has no multi-source OpenClaw source graph |
| Secret reachability | Upstream has no model for `skills.entries.*.env` / `apiKey` injection |
| Tool reachability | Upstream has no OpenClaw tool authority model |
| Install-chain semantics | Upstream can flag snippets, but not OpenClaw install-path asymmetry |
| Prompt-injection analysis | Upstream regex rules do not model indirect instruction or wrapped external content poisoning |
| Attack-path graph | Upstream has no toxic-flow composition layer |
| Verdict logic | Upstream score bands are not enough for OpenClaw-aware compound risk |

## OpenClaw-specific gaps in the original engine

In OpenClaw context, the original engine is insufficient because it does not model:

- multi-source precedence and same-name shadowing
- `command-dispatch: tool` and `command-tool`
- `disable-model-invocation` as a visibility/deception signal
- host secret injection via `skills.entries.<skillKey>.env` and `apiKey`
- installer metadata vs `openclaw skills install <slug>` asymmetry
- host-vs-sandbox split and residual risk
- `requires.config` and eligibility signals as context
- README-skip risk during install-path scanning

The README-skip point is especially important. A default install flow that skips README content may be acceptable for a generic marketplace scanner, but it becomes a blind spot in OpenClaw where manual setup docs, prompt-injection carriers, and copy-paste shell steps are part of the real attack surface.

## Increment matrix

| Capability | Upstream status | New verifier status | Implementation strategy |
| --- | --- | --- | --- |
| Recursive inventory | Mature | Preserve | Port baseline traversal with explicit scan-integrity notes |
| Text normalization | Mature | Preserve | Port normalization and encoding support |
| Regex prefiltering | Mature | Preserve | Reuse as `PatternRule` subsystem |
| Weighted scoring | Mature | Expand | Wrap into finding score + path escalation |
| Hard triggers | Mature | Preserve | Keep for direct high-confidence primitives |
| Install blocking | Mature | Expand | Keep block mindset, add context-aware verdict rules |
| Frontmatter parsing | Minimal | New | Structured parser with diagnostics |
| `metadata.openclaw` parse | Missing | New | Normalized metadata model |
| Invocation policy analysis | Missing | New | Model `user-invocable`, `disable-model-invocation`, dispatch |
| Tool reachability | Missing | New | Reachability graph fed by metadata and text evidence |
| Secret reachability | Missing | New | Host secret exposure model tied to OpenClaw config semantics |
| Install-chain analysis | Partial | New | Metadata + docs + helper scripts + authenticity controls |
| Source precedence | Missing | New | OpenClaw-aware collision engine |
| Shadowing/hijack detection | Missing | New | Compare names, slugs, display signals, source trust |
| Prompt injection | Partial regex only | New | Strong rules + heuristics + graph composition |
| Toxic-flow graph | Missing | New | Evidence graph and attack-path summaries |
| False-positive controls | Implicit | Expanded | Confidence levels + downgrade rules + suppressions |
| JSON report contract | Basic | Expanded | Canonical stable schema |
| Markdown/HTML report | UI-oriented | New | Renderer crate from canonical report |

## What “OpenClaw-aware” adds

The new verifier is not a renamed upstream scanner. Its net-new value is:

- runtime-context reasoning instead of file-only suspicion
- explicit host-vs-sandbox consequence modeling
- source precedence and trust hijack detection
- secret and tool reachability as first-class concepts
- compound risk and attack-path summaries
- explainable false-positive downgrades based on recent official OpenClaw lessons

## Migration strategy

The migration strategy is layered, not fork-based:

1. Phase 3 ports baseline scanner behavior into `core::baseline`.
2. Phase 3 locks inherited fixtures as regression tests.
3. Phase 4 adds OpenClaw-aware analyzers on top of the baseline output rather than rewriting the baseline scanner again.
4. Phase 4 upgrades verdict logic to combine baseline findings with contextual and graph evidence.
5. Phase 5 productizes reporting, packaging, and examples.

Operational constraints:

- no attempt to make a drop-in fork of `agent-skills-guard`
- inherited fixtures become regression tests, not architecture drivers
- OpenClaw-aware modules are allowed to degrade to warning-only if unstable, without disabling the inherited baseline scanner

## Recent OpenClaw signals absorbed as design principles

The verifier absorbs recent official OpenClaw signals as durable design constraints:

| Recent signal | Long-term design principle | Verifier consequence |
| --- | --- | --- |
| runtime env hardening such as `NODE_OPTIONS`, `OPENCLAW_*`, and `MINIMAX_API_HOST` | env is part of the execution surface | model env and config mutation as risk, not noise |
| gateway config mutation guards | delegated tool authority can rewire future trust boundaries | flag control-plane mutation pressure, not only shell payloads |
| external-content token stripping | prompt injection includes role-boundary spoofing | analyze wrapped-content poisoning and indirect instruction |
| false-positive fixes for secret visibility | credibility requires downgrade rules | separate confirmed secret absence from unresolved/indirect refs |
| dangerous-install fallback hardening | break-glass behavior must be explicit | suppression and override paths must be auditable |

This is why the new verifier is not a patch set for a few recent issues. The rules generalize those signals into:

- scanner boundary integrity
- config and env trust boundaries
- delegated authority abuse
- prompt-injection flows
- false-positive regression coverage

## The five most important differences

1. The new verifier reasons over OpenClaw runtime context, not just suspicious strings.
2. Same-name shadowing and source precedence become first-class findings.
3. Secret reachability and tool reachability are explicit structured outputs, not hidden assumptions.
4. Verdicts depend on attack-path composition, not on score bands alone.
5. Recent OpenClaw fixes are absorbed as generalized design principles and regression classes, not as issue-specific patches.

