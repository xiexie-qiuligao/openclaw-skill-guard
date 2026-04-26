# V3 Capability Audit

Date: 2026-04-24

This document audits the current `openclaw-skill-guard` capability set before v3 implementation. It separates analysis depth from product presentation so v3 does not mistake a polished GUI/report surface for complete security coverage.

## Executive Judgment

The project is already strong for an OpenClaw-aware verifier. It is materially stronger than a generic regex skill scanner because it models OpenClaw-specific structure: skill metadata, install chains, invocation policy, tool and secret reachability, source precedence, attack paths, consequence, guarded validation, suppression/audit, and canonical reports.

The remaining v3 work should not replace this architecture. The highest-value gaps are narrower:

1. OpenClaw configuration/control-plane audit is not yet first-class enough.
2. Capability and permission summaries are scattered across analyzers instead of presented as a stable manifest.
3. Indirect instruction and companion-document poisoning coverage is present but not deep enough.
4. Source identity, registry mismatch, and same-name ecosystem risk remain lightweight.
5. Corpus coverage is useful but still early and should be expanded only with targeted OpenClaw-specific families.

## Capability Matrix

| Area | Current strength | Assessment | Why it matters |
| --- | --- | --- | --- |
| Baseline static scanning | Strong | Mature | Covers obvious dangerous primitives and gives early evidence for scoring. |
| Text normalization and inventory | Strong | Mature | Reads multiple text files, tracks skipped files, and avoids treating a single `SKILL.md` as the whole target. |
| Frontmatter parsing | Strong | Mature | Parses OpenClaw skill metadata and turns parse failures into visible report evidence. |
| `metadata.openclaw` parsing | Medium-strong | Good first-class coverage | Models OpenClaw fields such as install, requirements, skill key, primary env, and gating, but v3 should deepen config/control-plane interactions. |
| Install-chain analysis | Strong | Mature | Detects remote bootstrap, package installs, weak provenance, and install risk without executing untrusted code. |
| Invocation-policy analysis | Strong | Mature | Understands user invocation, model visibility, direct tool dispatch, and command-tool exposure. |
| Tool reachability | Strong | Mature | Connects skill text/metadata to high-risk tools rather than counting keywords in isolation. |
| Secret reachability | Strong | Mature | Distinguishes inline secrets, declared env/config needs, and runtime secret access paths. |
| Precedence/shadowing | Strong | Mature | Treats same-name override and workspace precedence as OpenClaw-specific risk. |
| Prompt/instruction analysis | Strong | Mature | Covers model bypass, approval bypass, indirect instruction, tool coercion, sensitive-data coercion, and policy bypass. |
| Attack-path reasoning | Strong | Core differentiator | Combines evidence into chains such as prompt injection to secret exfiltration instead of additive regex scoring only. |
| Compound scoring | Strong | Core differentiator | Uses severity, confidence, hard triggers, attack paths, consequence, validation, and suppression rather than a flat deduction table. |
| Consequence model | Strong | Core differentiator | Separates host vs sandbox consequences and models filesystem, credential, network, and persistence blast radius. |
| Guarded runtime validation | Strong | Mature boundary | Refines assumptions with safe checks while avoiding exploit execution or unsafe install replay. |
| Suppression/audit | Strong | Mature | Suppressions remain explicit, narrow, auditable, and visible in reports. |
| Threat corpus analyzer | Medium | Useful first version | Corpus-backed and explainable, but corpus breadth is still small compared with real ecosystem campaigns. |
| Sensitive corpus analyzer | Medium | Useful first version | Good for inline material and false-positive shaping, but not a complete enterprise secret scanner. |
| Dependency audit | Medium | Good v1 | Covers npm, pip, and Cargo with explainable risk signals, but does not solve transitive graphs or live CVE intelligence. |
| URL/API classification | Medium | Good v1 | Classifies external references and local reputation hints, but does not fetch or verify remote content. |
| Source/domain reputation | Medium-low | Deliberately bounded | Useful local hints, not a live threat-intelligence platform. |
| Privacy review | Weak-medium | Partial | Sensitive data and endpoint summaries help, but the project does not yet model consent, retention, purpose limitation, or complete data-flow compliance. |
| Canonical JSON report | Strong | Mature | Stable single source of truth for CLI, GUI, and derived formats. |
| SARIF / Markdown / HTML output | Strong | Mature enough | Derived from canonical report and suitable for CI/review workflows. |
| CLI surface | Strong | Mature | Best for automation, repeatable scanning, and report export. |
| GUI surface | Strong | Product-ready | Chinese-first, overview-first, linked reading experience with multi-format export. |
| Regression fixtures | Strong | Good discipline | v1/v2 fixtures cover important families, but v3 needs targeted OpenClaw control-plane fixtures. |

## Strong Areas

### OpenClaw-aware analysis

The current project understands OpenClaw-specific security boundaries rather than treating a skill as a generic Markdown file. Strong examples include:

1. source precedence and same-name shadowing
2. `metadata.openclaw` install and requirement fields
3. `command-dispatch: tool` and direct tool invocation
4. host-vs-sandbox split
5. env/API key reachability
6. attack paths that combine prompt, tool, secret, network, and install evidence

This is the main architectural advantage and should remain the center of v3.

### Explanation quality

Findings are generally explainable:

1. evidence excerpts are preserved
2. severity and confidence are explicit
3. OpenClaw-specific rationale is included
4. provenance and suppression are visible
5. report sections are machine-readable and human-readable

This is stronger than scanners that only print a rule id and a score.

### Report-first product shape

The canonical report is the stable contract. GUI, CLI, SARIF, Markdown, and HTML derive from the same report rather than each inventing separate logic. This should remain non-negotiable in v3.

### Safety boundary

The verifier is a guard, not an exploit runner. Runtime validation is guarded and does not execute untrusted installs or payloads. This boundary is a product strength, not a limitation to remove.

## Medium Areas

### Corpus coverage

Typed corpus assets now exist and drive independent threat/sensitive findings. The weakness is not architecture; it is coverage depth. The corpus should gain only targeted OpenClaw-specific families in v3:

1. control-plane env mutation
2. hidden direct tool authority
3. generated-skill/write-and-shadow patterns
4. install metadata plus remote download combinations
5. obfuscated instruction and role-boundary poisoning examples

V3 should avoid adding a large generic malware rule dump.

### Dependency audit

Dependency audit v1 is valuable because it catches weak pins, remote sources, registry hints, and install-chain dependency pull risk. It is still heuristic:

1. no live advisory lookup
2. no complete transitive solver
3. no package maintainer reputation model
4. no lockfile integrity verification beyond first-pass signals

That is acceptable. V3 should improve integration with OpenClaw install/control-plane context before attempting a full CVE platform.

### URL/API/source classification

The URL/API layer is useful for explaining external references, raw downloads, shortlinks, direct IPs, dynamic DNS, and known local seeds. It should continue to be described as a local hint layer. It should not claim authoritative reputation.

### Privacy review

The project can identify sensitive material, env access, external services, and source risk, but it does not yet answer higher-level privacy questions such as:

1. whether data collection matches stated purpose
2. whether consent is requested
3. whether deletion/export rights are documented
4. whether data retention is bounded

V3 can add a small OpenClaw-oriented data-use narrative, but full privacy compliance should remain out of scope.

## Weak Areas

### OpenClaw config/control-plane coverage

The project parses skill metadata well, but OpenClaw risk also lives in config and control-plane state:

1. `skills.entries.*.env`
2. `skills.entries.*.apiKey`
3. `metadata.openclaw.primaryEnv`
4. `skills.load.extraDirs`
5. per-agent skill allowlists
6. sandbox mode and elevated execution settings
7. dangerous env override attempts
8. gateway/tool config mutation instructions

Some of this is indirectly modeled today. V3 should make it first-class and reportable.

### Permission/capability manifest

The engine already knows many capability facts, but users need a single synthesized view:

1. what tools the skill can reach
2. what secrets it asks for or can reach
3. what binaries/config/env it requires
4. what URLs and dependencies it introduces
5. whether it is hidden from model prompt but still user-invocable
6. whether it runs on host, sandbox, or a split boundary

V3 should add a normalized capability manifest derived from existing analyzers, not a new business logic branch.

### Companion-document and indirect content poisoning

The scanner reads multiple text files and detects prompt/instruction signals, but OpenClaw skills often delegate behavior to:

1. README files
2. examples
3. setup docs
4. comments
5. external URLs
6. generated skill proposals

V3 should better label untrusted companion content and explain when it can influence tool use or install behavior.

### Ecosystem identity and source mismatch

The current source reputation layer is local and URL-based. It does not deeply model:

1. same-name skills across registries
2. source URL mismatch between homepage, repository, package, and install target
3. registry package pointing to missing or unrelated code
4. stale mirrors and identity drift
5. typosquatting beyond simple pattern hints

V3 should add offline, explainable identity-mismatch checks where evidence is present in the target. It should not become an online registry crawler.

## GUI / CLI / Report Surface vs Analysis Surface

### GUI/CLI/report surface

The product surface is now strong:

1. GUI is Chinese-first and suitable as the main product entrance.
2. CLI is stable for automation.
3. JSON is the canonical contract.
4. SARIF/Markdown/HTML are usable derived formats.
5. GUI exposes findings, paths, provenance, validation, dependency, source, API, and export flows.

### Analysis surface

The analysis surface is also strong, but not complete. V3 should be honest that:

1. the verifier is evidence-driven, not omniscient
2. no local static scan can prove a skill safe
3. no findings means no known evidence was detected, not no risk
4. runtime validation reduces uncertainty only inside guarded boundaries
5. local reputation hints are not live threat-intelligence verdicts

## Product Boundary: No Findings Does Not Mean No Risk

The product should explicitly state:

1. `allow` means the scanner did not find enough evidence to warn or block under current rules.
2. `warn` means evidence needs review before trust.
3. `block` means the scanner found hard-trigger or compound evidence that should prevent normal use.
4. A clean report is not certification, not a trust badge, and not a replacement for human review of high-risk skills.
5. The scanner is a verifier/guard for OpenClaw skill risk, not an exploit runner, not an online threat-intelligence authority, and not a full compliance auditor.

This aligns with Cisco AI Defense `skill-scanner`, whose README explicitly warns that no findings do not guarantee a skill is threat-free.

## V3 Direction From This Audit

V3 should focus on tightening OpenClaw-specific gaps rather than adding broad generic security scanning:

1. first-class OpenClaw config/control-plane audit
2. synthesized capability/permission manifest in canonical report and GUI
3. deeper companion-document and indirect instruction risk analysis
4. offline source identity and registry mismatch signals
5. targeted corpus additions and regression fixtures for the above

## Sources

1. [OpenClaw Skills documentation](https://docs.openclaw.ai/tools/skills)
2. [OpenClaw Skills Config documentation](https://docs.openclaw.ai/tools/skills-config)
3. [OpenClaw Sandboxing documentation](https://docs.openclaw.ai/gateway/sandboxing)
4. [Cisco AI Defense skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)
5. Existing project docs: `docs/openclaw-current-signals.md`, `docs/openclaw-threat-model.md`, `docs/v2-scope.md`
