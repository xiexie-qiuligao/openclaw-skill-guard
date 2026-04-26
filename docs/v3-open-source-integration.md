# V3 Open-source Integration Review

Date: 2026-04-24

This document compares open-source and public skill-security projects as v3 references. The goal is to borrow durable assets, explanation patterns, report ideas, and regression cases without replacing the current Rust verifier architecture.

## Integration Principles

V3 should prefer:

1. corpus assets
2. report and policy patterns
3. false-positive and regression organization
4. OpenClaw-specific risk examples
5. local, explainable analysis

V3 should avoid:

1. shell-script orchestration as the core architecture
2. cloud/LLM verdicts as hard truth
3. online threat intelligence as a required dependency
4. dynamic exploit execution
5. simple additive score replacement
6. marketplace trust labels as final security decisions

## Project-by-project Review

## 1. `cls-certify`

Reference: [CatREFuse/cls-certify](https://github.com/CatREFuse/cls-certify)

### What it offers

`cls-certify` is valuable mainly because of its asset and report thinking. Its public docs emphasize:

1. six dimensions: static analysis, dynamic behavior, dependency audit, network traffic, privacy/compliance, source reputation/threat intelligence
2. threat and sensitive data pattern references
3. API/domain classification
4. Markdown, JSON, SARIF, and HTML output
5. structured report protocol
6. false-positive filtering and review concepts

### Directly reusable

1. reference-asset categories already validated in v2:
   - threat patterns
   - sensitive data patterns
   - API classification
   - known malicious patterns
   - CVE source inventory
   - GDPR checklist ideas
2. report section ideas:
   - external API inventory
   - source/reputation summary
   - structured recommendations
3. regression fixture ideas around obfuscation, hidden prompt instructions, and install/download chains

### Adapt and absorb

1. dynamic-download depth concepts should become typed OpenClaw install-chain and URL/source signals
2. prompt poisoning families should be encoded in corpus and instruction analyzers, not shell regex arrays
3. privacy checklist ideas should become a small data-use narrative, not a compliance product
4. score explanation should inspire narrative improvements, not replace compound scoring

### Learn only

1. six-dimension coverage as a mental map
2. teamized asset/report organization
3. candidate-to-review workflow

### Do not adopt

1. shell scripts as the primary engine
2. hard-coded trust tiers as final truth
3. additive deduction scoring
4. unsafe dynamic execution claims without bounded verifier semantics
5. release hygiene issues such as local-machine paths in examples

## 2. `agent-skills-guard`

Reference: [bruc3van/agent-skills-guard](https://github.com/bruc3van/agent-skills-guard)

### What it offers

`agent-skills-guard` is a desktop application for visual management and security scanning of Claude/agent skills. Its README presents:

1. lifecycle management: discover, install, update, uninstall
2. a visual marketplace/product experience
3. eight risk categories and twenty-two hard-trigger protections
4. symlink detection
5. parallel scanning
6. score, report, and confidence labels
7. bilingual UI

### Directly reusable

1. product-positioning lessons for GUI/UX
2. risk-category names as comparative vocabulary
3. test-skill ideas for destructive operations, prompt injection, and secret leakage

### Adapt and absorb

1. "installed skill overview" can inspire future batch GUI views, but not v3 core
2. symlink and path-boundary concern should remain part of inventory/integrity checks
3. hard-trigger labeling can improve report language where current findings already block

### Learn only

1. Chinese-first desktop product presentation
2. user-friendly lifecycle framing
3. marketplace scan-before-install UX

### Do not adopt

1. marketplace manager as the product center
2. install/uninstall/update workflow inside this verifier
3. flat 0-100 deduction scoring as the security model
4. broad GUI platform work in v3

## 3. Cisco AI Defense `skill-scanner`

Reference: [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)

### What it offers

Cisco's scanner is the strongest technical comparison point. Its README describes best-effort detection for AI agent skills using pattern-based detection, YAML/YARA, LLM-as-judge, behavioral dataflow, false-positive filtering, policy tuning, SARIF, GitHub Actions, and CI exit codes. It also explicitly states that no findings do not guarantee a skill is threat-free.

### Directly reusable

1. product boundary wording: no findings does not mean no risk
2. CI/SARIF positioning
3. policy-preset vocabulary as future design input
4. taxonomy/report documentation structure

### Adapt and absorb

1. behavioral dataflow idea should map into the existing attack-path graph rather than a new engine
2. meta-analyzer/false-positive filtering should map into confidence factors and suppression/audit
3. rule-pack extensibility should become typed corpus assets and provenance, not arbitrary plugin execution
4. trigger specificity can help reduce vague-description false positives

### Learn only

1. multi-engine architecture as a coverage model
2. documented limitations and human-review stance
3. CI policy ergonomics

### Do not adopt

1. cloud scanning as a required path
2. VirusTotal upload or external service calls by default
3. LLM verdicts as hard truth
4. custom analyzer plugin architecture that bypasses the Rust verifier boundary
5. Python scanner replacement for the current core

## 4. `security-skill-scanner`

Reference: public ClawHub/AGNXI listings for `security-skill-scanner`

### What it offers

Public listings describe a skill scanner for ClawdHub/OpenClaw skills with:

1. pattern detection for credential theft, command injection, network exfiltration, and suspicious downloads
2. whitelist management
3. permission manifests and "Isnad" chain ideas
4. pre-install hooks that block suspicious skills
5. daily markdown/JSON reports
6. Moltbook/security-feed monitoring

Some listings also warn about package/content mismatch, such as instructions referencing local scripts that are not bundled.

### Directly reusable

1. permission-manifest idea as a v3 capability manifest seed
2. package/content mismatch as a regression fixture family
3. whitelist rationale as an analogy to audited suppressions

### Adapt and absorb

1. pre-install gate concept should become GUI/CLI guidance and report verdicts, not shell wrappers
2. permission manifests should be generated from canonical analyzer evidence
3. whitelist should map to suppression/audit with provenance, not broad trust bypass

### Learn only

1. "scan before install" workflow language
2. recurring report concept for future automation

### Do not adopt

1. cron jobs or persistent monitors
2. hard-coded environment paths
3. shell wrapper replacement for package/install commands
4. marketplace whitelist as final trust
5. Moltbook monitoring as core verifier functionality

## 5. `skillguard`

Reference: [bossondehiggs/skillguard](https://github.com/bossondehiggs/skillguard)

### What it offers

`skillguard` is a simple JavaScript security scanner for OpenClaw skill files. Its README lists detection for hardcoded secrets, private keys, shell injection, prompt injection, data exfiltration, eval, base64 obfuscation, suspicious URLs, file writes, network requests, child process execution, and disabled validation. It provides JSON output, severity filtering, verbose mode, and a 0-100 score.

### Directly reusable

1. simple CLI ergonomics as a usability reference
2. small example-output style for concise findings
3. detection family checklist for regression comparison

### Adapt and absorb

1. obfuscation families can become targeted corpus entries
2. severity filters are already broadly covered by GUI/CLI report workflows

### Learn only

1. low-friction command UX
2. concise report summaries

### Do not adopt

1. shallow file-level scoring
2. single-file scanner assumptions
3. lack of OpenClaw precedence/config/host-sandbox modeling
4. JavaScript scanner replacement for Rust core

## 6. `caterpillar`

Reference: [alice-dot-io/caterpillar](https://github.com/alice-dot-io/caterpillar)

### What it offers

`caterpillar` is a TypeScript security scanning library for AI agent skill files. Its README describes offline pattern matching, optional OpenAI mode, optional Alice API mode, JSON/CSV output, CLI and library APIs, A-F grading, and detection families including credential theft, data exfiltration, persistence, crypto wallet theft, network attacks, code obfuscation, broad permissions, and supply-chain attacks.

### Directly reusable

1. detection family checklist for corpus gap review
2. offline mode as a product-boundary reference
3. library/API framing as a reminder to keep the Rust core embeddable

### Adapt and absorb

1. supply-chain and obfuscation families should become targeted corpus and dependency/source fixtures
2. "broad permissions" should map to OpenClaw capability manifest and config audit
3. A-F grade explanations can inspire user-facing narratives while preserving current verdict/score

### Learn only

1. scan-mode ladder as product language
2. programmatic scanner API shape
3. concise install-before-use positioning

### Do not adopt

1. remote Alice API dependency
2. OpenAI/LLM mode as default or hard gate
3. `curl | sh` installer pattern as recommended release posture
4. A-F score replacement
5. TypeScript engine replacement

## Cross-project Synthesis

### Assets worth borrowing

1. OpenClaw control-plane threat patterns
2. obfuscation and hidden instruction patterns
3. source mismatch/package mismatch fixtures
4. permission/capability manifest vocabulary
5. false-positive examples for docs and sample skills

### Report ideas worth borrowing

1. explicit "no findings does not mean no risk" section
2. capability summary
3. scan policy/coverage statement
4. CI/SARIF language
5. concise "why this matters" per finding

### Engineering organization worth borrowing

1. typed rule/corpus provenance
2. fixture-first regression for every new family
3. policy and suppression as auditable inputs
4. derived outputs from a canonical report
5. clear limitations in docs

### Things that would break the current verifier if adopted

1. replacing Rust core with shell/Python/TypeScript scanners
2. replacing attack-path scoring with additive scores or A-F labels
3. treating remote/cloud/LLM analysis as required
4. executing untrusted installs for behavior observation
5. turning GUI into a marketplace manager
6. turning the product into a live threat-intelligence platform

## V3 Borrowing Decision

The most valuable v3 borrow is not more generic scanning. It is a focused fusion:

1. Cisco-style limitation language and policy/CI discipline
2. `security-skill-scanner` permission manifest idea
3. Caterpillar supply-chain/permission/obfuscation families
4. `cls-certify` asset/report organization
5. `agent-skills-guard` product-language clarity
6. `skillguard` simple severity-family ergonomics

All of these should be absorbed into the existing OpenClaw-aware verifier, not installed beside it as a second system.

## Sources

1. [CatREFuse/cls-certify](https://github.com/CatREFuse/cls-certify)
2. [bruc3van/agent-skills-guard](https://github.com/bruc3van/agent-skills-guard)
3. [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner)
4. [security-skill-scanner listing on AGNXI](https://agnxi.com/openclaw/skills/security-skill-scanner)
5. [Security Skill Scanner listing on ClawHub](https://clawhub.ai/skills/openclaw-skills-security-checker)
6. [bossondehiggs/skillguard](https://github.com/bossondehiggs/skillguard)
7. [alice-dot-io/caterpillar](https://github.com/alice-dot-io/caterpillar)
