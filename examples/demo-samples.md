# Demo Samples

## `benign`

- Purpose: show a low-risk workspace-only helper
- Current demo report: [benign.json](D:/漏扫skill/standalone-openclaw-skill-guard/examples/reports/benign.json)
- Current observed outcome: `allow`

## `high-risk`

- Purpose: show baseline hard-trigger behavior
- Current demo report: [high-risk.json](D:/漏扫skill/standalone-openclaw-skill-guard/examples/reports/high-risk.json)
- Current observed outcome: `block`

## `install-risk`

- Purpose: show install-chain extraction and origin-integrity findings
- Current demo report: [install-risk.json](D:/漏扫skill/standalone-openclaw-skill-guard/examples/reports/install-risk.json)
- Current observed outcome: install findings plus attack-path uplift and `block`

## `prompt-risk`

- Purpose: show prompt coercion, secret access guidance, and attack paths
- Current demo report: [prompt-risk.json](D:/漏扫skill/standalone-openclaw-skill-guard/examples/reports/prompt-risk.json)
- Current observed outcome: strong prompt findings, multiple attack paths, and `block`

## `precedence-shadowing`

- Purpose: show naming collision / precedence hints within scanned scope
- Current demo report: [precedence-shadowing.json](D:/漏扫skill/standalone-openclaw-skill-guard/examples/reports/precedence-shadowing.json)
- Current observed outcome: local collision findings with scope-aware wording and elevated verdict

## `runtime-refinement`

- Purpose: show that runtime facts can block or narrow static paths
- Current demo report: [runtime-refinement.json](D:/漏扫skill/standalone-openclaw-skill-guard/examples/reports/runtime-refinement.json)
- Current observed outcome: attack path remains visible, runtime validation marks constraints as blocked, and score is narrowed relative to a fully unconstrained path

## `suppression-audit`

- Purpose: show that suppression affects scoring without hiding evidence
- Current demo report: [suppression-audit.json](D:/漏扫skill/standalone-openclaw-skill-guard/examples/reports/suppression-audit.json)
- Current observed outcome: suppression matches and audit summary remain visible while evidence is preserved
