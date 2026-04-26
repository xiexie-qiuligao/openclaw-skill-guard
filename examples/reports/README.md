# Example Reports

These JSON files were generated from the inert demo fixtures under [fixtures/v1](../../fixtures/v1).

They are intended to show:

- what the CLI emits in v1
- how verdicts and scores look in practice
- how runtime refinement changes path status
- how suppression remains visible in audit output

Included reports:

- [benign.json](./benign.json)
- [high-risk.json](./high-risk.json)
- [install-risk.json](./install-risk.json)
- [prompt-risk.json](./prompt-risk.json)
- [precedence-shadowing.json](./precedence-shadowing.json)
- [runtime-refinement.json](./runtime-refinement.json)
- [suppression-audit.json](./suppression-audit.json)

V2 demo reports are also included from the inert fixture under [fixtures/v2/report-demo](../../fixtures/v2/report-demo):

- [v2-report-demo.json](./v2-report-demo.json)
- [v2-report-demo.sarif](./v2-report-demo.sarif)
- [v2-report-demo.md](./v2-report-demo.md)
- [v2-report-demo.html](./v2-report-demo.html)

The v2 demo is intended to show:

- threat corpus findings
- sensitive corpus findings
- dependency audit findings
- URL/API/source reputation summaries
- canonical-report-first derived exports

V3 demo reports are included from the inert fixture under [fixtures/v3/config-control-plane](../../fixtures/v3/config-control-plane):

- [v3-config-demo.json](./v3-config-demo.json)
- [v3-config-demo.sarif](./v3-config-demo.sarif)
- [v3-config-demo.md](./v3-config-demo.md)
- [v3-config-demo.html](./v3-config-demo.html)

The v3 demo is intended to show:

- OpenClaw config / control-plane audit findings
- capability and permission summary fields
- companion-doc and source-identity summary fields
- the same canonical-report-first derivation into SARIF, Markdown, and HTML
