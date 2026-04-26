# openclaw-skill-guard report

## Summary

- Target: `fixtures\v3\config-control-plane`
- Verdict: `block`
- Score: `5`
- Blocked: `yes`
- Findings: `14`
- Attack paths: `0`
- External references: `0`

## V2 Summaries

- Threat corpus: Threat corpus produced 1 explainable finding(s) after overlap control against baseline and prompt analyzers.
- Sensitive data: Sensitive-data corpus produced 3 explainable inline-material finding(s).
- Dependency audit: No supported dependency manifests were discovered.
- API classification: No external references were extracted from scanned text artifacts.
- Source reputation: No source or domain reputation hints were generated.

## V3 OpenClaw Summaries

- Config / control-plane: OpenClaw config/control-plane audit generated 10 finding(s) from local evidence.
- Capability manifest: Capability manifest summarized 3 capability entry or entries, 0 risky combination(s), and 0 mismatch note(s).
- Companion docs: Scanned 1 companion document(s) with no companion-doc audit findings.
- Source identity: No offline source identity mismatch signals were generated from local evidence.

### Config / control-plane risky bindings

- NODE_OPTIONS
- sandbox disabled
- skills.entries.*.apiKey
- skills.entries.*.env
- skills.load.extraDirs

### Capability manifest entries

- `secret:DEMO_API_TOKEN` | `inferred` | `secret_reachability`: Declared via metadata.openclaw.primaryEnv.
- `env:DEMO_API_TOKEN` | `required` | `metadata.openclaw.requires.env`: The skill metadata declares an environment requirement.
- `config:skills.entries.config-demo.apiKey` | `required` | `metadata.openclaw.requires.config`: The skill metadata declares a configuration requirement.

## Findings

### OpenClaw skill config may contain a plaintext apiKey binding (`openclaw_config.plaintext_api_key`)

- Severity: `high`
- Confidence: `high`
- Category: `openclaw_config.plaintext_api_key`
- Location: `fixtures\v3\config-control-plane\README.md`:3

The scanned content references `skills.entries.*.apiKey`. In OpenClaw this is a host-side secret injection surface, not just descriptive metadata.

Analyst notes:
- Review whether the referenced config is operational or only documentation.
- If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.

### OpenClaw skill config may contain a plaintext apiKey binding (`openclaw_config.plaintext_api_key`)

- Severity: `high`
- Confidence: `high`
- Category: `openclaw_config.plaintext_api_key`
- Location: `fixtures\v3\config-control-plane\SKILL.md`:4

The scanned content references `skills.entries.*.apiKey`. In OpenClaw this is a host-side secret injection surface, not just descriptive metadata.

Analyst notes:
- Review whether the referenced config is operational or only documentation.
- If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.

### OpenClaw skill config may contain a plaintext apiKey binding (`openclaw_config.plaintext_api_key`)

- Severity: `high`
- Confidence: `high`
- Category: `openclaw_config.plaintext_api_key`
- Location: `fixtures\v3\config-control-plane\openclaw.json`:5

The scanned content references `skills.entries.*.apiKey`. In OpenClaw this is a host-side secret injection surface, not just descriptive metadata.

Analyst notes:
- Review whether the referenced config is operational or only documentation.
- If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.

### Control-plane config references a dangerous environment override (`openclaw_config.dangerous_env_override`)

- Severity: `high`
- Confidence: `high`
- Category: `openclaw_config.dangerous_env_override`
- Location: `fixtures\v3\config-control-plane\openclaw.json`:7

The content references `NODE_OPTIONS`, an environment name that can alter OpenClaw, interpreter startup, or host control-plane behavior.

Analyst notes:
- Review whether the referenced config is operational or only documentation.
- If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.

### Threat corpus matched openclaw_control_plane (`corpus.threat.openclaw-config-mutation`)

- Severity: `high`
- Confidence: `high`
- Category: `threat_corpus`
- Location: `fixtures\v3\config-control-plane\SKILL.md`:9

Typed threat corpus entry `v3.threat.openclaw_config_mutation` matched this text as `openclaw_control_plane`. Instruction or documentation attempts to mutate OpenClaw config/control-plane state.

Analyst notes:
- corpus entry: v3.threat.openclaw_config_mutation
- asset: threat-corpus-v2.yaml
- provenance: docs/v3-openclaw-gap-analysis.md
- false-positive note: Benign setup documentation can mention config keys; escalate only when text is operative.

### Skill content instructs mutation of OpenClaw control-plane configuration (`openclaw_config.control_plane_mutation`)

- Severity: `high`
- Confidence: `medium`
- Category: `openclaw_config.control_plane_mutation`
- Location: `fixtures\v3\config-control-plane\SKILL.md`:9

The text tells the operator or agent to edit OpenClaw config, env, trust roots, sandbox policy, or gateway/tool settings. Configuration mutation is an OpenClaw control-plane authority surface.

Analyst notes:
- Review whether the referenced config is operational or only documentation.
- If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.

### OpenClaw skill config exposes a host env binding surface (`openclaw_config.secret_binding`)

- Severity: `medium`
- Confidence: `high`
- Category: `openclaw_config.secret_binding`
- Location: `fixtures\v3\config-control-plane\README.md`:3

The scanned content references `skills.entries.*.env`, which can bind per-skill environment values into the OpenClaw host process for a run.

Analyst notes:
- Review whether the referenced config is operational or only documentation.
- If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.

### OpenClaw skill config exposes a host env binding surface (`openclaw_config.secret_binding`)

- Severity: `medium`
- Confidence: `high`
- Category: `openclaw_config.secret_binding`
- Location: `fixtures\v3\config-control-plane\SKILL.md`:4

The scanned content references `skills.entries.*.env`, which can bind per-skill environment values into the OpenClaw host process for a run.

Analyst notes:
- Review whether the referenced config is operational or only documentation.
- If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.

### OpenClaw skill config exposes a host env binding surface (`openclaw_config.secret_binding`)

- Severity: `medium`
- Confidence: `high`
- Category: `openclaw_config.secret_binding`
- Location: `fixtures\v3\config-control-plane\SKILL.md`:9

The scanned content references `skills.entries.*.env`, which can bind per-skill environment values into the OpenClaw host process for a run.

Analyst notes:
- Review whether the referenced config is operational or only documentation.
- If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.

### OpenClaw skill loading expands to extra directories (`openclaw_config.extra_dir_trust_expansion`)

- Severity: `medium`
- Confidence: `medium`
- Category: `openclaw_config.extra_dir_trust_expansion`
- Location: `fixtures\v3\config-control-plane\openclaw.json`:12

`skills.load.extraDirs` can introduce additional low-precedence skill roots; broad or unreviewed paths can change the effective skill supply chain.

Analyst notes:
- Review whether the referenced config is operational or only documentation.
- If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.

### OpenClaw sandboxing appears disabled or bypassed (`openclaw_config.sandbox_disabled`)

- Severity: `medium`
- Confidence: `medium`
- Category: `openclaw_config.sandbox_disabled`
- Location: `fixtures\v3\config-control-plane\openclaw.json`:15

The scanned content suggests sandbox execution may be disabled. That changes OpenClaw risk from sandbox-contained to host-reachable.

Analyst notes:
- Review whether the referenced config is operational or only documentation.
- If operational, correlate this binding with reachable tools, external references, and host-vs-sandbox consequence.

### Example-like openclaw_config_secret pattern needs review (`corpus.sensitive.openclaw-api-key-binding`)

- Severity: `low`
- Confidence: `medium`
- Category: `sensitive_corpus`
- Location: `fixtures\v3\config-control-plane\README.md`:3

Sensitive-data corpus entry `v3.sensitive.openclaw_api_key_binding` matched `openclaw_config_secret` material, but the surrounding text also looks like documentation, placeholders, or fake values. The finding is kept as a review signal rather than a high-confidence live-secret exposure.

Analyst notes:
- corpus entry: v3.sensitive.openclaw_api_key_binding
- asset: sensitive-data-corpus-v2.yaml
- sensitive category: openclaw_config_secret
- provenance: docs/v3-openclaw-gap-analysis.md
- context shaping: example/fake markers lowered confidence and severity for review-oriented handling.
- false-positive note: Placeholder examples should be downgraded when clearly inert and not paired with real-looking values.

### Example-like openclaw_config_secret pattern needs review (`corpus.sensitive.openclaw-api-key-binding`)

- Severity: `low`
- Confidence: `medium`
- Category: `sensitive_corpus`
- Location: `fixtures\v3\config-control-plane\SKILL.md`:4

Sensitive-data corpus entry `v3.sensitive.openclaw_api_key_binding` matched `openclaw_config_secret` material, but the surrounding text also looks like documentation, placeholders, or fake values. The finding is kept as a review signal rather than a high-confidence live-secret exposure.

Analyst notes:
- corpus entry: v3.sensitive.openclaw_api_key_binding
- asset: sensitive-data-corpus-v2.yaml
- sensitive category: openclaw_config_secret
- provenance: docs/v3-openclaw-gap-analysis.md
- context shaping: example/fake markers lowered confidence and severity for review-oriented handling.
- false-positive note: Placeholder examples should be downgraded when clearly inert and not paired with real-looking values.

### Example-like openclaw_config_secret pattern needs review (`corpus.sensitive.openclaw-api-key-binding`)

- Severity: `low`
- Confidence: `medium`
- Category: `sensitive_corpus`
- Location: `fixtures\v3\config-control-plane\openclaw.json`:5

Sensitive-data corpus entry `v3.sensitive.openclaw_api_key_binding` matched `openclaw_config_secret` material, but the surrounding text also looks like documentation, placeholders, or fake values. The finding is kept as a review signal rather than a high-confidence live-secret exposure.

Analyst notes:
- corpus entry: v3.sensitive.openclaw_api_key_binding
- asset: sensitive-data-corpus-v2.yaml
- sensitive category: openclaw_config_secret
- provenance: docs/v3-openclaw-gap-analysis.md
- context shaping: example/fake markers lowered confidence and severity for review-oriented handling.
- false-positive note: Placeholder examples should be downgraded when clearly inert and not paired with real-looking values.

## Context

### Parsing

Parsed 1 skill file(s); malformed frontmatter detected in 0 file(s).

### Metadata

metadata.openclaw present in 1 skill(s) and normalized successfully in 1 skill(s).

### Install

No install metadata or high-confidence manual install patterns were extracted.

### Prompt

No prompt-injection or indirect-instruction signals were detected across parsed skills.

### Threat corpus

Threat corpus produced 1 explainable finding(s) after overlap control against baseline and prompt analyzers.

### Sensitive data

Sensitive-data corpus produced 3 explainable inline-material finding(s).

### Dependency audit

No supported dependency manifests were discovered.

### API classification

No external references were extracted from scanned text artifacts.

### Source reputation

No source or domain reputation hints were generated.

### OpenClaw config / control-plane

OpenClaw config/control-plane audit generated 10 finding(s) from local evidence.

### Capability manifest

Capability manifest summarized 3 capability entry or entries, 0 risky combination(s), and 0 mismatch note(s).

### Companion docs

Scanned 1 companion document(s) with no companion-doc audit findings.

### Source identity

No offline source identity mismatch signals were generated from local evidence.

## Attack Paths

No attack paths.

## Validation And Consequence

- Runtime manifest: No runtime manifest supplied; runtime refinement is based on safe local checks and unknowns remain explicit.
- Guarded validation: Guarded validation collected 8 capability check(s), 7 assumption check(s), and refined 0 attack path(s) without executing untrusted code.
- Consequence summary: Execution surface is Sandbox; file-system=1, credentials=1, network=1, persistence=1. Runtime refinement applied with environment=Unknown, network=Unknown, writable_scope=Unknown.
- Host vs sandbox split: Phase 7 runtime validation refined host-vs-sandbox split using manifest-backed permission and environment facts.

## External References

No external references.

## Score And Provenance

- `openclaw_config.plaintext_api_key`: Finding `OpenClaw skill config may contain a plaintext apiKey binding` contributes a high severity penalty. (-20)
- `openclaw_config.plaintext_api_key`: Finding `OpenClaw skill config may contain a plaintext apiKey binding` contributes a high severity penalty. (-20)
- `openclaw_config.plaintext_api_key`: Finding `OpenClaw skill config may contain a plaintext apiKey binding` contributes a high severity penalty. (-20)
- `openclaw_config.dangerous_env_override`: Finding `Control-plane config references a dangerous environment override` contributes a high severity penalty. (-20)
- `corpus.threat.openclaw-config-mutation`: Corpus-backed threat finding `Threat corpus matched openclaw_control_plane` contributed a 20-point penalty at high severity because corpus entry: v3.threat.openclaw_config_mutation. (-20)
- `openclaw_config.control_plane_mutation`: Finding `Skill content instructs mutation of OpenClaw control-plane configuration` contributes a high severity penalty. (-15)
- `openclaw_config.secret_binding`: Finding `OpenClaw skill config exposes a host env binding surface` contributes a medium severity penalty. (-10)
- `openclaw_config.secret_binding`: Finding `OpenClaw skill config exposes a host env binding surface` contributes a medium severity penalty. (-10)
- `openclaw_config.secret_binding`: Finding `OpenClaw skill config exposes a host env binding surface` contributes a medium severity penalty. (-10)
- `openclaw_config.extra_dir_trust_expansion`: Finding `OpenClaw skill loading expands to extra directories` contributes a medium severity penalty. (-8)
- `openclaw_config.sandbox_disabled`: Finding `OpenClaw sandboxing appears disabled or bypassed` contributes a medium severity penalty. (-8)
- `corpus.sensitive.openclaw-api-key-binding`: Inline sensitive-material finding `Example-like openclaw_config_secret pattern needs review` contributed a 4-point penalty at low severity because sensitive category: openclaw_config_secret. (-4)
- `corpus.sensitive.openclaw-api-key-binding`: Inline sensitive-material finding `Example-like openclaw_config_secret pattern needs review` contributed a 4-point penalty at low severity because sensitive category: openclaw_config_secret. (-4)
- `corpus.sensitive.openclaw-api-key-binding`: Inline sensitive-material finding `Example-like openclaw_config_secret pattern needs review` contributed a 4-point penalty at low severity because sensitive category: openclaw_config_secret. (-4)
- `confidence_adjustment`: Scope-limited or lower-confidence context slightly reduced the overall escalation. (5)

Confidence factors:
- `corpus.threat.openclaw-config-mutation`: Typed corpus entries carry explicit provenance and false-positive notes, which makes the finding easier to audit and explain. (1)
- `corpus.sensitive.openclaw-api-key-binding`: Typed corpus entries carry explicit provenance and false-positive notes, which makes the finding easier to audit and explain. (1)
- `corpus.sensitive.openclaw-api-key-binding`: Typed corpus entries carry explicit provenance and false-positive notes, which makes the finding easier to audit and explain. (1)
- `corpus.sensitive.openclaw-api-key-binding`: Typed corpus entries carry explicit provenance and false-positive notes, which makes the finding easier to audit and explain. (1)
- `corpus.threat.openclaw-config-mutation`: The finding comes from typed threat corpus entry `v3.threat.openclaw_config_mutation` with direct text evidence. (1)

Provenance notes:
- `openclaw_config.plaintext_api_key`: Finding provenance records where the signal originated and which longer-lived risk family it belongs to.
- `openclaw_config.plaintext_api_key`: Finding provenance records where the signal originated and which longer-lived risk family it belongs to.
- `openclaw_config.plaintext_api_key`: Finding provenance records where the signal originated and which longer-lived risk family it belongs to.
- `openclaw_config.dangerous_env_override`: Finding provenance records where the signal originated and which longer-lived risk family it belongs to.
- `corpus.threat.openclaw-config-mutation`: Threat corpus provenance records the exact typed entry, asset file, and adapted reference that produced this additive finding.
- `openclaw_config.control_plane_mutation`: Finding provenance records where the signal originated and which longer-lived risk family it belongs to.
- `openclaw_config.secret_binding`: Finding provenance records where the signal originated and which longer-lived risk family it belongs to.
- `openclaw_config.secret_binding`: Finding provenance records where the signal originated and which longer-lived risk family it belongs to.
- `openclaw_config.secret_binding`: Finding provenance records where the signal originated and which longer-lived risk family it belongs to.
- `openclaw_config.extra_dir_trust_expansion`: Finding provenance records where the signal originated and which longer-lived risk family it belongs to.
- `openclaw_config.sandbox_disabled`: Finding provenance records where the signal originated and which longer-lived risk family it belongs to.
- `corpus.sensitive.openclaw-api-key-binding`: Sensitive-data corpus provenance records the exact typed entry and whether the analyzer treated the match as high-value inline material or example-like review content.
- `corpus.sensitive.openclaw-api-key-binding`: Sensitive-data corpus provenance records the exact typed entry and whether the analyzer treated the match as high-value inline material or example-like review content.
- `corpus.sensitive.openclaw-api-key-binding`: Sensitive-data corpus provenance records the exact typed entry and whether the analyzer treated the match as high-value inline material or example-like review content.
- `corpus.threat.openclaw-config-mutation`: This finding came from typed corpus entry `v3.threat.openclaw_config_mutation` in `threat-corpus-v2.yaml`.
- `corpus.sensitive.openclaw-api-key-binding`: This finding came from typed corpus entry `v3.sensitive.openclaw_api_key_binding` in `sensitive-data-corpus-v2.yaml`.
- `corpus.sensitive.openclaw-api-key-binding`: This finding came from typed corpus entry `v3.sensitive.openclaw_api_key_binding` in `sensitive-data-corpus-v2.yaml`.
- `corpus.sensitive.openclaw-api-key-binding`: This finding came from typed corpus entry `v3.sensitive.openclaw_api_key_binding` in `sensitive-data-corpus-v2.yaml`.
- `openclaw_config.NODE_OPTIONS`: Control-plane audit observed `NODE_OPTIONS` in scanned local evidence.
- `openclaw_config.sandbox disabled`: Control-plane audit observed `sandbox disabled` in scanned local evidence.
- `openclaw_config.skills.entries.*.apiKey`: Control-plane audit observed `skills.entries.*.apiKey` in scanned local evidence.
- `openclaw_config.skills.entries.*.env`: Control-plane audit observed `skills.entries.*.env` in scanned local evidence.
- `openclaw_config.skills.load.extraDirs`: Control-plane audit observed `skills.load.extraDirs` in scanned local evidence.
- `threat-corpus-v2.yaml`: Loaded corpus asset `threat-corpus-v2.yaml` with 7 entry or entries.
- `sensitive-data-corpus-v2.yaml`: Loaded corpus asset `sensitive-data-corpus-v2.yaml` with 5 entry or entries.
- `api-taxonomy-v2.yaml`: Loaded corpus asset `api-taxonomy-v2.yaml` with 9 entry or entries.
- `reputation-seeds-v2.yaml`: Loaded corpus asset `reputation-seeds-v2.yaml` with 7 entry or entries.
