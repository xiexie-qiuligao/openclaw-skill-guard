# Validation Adapter

The current release includes a controlled validation adapter plus a sandbox-backed guarded validator. Together they consume:

- static attack paths
- validation hooks
- runtime manifests
- safe local checks

and emit:

- validation results
- path validation status
- runtime refinement notes
- constraint effects
- environment blockers
- environment amplifiers
- runtime score adjustments
- guarded validation summaries and capability checks

## Current validation families

- permission validation
  - exec/process
  - network
  - write scope
  - browser/web fetch
  - gateway/nodes/cron
- environment validation
  - host vs sandbox
  - home-directory access
  - mounted secrets/configs
  - workspace-only vs broader writable scope
- prerequisite validation
  - expected env vars
  - expected config files
  - secret-access surfaces
- scope validation
  - precedence missing roots
- guarded capability validation
  - exec / process / shell / child-process availability
  - write / edit / apply-patch availability
  - browser / web-fetch / gateway / nodes / cron availability

## Safety boundary

The adapter is intentionally:

- non-executing
- non-networking against unknown targets
- non-installing
- non-payload-running

It is a controlled checker, not a sandbox exploit runner.

## Planned vs guarded behavior in practice

- `planned`
  - records what should be checked
  - preserves uncertainty when runtime facts are missing
- `guarded`
  - evaluates capability and scope constraints
  - marks paths as supported, narrowed, blocked, or still assumed
  - refines consequence and confidence
  - still does not run attacker-controlled code
