# Validation Adapter

Phase 7 adds a controlled validation adapter that consumes:

- static attack paths
- validation hooks
- runtime manifests
- safe local checks

and emits:

- validation results
- path validation status
- runtime refinement notes
- constraint effects
- environment blockers
- environment amplifiers
- runtime score adjustments

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
- prerequisite validation
  - expected env vars
  - expected config files
  - secret-access surfaces
- scope validation
  - precedence missing roots

## Safety boundary

The adapter is intentionally:

- non-executing
- non-networking against unknown targets
- non-installing
- non-payload-running

It is a controlled checker, not a sandbox exploit runner.
