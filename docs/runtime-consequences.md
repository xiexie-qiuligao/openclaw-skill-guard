# Runtime Consequences

Phase 7 keeps the typed Phase 6 consequence model, then refines it with runtime-manifest-backed permission and environment facts.

## Current modeled dimensions

- execution surface
  - host
  - sandbox
  - mixed
  - uncertain
- file-system consequence
  - local user files
  - home directory artifacts
  - workspace-only scope
  - mounted secrets or configs
  - unknown
- credential consequence
  - environment secrets
  - config-backed secrets
  - local secret files
  - auth-profile exposure
  - browser credential proximity
  - unknown
- network consequence
  - no meaningful egress
  - browser / web-fetch egress
  - exec / process egress
  - gateway / nodes / cron egress
  - unknown
- persistence consequence
  - none
  - local script drop
  - shell profile modification hint
  - scheduled task / cron hint
  - startup persistence hint
  - unknown

## Output shape

Phase 6 writes:

- `consequence_summary`
- `host_vs_sandbox_split`
- environment assumptions
- impact deltas

The scanner keeps evidence and inference separate so the report can explain why host impact may exceed sandbox impact, and which missing runtime assumptions would weaken the path.

## Phase 7 refinement

Runtime refinement now adjusts consequence and host/sandbox split when facts are available:

- host + home-directory access + mounted secrets
  - amplifies credential and file-system consequence
- sandbox + network disabled
  - narrows egress-dependent impact
- workspace-only writable scope
  - narrows mutation impact to project boundaries
- explicit permission denial
  - blocks or narrows path-level consequence without erasing static evidence

This is still a controlled model, not a dynamic execution sandbox. The report therefore distinguishes:

- static evidence
- validated runtime facts
- environment blockers
- environment amplifiers
- remaining unknowns
