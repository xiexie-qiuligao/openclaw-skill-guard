# Suppression And Audit

Phase 7 extends the Phase 6 workflow with lifecycle and runtime-awareness.

## Current capabilities

- suppress by finding id
- suppress by attack-path id
- optionally narrow by target path substring
- reason required
- note supported
- high-risk suppressions remain visible in audit output
- optional expiration date
- validation-aware audit notes when a suppressed path was already runtime-validated

## Design constraints

- suppressed findings remain in the report with suppression status
- suppressed attack paths remain visible in the report and in suppression matches
- suppressed content is removed from final scoring, not erased from evidence
- high-risk suppression emits audit records
- expired suppressions remain visible and should be reviewed
- validated high-risk suppressions emit stronger audit notes

## Why this matters

OpenClaw-aware verification needs an operator escape hatch for reviewed exceptions, but recent hardening and scanner lessons show that broad hidden allowlists are dangerous.

This is why Phase 6 uses:

- minimal scope
- explicit reason
- audit visibility
- preserved evidence and provenance

instead of a blanket ignore mechanism.
