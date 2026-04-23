# Validation Hooks

Phase 7 keeps the Phase 6 planning surface, then adds a controlled runtime-aware adapter that can execute safe checks against a runtime manifest and local environment facts.

## Purpose

Validation hooks and adapters exist to:

- confirm high-risk install or invocation paths without executing untrusted content
- reduce false positives when runtime prerequisites are uncertain
- expand precedence scope when the current scan lacks all OpenClaw roots
- clarify host-vs-sandbox assumptions that materially change consequence
- refine attack-path status with validated, partially validated, blocked, or still-assumed outcomes

They do **not** execute attacker-controlled code or replace the static verifier.

## Current hook families

- install-chain confirmation
  - confirm remote download plus execution
  - confirm integrity / checksum / pinning gaps
- direct dispatch confirmation
  - confirm whether `command-dispatch: tool` is truly required
  - review `command-tool` least-privilege choice
- runtime clarification
  - check host vs sandbox
  - check network / write access / mounted secrets / forwarded env
- precedence scope expansion
  - scan missing roots before treating a collision as globally resolved
- secret prerequisite confirmation
  - check whether the referenced env vars or secret-bearing files are actually present
- runtime-backed refinement
  - load execution environment and permission facts from a runtime manifest
  - combine those facts with safe local checks such as env/config presence

## Planned vs guarded mode

- `planned`
  - preserves the hook list and validation intent
  - records unknowns when runtime facts are absent
- `guarded`
  - still does not execute untrusted code
  - applies manifest-backed permission checks, scope checks, capability checks, and safe local presence checks
  - refines attack-path status and consequence output

## Why this follows recent OpenClaw signals

The hook system absorbs recent OpenClaw signals around:

- delegated tool authority
- install-path asymmetry
- prompt/runtime hardening
- scanner-boundary and scope limitations

But it turns them into durable validation families instead of issue-specific patches.
