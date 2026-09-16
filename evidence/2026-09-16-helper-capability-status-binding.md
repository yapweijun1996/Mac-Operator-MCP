# Privileged helper capability/status binding

- Date: 2026-09-16
- Scope: L5 helper capability projection and authenticated runtime readback

## Implementation

`AllowlistedPrivilegedHelper` now snapshots its own-handler map, then derives
its `enabledCapabilities` and `available` state from that immutable registry.
The fail-closed adapter always
projects an empty capability set. The authenticated status path validates a
bounded, canonical capability list and compares it with the live adapter
before signing the status response.

The comparison is independent of request arguments and rejects both states:

- an enabled handler with a disabled or incomplete status projection;
- a status projection that advertises a capability without a matching
  allowlisted handler.

The package readback contract remains disabled-only until root-domain helper
installation, signing provenance, and host enablement evidence are accepted.

## Verification

Focused helper tests pass 17/17. They cover capability derivation, canonical
status validation, authenticated status readback, and a deliberate adapter /
status drift that returns stable `EXECUTION_FAILED` without advertising the
inconsistent state. Typecheck passes.

This evidence proves status/handler consistency only. It does not prove a
privileged operation, root LaunchDaemon, Developer ID signature, or physical
helper enablement.
