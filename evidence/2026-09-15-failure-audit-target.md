# Failure audit target readback

Date: 2026-09-15

## Scope

Post-authorization failures now retain the Broker-normalized target in the
completion audit row. Invalid or unauthorized requests still use
`unresolved`; raw tool arguments are never copied into audit records.

## Implementation

`Broker.handle` captures `execution.auditTarget` (or the normalized target
kind/reference fallback) only after planning and target authorization succeed.
`auditFailure` accepts that bounded value and falls back to `unresolved` for
earlier failures. This preserves the existing decision/completion event model
while making a failed execution attributable to the target that the Broker
actually authorized.

## Verification

The existing post-authorization failure test now asserts both audit rows use
`host:broker` for the `mac_health` target. A temporary built-distribution
harness independently reproduced the signed request with an unknown argument:

```text
resultClass=PRECONDITION_FAILED
targets=["host:broker","host:broker"]
```

`npm run build` and `git diff --check` pass. The full broker test file was not
restarted because an existing long-running broker/persistence test process was
already active; the focused assertion remains queued for that process boundary.

## Residual risk

This is audit attribution evidence only. It does not close the broader audit,
runtime, physical-Mac, mutation-recovery, or independent P0/P1 release gates.
