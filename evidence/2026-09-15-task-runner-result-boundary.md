# Task-runner result boundary evidence

Date: 2026-09-15
Source commit: `0c486c9`
Host: physical Darwin arm64 development host

## Boundary

Task isolation proofs and runner results are host-controlled authority and
postcondition data. They must be plain data records, must not accept unknown or
inherited fields, and must remain bounded before the Broker persists or audits
them.

## Implementation

`validateTaskIsolationProof` now rejects non-plain records before reading any
authority field. `validateTaskExecutionResult` requires the exact top-level
result shape, a plain verification record with only `status` and optional
`summary`, a combined 2 MiB UTF-8 output cap, and a bounded duration. The
validator returns a sanitized validated shape rather than retaining caller
references.

## Verification

- The focused task-runner and guest-attestation suite passes 19/19.
- Hostile tests cover inherited records, accessors, symbols, unknown fields,
  oversized output, and optional verification summaries.
- The non-overlapping package regression passes 512 total (506 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This closes local task-result representation integrity only. It does not prove
the deprecated sandbox-exec boundary, credential/persistence isolation, VM
boot or guest isolation, production signing, or `mac_task_run` enablement.

## Rollback

Revert commit `0c486c9`. No MCP wire schema or persisted ledger format changes
are introduced.
