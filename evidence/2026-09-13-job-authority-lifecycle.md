# Job authority lifecycle evidence

Date: 2026-09-13
Host: macOS arm64 development host
Scope: local synthetic Job Ledger and Broker admission fixtures; no production workers or user data

## Boundary exercised

The SQLite Job Ledger now applies authority changes and queued-job cancellation
in one `BEGIN IMMEDIATE` transaction. Disabling `global` or `mutations`
cancels all queued Jobs; disabling `process` or `network` cancels queued
`mac_task_run` Jobs while leaving unrelated queued write Jobs intact. The
current catalog has no queued GUI, destructive, or privileged executor, so
those switches do not cancel unrelated rows. Principal/session revocation
cancels matching queued ownership. Edge/key/approval/policy-signer revocation
conservatively cancels every queued Job because upstream provenance is not yet
stored in the Job row.

Each automatic cancellation persists `cancel_requested`, terminal `cancelled`
state, a stable authority reason, revision increment, and a hash-linked
completion audit event. Repeated switch/revocation changes do not recancel
terminal Jobs. Before a Broker starts a queued Job, it revalidates the current
session, revocations, policy version, target authorization, and kill switches;
an authority failure leaves the Job cancelled or queued-but-not-started and
does not dispatch the stale execution plan.

## Tests

- A single mutation-switch transaction cancels queued task and write Jobs and
  records one internal completion audit event per Job.
- A process-switch transaction cancels a queued task but leaves a queued write
  Job queued, demonstrating capability-family independence.
- Session revocation cancels only the matching session's queued Job and leaves
  another principal/session queued.
- The focused run and full suite pass with 246 tests.

## Limits and next gate

This is persistence and pre-start admission evidence, not proof of active
process termination. Durable worker leases, prior-process ownership across
restart, descendant cleanup, remote revocation propagation, and operator
control authorization remain open. New queued tool families must extend the
switch mapping before they can be enabled.

## Authority-audit addendum

Source revision `abe0409` extends the same SQLite transaction boundary so every
generic revocation and kill-switch change records a hash-linked `intent` and
`completion` event. Completion evidence includes the affected authority
identity, the persisted state, and the number of queued Jobs cancelled by the
change. Audit evidence is recursively redacted before hashing, and the tests
verify that a switch or revocation cannot commit without its matching audit
pair. This improves operator traceability but does not add an operator IPC
command or prove active process termination.

## Authority Control IPC addendum

Source revision `dd824b4` adds a separate Broker-local
Authority Control IPC. The native Unix peer boundary checks the configured
UID/GID/PID policy before handing a socket to the command parser. A 32-byte-or-
longer HMAC key, protocol version `0.1`, bounded JSON envelope, timestamp and
nonce-expiry window, strict operation/target allowlist, and durable
request/nonce admission are required. Only `set_switch` and `revoke` are
representable; there is no executable, shell, capability-grant, or MCP Edge
route. Switch changes require an `expectedDisabled` precondition, so a stale
operator command returns `CONFLICT` without overwriting newer authority state.

The command request ID is reused for the transactional authority audit pair.
Audit evidence contains a SHA-256 reason digest rather than operator reason
text. Focused native tests cover successful disable/re-enable and revocation,
queued-job cancellation, wrong-key rejection, stale-state rejection, denied
peer pre-parse drop, and replay rejection after SQLite/Broker restart.
The focused Authority Control IPC run passes 2/2 tests; the complete suite on
`dd824b4` passes 292/294 tests, with the two opt-in real-sandbox tests skipped
by default.

This remains a source-level control boundary. Protected key distribution,
installed startup/readback, active process-tree termination, remote propagation,
and an executable operator recovery/re-enable procedure remain open.
