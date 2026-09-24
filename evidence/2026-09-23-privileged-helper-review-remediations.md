# Privileged Helper Review Remediations

Date: 2026-09-23

Scope: MOP-073 read-only adversarial review of the privileged helper IPC,
native peer adapter loading, Job authority, and replay boundary.

This was a separate internal code review, not an external security audit or a
production-host acceptance review.

## Findings and code-level response

### P1 — Native module path replacement before `require`

The loader verified a native module by path, then loaded it by path. The digest
checks alone could not bind validation to the exact file later loaded. The
loader now rejects symlinked, group/world-writable, or untrusted-owner parent
directories across the full path. When running as root, every parent directory
must be root-owned; thus an unprivileged account cannot replace the module
between path validation and `require` in the intended installed layout.

The native loader remains path-based because Node's `require` does not accept an
already-open descriptor. Release evidence must still prove the installed module
and all parent directories are root-owned. A writable or user-owned path fails
closed. The added regression rejects a protected module file under a
group/world-writable parent.

### P2 — Privileged authority outlived its Job lease

Broker authority now checks the persisted lease owner/token presence, running
state, cancellation marker, and expiry without exposing the lease token. The
Broker command factory also caps the signed helper command expiry at the active
Job lease deadline. Subsequent authority polls reject a command after lease
expiry, and the helper's existing poll path sets its cancellation fence;
uncertain in-flight work remains `UNKNOWN_OUTCOME` for readback rather than
being replayed.

Regression coverage keeps approval active while advancing past a short Job
lease, verifies authorization before expiry and denial afterward, and asserts
the signed command expires at the lease deadline.

### P2 — Replay guard durability was implicit

Replay guards now declare `durability` as `durable` or `process-local`. The
in-memory guard is explicitly process-local. Any helper IPC server or runtime
with an enabled privileged adapter rejects an unmarked/process-local guard
before dispatch or startup. The `BrokerStore` guard identifies its durable
ledger implementation, and its existing reopen test proves Broker-side replay
state survives process restart.

The durability marker is a contract, not proof that an arbitrary injected
implementation actually persists. The root-only key-material startup still
requires a production-owned persistent store to be supplied and validated;
that installed wiring has not been accepted or deployed.

## Verification

- `npm run build` passed.
- Focused peer-credentials, helper, runtime, Broker dispatch, service-inspector,
  and service-control tests passed 68/68.
- Full `npm test` passed 1,183/1,198 tests, with 15 skipped and 0 failures.
- Existing helper authority-poll regression verifies Broker denial during
  execution cannot produce success; the new lease regression verifies the
  denial condition is reached after expiry.
- No helper was installed or enabled. No host service, credential, policy,
  launchd state, or permission changed.

## Remaining release gates

The helper remains disabled by default. Root-owned installed-path evidence,
production persistent replay-guard wiring and restart validation, Developer ID
provenance, root-domain installation/readback, rollback acceptance, and
external independent security review remain open. VT-PRIV-01 therefore remains
`BLOCKED`; these source-level regressions do not constitute production proof.
