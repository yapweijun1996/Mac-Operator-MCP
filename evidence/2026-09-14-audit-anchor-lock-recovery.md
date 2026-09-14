# Audit Anchor Lock Recovery Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: host-only recovery primitive; no capability enablement

## Boundary

`recoverAuditAnchorLock` is not part of Broker startup or normal audit-anchor
publication. It requires a host-provided stopped-service readback callback and
the exact owner-only lock device/inode captured from the same operator readback.
It canonicalizes the protected parent, rejects symlinks and identity changes,
then uses the existing native descriptor-relative `unlinkat` plus parent
`fsync` boundary. The result must identify the exact removed lock and a
postcondition readback must prove the pathname is absent.

No PID, lock age, or caller-supplied path heuristic can authorize recovery.
If the stopped-service callback fails, the lock remains untouched. Startup
continues to fail closed on an existing lock.

## Verification

```text
npm run build
node --test --test-name-pattern='stopped-service audit anchor recovery' packages/broker/dist/audit-anchor.test.js
```

Observed result on Darwin: 3/3 focused recovery tests passed. The full
`MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test` regression also passed
483/484 with one explicit skip. The focused tests cover exact identity
removal, replacement-lock rejection, and the running-service stop-gate
refusal.

## Limits

This proves the repository-level exact-target recovery primitive and its native
filesystem boundary. It does not prove installed operator authentication,
launchd stop orchestration, external immutable anchoring, or production
Keychain/Developer ID deployment. The recovery function remains host-only and
must be called under a separately authenticated operator workflow.
