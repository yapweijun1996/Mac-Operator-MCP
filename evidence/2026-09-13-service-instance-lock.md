# Broker service instance-lock evidence

- Source commit: `0c34c65`
- Working tree: clean before this evidence document update
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Contract/policy: tool contracts `0.1`; Broker policy fixtures `policy-0.1`
- Scope: packaged Broker startup serialization and stale-lock recovery; no
  service installation, privilege escalation, credential access, or external
  network

## Implemented boundary

Broker service startup now acquires an owner-only `broker.instance.lock` under
the canonical runtime root before checking the Broker socket, opening the
BrokerStore, or reconciling restart-unknown Jobs. The lock document contains
only a schema version and the current process PID/start-time identity. A
second startup fails with `ALREADY_ACTIVE` while the recorded identity is
alive. A leftover lock is reclaimed only when PID/start-time observation proves
the owner is stale; observer uncertainty, malformed content, weak permissions,
symlink replacement, and target changes fail closed.

The lock handle remains open for the whole assembled service lifetime and is
released after transport, Broker resources, keys, and the store close. Normal
and startup-failure paths release it even when an earlier cleanup step throws.
This prevents the pre-listener race where two
Broker instances could both pass socket preflight and recover the same Job
Ledger before either listener exists.

## Verification

- `npm test` — 394 tests, 391 passed, 3 opt-in sandbox tests skipped.
- `MOPS_REAL_SANDBOX=1 npm test` — 394 tests, 394 passed, 0 skipped.
- Focused service-instance-lock tests cover active duplicate denial, proven
  stale reclaim, observer uncertainty, unsafe symlink targets, and replacement
  lock protection during close.
- Broker service-startup tests pass with the lock active.
- `npm run verify:contracts` — 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- `git diff --check` — passed.

## Interpretation and limits

This proves repository-level startup serialization and conservative stale-lock
handling on the supported Mac host. It does not prove launchd installation or
bootstrap behavior, a kernel-level lock against arbitrary non-cooperating
processes, or physical crash/remount durability. Those remain deployment and
release evidence.

Source hashes at capture:

```text
30e11367464936114b103c7d0e1fcef1c93ea56163cd46c2c1d9ddcf8da910b0  packages/broker/src/service-instance-lock.ts
6542e3ac71d7baccc7054e5f09f9e8f687f83286aad154bb347cb26efb6e7aa5  packages/broker/src/service-instance-lock.test.ts
56e81c3fdeeb697eead5c891810ad0655bca89084ef25de8283b37e12bbaaae78  packages/broker/src/service-startup.ts
```
