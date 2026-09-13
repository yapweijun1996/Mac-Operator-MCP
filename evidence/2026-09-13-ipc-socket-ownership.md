# Broker IPC socket ownership evidence

- Source commit: `44cae6a`
- Working tree: clean before this evidence document update
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Contract/policy: tool contracts `0.1`; Broker policy fixtures `policy-0.1`
- Scope: local Unix-socket startup, stale-path, replacement, and close fencing;
  no service installation, privilege escalation, credential access, or external
  network

## Implemented boundary

Shared IPC startup now probes an existing Unix socket before treating it as
stale. A successful connection is an active-listener signal and startup fails
closed without unlinking the pathname. A refused/missing connection is allowed
to proceed only when the socket device/inode remains unchanged across the
probe. Non-socket paths, probe errors, timeouts, and target changes are
rejected.

Every generic Node IPC server records its socket device/inode after listen.
Before `server.close()`, it atomically detaches the owned socket and places a
temporary symlink barrier at the public pathname. This prevents Node's own
close cleanup from unlinking a replacement listener that races into the same
pathname. Native peer servers remove only their recorded identity after the
listener descriptor is closed. Broker service assembly performs the active
socket preflight before opening the BrokerStore or reconciling restart-unknown
Jobs, so an existing Broker is not disrupted by startup recovery.

The boundary is shared by Broker IPC, Approval IPC, Authority Control, Policy
Signer, Privileged Helper, and the native peer transport.

## Verification

- `npm test` — 390 tests, 387 passed, 3 opt-in sandbox tests skipped.
- `MOPS_REAL_SANDBOX=1 npm test` — 390 tests, 390 passed, 0 skipped.
- Focused IPC/service-startup tests cover active listener refusal, startup
  preflight without unlink, replacement fencing during close, socket identity
  checks, native transport startup, and all authenticated local channels.
- `npm run verify:contracts` — 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high` — 0 vulnerabilities.
- `git diff --check` — passed.

## Interpretation and limits

This proves the repository-level IPC pathname boundary rejects obvious active
listeners and protects replacement listeners during controlled close races. It
does not prove installed launchd singleton enforcement, a kernel-level lock
across arbitrary non-cooperating processes, or physical crash/remount behavior.
Those remain deployment and release evidence.

Source hashes at capture:

```text
72565137d14baefe9dd5d6ee56851f8ce16fb86028ab3f9637dc47dd102312e1  packages/broker/src/ipc-server.ts
6eb35e918ff1ce894bf4172632de933718ad0cda1a7eea5637c2f5ea85cca2eb  packages/broker/src/native-peer-ipc-server.ts
cf23cdacf63996e455a7059154c9634a7ee6f82d8ff3926de0e9310261397349  packages/broker/src/service-startup.ts
a8997d95c28370ed62607ed5ec393ece4225b1df4d61cd64cf07b001830ea2df  packages/broker/src/ipc-server.test.ts
```
