# Docker CLI executable trust boundary evidence

- Source revision: `ff4f4d6`
- Capture date: 2026-09-16 (Asia/Kuala_Lumpur)
- Host: Apple silicon Mac mini, macOS 26.2, Darwin 25.2.0, arm64

## Boundary exercised

The Broker's shared `ProcessSupervisor` still requires root-owned executables
by default. A fixed Docker adapter may opt into a narrow exception only when
the executable path is in the Broker-owned Docker candidate list, is canonical
and non-symlinked, is owned by the current user, and has owner-only write
permissions. Task profiles and MCP arguments cannot set this flag through the
Docker adapter.

## Verification

```text
node --test packages/broker/dist/process-supervisor.test.js \
  packages/broker/dist/docker-inspector.test.js
50 tests, 49 passed, 0 failed, 1 explicit opt-in skip

MOPS_REAL_DOCKER=1 node --test --test-name-pattern='real Docker Desktop' \
  packages/broker/dist/docker-inspector.test.js
1 test, 1 passed, 0 failed

Docker Desktop daemon: version 29.1.3, context desktop-linux,
24 container records, no warnings or truncation.
```

The negative supervisor test rejects the same user-owned executable without
the explicit fixed-path exception. The physical readback confirms the
exception can execute Docker's canonical app-bundle CLI and that status plus
container inspect remain read-only and bounded.

## Limitations

The exception is a narrow owner/path control and does not itself prove Docker
code-signature provenance, native macOS container isolation, arbitrary socket
denial at the operating-system layer, or production deployment. Docker
mutation commands remain absent from the adapter allowlist.
