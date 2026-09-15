# Request Authentication-Key Lifetime Evidence

- Source revision: `fec6e5b`
- Date: 2026-09-15
- Scope: Broker request authentication and response signing

## Decision

Per-request Edge HMAC key copies are now cleared in `finally` blocks after
request verification and after authenticated response signing, including
failure paths. The long-lived Edge keyring remains the sole service-owned key
copy; request code cannot retain a transient authentication buffer after the
operation returns.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- `node --test --test-timeout=120000 packages/broker/dist/ipc-server.test.js packages/broker/dist/native-ipc-server.test.js packages/broker/dist/broker-result-boundary.test.js`: 18 passed, 0 failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Full Broker regression and production key-storage evidence remain
open.
