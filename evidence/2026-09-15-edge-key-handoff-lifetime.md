# Edge Protected-Key Handoff Lifetime Evidence

- Source revision: `5695db0`
- Date: 2026-09-15
- Scope: Edge request-factory startup key loading

## Decision

`EdgeRequestFactory.fromProtectedKeyFile` now clears the loader-owned key
buffer after the constructor takes its defensive in-memory copy. This matches
the existing Keychain-delivery path and prevents a second startup key copy from
surviving until garbage collection.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Edge authentication-key/request-factory boundary suite: 5 passed, 0 failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Full HTTPS Edge regression and production key-storage evidence
remain open.
