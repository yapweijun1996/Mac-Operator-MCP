# Edge Request Factory Disposal Evidence

- Source revision: `e3ad73d`
- Date: 2026-09-15
- Scope: Edge request-factory shutdown and post-disposal use

## Decision

`EdgeRequestFactory.dispose()` is now an idempotent terminal transition. After
disposal, request creation fails with a stable error and response verification
returns `false`; no operation can silently sign with the wiped in-memory key.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed across 653 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Focused Edge authentication, IPC, TLS, and startup suites: 18 passed, 0
  failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. Full HTTPS Edge lifecycle, production key storage, and installed
shutdown readback remain open.
