# Authentication-Key Memory Lifecycle Evidence

- Source revision: `42766c9`
- Date: 2026-09-15
- Scope: Edge and approval issuer key configuration loading

## Decision

Edge and approval key loaders now clear every key already loaded when a later
entry, digest, revocation, or activation check fails. Their managers wipe the
previous raw snapshot before replacement, expose explicit `dispose()` cleanup,
and clear the raw startup snapshot after the Broker receives its defensive Edge
keyring copy. The Broker-owned keyring remains responsible for its live copy.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- `node --test --test-timeout=120000 packages/broker/dist/edge-keyring-config.test.js packages/broker/dist/approval-keyring.test.js`: 10 passed, 0 failed.
- Manager lifecycle regressions verify that explicit disposal zeroes the raw
  loaded buffers.

Production cross-process key delivery, code-signing identity, and final
service shutdown evidence remain open.
