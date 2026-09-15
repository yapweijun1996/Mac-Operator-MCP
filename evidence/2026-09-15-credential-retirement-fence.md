# Credential Retirement Identity-Fence Evidence

- Source revision: `737ab3a`
- Date: 2026-09-15
- Scope: Broker-owned file authentication-key retirement

## Decision

Revoked file-backed authentication and approval-issuer keys are now retired
only after a digest precondition plus owner, mode, device, inode, size, and
modification-time checks before and after quarantine rename. A failed rename
or post-rename check attempts a non-overwriting hard-link restoration of the
exact quarantined inode; an attacker-created replacement at the original path
is never replaced. The loaded key buffer is cleared on every retirement path.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed.
- `npm run typecheck`: passed.
- `npm run verify:docs`: passed for 29 README links and 8 required runbooks.
- `git diff --check`: passed.
- `MOPS_REAL_KEYCHAIN=1 node --test --test-timeout=120000 packages/broker/dist/credentials.test.js`: 11 passed, 0 failed.

The long-running Broker/Persistence and helper IPC test processes were left
untouched. This evidence does not claim production Keychain distribution,
installed helper recovery, or final release approval.
