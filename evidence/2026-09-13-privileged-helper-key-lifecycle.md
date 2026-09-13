# Privileged Helper Key Lifecycle Evidence

Date: 2026-09-13
Source commit: `72a3284`
Dirty-state: clean at capture
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0
Tool contract version: 0.1
Policy version: policy-0.1

## Scope

This record covers active key fencing after helper factory/server construction.
It does not enable a helper adapter or run a privileged operation.

## Implemented boundary

`PrivilegedHelperKeyManager` captures the activated key's key ID, revision,
payload digest, and validity window when constructing the Broker command
factory or helper IPC server. The factory checks the binding before issuing and
before the Broker authority callback; the IPC server checks it after HMAC
authentication and before replay admission, then rechecks through the
Broker-owned authorization callback.

The active check rejects dedicated `helper_key` revocation, a missing or
different BrokerStore active revision/digest, and `notBefore`/`expiresAt`
violations. This fences an old in-memory owner when a key is revoked, rotated,
or expires without requiring process restart. Existing defensive key-copy and
dispose/close wiping remains in place.

## Verification

- `npm test`: 344 tests, 342 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- Focused helper key/IPC tests: 9 passed, 0 failed.
- `npm run typecheck -- --pretty false`: passed.
- `npm run build -- --pretty false`: passed.
- `npm run verify:contracts`: 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.

Negative coverage includes expired factory keys, revoked keys, and unchanged
helper IPC behavior for replay, allowlist, peer, and authority failures.

## Remaining gates

Real installed helper/root process lifecycle, Developer ID provenance,
Keychain ACL approval, crash recovery, helper adapters, and independent
security review remain open. The helper remains disabled.
