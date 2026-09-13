# Privileged Helper Key Activation Evidence

Date: 2026-09-13
Source commit: `afe73c4`
Dirty-state: clean at capture
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0
Tool contract version: 0.1
Policy version: policy-0.1

## Scope

This record covers protected key delivery for the separately authenticated L5
helper. It does not enable a privileged adapter, launch a root process, or
claim service/package/power execution.

## Implemented boundary

`PrivilegedHelperKeyConfig` stores only one explicitly selected file or
Keychain source, key ID, SHA-256 digest, and validity window. File loading
uses owner-only regular-file checks, `O_NOFOLLOW`, canonical path validation,
and stable device/inode identity. Keychain loading uses explicit Broker-owned
service/account coordinates. The dedicated `helper_key` revocation kind is
checked before secret bytes are admitted.

`PrivilegedHelperKeyManager` persists audited monotonic activation, requires
exact revision/digest restart restore, enforces the validity window, and wipes
temporary/replaced key buffers. It can construct the helper command factory or
IPC server only from an activated key snapshot; raw helper arguments cannot
select a key. The command factory and helper IPC server defensively copy their
HMAC keys and expose disposal/close wiping. The helper adapter remains
fail-closed by default.

## Verification

- `npm test`: 335 tests, 333 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- Focused helper-key, helper IPC, persistence tests: 33 passed, 0 failed.
- `npm run build -- --pretty false`: passed.
- `npm run typecheck -- --pretty false`: passed.
- `npm run verify:contracts`: 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.

Coverage includes secret-free metadata, symlink and unsafe-mode rejection,
digest mismatch, dedicated-key revocation, exact restart restore, monotonic
revision conflict, helper factory/server assembly, key disposal, durable
helper replay, operation allowlisting, approval/Job binding, active authority
revocation, and denied-peer handling.

## Remaining gates

Caller identity packaging, separate helper process/root boundary, signed and
notarized artifacts, Keychain ACL approval, real adapters, crash recovery,
rollback, independent security review, and any privileged host evidence remain
open. No privileged operation is enabled.
