# Authority Control Key Activation Evidence

Date: 2026-09-13
Source commit: `f47ecc5`
Dirty-state: clean at capture
Host: macOS 26.2 (25C56), arm64
Runtime: Node.js v25.5.0
Tool contract version: 0.1
Policy version: policy-0.1

## Scope

This record covers protected operator-key selection for the host-only Authority
Control channel and its uninstall assembly. It does not claim installed
launchd startup, production Keychain ACL approval, live key rotation/deletion,
or a real service uninstall.

## Implemented boundary

`AuthorityControlKeyConfig` is a versioned owner-only metadata document. It
must declare exactly one key and an explicit `file` or `keychain` source; raw
secret bytes are never written to the document. File sources use the existing
owner-only regular-file loader with `O_NOFOLLOW`, canonical path and stable
device/inode checks. Keychain sources use the explicit Broker-owned Keychain
coordinates. Both sources are bound to the configured SHA-256 digest.

`BrokerStore` now persists a dedicated `authority_key` revocation kind and
audited monotonic activation history. Activation rejects revision reuse,
rollback, concurrent changes, revoked keys, digest mismatch, and malformed
metadata. Restart restore requires the exact persisted revision and payload
digest. The manager enforces the configured validity window, wipes temporary
and replaced key buffers, and exposes client construction only after an
activated snapshot exists.

The uninstall host assembly receives an activated key manager, creates the
authenticated Authority Control IPC client from that manager, and binds the
client to the exact selected Edge ID. Uninstall arguments cannot supply or
replace the operator key.

## Verification

- `npm test`: 332 tests, 330 passed, 0 failed, 2 opt-in real-sandbox tests skipped.
- Focused authority key/IPC/persistence tests: 28 passed, 0 failed.
- `npm run build -- --pretty false`: passed.
- `npm run typecheck -- --pretty false`: passed.
- `npm run verify:contracts`: 44 unique tool contracts validated.
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities.
- `git diff --check`: passed.

Focused coverage includes secret-free metadata, owner-only mode checks,
symlink rejection, digest mismatch, dedicated-key revocation, exact restart
restore, monotonic revision conflict, validity-window denial, legacy
revocation-schema migration, real client assembly, authenticated switch and
revocation readback, and exact Edge binding.

## Remaining gates

The production boundary still needs signed/notarized packaging, approved
Keychain ACLs and operator-key provisioning/rotation procedure, launchd
startup ownership, live key retirement/physical-erasure evidence, active
process termination, remote propagation, and final real-Mac install/uninstall
readback.
