# Keychain ACL rerun evidence

Date: 2026-09-16
Source revision: `31a78c0`
Host: physical Darwin arm64 Mac mini; macOS 26.2

## Verification

Command:

```text
MOPS_REAL_KEYCHAIN=1 node --test --test-timeout=120000 packages/broker/dist/credentials.test.js
```

Result: 11/11 tests passed, 0 failed, 0 skipped.

The real-host test provisioned a random 32-byte generic-password item with a
file-based ACL bound to the current Node executable, loaded and digest-checked
the bytes, and read back non-secret protection metadata. The same item was
rechecked against `/usr/bin/security` and rejected. Retirement first rejected
an incorrect digest, then removed the exact item and verified that a subsequent
load failed closed. The random account and item were cleaned in a `finally`
path; no repository secret or persistent production credential was written.

## Boundary

This is real user-Keychain ACL and digest-retirement evidence only. It does not
prove Developer ID/notarization, an installed Broker executable identity,
cross-process launchd rotation, or production capability enablement.

## Rollback

The test owns and removes its unique Keychain item. No host rollback is needed.
