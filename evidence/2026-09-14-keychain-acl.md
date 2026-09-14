# Broker Keychain ACL readback evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: file-based Keychain secret distribution and reversible retirement; no MCP capability enablement

## Decision

The Broker runs as an unprivileged launchd process, so the macOS Keychain
boundary uses the file-based Keychain ACL model. Provisioning creates a random
32-byte generic-password item and binds its read ACL to one canonical,
protected Broker executable through `SecTrustedApplicationCreateFromPath` and
`SecAccessCreate`. The runtime supplies the current `process.execPath` as the
trusted identity and checks the ACL before requesting secret bytes. The native
adapter never accepts an MCP-selected executable, path, or secret reference.

The data-protection `SecAccessControl` path is not used by this daemon boundary:
an unsigned command-line host returned macOS `errSecMissingEntitlement` while
testing it, and Apple documents that data-protection access groups require a
signed app-like bundle/provisioning profile. The file-based ACL path is the
documented daemon-compatible choice; production signing and identity
provenance remain separate release gates.

## Commands

```text
npm run build
MOPS_REAL_KEYCHAIN=1 node --test \
  packages/broker/dist/credentials.test.js \
  packages/broker/dist/peer-credentials.test.js
```

## Observed result

- Focused credential and native peer suites: 16 tests, 16 passed, 0 failed,
  0 skipped.
- A random item was provisioned with an ACL bound to the active Node
  executable, read back as exactly 32 bytes, and inspected without returning
  the key. Readback reported `protection: file-based-acl`,
  `synchronizable: false`, and `trustedApplicationMatches: true`.
- The same item inspected against `/usr/bin/security` failed the protection
  check, demonstrating that a different executable identity cannot reuse the
  service/account coordinates.
- Retirement first rejected an incorrect SHA-256 digest, then deleted the
  exact item through its bound keychain item reference; a final read failed
  closed as unavailable.
- The test used a unique account and cleaned the item in a `finally` path. No
  persistent production item, password, key, or access token was written to
  the repository or test output.

## Boundary checks

- Service and account are fixed namespace components; traversal, separators,
  and malformed identifiers are rejected.
- The trusted executable must be an absolute canonical regular file with no
  group/other write bits. Native code rechecks the path before creating the
  trusted-application requirement.
- Native read and retirement enumerate the legacy keychain search result and
  reject duplicate service/account identities. ACL authorization is checked
  before content access, avoiding an implicit credential prompt for an
  unauthorized caller.
- Retirement compares the exact 32-byte value in constant time and deletes the
  item reference returned by that lookup, rather than issuing a broad
  service/account delete.
- Provisioning failure after item creation cannot publish a key: the caller
  receives only a digest, and all temporary key buffers are cleared after use.

## Limitations and next gate

This is real user-keychain evidence on the development host, not production
service evidence. Developer ID signing/notarization, a stable installed Broker
executable identity, launchd deployment, cross-process key delivery, ACL
rotation under an installed revision, and physical erasure limits remain open.
The operator must provision each item only after the exact signed Broker path
and release revision are known; changing that executable identity requires a
new item and an audited revoke-before-retire cutover.

Reference: Apple TN3137, “On Mac keychains”, and Apple’s “Signing a daemon with
a restricted entitlement”.
