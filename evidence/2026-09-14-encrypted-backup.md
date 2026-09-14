# Encrypted Broker Backup Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: Broker persistence backup confidentiality and integrity; no capability enablement

## Commands

```text
npm run build
node --test packages/broker/dist/persistence.test.js packages/broker/dist/credentials.test.js
```

## Observed result

- Focused persistence and credential suites: 47 tests, 47 passed, 0 failed.
- Backup output uses the `.sqlite.enc` filename and `MOPSBAK1` envelope magic;
  the SQLite header is not present in the stored bytes.
- Restore succeeds with the matching key source and fails with a mismatched key
  identity, wrong key material, or a modified authentication tag.
- Retention refuses legacy plaintext `.sqlite` backup names.
- Temporary raw/encrypted/decrypted files are removed after successful and
  failed publication paths.

## Boundary

The Broker streams a SQLite snapshot through AES-256-GCM using a 32-byte key
loaded from an explicit configuration-owned source. The envelope binds the
format version and key identity as authenticated data. Restore authenticates and
decrypts to a protected temporary file before SQLite quick-check and audit-chain
verification; only a fresh destination is atomically published. Key bytes are
copied only in memory and cleared after each operation.

## Limitations

The test key is injected in memory. The macOS Keychain source factory is wired;
the separate live ACL/readback result is recorded in
`evidence/2026-09-14-keychain-acl.md`, but production backup scheduling is not
claimed. External audit anchoring, production migration cutover, single-owner
service deployment, and physical-erasure guarantees remain open.
