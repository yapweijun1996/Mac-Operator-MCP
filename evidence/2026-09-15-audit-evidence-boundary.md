# Audit Evidence Data Boundary Evidence

Date: 2026-09-15
Source revision: `fbb197b`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:57:56Z
Artifact hashes: `packages/broker/src/persistence.ts` SHA-256
`ddc49b70c47a2c9809a2ca9bd9de1eb61673bff9b3fb5ea2d8f8dcff56519477`;
`packages/broker/src/broker.test.ts` SHA-256
`7ff830eda9ed57d5a620dfa6f66161a5c99dbabc6c6bb77266374d6193a6c014`.

## Decision

Audit evidence must remain data-only before redaction, canonical hashing, or
SQLite persistence. Accessors, inherited fields, symbolic fields, and other
non-data objects are not evidence and must never be traversed as authority.

## Implemented controls

- Evidence record projection accepts only shared plain-data records; invalid
  evidence contributes no caller-controlled fields to audit pairs.
- Recursive redaction traverses only plain records and dense data arrays.
  Non-data objects are replaced by a fixed non-data marker without invoking
  getters or serializing hidden properties.
- Existing secret-key redaction, canonical event hashing, audit-chain
  verification, and bounded audit persistence remain unchanged.

## Verification

Focused command:

```text
npm run build && node --test --test-name-pattern='audit evidence' packages/broker/dist/broker.test.js
```

Result: 2 tests passed, 0 failed, 0 skipped. Recursive secret redaction stays
green while accessor, inherited, symbolic, and accessor-array fixtures are
replaced with the stable non-data marker.

## Boundary status

This proves audit evidence representation/redaction integrity only. It does not
prove SQLite corruption recovery, disk exhaustion, external anchoring,
production Keychain provenance, installed-service recovery, or final release
acceptance. Those gates remain fail-closed and incomplete.
