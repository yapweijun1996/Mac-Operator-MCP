# Audit Anchor Result Boundary Evidence

Date: 2026-09-15
Source revision: `e54a862`
Host: physical macOS host used by the repository test harness
Dirty-state status: clean at implementation verification; documentation was committed separately
Tool contract version: 0.1
Policy version: 0.1
Verification timestamp: 2026-09-15T05:38:12Z
Artifact hashes: `packages/broker/src/audit-anchor.ts` SHA-256
`0bebf00efd6684013b5b6bec75e4de8c95456ff92be98ae709da083828954619`;
`packages/broker/src/audit-anchor.test.ts` SHA-256
`4f0c05cb57aba5eadef4e01a3792860be8d373b73e9b71d0dc20b0476721e685`.

## Decision

The keyed audit sidecar and native lock-recovery readback influence whether
the Broker trusts its persisted audit tail and whether one exact lock may be
removed. Parsed JSON/native objects are not authoritative by default.

## Implemented controls

- Audit anchor files require an exact five-field plain record before MAC and
  persisted-tail comparison.
- Native lock-recovery results require an exact plain record before path,
  device, inode, and removal readback checks.
- Unknown, inherited, symbolic, non-enumerable, and accessor fields fail
  closed without unlinking or accepting the sidecar.
- Validated values are projected into fresh records before cryptographic or
  filesystem decisions.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/audit-anchor.test.js
```

Result: 8 tests passed, 0 failed, 0 skipped. The hostile sidecar fixture
rejects an extra authority field; forged MAC, missing-anchor, lock ownership,
replacement identity, and stopped-service recovery tests remain green.

Non-overlapping package regression (excluding the two pre-existing long-lived
broker/persistence test processes): 530 tests total, 524 passed, 6 skipped,
0 failed.

## Boundary status

This proves audit sidecar/result-shape integrity only. It does not prove
SQLite corruption recovery, key provenance, disk exhaustion, physical
service crash recovery, or final release acceptance. Those gates remain
fail-closed and incomplete.
