# Audit Anchor Lock Orphan-Recovery Evidence

- Source revision: `3ddc056`
- Date: 2026-09-15
- Scope: Broker audit-anchor lock crash-orphan recovery

## Implementation

Audit-anchor lock quarantine names now include a creation timestamp, UUIDv4
nonce, and SHA-256 fingerprint of the lock basename. The explicit
`recoverAuditAnchorLockOrphan` path requires the authenticated host
stop/recovery gate, canonical protected anchor directory, stable parent
identity, bounded age, exact regular single-link device/inode, and a unique
candidate matching the original lock basename. A replacement target, recent
or duplicate artifact remains untouched; old quarantine names without the
new binding are ignored rather than guessed.

Stale removal is followed by directory sync and absence readback. The stop
gate is mandatory because the lock payload does not independently provide a
trustworthy process start-time owner identity.

## Verification

- `npm run build`: passed, including Darwin native artifacts and TypeScript.
- `npm run lint`: passed across 661 tracked files.
- Dedicated audit-anchor plus read-only suites: 10 passed, 0 failed.
- Physical probe covered stale recovery, recent preservation, replacement
  fencing, and stop-gate refusal.

Production crash/remount evidence and installed-service lifecycle evidence
remain open.
