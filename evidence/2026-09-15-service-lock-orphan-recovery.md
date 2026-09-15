# Service Instance Lock Orphan-Recovery Evidence

- Source revision: `3ddc056`
- Date: 2026-09-15
- Scope: Broker service-instance lock crash-orphan recovery

## Implementation

Service-lock quarantine names now include a creation timestamp, UUIDv4 nonce,
and SHA-256 fingerprint of the lock basename. The explicit
`recoverOrphanedServiceInstanceLock` path validates a canonical owner-only
parent, stable directory identity, exact regular single-link file identity,
and the age bound. It then parses the quarantined lock document and requires
the recorded PID/start-time probe to be `stale`; active, unknown, malformed,
recent, duplicate, or target-replacement cases are preserved as `ambiguous`
or `not_stale`.

Stale removal uses an exact identity recheck, parent recheck, directory sync,
and absence readback. No startup heuristic or filename-only deletion was
added.

## Verification

- `npm run build`: passed, including Darwin native artifacts and TypeScript.
- `npm run lint`: passed across 661 tracked files.
- Dedicated service-lock suite: 6 passed, 0 failed.
- Physical probe covered stale recovery, recent preservation, and active-owner
  stop behavior.

Production crash/remount evidence and persisted Job integration remain open.
