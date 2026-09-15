# IPC Socket Orphan-Recovery Evidence

- Source revision: `49b575a`
- Date: 2026-09-15
- Scope: Node Unix IPC socket quarantine and explicit crash-orphan recovery

## Implementation

IPC socket quarantine names now contain a creation timestamp, UUIDv4 nonce,
and SHA-256 fingerprint of the original basename. The basename is not stored
in cleartext, and the fingerprint grants no permission; it only bounds which
private entries can be considered for one requested socket path.

`recoverOrphanedSocket` is explicit and non-automatic. It requires a canonical
absolute target, a valid device/inode identity, an age between one second and
seven days, an owner-only parent, and a parent device/inode that remains stable
through the scan and immediately before removal. Candidate sockets must match
the fingerprint and identity, be inactive, and be uniquely stale. Recent,
active, mixed-age, or multiple matches return `not_stale`/`ambiguous` without
deletion; a different basename returns `absent`. The removal is followed by
an identity readback proving the private artifact is absent.

The macOS detached-socket `EINVAL` liveness result is treated as inactive only
inside this explicit recovery path. All other liveness ambiguity remains
fail-closed.

## Verification

- `npm run build`: passed, including the Darwin native artifacts and TypeScript.
- `npm run lint`: passed across 660 tracked files.
- `git diff --check`: passed.
- Dedicated IPC suite: 11 passed, 0 failed.
- Physical Darwin probe covered stale recovery, recent-artifact preservation,
  and wrong-target non-selection.

Production crash/remount evidence, durable Job-record integration, and
Developer ID signing remain open release gates. Existing long-running Broker,
Persistence, and helper IPC processes were left untouched.
