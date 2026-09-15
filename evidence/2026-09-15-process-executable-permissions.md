# Process Executable Permission Gate Evidence

- Source revision: `339d932`
- Date: 2026-09-15
- Host: physical Mac mini, arm64, macOS 26.2 (Build 25C56), Darwin 25.2.0
- Runtime: Node.js v25.5.0
- Scope: Broker child-process executable preflight

## Decision

`ProcessSupervisor` must reject an executable whose group or other permission
bits include write access. Fixed host adapters additionally require a root-owned
executable. These are independent preconditions, before any child is spawned;
they do not treat path/content identity checks as a substitute for protected
ownership and permissions.

## Implemented boundary

The executable validator still requires a canonical, regular, non-symlink,
executable file and bounded descriptor-backed content hashing. It now also
requires `(mode & 0022) == 0`, returning the stable `POLICY_DENIED` class for
group- or other-writable files. A fixed-adapter supervisor can additionally
require `ownerUid === 0`; the Broker's default fixed-adapter supervisor enables
that option. Owner UID/GID now participate in descriptor metadata stability
readback. Existing post-spawn path and digest checks remain unchanged, while
the experimental sandbox task boundary remains separately evidence-gated.

## Verification

```text
npm run build
npm run lint
node --test packages/broker/dist/process-supervisor.test.js
```

Results: build and style checks passed; the focused ProcessSupervisor suite
passed 36/36 with 0 failures. Regressions create a temporary group-writable
executable and a current-user-owned executable under root-owned-only mode, and
prove both are denied before process admission; `/usr/bin/printf` remains
allowed.

## Limits

Permission checks do not provide kernel-held descriptor execution. The child is
still started by path after authorization, so a post-check mutation or volume
remount remains unresolved. Descriptor-backed execution (`fexecve`/`execveat`
or an equivalent reviewed helper), remount resistance, and production task
enablement remain open under MOP-086.

## Rollback

Revert `339d932` to restore the prior executable preflight; no data migration
or persistent state change is required.
