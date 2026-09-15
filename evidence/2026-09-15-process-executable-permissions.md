# Process Executable Permission Gate Evidence

- Source revision: `3dc9219`
- Date: 2026-09-15
- Host: physical Mac mini, arm64, macOS 26.2 (Build 25C56), Darwin 25.2.0
- Runtime: Node.js v25.5.0
- Scope: Broker child-process executable preflight

## Decision

`ProcessSupervisor` must reject an executable whose group or other permission
bits include write access. This is an independent precondition, before any
child is spawned; it does not treat path/content identity checks as a
substitute for protected permissions.

## Implemented boundary

The executable validator still requires a canonical, regular, non-symlink,
executable file and bounded descriptor-backed content hashing. It now also
requires `(mode & 0022) == 0`, returning the stable `POLICY_DENIED` class for
group- or other-writable files. Existing post-spawn path, metadata, and digest
readbacks remain unchanged. This protects fixed Broker adapters from an
obviously user/group/world-writable executable path while keeping the
experimental sandbox task boundary separately evidence-gated.

## Verification

```text
npm run build
npm run lint
node --test packages/broker/dist/process-supervisor.test.js
```

Results: build and style checks passed; the focused ProcessSupervisor suite
passed 35/35 with 0 failures. The new regression creates a temporary
group-writable executable and proves it is denied before process admission.

## Limits

Permission checks do not provide kernel-held descriptor execution. The child is
still started by path after authorization, so a post-check mutation or volume
remount remains unresolved. Descriptor-backed execution (`fexecve`/`execveat`
or an equivalent reviewed helper), remount resistance, and production task
enablement remain open under MOP-086.

## Rollback

Revert `3dc9219` to restore the prior executable preflight; no data migration
or persistent state change is required.
