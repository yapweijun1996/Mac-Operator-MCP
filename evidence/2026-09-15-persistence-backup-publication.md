# Persistence Backup Publication Evidence

- Source revision: `8e57790`
- Date: 2026-09-15
- Scope: Broker persistence backup and restore target-swap boundary

## Decision

Backup publication must never replace an existing path after an existence
check. Both encrypted backup creation and restore now publish with an atomic
same-directory hard link, which fails with `CONFLICT` when the destination is
already present. The source temporary file identity is checked again before
publication and the file identity is re-read after linking. File identity
checks include device, inode, owner, mode, size, and modification time.

## Verification

- `npm run build`: passed, including native artifact builds and TypeScript.
- `npm run lint`: passed.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Physical-host restore probe: an existing owner-only destination remained
  byte-for-byte unchanged and restore returned `CONFLICT`.
- Added regression coverage: `BrokerStore restore never replaces an existing
  destination` in `packages/broker/src/persistence.test.ts`.

The long-running Broker/Persistence test process was left untouched; the
targeted physical-host probe verified the new publication boundary directly.
