# IPC Key-Copy Gate Evidence

- Source revision: `af68248`
- Date: 2026-09-15
- Scope: IPC and guest-transport constructor validation

## Decision

Policy Signer, Authority Control, Broker Status, Privileged Helper, and
Virtualization Guest Transport constructors now validate all non-secret limits,
callbacks, and bindings before copying authentication key bytes. Invalid
configuration therefore fails before an object-owned key buffer exists.

## Verification

- `npm run build`: passed, including native artifacts and TypeScript.
- `npm run lint`: passed across 654 tracked files.
- `npm run typecheck`: passed.
- `git diff --check`: passed.
- Focused Policy Signer, Authority Control, Broker Status, Privileged Helper,
  and Virtualization Guest Transport suites: 41 passed, 0 failed.

The long-running Broker/Persistence and helper-authority IPC test processes
were left untouched. Production cross-process key delivery, signing identity,
and installed-service evidence remain open.
