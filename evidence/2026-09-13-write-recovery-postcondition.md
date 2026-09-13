# Controlled write recovery-postcondition evidence

Date: 2026-09-13  
Host: macOS arm64 development host  
Scope: local synthetic fixtures only; no production roots or user data

## Boundary exercised

The disabled `mac_write_file_atomic` path persists a bounded write descriptor in the Broker Job Ledger: authorized root ID, normalized path, requested byte count, desired SHA-256, expected SHA-256 (when present), and `create_only`. Requested content is not persisted in the descriptor.

When startup reconciliation marks a running write `UNKNOWN`, `mac_job_status` may inspect the current target through the current signed write-root policy. The probe uses descriptor-backed metadata and SHA-256 readback and returns one of `matches`, `mismatch`, or `unavailable`. It never changes the Job state; even `matches` remains `UNKNOWN` because a process crash leaves actor attribution unproven.

## Tests

- Broker integration: an unknown write with a matching target returns `recovery.postcondition = matches`, `resolution = remains_unknown`, and no file content; the Job remains `unknown`.
- Broker crash-window simulation: the native atomic write commits in a temporary test executor, completion then fails, and the Broker records `UNKNOWN`; the target is fully committed and status readback reports `matches` without promoting the Job.
- Native controller-kill boundary: a test-only worker calls the native atomic-write primitive, signals after the atomic operation returns, and is terminated before a hypothetical controller readback; both create-only and replacement cases leave complete `after` content with no temporary file.
- Persistence restart: the non-secret descriptor survives a BrokerStore close/reopen while stdout remains empty and the Job reconciles to `unknown`.
- Contract validation: the optional recovery object is bounded and schema-valid under `mac_job_status`.

Observed verification on this revision: `npm test` passed with 242 tests; `npm run typecheck` passed; `npm run verify:contracts` validated 44 contracts; `git diff --check` passed.

## Limits and next gate

The controller-kill test is a bounded worker termination after the native atomic operation returns, not an OS process kill injected at every native syscall boundary. It does not prove which actor created or replaced a target, and it deliberately does not auto-retry or transition `UNKNOWN` to success. Native syscall-boundary crash injection, filesystem remount identity, durable backup/restore, and final release readback remain open under VT-REL-01 and MOP-046.
