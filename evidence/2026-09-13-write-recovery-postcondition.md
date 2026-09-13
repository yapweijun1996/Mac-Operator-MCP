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
- Native syscall crash boundary: a test-only fault-instrumented native module terminates its child process with `SIGKILL` after temporary-file `fsync` and after `rename`; create-before-rename leaves the target absent and only the orphan temporary file, while create/replace-after-rename leave complete `after` content with no temporary file.
- Active authority boundary: a filesystem write adapter that trips the Broker mutations kill switch before returning cannot complete its Job; the request is `CANCELLED` and the Job remains `UNKNOWN`.
- Persistence restart: the non-secret descriptor survives a BrokerStore close/reopen while stdout remains empty and the Job reconciles to `unknown`.
- Contract validation: the optional recovery object is bounded and schema-valid under `mac_job_status`.

Observed verification on this revision: `npm test` passed with 243 tests; `npm run typecheck` passed; `npm run verify:contracts` validated 44 contracts; `git diff --check` passed.

## Limits and next gate

The crash fixture is test-only and injects `SIGKILL` at selected native syscall boundaries; it is not exhaustive arbitrary-instruction crash coverage and does not prove post-crash filesystem durability across remount. It does not prove which actor created or replaced a target, and it deliberately does not auto-retry or transition `UNKNOWN` to success. Filesystem remount identity, orphan-temporary cleanup policy, durable backup/restore, and final release readback remain open under VT-REL-01 and MOP-046.
