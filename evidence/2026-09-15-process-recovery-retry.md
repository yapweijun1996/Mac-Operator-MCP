# UNKNOWN Process Recovery Retry Evidence

- Source revision: `436917d`
- Date: 2026-09-15
- Scope: Restart reconciliation for Broker-owned task processes

## Decision

`PROCESS_RECOVERY_UNKNOWN` is an observer failure, not a terminal recovery
result. The Broker now retries that exact persisted PID/start-time/process-group
identity on a later startup, while still refusing to promote the Job or replay
the task. Definitive `PROCESS_DRAINED`, `PROCESS_ABSENT`, and
`PROCESS_IDENTITY_MISMATCH` results remain terminal for that recovery record.

## Verification

- `npm run build`: passed, including native artifact builds and TypeScript.
- `npm run lint`: passed.
- `npm run typecheck`: passed.
- Physical-host recovery probe: a first observer `unknown` result was retained,
  and a second reconciliation retried the same identity and recorded
  `PROCESS_DRAINED`.
- Added regression coverage: `restarted Broker retries an observer-unknown
  process recovery on a later startup` in `packages/broker/src/broker.test.ts`.

The long-running Broker/Persistence and helper IPC test processes were left
untouched.
