# Broker startup recovery wiring evidence

- Source commit: `9c96605`
- Working tree: clean before this evidence document update
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Contract/policy: tool contracts `0.1`; Broker policy fixtures `policy-0.1`
- Scope: service startup ordering and resource cleanup; no service installation,
  privilege escalation, credential access, or external network

## Implemented boundary

`createBrokerServiceFromStartupConfig()` now retains the constructed Broker and
reconciles interrupted task processes and restart-unknown write artifacts before
returning a service assembly. The recovery hooks run before
`BrokerServiceEntrypoint.start()` can invoke the native IPC runtime, so the
service cannot expose a listener while this bounded startup reconciliation is
pending. Task-process recovery remains conservative: exact persisted process
identities are required, unresolved work remains `UNKNOWN`, and recovery never
promotes a Job to success. Write cleanup remains exact-artifact, descriptor-
checked, audited, and kill-switch aware.

If startup assembly fails after Broker construction, the Broker-owned worker and
process resources are closed before the Edge keyring and BrokerStore are
disposed. Assembly disposal also closes the Broker when a caller disposes an
unstarted service, avoiding a resource leak before the runtime close hook has
been activated.

## Verification

- `npm test` — 387 tests, 384 passed, 3 opt-in sandbox tests skipped.
- `npm run typecheck -- --pretty false` — passed.
- `git diff --check` — passed.
- Existing Darwin native service-startup coverage still restores signed policy
  and Edge-key authority before starting the native runtime.

## Interpretation and limits

This proves startup assembly invokes the recovery boundary before the service
runtime is started and closes resources on both failed and unstarted assembly
paths. It does not prove installed launchd singleton enforcement, stale-socket
ownership fencing, recovery of descendants created after the last persisted
snapshot, credential isolation, or production task-runner enablement. Those
remain open release evidence.

Source hash at capture:

```text
9032bbe418cf7c41c34e1178c99b77e4fec73e25b4e521be35858f185c96ed10  packages/broker/src/service-startup.ts
```
