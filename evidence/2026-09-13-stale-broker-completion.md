# Cross-Broker stale completion fencing

- Source commit: `f2ce163b088eafbdb6b1bf502b907ebe992f40ae`
- Working tree: clean before this evidence document was added
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Scope: Broker Job lease/revision fencing across a second `BrokerStore` reopen; temporary fixture only, no service installation, privilege escalation, credential access, or external network

## Procedure

The test creates a real signed `mac_write_file_atomic` request and lets the
first `Broker.handle` instance admit the Job and enter `running`. Its injected
filesystem executor deliberately holds the result. A second `BrokerStore`
connection opens the same database; startup reconciliation changes the running
Job to `UNKNOWN`. The old executor result is then released through the first
Broker instance. A signed `mac_job_status` request is finally handled by a new
Broker instance using the reopened store.

## Observed result

- Prior Broker delayed completion: rejected (`ok: false`), never published success
- Reopened store Job state: `unknown`
- Reopened Broker `mac_job_status`: `state: unknown`
- Focused Broker suite: 64 tests, 64 passed, 0 failed
- `npm test`: 378 tests, 375 passed, 0 failed, 3 opt-in real-sandbox tests skipped
- `MOPS_REAL_SANDBOX=1 npm test`: 378 tests, 378 passed, 0 failed, 0 skipped
- `npm run typecheck -- --pretty false`: passed
- `npm run verify:contracts`: passed (44 unique contracts)
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities
- `git diff --check`: passed

## Interpretation and limits

This proves the Broker's persisted Job state, revision, and lease fencing stop
an old Broker completion from becoming success after a second BrokerStore
reopen. It does not prove that a crashed Broker's old worker thread or an OS
worker process has exited, nor that cleanup may safely begin without a separate
process-ownership proof. Those remain release-gate items; `mac_task_run` stays
disabled.

Source hash at capture:

```text
d097eb365be68ea9f6d2dd7aa5c8fc70e4c468187cda18c53120e956c2554447  packages/broker/src/broker.test.ts
```
