# Broker worker shutdown and lifecycle fencing

- Source commit: `84f499188c487fed4d6e3a12d8117b48d4c443b6`
- Working tree: clean before this evidence document was added
- Host: Mac mini M4, `Darwin yaps-Mac-mini.local 25.2.0`, arm64
- Runtime: Node `v25.5.0`; macOS platform reported by Node as `darwin`
- Captured: 2026-09-13 (Asia/Kuala_Lumpur)
- Scope: Broker lifecycle and worker-thread shutdown; no service installation, privilege escalation, credential access, or external network

## Implemented boundary

`BoundedWorkerExecutor` now keeps an explicit set of active `Worker` objects.
It rejects new work after `close()`, calls `Worker.terminate()` for every owned
worker, and removes capacity only from the worker exit handler. Filesystem and
process executors expose the close operation. `Broker.close()` marks the Broker
as closing, closes both worker executors, and rejects new requests; active
completion paths re-check the closing state before publishing success.
`LocalBrokerRuntime` closes transport channels first and then invokes its
Broker-resource close callback. The production native runtime supplies this
callback; the close path is not controlled by MCP arguments.

## Verification

- Focused lifecycle command (`runtime.test.js` + `worker-executor.test.js`): 13 tests, 13 passed, 0 failed
- `npm test`: 377 tests, 374 passed, 0 failed, 3 opt-in real-sandbox tests skipped
- `MOPS_REAL_SANDBOX=1 npm test`: 377 tests, 377 passed, 0 failed, 0 skipped
- `npm run typecheck -- --pretty false`: passed
- `npm run verify:contracts`: passed (44 unique contracts)
- `npm audit --omit=dev --audit-level=high`: 0 vulnerabilities
- `git diff --check`: passed

The focused close test starts a slow worker, requests executor shutdown, waits
for the worker-backed promise to fail and the exit event to release capacity,
then confirms a new request is rejected with `CANCELLED`. Runtime ordering is
read back as transport close followed by resource close. Native runtime startup
tests also pass with the production Broker close callback wired.

## Interpretation and limits

This establishes a graceful in-process drain boundary and prevents late
success publication after shutdown begins. It does not prove that a crashed
Broker process has terminated every old worker, that an OS process worker is
owned across restart, or that physical disk/remount failures are recoverable.
Those remain release-gate items, and `mac_task_run` remains disabled.

Source hashes at capture:

```text
891b88c10e4425a7557c07f3b60d2abb3068b1df4d291ca2bbb6438f3b09791d  packages/broker/src/worker-executor.ts
0568f9883068de2c8510b79847e09fc38bdf8e5c565bf3469f8e27f5d54ec529  packages/broker/src/filesystem-executor.ts
5a56879f5d1e32d68b8b204d0d581d6530215be8012e874787e70a4b3aeae358  packages/broker/src/process-executor.ts
909f41f78ff4d8a10e30f774db519a6cb970d01fe61de5264d7bd70c6685d121  packages/broker/src/broker.ts
7ca18f7851c63a65d9230b0eab45f9527bc0adbb05588f5ac0dfae485ac5d2dd  packages/broker/src/runtime.ts
```
