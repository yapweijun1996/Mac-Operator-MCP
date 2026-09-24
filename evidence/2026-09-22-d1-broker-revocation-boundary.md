# D1 Broker task revocation boundary

- Date: 2026-09-22
- Scope: physical Broker cancellation and recovery handling for a named task
- Status: physical Darwin arm64 evidence passed; public task capability remains disabled
- Host boundary: unprivileged Broker, `/usr/bin/sandbox-exec`, fixed `/bin/sleep`

## Verification

The focused opt-in run used the existing Broker integration tests after changing
only these three cases to the explicit system-published task boundary:

```text
MOPS_REAL_SANDBOX=1 node --test --test-timeout=120000 \
  --test-name-pattern='real macOS Broker task cancellation drains the process after (session|Edge) revocation|real macOS Broker task cancellation drains the process after process kill switch' \
  packages/broker/dist/broker.test.js
```

Result: 3/3 passed, 0 failed, 0 skipped.

The tests use a Broker-owned named `tests.sleep` profile with `/bin/sleep` as
the only executable in the system-published allowlist, single-process
ownership, no network, empty environment, bounded arguments/output/timeout,
and a protected persistence root. The runner independently checks the
canonical root-owned `/usr/bin/sandbox-exec` and `/bin/sleep` paths and records
the `sandbox-exec-no-fork-v1` ownership proof.

The three authority events are covered independently:

- session revocation through the durable Broker revocation store;
- host-lifecycle Edge revocation through `Broker.revokeEdge()`;
- the global `process` kill switch through `BrokerStore.setSwitch()`.

Each running task returns `CANCELLED`, the Request is `CANCELLED`, and the
corresponding Job remains `UNKNOWN` with `UNKNOWN_OUTCOME` semantics and the
non-secret process ownership proof retained for recovery. The session case
also confirms the expected decision/intent/completion audit sequence. This is
Broker-side active-work evidence; it does not claim automatic Auth grant
revocation propagation into Broker or remote revocation distribution.

## Limits and rollback

The default task boundary remains disabled, public `mac_task_run` remains absent
from the live tools list, and generic descriptor-backed executable selection is
still unavailable on this host. Production signing/notarization, installed
helper or App Sandbox deployment, restart recovery readback, rollback, and
public enablement remain release gates. The test change is reversible by
restoring descriptor-mode construction for these three opt-in cases; it does
not change production policy or deployment state.
