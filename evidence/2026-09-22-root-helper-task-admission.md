# Root Helper Task Admission Evidence

Date: 2026-09-22
Host: Darwin arm64 physical Mac, current process UID 501
Status: `implemented` as a fail-closed Broker admission seam; root-helper
execution remains unavailable on this host

## Boundary

The final Broker task execution control now wraps root-helper request admission
with a fresh `ensureActiveAuthority` check. That check covers the authenticated
MCP request, normalized target, active policy revision, session/Edge/principal
revocation, kill-switch state, and Broker shutdown state before the exact signed
root-helper envelope digest enters the Broker-owned active-request registry.

The admission/release object is forwarded through `RootHelperSnapshotTaskRunner`
to `RootHelperSnapshotTaskExecutor` and `NativeRootHelperSnapshotTransport`.
The root-helper runner refuses execution with `PRIVILEGE_DENIED` when the final
Broker gate is absent. The transport releases the same digest in its exchange
cleanup path, while the separately authenticated root-helper authority poller
continues to recheck that digest before, during, and after execution.

This is a source and test boundary only. It does not install a LaunchDaemon,
create a root-owned process, enable `mac_task_run`, or expose a public helper
scope.

## Verification

- `npm run typecheck` passed.
- `npm run build` passed, including native addon rebuilds.
- Root-helper snapshot, authority, and task-runner focused tests passed 27/27.
- Broker task admission regression passed, including propagation of the
  Broker-owned admission object through a verified task Job.
- Full repository regression remains 977/992 with 15 explicit skips and 0
  failures after the complete verification rerun.
- The physical root-helper probe remains fail-closed with `POLICY_DENIED`;
  public task scope remains disabled.

## Remaining gates

This evidence does not prove a signed/notarized native root-helper executable,
root-owned package installation, live root-domain socket/process readback,
crash/restart recovery, or public task enablement. Production startup must
construct one registry and pass it consistently to the Broker task runner and
the root-helper authority listener; a mismatched or missing registry remains a
startup failure.

## Rollback

Rollback is source-level removal of the admission seam, propagation tests, and
this evidence. No host service, LaunchDaemon, OAuth grant, policy entry,
database, or credential store was changed.
