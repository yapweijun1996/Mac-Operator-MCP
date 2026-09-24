# Root Helper Task Startup Assembly Evidence

Date: 2026-09-22
Host: Darwin arm64 physical Mac, current process UID 501
Status: `implemented` as a fail-closed Broker startup assembly; root-helper execution remains unavailable

## Boundary

`createRootHelperSnapshotTaskRunnerFromActiveKeyConfig` now assembles the
Broker-side root-helper task boundary used by production service startup. The
default branch constructs a disabled `DescriptorSnapshotRegistry`, disabled
`RootHelperSnapshotTaskExecutor`, and unavailable `RootHelperSnapshotTaskRunner`
without reading helper key material or querying launchd.

The explicit enabled branch requires independent host evidence, host-owned
Ed25519 descriptor signer/verifier objects, a complete root-helper capability
projection, and the protected helper key configuration. It restores the exact
persisted helper key, captures the exact system LaunchDaemon PID/start-time and
uid-0 identity, constructs `NativeRootHelperSnapshotTransport` with the
Broker-side HMAC copy, and wipes the startup key copy. The service startup
passes the resulting runner and the same Broker-owned active-request registry
through the Broker task path; competing sandbox or virtualization runners are
rejected.

The startup config now validates a distinct root-helper snapshot socket beside
the Broker and authority sockets. No raw key, socket, executable path, or
capability can be selected by MCP request arguments.

## Verification

- `root-helper-snapshot-task-startup.test.ts` passed 2/2 focused tests.
- The full repository regression passed 979/994 tests with 15 explicit skips
  and 0 failures.
- `npm run typecheck` and `npm run build` passed.
- The physical root-helper probe remains fail-closed with `POLICY_DENIED` on
  UID 501; no LaunchDaemon or public task scope was changed.

## Remaining gates

This evidence does not prove a signed/notarized native root-helper executable,
root-owned package installation, live root-domain round-trip, crash/restart
recovery, or public task enablement. The enabled startup branch remains
unusable until those independent host gates and the shared active-request
registry are present.

## Rollback

Rollback is source-level removal of the startup factory, service wiring, tests,
and this evidence. No host service, LaunchDaemon, OAuth grant, policy entry,
database, or credential store was changed.
