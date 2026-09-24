# Root Helper Snapshot Transport Evidence

Date: 2026-09-21
Host: Darwin arm64 physical Mac, current process UID 501
Status: `implemented` as a disabled, fail-closed native transport/server and TaskRunner seam; production root-helper execution is not accepted

## Boundary

The Broker now contains a separate `NativeRootHelperSnapshotTransport` client
and `RootHelperSnapshotServer` in
`packages/broker/src/root-helper-snapshot-transport.ts`. The seam uses the
existing native UNIX peer IPC and `SCM_RIGHTS` frame boundary to transfer only
already-open executable and cwd descriptors plus a bounded authenticated
envelope. The envelope is bound by:

- a versioned HMAC request/response domain;
- a Broker-signed Ed25519 descriptor attestation;
- native peer UID/GID/PID and PID start-time identity;
- one-shot request replay admission and bounded freshness;
- argument/environment/task-policy digests; and
- bounded result, timeout, output, and process-tree fields.

The Broker `RootHelperSnapshotTaskRunner` now uses the descriptor registry for
one-shot executable/cwd handoff and forwards HMAC-bound helper process-start
and ownership-change events into the existing Job process-ownership ledger.
This enables the existing exact PID/start-time recovery path without exposing
pathnames or raw helper authority to MCP callers.

The root helper materializes the executable into a fresh private snapshot only
after descriptor identity and content verification. The snapshot is expected to
be root-owned, mode `0700`, and under an independently protected root. The
child is launched through the fixed system-published `/usr/bin/sandbox-exec`
adapter and is dropped to the authenticated Broker UID/GID; the root helper
does not receive a pathname supplied by the Broker request.

The working tree now includes `RootHelperSnapshotRuntime` and
`createRootHelperSnapshotRuntimeFromKeyMaterial`. This startup seam loads the
protected helper key without opening `BrokerStore`, rejects socket reuse and
unnamed Broker peers, and preserves the server's root/evidence gate. It does
not install launchd, change ownership, or enable an MCP capability.

## Physical host result

The boundary probe passed with this result:

```json
{
  "schema_version": "0.1",
  "probe": "root-helper-snapshot-boundary",
  "platform": "darwin",
  "arch": "arm64",
  "uid": 501,
  "root_owned_snapshot_gate": "unavailable",
  "server_available": false,
  "server_start": "POLICY_DENIED",
  "descriptor_path_readback": "verified",
  "public_task_scope": "disabled"
}
```

The current host is not root and the probe intentionally uses a user-owned
temporary root. Consequently the server advertises no capability and refuses
to listen. No root-owned snapshot, production helper socket, LaunchDaemon,
public task scope, OAuth grant, policy entry, or deployment was changed.

## Verification

- `npm run probe:root-helper-snapshot` passed; the probe verified native FD path
  readback and fail-closed root ownership admission.
- `packages/broker/dist/root-helper-snapshot.test.js` passed 9/9, including
  live SCM_RIGHTS request delivery, two authenticated ownership-event frames,
  the final response frame, tampered-HMAC rejection, active-exchange close
  cancellation, and the disabled root-owned host gate.
- `packages/broker/dist/root-helper-snapshot-runtime.test.js` passed 2/2,
  including protected key-material startup and socket-boundary rejection on
  the non-root physical host.
- `packages/broker/dist/task-runner.test.js` passed 14/14, including the
  descriptor-bound root-helper runner and ownership-event forwarding.
- Native descriptor-handoff timeout regression passed: an authenticated peer
  that sends no frame is rejected within the configured 25ms test deadline.
- Server lifecycle now tracks active handler promises and waits for them after
  socket shutdown before wiping the helper authentication key.
- Full repository regression passed 969/984 with 15 explicit skips and 0
  failures.
- Build, typecheck, lint, documentation links, verification matrix, contract
  checks, and `git diff --check` are required before release acceptance.

## Remaining release gates

This evidence does not prove a root-owned production snapshot directory, an
installed or signed LaunchDaemon, Developer ID/notarization, a live helper
round trip, root-domain process readback, crash/restart recovery, or public
`mac_task_run` enablement. Native receive now has an absolute bounded deadline
for the initial frame, continuation bytes, and stream close; it remains a
synchronous native section and still needs production integration hardening,
including an approved root-helper key/socket install and real root-domain
readback.

## Rollback

Rollback is source-level removal of the transport/server export, its native
descriptor-path export, the focused tests/probe, and this evidence. No host
service, OAuth grant, policy, database, or credential store was changed.
