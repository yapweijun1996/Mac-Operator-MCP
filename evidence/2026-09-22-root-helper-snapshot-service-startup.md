# Root Helper Snapshot Service Startup Evidence

Date: 2026-09-22
Host: Darwin arm64 physical Mac, current process UID 501
Status: `implemented` as a fail-closed startup and authority-channel seam; root-domain installation remains blocked

## Boundary

The Broker now has an explicit startup assembly for the root-helper snapshot
authority listener. It restores the active helper-key configuration through
`PrivilegedHelperKeyManager`, binds the exact system LaunchDaemon identity, and
adds the authority listener as a Broker-owned native operator channel. The
channel is separate from the MCP Broker socket and is closed on partial startup
or assembly disposal.

The root-helper service startup entrypoint binds back to the per-user Broker
LaunchAgent using exact launchd service readback plus native PID/start-time
identity. The Broker-side root-helper identity capture additionally reads native
process credentials and rejects any process that is not uid 0. The root helper
itself still loads protected key material without opening `BrokerStore`.

The transport and authority listener share a Broker-owned active-request
registry. The final Broker task admission rechecks current request, target,
policy, session, and revocation authority before admitting the digest of the
exact signed snapshot envelope. That one-shot admission/release object is
forwarded through the root-helper TaskRunner and executor to the transport,
which releases it after the exchange. The helper's authenticated authority
poll is accepted only while that digest is active and unexpired; revocation or
release causes a fail-closed authority response.

## Verification

- `npm run typecheck` passed.
- `npm run build` passed, including the rebuilt native peer-credentials addon.
- Root-helper service and runtime focused tests passed 8/8; root-helper
  TaskRunner/transport authority propagation tests also passed.
- Full repository regression passed 977/992 with 15 explicit skips and 0 failures.
- Native peer-credential tests passed, including the rebuilt addon export set.
- No LaunchDaemon was written or bootstrapped; the current non-root host keeps
  the root-helper runtime unavailable with `POLICY_DENIED`.

## Remaining gates

This evidence does not prove a signed/notarized native root-helper executable,
root-owned package installation, live root-domain socket/process readback,
crash/restart recovery, or public task enablement. Production startup must
still supply the same active-request registry to the Broker task runner and
authority listener, and release acceptance still requires live root-domain
evidence.

## Rollback

Rollback is source-level removal of the startup seam, active-request registry,
native credentials export, focused tests, and this evidence. No host service,
LaunchDaemon, OAuth grant, policy entry, database, or credential store was
changed.
