# Operator LaunchAgent identity boundary

- Source revision: `working-tree` (dirty; no commit created)
- Captured: 2026-09-22, Asia/Kuala_Lumpur
- Contract: `mac-operator-mcp` repository contracts at source revision above
- Host profile: macOS Darwin arm64, owner UID 501
- Result: PASS for the code-level startup boundary; production enablement remains OPEN

## Boundary verified

The Broker startup configuration now has an explicit optional operator-control
channel. When configured, all three values are required and are independently
validated:

- owner-only authority key configuration below the Broker data root;
- a distinct owner-only authority Unix socket below the Broker runtime root;
- the fixed LaunchAgent identity `gui/<expectedEdgeUid>/com.mac-operator.authority`.

Startup reads the bounded launchd record for that exact service ID, accepts only
an owner-domain LaunchAgent in `running` state, and then captures the native
peer PID/start-time identity. A transient `xpcproxy` record is retried within a
bounded deadline. A missing service, wrong UID, wrong label, non-running state,
missing PID, or unavailable native identity fails closed. The implementation
does not substitute another same-UID process and does not bootstrap or mutate
launchd state.

The optional branch assembles the existing separately authenticated Authority
Control IPC runtime with that exact process identity and disposes key-manager
state on startup failure. The stable `authority-control-service.js` entrypoint
now acts as an owner-only proxy: CLI traffic reaches its separate operator
socket, is verified with the same command HMAC, and is forwarded to the
Broker-owned authority socket. The read-only
`npm run plan:macos:authority` boundary emits fixed install/rollback/uninstall
actions for the exact `--config` path without invoking launchd. The default
startup path is unchanged. Combining the new operator channel with the
root-helper authority channel is rejected until a single explicit combined
assembly exists; this avoids silently starting with only one authority source.

The reusable owner-socket parent-chain validator also protects the Authority
Control, Broker Status, Approval IPC, Virtualization guest, and base Broker IPC
channels. It
rejects ancestor symlinks and unprotected writable directories while allowing
only the fixed macOS `/var` and `/tmp` aliases.

## Verification

Commands:

```text
npm run build
node --test packages/broker/dist/native-runtime-startup.test.js
node --test packages/broker/dist/service-startup.test.js
node --test packages/broker/dist/authority-control-proxy.test.js packages/broker/dist/authority-control-install-plan.test.js packages/broker/dist/authority-control-service.test.js packages/broker/dist/launchd.test.js
```

Observed results:

- build completed successfully;
- native runtime startup identity suite: 10/10 passed;
- service-startup suite: 10/10 passed;
- operator proxy transport test: 1/1 passed;
- operator LaunchAgent plan/readback tests: 4/4 passed, including owner-only
  operator-socket parent-chain, device/inode, and symlink readback;
- focused IPC/helper regression slice: 42/42 passed;
- operator service-entrypoint argument test: 1/1 passed;
- LaunchAgent template coverage: 3/3 passed;
- full repository regression: 1,113 total, 1,098 passed, 15 skipped, 0 failed;
- no launchd service was installed, bootstrapped, restarted, or removed;
- no production Keychain item, root helper, live R1 process, or public MCP
  capability was changed.

## Remaining release evidence

This record does not prove that the operator artifact is production-packaged,
Developer ID signed, notarized, Keychain-provisioned, persistently installed,
or accepted by a live production host. Direct operator protocol end-to-end,
upgrade/rollback, recovery, and final independent review remain open under
`VT-AUTH-01`, `VT-OPS-01`, and the release gates.
