# Packaged Edge/Broker LaunchAgent smoke evidence

Date: 2026-09-14
Status: host evidence for a temporary, opt-in smoke; not a release gate

## Scope

This check exercises the reviewed packaged entrypoints under two real user
LaunchAgents. It creates an owner-only temporary package, data root, runtime
root, logs, policy activation, Edge-key activation, TLS material, and signed
policy, then removes every temporary service and file during cleanup.

The test refuses to proceed when either fixed Mac-Operator label is already
loaded. It bootstraps Edge first, waits for the exact launchd program and
argument vector plus a successful TLS handshake, then bootstraps Broker. The
Broker must expose owner-only native Broker and status sockets, and an
independent HMAC status client must read `state=running`, `runtimeState=running`,
the expected source revision, and an empty enabled-capability set. Cleanup
boots out Broker before Edge and boundedly verifies both labels are absent.

## Host and command

- Host: Darwin 25.2.0 arm64
- Node: v25.5.0
- Command: `MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1 node --test packages/broker/dist/packaged-service-smoke.test.js`
- Result: 1 passed, 0 failed, 0 skipped

## Boundary observations

- launchd readback reported `LaunchAgent`, `running`, the canonical Node
  executable, and the exact component `service-main.js` argument for both
  agents.
- Edge HTTPS became reachable before Broker bootstrap.
- Broker native and status sockets were regular Unix sockets owned by the test
  UID with mode `0600`.
- Native process identity was captured for both launchd PIDs.
- Signed policy and Edge-key activation restored successfully; no capability
  was enabled in the smoke policy.
- The compiled Broker loaded its audit-anchor HMAC key through the temporary
  Keychain item bound to the packaged Broker executable and verified the
  owner-only audit sidecar before reporting `running`.
- The postcondition checked both services were absent after bootout.

## Limitations

This is a temporary per-user LaunchAgent fixture. It does not prove Developer
ID signing, notarization, production Keychain provisioning/rotation, remote
OAuth/JWKS interoperability, production package installation, upgrade/rollback,
or privileged helper installation. The test copies runtime dependencies into
the temporary package to avoid treating a workspace `node_modules` symlink as
installed packaging.
