# Live Broker Startup Assembly Evidence

Status: Partial real-host startup assembly; installed packaging remains open

## Scope

This smoke exercises `createBrokerServiceFromStartupConfig` on a physical
Darwin arm64 host. A unique temporary per-user LaunchAgent supplies the real
Edge launchd identity; the Broker uses temporary owner-only data/runtime roots
and a zero-enabled-capability signed policy. No persistent service, remote
Edge, privileged helper, or capability was installed.

## Procedure and result

- Bootstrapped a unique `gui/<uid>` LaunchAgent running only `/bin/sleep 60`
  from a `0600` temporary plist, then read it through the production launchd
  adapter until the state was `running` with a positive PID.
- Provisioned a temporary owner-only Edge key, activated its exact metadata in
  `BrokerStore`, generated an Ed25519 policy-signing key, and activated a
  signed revision-1 policy trusting only the temporary Edge identity.
- Called `createBrokerServiceFromStartupConfig` without a synthetic launchd
  executor. Startup restored the persisted policy and Edge-key identities,
  captured the LaunchAgent PID/start-time through native readback, acquired the
  runtime instance lock, reconciled restart state, and constructed the native
  Broker IPC runtime.
- Started the service and verified the owner-only native Broker socket. Closed
  the assembly, verified socket removal, booted out the temporary LaunchAgent,
  and removed all temporary files in a `finally` path.

Observed result:

```text
serviceId=gui/501/com.mac-operator.mops-broker-c6f729733d
edgePid=42328
edgeState=running
brokerState=running
runtimeState=running
enabledCapabilities=[]
brokerSocketMode=600
nativeTransportRequired=true
```

## Acceptance boundary

This proves the real host startup assembly can bind a Broker to a live,
per-user launchd Edge identity and start the native listener only after signed
authority restoration. It does not prove Edge-to-Broker request exchange,
production package installation, Developer ID signing/notarization, upgrade or
rollback of the real package, persistent launchd service operation, or helper
installation.

Two earlier harness attempts were rejected before listener startup by existing
fail-closed checks: non-canonical `/var` temporary roots and an overlong Unix
socket path. The corrected run used canonical `/private/tmp` roots and passed
without weakening either boundary.

## Verification context

- Source baseline: `baae3a3`.
- Host: Darwin arm64, Node `v25.5.0`, non-root UID `501`.
- No secret bytes, signing private keys, or persistent launchd artifacts were
  recorded in this evidence.
