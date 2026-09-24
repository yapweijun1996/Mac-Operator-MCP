# D1 App Sandbox executor physical rerun

- Date: 2026-09-22
- Scope: bounded D1 task execution through the signed App Sandbox helper candidate
- Status: physical macOS arm64 boundary passed; production enablement remains gated
- Host boundary: unprivileged Broker, fixed `/bin/sh` interpreter, descriptor-only staged roots, Broker-owned loopback proxy

## Verification

The opt-in physical run used the existing executor probe with the positive
Broker-owned network channel and hostile process-tree case enabled:

```text
MOP_PROBE_NETWORK_PROXY=1 MOP_PROBE_HOSTILE_PROCESS_TREE=1 \
  npm run probe:app-sandbox:executor
```

The probe built the native helper and returned a successful structured result.
The verified boundaries were:

- native helper authentication and descriptor snapshot attestation;
- fixed `/bin/sh` script descriptor and process-start event;
- staged authorized-root read/write;
- outside-root read denial;
- control-material unreachability;
- direct child network denial;
- one exact request through the Broker-owned loopback proxy;
- LaunchAgents persistence-write denial;
- `.ssh` credential-zone read denial;
- hostile background-fork detection with `UNKNOWN_OUTCOME` in 52 ms;
- no staged container or canary residue after close.

The hostile process case did not report success after a descendant escaped the
single-process policy. It preserved an unknown outcome, which is the required
conservative result when termination cannot be proven.

## Limits and rollback

This is a disposable physical boundary probe, not a production install. The
host has no valid Developer ID identity, the helper artifact is ad-hoc signed,
and the current macOS host returns `EPERM` for executing a freshly materialized
arbitrary binary from the App Sandbox container. The supported path therefore
remains fixed-interpreter, digest-bound script data with explicit filesystem,
network, credential, timeout, output, and process-tree limits. Generic shell
strings, arbitrary executable selection, unrestricted repository scripts, root
execution, and public `mac_task_run` enablement remain disabled.

The probe creates only disposable temporary roots/canaries and removes them on
completion. No persistent service, OAuth grant, policy scope, or public MCP
tools list was changed.
