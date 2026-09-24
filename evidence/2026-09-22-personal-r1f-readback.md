# Personal R1f deployment readback

- Date: 2026-09-22
- Scope: current owner-only R1 deployment state and process readback
- Status: current live snapshot matches the loopback-status deployment contract
- Mutation: none; this evidence uses only local configuration/process/listener readback

## Verification

The owner-only preflight was run against the protected runtime state root:

```text
npm run verify:personal:snapshot -- \
  "/Users/yapweijun/Library/Application Support/MacOperator-r1f"
```

Result:

```text
Personal snapshot preflight passed:
sourceRevision=6e971c38a660588fbea6bfbfc067896ebbad7aa2a7c46f7220d3f8726989fdf1
loopbackStatus=bound
```

The readback also confirmed:

- PM2 process `mac-operator-personal` is online with zero restarts;
- its working directory is the protected `personal-20260921-r1f` release;
- the supervisor owns separate Auth and Edge child listeners;
- Auth and Edge are listening only on `127.0.0.1:3444` and `127.0.0.1:3443`;
- the Edge startup document carries the expected 17 R1 required scopes and
  loopback OAuth status URL/CA binding;
- no root LaunchDaemon or unrelated `com.mac-operator.*` LaunchAgent was
  found by the bounded label readback.

The first preflight attempt used the release-artifact directory as the state
root and correctly failed because it had no `personal/edge-service.json`.
The correct state root is the sibling `MacOperator-r1f` directory documented
by the deployment contract. No configuration was changed to correct the
mistake.

## Limits

This proves current local process/configuration readback, not a fresh external
ChatGPT tools/call. The snapshot is still unsigned for formal release purposes;
Developer ID identity, notarization, persistent LaunchDaemon installation,
D1/G1/P1 public enablement, and root-helper deployment remain separate gates.
