# D1 App Sandbox Auth-to-Edge-to-Broker Canary Evidence

Date: 2026-09-22

Scope: MOP-102 / D1 physical task admission through the real Auth grant,
HTTPS Edge, Broker request authentication, owner approval, Job persistence, and
the App Sandbox helper candidate.

## Physical-host result

The existing isolated D1 canary was extended with an opt-in
`MOPS_REAL_APP_SANDBOX=1` mode. The mode binds one ephemeral Broker-owned
Ed25519 signer/verifier pair, a fixed `/bin/sh` script profile, the signed
App Sandbox helper bundle, and the helper's OS-owned container. It does not
fall back to `sandbox-exec` or an unsandboxed child when the App Sandbox
assembly is unavailable.

Command:

```text
npm run probe:d1:app-sandbox
```

Observed result on the physical Darwin arm64 host:

```text
1 test, 1 pass, 0 fail, 0 skipped
isolated D1 canary binds the Auth grant to Edge tools/list and owner-approved write
```

The canary verified the real owner OAuth grant, HTTPS MCP `tools/list`,
unapproved mutation denial with durable preview, owner-approved atomic write,
bounded patch, local Git stage/commit, queued Job cancellation, and the
App-Sandbox-backed `mac_task_run` profile. The task result was verified by
Broker Job status and produced the fixed output `d1-auth-app-sandbox-task`.

## Boundary conclusion

This closes the previously missing Auth-to-Edge-to-Broker integration evidence
for the App Sandbox candidate. The candidate remains staging-only: no live
policy, public OAuth profile, production package, or public `mac_task_run`
tool was enabled. Active App Sandbox cancellation, hostile process-tree
detection, network/credential/persistence denial, and cleanup remain covered
by the separate physical executor probe.

## Verification

- TypeScript typecheck passed before the physical run.
- The App Sandbox helper was rebuilt and ad-hoc signature verification passed.
- The isolated physical canary passed 1/1 with no failures.
- The canary's `finally` path closed the MCP client, HTTPS Edge, Broker, and
  Broker-owned helper runner; its temporary state remained under the test
  directory.

## Rollback

Unset `MOPS_REAL_APP_SANDBOX`; the default canary remains unchanged. Remove
the opt-in package script and this evidence file to revert the integration
evidence. No live policy, OAuth grant, service, or persistent host capability
was changed.
