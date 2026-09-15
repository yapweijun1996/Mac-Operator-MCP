# Real macOS sandbox readback evidence

Date: 2026-09-15
Source revision: `633f538`
Host: physical Mac mini, arm64, macOS 26.2 (Build 25C56), Darwin 25.2.0
Runtime: Node.js v25.5.0

## Command and result

```text
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js
16 tests, 16 passed, 0 failed, 0 skipped
```

## Covered boundary

The readback exercises the Broker-rendered deny-default profile and temporary
root, explicit empty child environment, protected controller/credential-surface
denials, root-contained secret-file denial, outside symlink denial, selected
loopback TCP/UDP allowlists, external network/DNS denial, single-process fork
and `setsid` escape denial, and active cancellation mapped to owned process-group
termination.

## Limits and release impact

This is host evidence for the opt-in deprecated `sandbox-exec` candidate only.
It does not prove real credential contents, persistent/remount resistance,
post-snapshot descendants, owned-group process-tree semantics, crash/restart
cleanup, external allowlisted networking, Docker/persistence isolation,
production packaging, or a supported production task runner. `mac_task_run`,
`MOP-043`, `MOP-045`, `VT-SBX-01`, and `VT-SBX-02` remain gated.

## Rollback

Evidence-only change; remove this record if the host readback is superseded.
