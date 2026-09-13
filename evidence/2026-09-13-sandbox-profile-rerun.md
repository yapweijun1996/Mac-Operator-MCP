# Current-revision sandbox profile rerun

Status: PASS for the existing opt-in synthetic sandbox smoke; production task
execution remains BLOCKED because credential, persistence, hostile descendant,
and crash/restart isolation evidence is incomplete.

- Date: 2026-09-13 (Asia/Kuala_Lumpur)
- Host: Mac mini M4, arm64, macOS 26.2 build 25C56
- Source revision: `4d18b31166c3bf333adce596f3c985408b6741c3`
- Working tree before this evidence document: clean after the source revision
- Scope: disabled-by-default `SandboxExecTaskRunner`, disposable temporary fixture only
- Host mutation: temporary fixture files/processes; no service, credential, Keychain, or privileged state changed

## Verification

- `MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js` — 7/7 passed, 0 skipped.
- The smoke covers Broker-rendered deny-default profile construction, explicit
  empty environment, temporary-root access, protected-file and symlink denial,
  selected loopback/network denial, child-launch denial, and active sleep
  cancellation through the process boundary.
- Full opt-in regression at the same current revision: `MOPS_REAL_SANDBOX=1 npm test` — 370/370 passed.

## Interpretation

This is a fresh current-host readback of an existing partial boundary. It does
not prove real credential contents, arbitrary descendant/`setsid` ownership,
crash/restart cleanup, persistence, Docker isolation, privilege isolation,
external allowlisted networking, or remount behavior. `sandbox-exec` remains a
deprecated host primitive; the default task runner and `mac_task_run` remain
fail-closed and disabled.
