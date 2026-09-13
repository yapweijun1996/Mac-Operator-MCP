# Real macOS sandbox regression evidence

Date: 2026-09-14
Host: Darwin arm64 development host
Scope: opt-in temporary fixtures only; no production task capability enabled

## Command

```text
MOPS_REAL_SANDBOX=1 npm test
```

## Result

The full repository suite completed with 431 tests: 430 passed, 0 failed, and
1 explicit skip. The three real sandbox runner checks executed successfully:

- inherited controller/credential environment and protected filesystem paths
  were denied;
- the single-process profile denied hostile `fork`/`setsid` child launch and
  external network access while allowing only the selected loopback fixture;
- active cancellation terminated the bounded `/bin/sleep` process group.

The run also exercised the existing Edge/Broker, filesystem-race, audit,
revocation, GUI, helper, and packaging tests in the same source revision.

## Interpretation

This is stronger current-host evidence for the experimental
`SandboxExecTaskRunner`, but it does not select deprecated `sandbox-exec` as a
production isolation mechanism. Credential contents, Docker protocol access,
post-snapshot descendants, physical remounts, and production task enablement
remain unproven; `mac_task_run` stays disabled and its release gate remains
blocked pending a supported sandbox/process-ownership decision.

The proof schema now records the exact `sandboxMechanism` (`sandbox-exec`) and
rejects other mechanism values. This prevents this experimental evidence from
being silently reused by a future App Sandbox or Virtualization runner.

The `TaskRunner` must declare the same host mechanism. Broker admission and
dispatch reject a missing or mismatched declaration before consuming approval
or launching a child process.
