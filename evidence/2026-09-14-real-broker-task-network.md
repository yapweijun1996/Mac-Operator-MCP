# Real Broker Task Network-Allowlist Evidence

Date: 2026-09-14
Host: physical Darwin arm64 development host
Scope: opt-in integration only; no production capability enablement

## Command

```text
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/broker.test.js
MOPS_REAL_SANDBOX=1 npm test
```

## Observed result

- Focused Broker suite: 72/72 passed.
- Full real-sandbox suite: 448/449 passed, 0 failed, 1 explicit host-boundary/opt-in skip.
- The network integration ran only with `MOPS_REAL_SANDBOX=1` on Darwin.

## Boundary exercised

The test starts a temporary loopback HTTP fixture and creates a Broker-owned
`tests.curl` TaskProfile. The profile fixes `/usr/bin/curl`, a canonical
temporary cwd, an empty environment, no requested arguments, a two-second
timeout, bounded output, and the exact `tcp://localhost:<port>` network
allowlist. The URL and curl flags are fixed profile arguments; the signed MCP
request can select only the named profile and cwd.

The Broker validates the signed request, target, approval digest, profile, and
Job before dispatching `SandboxExecTaskRunner`. The sandbox reaches the
selected local fixture and returns `broker-network-readback`; Broker verifies
the result and reads back a completed Job.

## What this proves

- Network policy is profile-owned and cannot be expanded by task arguments.
- A real Broker request can traverse the allowlisted loopback boundary and
  publish only verified output.
- The process executable, URL, environment, timeout, and output budget remain
  fixed by Broker-owned profile data.

## What this does not prove

This test does not establish external allowlisted networking, DNS pinning,
UDP behavior, or production network-filtering guarantees. Existing real
sandbox tests deny unlisted loopback and external destinations, but the runner
still uses deprecated `sandbox-exec`; `mac_task_run` remains disabled by
default.
