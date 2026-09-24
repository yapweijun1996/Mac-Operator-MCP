# System-published executable boundary

- Date: 2026-09-21
- Scope: MOP-045 / MOP-104 fixed host-adapter process launch
- Status: implemented boundary evidence; not public capability enablement
- Host: Darwin arm64, unprivileged user Broker

## Boundary

The native descriptor launcher is unavailable on the current host. Fixed
Broker-owned adapters still need a pathname launch path for immutable system
commands such as `/bin/launchctl`. The new
`requireSystemPublishedExecutable` ProcessSupervisor mode accepts only a
regular executable owned by root with no group/other write bits and verifies
every canonical ancestor directory is root-owned, non-symlink, and not
group/other writable. The target also has no setuid/setgid bits. The Broker
rejects this mode when running as root.

This blocks replacement by an unprivileged same-user process during the
pathname spawn window. It does not authorize user-owned binaries, repository
scripts, shell/interpreter profiles, arbitrary task paths, or root rotation.
The descriptor-backed task-launch gate remains closed.

## Implementation

`packages/broker/src/system-published-executable.ts` provides the asynchronous
boundary assertion and a synchronous startup/readiness readback. The fixed
user-domain service-control candidate now uses this boundary when no native
descriptor launcher is supplied, but still requires explicit operator
acceptance and remains outside the public MCP catalog and default policy.

## Physical readback

Command:

```text
npm run probe:system-published-executable
```

Observed result:

```json
{
  "schemaVersion": "0.1",
  "mechanism": "darwin-system-published-executable-v1",
  "paths": {
    "/bin/launchctl": true,
    "/usr/bin/sandbox-exec": true,
    "/usr/bin/printf": true
  }
}
```

Focused system-published, ProcessSupervisor, and user-service-control tests
pass 60/60. The full repository regression passes 965 total tests: 951 passed,
14 explicit skips, and 0 failures. Build, lint, typecheck, documentation-link,
verification-matrix, and diff checks pass.

## Decision

Use this boundary only for fixed Broker-owned host adapters whose executable
and argument vector are defined by code/configuration outside MCP arguments.
Do not use it as a substitute for the missing descriptor launcher in generic
`mac_task_run`; repository scripts remain untrusted and task enablement still
requires a separate executable-selection and complete-isolation proof.

## Rollback

Remove the system-published executable module, ProcessSupervisor option, fixed
service-control selection, probe script, tests, and this evidence. No public
scope, OAuth grant, service state, permission, or persisted schema is changed
by this slice.
