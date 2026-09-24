# Native Descriptor Execution Probe Evidence

Date: 2026-09-21

Scope: MOP-060/MOP-061/MOP-102 descriptor-execution investigation on the
physical Darwin host.

## Host probe

The native peer adapter exposes a read-only `getDescriptorExecProbe()` probe.
It checks for a runtime `fexecve` symbol and, only if present, attempts a
fixed `/usr/bin/true` child execution with an already-open descriptor. It also
tests the macOS `O_EXEC` plus `/dev/fd/<fd>` route with that same fixed binary.
It uses no MCP arguments, caller-selected path, argv, environment, or task
profile. The probe does not change the production process-launch capability
and is not consulted by `ProcessSupervisor`.

Observed result on Darwin 25.2.0 arm64 / macOS 26.2:

```json
{
  "schemaVersion": "0.1",
  "mechanism": "darwin-descriptor-exec-probe-v1",
  "fexecveSymbol": "absent",
  "fexecveExecution": "unavailable",
  "execveatSymbol": "absent",
  "executableCoverage": "unproven",
  "immutableSelection": "unproven",
  "descriptorPathOpen": "passed",
  "descriptorPathExecution": "failed",
  "evidenceRef": "mac-operator-native-descriptor-exec-probe-v1"
}
```

The result is mixed: the installed runtime has no `fexecve`/`execveat`, and the
fixed `O_EXEC` plus `/dev/fd/<fd>` experiment opened the descriptor but failed
to execute `/usr/bin/true`. This rejects that route as a proven launch
mechanism on this host. It also does not establish safe argument/cwd handoff,
sandbox integration, child-process coverage, or resistance to descriptor
inheritance and target swaps.

A supplemental Node `spawn()` experiment attempted the same fixed
`/dev/fd/<fd>` path with both an `O_RDONLY` descriptor and an `O_EXEC`
descriptor. Both attempts failed with `EACCES`. This rules out treating a
pathname-based `/dev/fd` shim as an equivalent descriptor launcher; it does
not change the production capability state.

## Verification

- Native addon build passed with `-Wall -Wextra -Werror`.
- The descriptor-execution probe and parser suite passed 2/2.
- The existing descriptor-launch capability suite still passed 3/3 and
  remains unavailable with `POLICY_DENIED` admission.
- The existing descriptor handoff, helper receiver, and signed snapshot
  suites passed 17/17 in the focused run.
- Full repository regression passed 946/960 with 14 explicit skips and no
  failures.

## Boundary conclusion

This probe adds runtime evidence only. It does not prove arbitrary executable
coverage, immutable program selection for Broker-selected paths, close-on-exec
across all descendants, remount resistance, sandbox isolation, helper
packaging, or task admission. The native process-launch capability remains
unavailable, pathname launch is not enabled as a substitute, and all task
execution paths remain disabled.

## Rollback

Rollback removes the native probe/export, its TypeScript parser/tests, and this
evidence. No helper, launchd service, OAuth scope, policy, database, or host
configuration was changed.
