# Privileged service-control adapter

- Date: 2026-09-16
- Scope: L5 allowlisted service-control operation

## Implementation

`PrivilegedServiceControlAdapter` is a host-owned helper adapter for the
already-authenticated `service_control` payload. It accepts only `start`,
`stop`, and `restart`; `enable` and `disable` remain rejected as
`UNSUPPORTED_CAPABILITY` until their enabled-state readback is separately
specified.

The command boundary is fixed:

- executable: `/bin/launchctl`;
- working directory: `/`;
- environment: empty;
- output cap: 128 KiB;
- command timeout: at most 5 seconds;
- descriptor execution: required by the production `ProcessSupervisor`.

The adapter reads the service state before dispatch, uses only fixed argv
(`kickstart`, `kill SIGTERM`, or `kickstart -k`), and reads the same service
again afterward. A matching state is the only success condition. Already
satisfied `start`/`stop` requests are idempotent but still require a final
readback. A post-dispatch readback failure returns `UNKNOWN_OUTCOME`; a state
mismatch returns `VERIFICATION_FAILED`.

The production adapter is explicitly disabled unless the helper process is
root and the host reports the complete descriptor-exec capability. A test-only
injected command runner does not change production startup configuration or
install a root service.

On the current physical host, constructing the adapter with explicit
`enabled: true` still produced:

```json
{"available":false,"enabledCapabilities":[]}
```

This is the expected fail-closed result from the host descriptor capability
probe, not evidence that launchd mutation is available.

## Verification

The focused adapter suite passes 6/6 and repository typecheck passes. The
full repository regression passes 867 tests: 853 passed, 14 explicit skips,
and 0 failures. No real launchd mutation was performed; current physical-host
descriptor-exec evidence keeps the production adapter unavailable.

This evidence proves the bounded adapter contract and verification behavior,
not root LaunchDaemon installation, Developer ID provenance, or enabled
privileged execution.
