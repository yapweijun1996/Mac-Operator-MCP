# Privileged service-control system-published boundary

- Date: 2026-09-21
- Scope: MOP-105 / P1 `mac_priv_service_control` implementation boundary
- Status: implemented candidate; not privileged capability enablement
- Host: Darwin arm64, unprivileged Broker and separately authenticated root-helper design

## Boundary

`PrivilegedServiceControlAdapter` now uses the fixed `/bin/launchctl` system-
published executable boundary for native helper wiring. The Broker-owned
supervisor requires root ownership, canonical non-symlink ancestors, no
group/other write bits, no setuid/setgid bits, and an unprivileged caller
where applicable. Native availability also requires the root-helper process,
explicit host acceptance of this fixed boundary, and a physical path readback.

The adapter still accepts only the versioned service-control payload. The
action is limited to `start`, `stop`, or `restart`; launchctl arguments,
working directory, environment, timeout, output cap, and readback remain
adapter-owned. Broker approval, HMAC helper IPC, authority polling, replay
protection, cancellation, and postcondition verification remain separate
gates. No MCP scope, OAuth grant, default policy, or live service mutation was
enabled.

The descriptor launcher is not silently treated as available: the current
physical host has no proven `fexecve`/`execveat` execution path, so the fixed
system-published route is the only pathname route used by this adapter.

## Verification

Focused privileged service-control, helper-runtime, and Broker-dispatch tests
pass 18/18. Typecheck and build pass. The native system-published executable
probe reports `/bin/launchctl`, `/usr/bin/sandbox-exec`, and `/usr/bin/printf`
as acceptable fixed host paths.

The root-helper runtime remains fail-closed until Developer ID/notarization,
protected production key material, root LaunchDaemon installation, exact
runtime readback, independent review, and owner-approved live mutation
evidence are complete.

## Rollback

Remove the native system-published selection and its acceptance option from
`PrivilegedServiceControlAdapter`, restore the unavailable descriptor-only
production gate, remove this evidence, and rerun the helper/runtime,
full-regression, documentation, and verification-matrix checks. No system
service, permission, key, socket, or persisted authority state is changed by
this implementation slice.
