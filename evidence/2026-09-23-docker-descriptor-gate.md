# Docker Descriptor-Execution Gate

Date: 2026-09-23
Host: physical macOS host used by the repository test harness
Scope: Broker default Docker process authority

## Decision

The default Broker Docker adapter now receives a separate
`ProcessSupervisor`. That supervisor requires the host-proven
`darwin-descriptor-exec-v1` launcher before admission. It is not the shared
supervisor used by Git, launchd, GUI, and other fixed adapters, so ordinary
pathname execution cannot be inherited by Docker. A missing native launcher
returns `POLICY_DENIED` before spawn; no pathname fallback is permitted.

## Implemented controls

- Docker keeps its fixed executable allowlist, root-owner requirement, bounded
  environment, local socket profile, code-signature check, and content-identity
  check.
- The Docker-specific supervisor is Broker-owned and closed with the Broker.
- A host-owned descriptor launcher may be supplied only through the typed
  construction seam; MCP arguments cannot select or replace it.
- Existing Docker object identity rechecks and ProcessSupervisor executable
  target-swap checks remain in force.

## Verification

Focused command:

```text
npm run build && node --test packages/broker/dist/docker-inspector.test.js packages/broker/dist/process-supervisor.test.js
```

Result: 61 passed, 1 skipped, 0 failed. The Docker suite now also proves that
the production supervisor rejects descriptor-required admission on this host;
the ProcessSupervisor suite proves that an unavailable descriptor capability
does not invoke a launcher or fall back to pathname spawn.

## Remaining boundary

This is a fail-closed gate, not proof that Docker is executable through a
kernel-held descriptor on this host. The native descriptor launcher,
same-name replacement race harness around a real Docker daemon, host-level raw
socket negative test, VM isolation, and production Docker readback remain open.
The prior Docker daemon readback is historical evidence only and does not
override the new default gate.

## Recovery

The change is reversible by restoring the previous Docker supervisor assembly,
but doing so would re-open the pathname-spawn target-swap boundary. No host
service, Docker daemon, permission, credential, or launchd state was changed.
