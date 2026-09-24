# Task-profile executable content binding

- Date: 2026-09-21
- Scope: MOP-045 / MOP-086 executable-selection boundary
- Status: implemented authorization hardening; production task execution remains disabled

## Boundary

`TaskProfileRegistry.resolve()` now captures the Broker-observed SHA-256 content
identity of the canonical profile-owned executable and places it in the
resolved `ProcessExecutionRequest.expectedExecutableContentSha256` field. A
profile may also declare a signed `executableContentSha256`; when present, the
observed identity must match it before the resolved profile is returned.

The resolved request is frozen with the digest. `ProcessSupervisor` therefore
rechecks the same content identity during its own executable validation and
startup path. The MCP request can still select only a named profile and bounded
arguments; it cannot supply or replace the executable digest.

This binds the future descriptor/helper handoff to an exact executable content
identity, but it is not itself an atomic descriptor launch or an immutable
snapshot. The native descriptor capability remains unavailable, and the
production task runner remains fail-closed.

## Verification

- `npm run build` passed, including all native build steps.
- Task profile and task runner suites pass 20/20.
- The mismatch fixture rejects a profile whose declared executable digest does
  not match the host-observed executable.
- No production task or real mutation was executed.

## Rollback

Remove the `executableContentSha256` profile field and the resolved digest
binding; no host configuration, service, credential, or installed artifact was
changed.
