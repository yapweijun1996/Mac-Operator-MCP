# Root helper snapshot contract evidence

Date: 2026-09-21
Host: Darwin arm64 physical Mac
Status: `implemented` as a fail-closed protocol and adapter seam; the native transport/server seam is now implemented but production root-helper execution is not accepted

## Scope

This evidence records the next boundary for the future separately authenticated
root helper. It does not install a root helper, launch a privileged process,
enable a public MCP scope, or change the current personal deployment.

The Broker-side contract is implemented in
`packages/broker/src/root-helper-snapshot.ts` and the native transport/server
seam is implemented in
`packages/broker/src/root-helper-snapshot-transport.ts`; both are exported from
the Broker package. The adapter is deliberately not wired into
`SandboxExecTaskRunner`, task admission, the public MCP catalog, OAuth grants,
or default policy. Current transport and physical-gate evidence is recorded in
[`evidence/2026-09-21-root-helper-snapshot-transport.md`](2026-09-21-root-helper-snapshot-transport.md).

## Required independent capability proof

The transport is considered available only when all of the following are true:

- the capability is explicitly enabled and host evidence is independently accepted;
- executable and cwd FD identity is verified;
- immutable executable selection is enforced;
- the snapshot is root-owned and private;
- close-on-exec is enforced;
- the helper is authenticated by native peer checks and HMAC;
- a bounded evidence reference is present.

Any incomplete or malformed capability is rejected. There is no pathname,
`/dev/fd`, `ProcessSupervisor`, or system-published-executable fallback.

## Request and result boundary

The future transport receives only Broker-resolved arguments, environment,
timeouts, output budget, already-open executable/cwd descriptors, and a short-
lived signed descriptor-snapshot attestation. Executable and cwd paths are not
part of the request. The adapter verifies the attestation signature and
recomputes the argument/environment digests before transport dispatch.

The returned process result is strict and bounded. It requires consistent
terminal state, bounded output and duration, valid process identity, and
observed termination. A missing termination observation or an inconsistent
`unknown` result becomes `UNKNOWN_OUTCOME`; non-Broker transport failures are
also converted to retryable `UNKNOWN_OUTCOME`.

## Verification

Focused build and tests passed:

```text
npm run build
node --test packages/broker/dist/root-helper-snapshot.test.js
6 tests, 6 passed, 0 failed
```

The focused tests cover strict capability completeness, independent host-gate
fail-closed behavior, signed argument/environment digest verification before
transport dispatch, malformed result rejection, and unresolved termination.

The current host still lacks accepted root-owned production evidence: the
physical `fexecve`/`execveat` probe and fixed `O_EXEC` plus `/dev/fd` experiment
remain negative, and the root-owned snapshot gate is unavailable under the
current UID. Therefore no production helper installation, live helper
round-trip, or immutable snapshot launch claim is made.

## Rollback and next gate

Rollback is source-level removal of the new export/adapter and evidence file;
there is no deployment or policy migration. The next gate is an independently
reviewed root-owned deployment that authenticates the helper, materializes and
reads back a private immutable snapshot, proves close-on-exec and process
identity behavior, and remains disabled until real-Mac round-trip and recovery
evidence pass.
