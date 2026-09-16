# Process working-directory permission boundary evidence

Date: 2026-09-16
Source revision: `5feda4c`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

`ProcessSupervisor` now rejects a process working directory when group or
other write bits are set. The check runs in the final Broker-owned path
validation and is repeated by the existing pre/post startup identity checks.
Canonical, non-symlink directories remain required; owner write permission is
allowed. This prevents an externally writable cwd from participating in the
pathname startup race.

## Verification

The focused physical-Darwin ProcessSupervisor suite creates a temporary
canonical directory, changes it to mode `0777`, and verifies stable
`POLICY_DENIED` before any child starts. The same suite covers descriptor
admission, executable/cwd swaps, content identity, cancellation, ownership,
output, timeout, and capacity:

```text
npm run typecheck -- --pretty false
npm run lint
npm run build --silent
node --test packages/broker/dist/process-supervisor.test.js
tests 42
pass 42
fail 0
```

The temporary directory was restored to owner-only mode and removed. No
installed service, credential, or key material was accessed.

## Limits

This closes the writable-cwd admission gap. It does not provide atomic kernel
descriptor execution, remount resistance, or production sandbox/process-tree
isolation; those gates remain open or blocked as recorded in the matrix.

## Rollback

Revert commit `5feda4c`; no persistent host configuration changed.
