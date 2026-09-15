# Docker inspect object identity evidence

- Source revision: `423985d`
- Capture date: 2026-09-16 (Asia/Kuala_Lumpur)
- Host: Apple silicon Mac mini, macOS 26.2, Darwin 25.2.0, arm64
- Contract version: `0.1`

## Boundary exercised

The fixed Docker inspect adapter now binds the returned object before it can
be serialized as a successful result. An exact requested ID must match the
reported ID. A short hexadecimal Docker ID is accepted only when the
reported ID is the longer canonical value with that prefix. A non-ID name is
accepted only when the response reports the exact name after normalizing
Docker's one leading `/`; a name that looks like a hexadecimal ID remains an
ID target. A different reported ID fails closed as `CONFLICT`, and an
ambiguous `ID`/`Id` pair remains an execution failure.

## Verification

```text
npx tsc -b --pretty false
pass

node --test packages/broker/dist/docker-inspector.test.js
12 tests, 11 passed, 0 failed, 1 explicit opt-in skip

MOPS_REAL_DOCKER=1 node --test --test-name-pattern='real Docker Desktop' \
  packages/broker/dist/docker-inspector.test.js
1 test, 1 passed, 0 failed
```

The negative test sends a different full ID while retaining a matching
container name for an ID-shaped request and receives `CONFLICT`. Unit
coverage also checks one-way short-ID prefix handling, exact name readback,
name mismatch, ID-looking names, digest normalization, and rejection of a
truncated reported ID. The physical readback used Docker Desktop 29.1.3 in
the `desktop-linux` context, observed the host's bounded container listing,
and inspected one returned container by its canonical ID without warnings or
truncation.

## Limitations

This is a response/result-binding fence, not a kernel-held Docker object
handle. A mutable name can still be replaced between name resolution and the
single CLI invocation; the adapter records that limitation and does not claim
same-name replacement immunity. The evidence does not prove native macOS
daemon isolation, host-level Docker socket denial, code-signature provenance,
container mutation safety, or production deployment.
