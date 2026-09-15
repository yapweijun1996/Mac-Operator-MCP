# Sandbox protected-root evidence

Date: 2026-09-15
Source revision: `5fb0f3a` (`fix: deny broker-owned sandbox roots`)

## Boundary

The Broker-owned Seatbelt renderer accepts a host-supplied list of canonical
protected filesystem roots. It emits read and write `deny subpath` rules after
task allow rules, so a persistence or runtime root remains inaccessible even
when a task filesystem root overlaps it. The runner copies this list into its
Broker-owned profile options; MCP request arguments cannot add or remove it.
The option is bounded to 32 canonical absolute paths and rejects traversal-like
forms before rendering.

The real-Darwin regression creates a synthetic `broker-persistence` directory,
lists it both as an allowed task root and as a protected root, and verifies
that a child cannot read `ledger.sqlite` while it can still write its ordinary
task fixture. This proves deny-overrides-allow behavior for a non-secret,
Broker-shaped persistence surface.

## Verification

Commands run from the repository root:

```text
npm run lint
npm run build
MOPS_REAL_SANDBOX=1 node --test packages/broker/dist/sandbox-profile.test.js
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 node --test --test-concurrency=1 packages/*/dist/**/*.test.js
npm run verify:contracts
npm run verify:canonical:native
git diff --check
```

Results:

- Sandbox-profile tests: 15 passed, 0 failed.
- Complete serial physical-Darwin suite: 606 passed, 0 failed, 0 skipped.
- Style, build, contract, native canonical-vector, and diff checks passed.

## Limits

Protected roots are an explicit host wiring seam; the production service does
not yet construct or enable `SandboxExecTaskRunner`, so `mac_task_run` remains
disabled. The rules are path-based Seatbelt policy and do not prove a kernel
mount namespace, in-syscall remount resistance, descriptor-held access, or
credential/Docker isolation on a real installed Broker. Host startup must pass
canonical realpaths for its data, runtime, package, and key/config roots before
this boundary can support a production isolation claim.
