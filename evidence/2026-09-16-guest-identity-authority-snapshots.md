# Guest Identity Authority Snapshot Evidence

- Date: 2026-09-16
- Status: implemented and locally verified; Guest lifecycle and transport
  remain independently host-gated and disabled without native evidence.
- Source revision: `5d1084e7a040eeae8e16d7932ce3f3600e8633a6`
- Host: Darwin 25.2.0, arm64; macOS 26.2 (25C56)

## Boundary

The Guest Agent, Broker transport client, VM lifecycle, and composed runtime
now copy and freeze their expected or published Guest identity at construction.
Later mutation of the caller-owned identity object cannot change the image
digest or runtime version used for request verification, lifecycle transitions,
status readback, or runtime authority.

The transport client also validates and snapshots an optional expected identity
before every request-bound verification path. Adapter-provided identities are
still checked independently on each operation, so a changed adapter identity
fails closed rather than widening authority.

This closes in-process Guest identity reference substitution only. It does not
prove native VM boot, descriptor pinning, remount resistance, signed attestation
production, guest isolation, or production capability enablement.

## Verification

Focused command:

```text
node --test packages/broker/dist/virtualization-guest-lifecycle.test.js packages/broker/dist/virtualization-guest-transport.test.js packages/broker/dist/virtualization-guest-agent.test.js packages/broker/dist/virtualization-guest-startup.test.js
```

Result: 32 tests passed, 0 failed, 0 skipped.

Additional checks passed:

- `npm run build`
- `npm run typecheck`
- `npm run lint`
- `git diff --check`

Serial physical regression (concurrency 1):

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 \
node --test --test-concurrency=1 $(find packages -path '*/dist/*.test.js' \
  ! -name 'broker.test.js' ! -name 'persistence.test.js' \
  ! -name 'privileged-helper-authority-ipc.test.js' | sort)
```

Result: 674 tests, 669 passed, 0 failed, 5 explicit descriptor-capability
skips. The three pre-existing long-running suites were excluded and left
untouched.

SHA-256 source readback:

```text
9d7e5c98aab5320f3749e3bb81e3059c326eb9b5ed1c5f7564ba7e76741e3e80  packages/broker/src/virtualization-guest-agent.ts
02635f8d8e699d5b101e36609a3ced77864036e0a12ab7a8c3703980539b932f  packages/broker/src/virtualization-guest-lifecycle.ts
77c8fc3fe09c9830e2840614e0801d95b276913265e81d1559b8ba077806e374  packages/broker/src/virtualization-guest-startup.ts
015a05734a1998538e65835f9d23077e9ce0ae600b09dce7f7f34c997b33b6ec  packages/broker/src/virtualization-guest-transport.ts
```

## Rollback

Revert commit `5d1084e` with `git revert 5d1084e` if this boundary must be
withdrawn. No host policy, credential, key activation, or virtualization
enablement state was changed.
