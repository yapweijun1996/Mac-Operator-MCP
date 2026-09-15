# Signed Guest Attestation Snapshot Evidence

- Date: 2026-09-16
- Status: implemented and locally verified; signed provenance remains
  evidence-gated and does not enable virtualization by itself.
- Source revision: `08770f390de1bab98a8ddc38173892c6b19fd68c`
- Host: Darwin 25.2.0, arm64; macOS 26.2 (25C56)

## Boundary

The Broker now copies and recursively freezes signed Guest attestation
envelopes at every long-lived retention point. `VirtualizationGuestAttestationVerifier.verify()` returns a frozen verification result;
`VirtualizationGuestTransportExecutor` freezes an optional signed envelope
before exposing it; and `VirtualizationTaskRunner` binds its own immutable
startup snapshot before checking availability or dispatching work.

The snapshot includes the version, key ID, algorithm, validity window, payload
digest, signature, complete attestation claims, and nested Guest identity.
Mutation of the original caller object after construction cannot change the
envelope used for later freshness, revocation, signature, or proof checks.

This closes in-process post-verification object substitution only. It does not
prove native attestation production, protected private-key distribution, VM
boot, guest isolation, remount resistance, or production capability enablement.

## Verification

Focused command:

```text
node --test packages/broker/dist/virtualization-guest-attestation.test.js packages/broker/dist/task-runner.test.js
```

Result: 20 tests passed, 0 failed, 0 skipped.

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

Result: 672 tests, 667 passed, 0 failed, 5 explicit descriptor-capability
skips. The three pre-existing long-running suites were excluded and left
untouched.

SHA-256 source readback:

```text
a67cc266eb9a662c186e866cc58603c4fd803194a3a3eb0307620450b9bc46aa  packages/broker/src/virtualization-guest-attestation.ts
049e935654356579e9ef3632442d12c06ac49f3875243b8471f39fef3a9daf2a  packages/broker/src/task-runner.ts
84c4fc18fa2c150ce761e0e730621d966b385b2f6e9fba19cefa7b26589b3691  packages/broker/src/virtualization-guest-attestation.test.ts
9e142de688d37b5720ef91e3d33dc9fff7a6f748f5525fcfb1a7c57d845fefd6  packages/broker/src/task-runner.test.ts
```

## Rollback

Revert commit `08770f3` with `git revert 08770f3` if this boundary must be
withdrawn. No host policy, credential, key, or virtualization enablement state
was changed.
