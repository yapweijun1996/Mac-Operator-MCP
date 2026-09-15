# Guest Attestation Key Snapshot Evidence

- Date: 2026-09-16
- Status: implemented and locally verified; key activation remains governed by
  protected files, durable revision checks, and explicit operator actions.
- Source revision: `33253763ff19551242ac757aa1b665b900e04635`
- Host: Darwin 25.2.0, arm64; macOS 26.2 (25C56)

## Boundary

`loadVirtualizationGuestAttestationKeyConfig()` and
`VirtualizationGuestAttestationKeyManager` now expose a copied, recursively
frozen authority snapshot. Config documents, key entries, key arrays, and the
active snapshot cannot be mutated by callers after loading or activation.

Protected public-key bytes are copied into immutable PEM strings before
exposure, so a caller cannot modify a returned `Buffer` and change the
material later supplied to a Guest attestation verifier. Revision, key ID,
validity window, configured path, public-key digest, and payload digest remain
the startup-validated values.

This closes in-process active-key object and buffer substitution only. It does
not claim private-key distribution, Developer ID provenance, native attestation
production, VM isolation, or production virtualization enablement.

## Verification

Focused command:

```text
node --test packages/broker/dist/virtualization-guest-attestation-keyring.test.js
```

Result: 4 tests passed, 0 failed, 0 skipped.

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
ea50fa03d5fbcf6bd1b7d640660ff550ea5cba602742fec0087f1cadddb4a3c0  packages/broker/src/virtualization-guest-attestation-keyring.ts
65db75b203e1313920f425b2bd59915f105785b443f638be81f23afadca3d98d  packages/broker/src/virtualization-guest-attestation-keyring.test.ts
```

## Rollback

Revert commit `3325376` with `git revert 3325376` if this boundary must be
withdrawn. No host policy, credential, key activation, or virtualization
enablement state was changed.
