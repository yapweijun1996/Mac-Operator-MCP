# Signed Virtualization Guest Attestation Evidence

Status: signed provenance verifier implemented; VM execution remains disabled

Date: 2026-09-15

Host: physical Apple silicon Mac mini, macOS 26.2 (Build 25C56), Darwin 25.2.0, arm64

Source revision: `84da3e0`

## Boundary implemented

`packages/broker/src/virtualization-guest-attestation.ts` defines a versioned
Ed25519-signed envelope for the existing guest attestation claims. The
signature covers the key ID, algorithm, issue/expiry window, payload digest,
and the complete attestation payload. The verifier accepts only startup-owned
trusted keys, enforces key validity and revocation callbacks, bounds envelope
lifetime, rejects future/expired claims, and validates the inner digest-only
attestation without accepting host paths, commands, or credentials.

`VirtualizationTaskRunner` keeps the prior disabled-by-default behavior. When a
host supplies an attestation verifier, the runner requires a matching signed
attestation at construction and revalidates the same envelope before each
dispatch and restart status recovery. Key revocation, expiry, envelope
replacement, or payload mismatch fails closed before the executor is called.

## Verification

Focused guest-attestation and task-runner tests:

```text
node --test packages/broker/dist/virtualization-guest-attestation.test.js packages/broker/dist/task-runner.test.js
15 tests, 15 passed, 0 failed
```

Full physical-host regression:

```text
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
527 tests, 527 passed, 0 failed, 0 cancelled, 0 skipped
```

## Remaining release gates

The verifier uses injected startup trust material and does not itself provide
Keychain-backed guest signing-key distribution, a native guest attestation
producer, VM boot, guest filesystem/network/credential/process isolation,
postcondition readback, or production capability enablement. Those remain
separate MOP-086/VT-VZ-02 release gates.
