# Canonical JSON wire profile evidence

- Date: 2026-09-15
- Host: physical Darwin arm64, macOS 26.2 (25C56)
- Scope: request/response/ledger digest serialization; no capability enablement
- Source revision: `ae2e9eb`

## Boundary

`@mac-operator/contracts` now publishes the versioned `jcs-utf8-v1` profile and
the `canonicalJsonUtf8` helper. The profile uses ECMAScript JSON escaping,
UTF-16 property-name ordering, and UTF-8 bytes as the digest/signature input.
Existing canonical output is unchanged; the helper centralizes the byte
boundary used by future native adapters.

## Verification

The fixed vector file `schemas/canonical-json-vectors.json` covers nested
objects/arrays, escaping, number formatting, Unicode ordering without
normalization, empty values, and SHA-256 readback. The contracts package test
also compares a TextDecoder round trip to the expected canonical string.

The native probe `scripts/verify-canonical-json-native.sh` compiles a bounded,
read-only Swift standard-library implementation (including its own JSON parser
and SHA-256) and checks the same vector file. It reports `vectors:5,
passed:5` on this host, including the ECMAScript notation thresholds at
`1e-6`, `1e-7`, `1e20`, and `1e21`.

The compiled C++ N-API artifact also exposes a bounded `sha256Utf8` primitive.
`peer-credentials.test.ts` loads that protected `.node` artifact and verifies
all five canonical byte digests, the empty-input digest, and the 1 MiB input
limit. This checks the digest byte boundary used by the native module without
granting it any new host authority.

```text
npm run typecheck
node --test packages/contracts/dist/canonical-json.test.js
npm run verify:canonical:native
MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test
```

Result: 2/2 focused TypeScript tests, 5/5 Swift vectors, 2/2 C++ native digest
checks, and the full physical-Darwin regression passed 537/537 with 0 skipped
tests.

## Limits

The probe establishes an independent native serialization readback, but it is
not the production Swift/C++ guest adapter and does not prove VM boot, guest
isolation, credential/process/network limits, or capability enablement. A
cross-runtime release gate still requires the actual adapter implementation to
consume these exact UTF-8 bytes and pass the vectors.
