# Canonical JSON wire profile evidence

- Date: 2026-09-15
- Host: physical Darwin arm64, macOS 26.2 (25C56)
- Scope: request/response/ledger digest serialization; no capability enablement
- Source revision: `7860a00`

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

```text
npm run typecheck
node --test packages/contracts/dist/canonical-json.test.js
```

Result: 2/2 focused tests passed and the full physical-Darwin regression on
this source revision passed 535/535.

## Limits

These vectors establish a stable repository contract, not interoperability
evidence from a Swift/C++ guest implementation. Native adapters must consume
the exact UTF-8 bytes and pass the same vectors before a cross-runtime release
gate can close. This change does not alter authentication keys, VM boot,
guest isolation, or capability enablement.
