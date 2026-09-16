# Remote JWKS content-length validation evidence

Date: 2026-09-16
Source revision: `dc80e9f`
Host: Darwin `25.2.0`, arm64; macOS `26.2`; Node.js `25.5.0`

## Boundary exercised

The Edge JWT verifier now validates a normal numeric `content-length` header
with the intended digit grammar. Previously, an accidentally double-escaped
regular expression rejected every numeric header and could deny otherwise
valid issuer responses. Oversized and malformed lengths remain fail-closed;
response status, content type, redirect, streaming byte cap, issuer,
audience, algorithm, and token-age checks are unchanged.

## Verification

The remote-JWKS test now includes a valid exact byte length and continues to
exercise key caching, rotation, malformed/oversized lengths, wrong content
types, redirects, and non-success status responses:

```text
npm run typecheck -- --pretty false
npm run lint
npm run build --silent
node --test packages/edge/dist/jwt-verifier.test.js
tests 8
pass 8
fail 0
```

The fetches use synthetic signing keys and in-memory responses only; no real
issuer or credential was contacted.

## Limits

This fixes numeric header interoperability and preserves the bounded remote
JWKS boundary. It does not prove a production issuer deployment, certificate
provenance/pinning, distributed key rotation, or remote revocation delivery.

## Rollback

Revert commit `dc80e9f`; no network or host configuration changed.
