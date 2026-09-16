# Encoded secret representation guard evidence

Date: 2026-09-16
Source revisions: `b1732bd`, `b83d043`
Host: Darwin arm64, Node.js 25.5.0

## Boundary exercised

The Broker secret policy now checks UTF-16LE/BE content and bounded Base64
candidates in addition to the existing plain-text signatures. A value is
treated as secret only when its decoded text matches an already-known
credential signature; arbitrary binary and high-entropy text are not denied by
this change. The same Base64 check runs before child spawn for argv and
allowlisted environment values, and log redaction replaces matching encoded
candidates with `[REDACTED]`.

## Verification

The focused synthetic suite covers Base64, UTF-16LE, UTF-16BE, argv,
environment (including task and guest profile admission), log redaction, and
a safe Base64 false-positive case:

```text
npm run typecheck -- --pretty false
npm run lint
npm run build --silent
node --test packages/broker/dist/secret-policy.test.js \
  packages/broker/dist/security-fuzz.test.js \
  packages/broker/dist/process-supervisor.test.js \
  packages/broker/dist/task-profile.test.js
tests 63
pass 63
fail 0
```

No real credential, private key, browser profile, or Keychain item was read.

## Limits

This is a conservative encoded-signature guard, not arbitrary secret
discovery. Opaque values without a recognizable signature, binary key formats
such as DER, complete credential-store coverage, false-positive analysis on a
production corpus, and production child-process isolation remain open. No
capability was enabled and no host configuration changed.

## Rollback

Revert commit `b1732bd`; no installed service, signing key, or credential
store was changed.
