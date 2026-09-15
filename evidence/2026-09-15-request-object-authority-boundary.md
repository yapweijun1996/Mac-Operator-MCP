# Request object authority-boundary evidence

Date: 2026-09-15
Source commit: `8a8f335`
Host: physical Darwin arm64 development host

## Boundary

The Broker authenticates the exact request object before planning or executing
the selected tool. A direct in-process caller must not be able to provide an
inherited tool, argument, or principal field that is read during execution but
omitted from the canonical signed payload.

## Implementation

`parseBrokerRequest()` now accepts only ordinary records or null-prototype
records for the request envelope, arguments, and principal. Prototype-bearing
objects and objects whose key enumeration throws fail closed as `AUTH_INVALID`
before authentication, authorization, audit admission, or execution.

## Verification

- The security-fuzz suite passes 8/8, including signed requests with inherited
  envelope, argument, and principal fields.
- The non-overlapping package regression passes 498 total (492 pass,
  6 skipped, 0 fail).
- `npm run build`, `npm run typecheck`, `npm run lint`, and `git diff --check`
  pass.

This evidence covers request object-shape integrity at the local Broker
boundary only. It does not establish remote transport serialization,
production policy signing, VM isolation, credential isolation, helper
installation, or capability enablement.

## Rollback

Revert commit `8a8f335`. No wire contract or persisted state changes are
introduced; malformed direct callers receive an earlier stable rejection.
