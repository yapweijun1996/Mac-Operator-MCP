# Broker Request Snapshot Evidence

- Date: 2026-09-16
- Host: local development macOS host
- Source revision: `cbc27ea`
- Contract/protocol versions: 0.1
- Evidence class: local request-boundary regression

## Decision

`parseBrokerRequest` is the handoff from untrusted caller data to Broker
authentication and authorization. A validated request must not retain any
caller-owned object that can be changed while asynchronous dispatch is in
flight.

## Implemented controls

The parser now recursively copies and freezes the complete request envelope,
including arguments, principal fields, scope arrays, and nested values. Copies
use null prototypes and own data properties, so an own `__proto__` field stays
inert data rather than becoming prototype authority. `Broker.handleForIpc`
parses once and carries that immutable snapshot through dispatch and response
signing instead of reparsing caller-owned input after execution.

## Verification

Focused command:

```text
npx tsc -b --pretty false
node --test packages/broker/dist/request-validator.test.js
npm run lint
git diff --check
```

Result: 2/2 request-snapshot tests passed, the typecheck passed, the style
check passed for 731 tracked files, and the diff check passed.

The tests mutate the original arguments, nested values, scopes, principal, and
an own `__proto__` field after parsing. The frozen Broker snapshot remains
unchanged and has no mutable prototype authority. This is local in-process
evidence; it does not replace native transport, remote issuer, or installed
service evidence.

## Boundary status

This closes same-process request-object substitution between validation and
asynchronous Broker dispatch. Authentication, policy, target, replay, and
transport checks remain independently required; a snapshot does not grant
authority or enable any capability.
