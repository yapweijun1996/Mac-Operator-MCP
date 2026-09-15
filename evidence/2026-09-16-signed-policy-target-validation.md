# Signed Policy Target Validation Evidence

Date: 2026-09-16
Source revision: `7e92fe9`

## Boundary

The Broker's runtime policy validator now checks every signed or in-memory
target rule with a target-kind-specific reference grammar after the generic
shape check. Host and Docker runtime rules are limited to their Broker-owned
identities; filesystem rules remain root IDs; project rules are canonical
absolute paths; process, Job, profile, app, app-window, UI element, service,
log, Docker object, package, and power rules use the bounded identities accepted
by their adapters. Traversal components, malformed bundle/window/UI values, and
cross-kind references therefore cannot enter the active policy map.

Caller target validation remains deliberately separate: an unknown but safely
shaped target can still reach `authorizeTarget` and receive the normal default
deny result, while the signed policy itself must contain only canonical target
references. This preserves stable authorization errors without weakening the
authority source-of-truth boundary.

## Verification

Focused `policy-target-authority.test.ts` coverage passes 2/2 tests (18
canonical/malformed target cases):

- canonical adapter references are accepted, including `pid:42`, opaque UI
  element identities, and `power:local`;
- malformed path/project/process/Job/profile/app/window/UI/service/log/Docker,
  package, and power references are rejected as malformed active policy;
- existing policy snapshot authorization behavior still returns the expected
  default-deny result for an unknown caller target.

The combined policy and policy-loader regression passes 29/29 tests. Typecheck,
lint, documentation, matrix, and diff checks pass. This closes signed target
reference syntax validation only; parameterized grant serialization, live
resource identity readback, native transport, remote issuer, and release gates
remain open.
