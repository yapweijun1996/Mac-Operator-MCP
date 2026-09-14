# Idempotency Policy-Binding Evidence

Date: 2026-09-15
Source revision: `d715512`
Host: physical Darwin arm64 development host

## Implemented boundary

`BrokerStore.createJob` now treats the policy version as part of the durable
idempotency identity. Reuse is allowed only when the owner principal, tool,
target reference, payload digest, and policy version all match the original
Job. A different policy revision returns `CONFLICT` before the existing Job
is reused, preserving the Broker's current authorization boundary for retries.

## Verification

- Persistence regression covers successful reuse, payload substitution,
  policy-version substitution, and principal isolation.
- The complete physical-Darwin command
  `MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
  passes 597/597 tests with 0 skips and 0 failures, including temporary
  LaunchAgent, sandbox, and Keychain checks.
- `git diff --check` passes.

## Remaining boundary

Mutation crash-window, concurrency, and installed-service evidence remain
open; this change is a defense-in-depth persistence invariant, not a release
gate closure.

## Rollback

Revert the source revision recorded above. Job reuse would again omit the
policy-version binding and would rely on the higher-level Broker write check.
