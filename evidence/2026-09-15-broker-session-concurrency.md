# Broker Session-Concurrency Evidence

Date: 2026-09-15
Source commits: `d185f12`, `9d92f0d`
Host: physical Darwin arm64 development host

## Implemented boundary

The local Broker now validates request-age and clock-skew configuration at
startup and bounds active requests by the authenticated principal/session
pair. The default limit is eight active requests and the configured maximum is
64. Capacity is reserved only after request authentication, rejected with the
stable retryable `CONFLICT` result before durable admission or audit, and
released on every success or failure path.

## Verification

- Broker focused suite with install, sandbox, and Keychain gates: 78/78 pass,
  0 skipped, 0 failed.
- Full physical-Darwin regression with install, sandbox, and Keychain gates:
  585/585 pass, 0 skipped, 0 failed.
- Native canonical JSON probe: 5/5 fixed wire vectors pass.
- `npm run build`, `npm run typecheck`, `npm run lint`,
  `npm run verify:contracts`, and `git diff --check` pass.
- The concurrency regression proves a second request in the same principal
  session receives retryable `CONFLICT` without a persisted request record,
  while the first request completes and releases capacity.

## Remaining boundary

This closes the in-process Broker session-concurrency and startup-budget
validation boundary. It does not prove cross-process or multi-instance global
quotas, installed service packaging, or final release-gate acceptance.

## Rollback

Revert `d185f12` and `9d92f0d`. The prior Broker has no per-session
active-request cap, accepts out-of-range request-age or clock-skew constructor
values, and lacks constructor regression coverage for those limits.
