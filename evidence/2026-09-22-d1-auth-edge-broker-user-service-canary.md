# D1 Auth-to-Edge-to-Broker user-service canary evidence — 2026-09-22

## Result

An opt-in, isolated D1 canary now proves the staging `mac_service_control`
path through Auth, HTTPS Edge, Broker policy and approval, the durable Job
executor, real user-domain `launchctl`, and service-state readback. The live
personal R1 deployment was not changed.

## Boundary covered

- Auth issues the exact staging D1 profile, now containing 23 scopes: the 17
  R1 scopes plus six explicitly materialized developer scopes.
- Edge verifies the Auth-issued token and exposes `mac_service_control` only
  when the canary assembles the explicit D1 owner grant and host binding.
- An unapproved start request returns `POLICY_DENIED` and creates a durable
  non-secret approval preview.
- An exact owner approval matching the service target, action, payload digest,
  contract, and policy permits one start operation through the real
  `gui/<uid>/com.mac-operator.d1-auth-canary` LaunchAgent.
- Broker Job completion verifies the expected running state and source
  revision through launchd readback; an exact owner-approved stop then verifies
  the stopped state and source revision.
- The disposable LaunchAgent plist is created owner-only with exclusive
  creation, bootstrapped into the owner GUI domain, and removed by exact
  cleanup. The post-run service identity was absent and the plist was absent.

## Verification

The canary is the existing `isolated D1 canary binds the Auth grant to Edge
tools/list and owner-approved write` test in `packages/auth/src/auth.test.ts`,
run with:

```text
npm run build
MOPS_REAL_USER_SERVICE=1 node --test --test-timeout=120000 --test-name-pattern='isolated D1 canary binds' packages/auth/dist/auth.test.js
```

Result: 1 test passed, 0 failed. The full repository regression then passed
1,074/1,089 tests with 15 explicit skips and 0 failures.

The run also fixed two contract defects found by the end-to-end path:

1. The user-service Job executor now accepts the canonical Broker/Edge request
   ID shape instead of requiring a non-existent `request:` prefix.
2. The Broker service-control verification evidence now matches the strict
   `mac_service_control` output schema and no longer emits undeclared fields.

This is staging evidence only. It does not enable the public OAuth profile,
change the live R1 policy, install a persistent service, control an ordinary
user service, control a system/root service, prove Developer ID/notarization,
or provide ChatGPT mutation-call evidence.
