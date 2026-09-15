# Privileged Tool Policy-State Evidence

Date: 2026-09-15

Source revision: `7926c99`

## Boundary

The default Broker policy now represents all 44 catalog tools. The three L5
privileged tools have explicit required scopes, the `privileged` capability
family, target types, timeout/output budgets, and
`explicit_privileged_policy` approval. They remain `implemented=false` and
`enabled=false`, so capability discovery cannot advertise a privileged helper
operation before the separately authenticated helper and root-domain evidence
gates are complete.

Package targets are now a first-class policy target type and are authorized
through exact Broker-owned package target rules when a future policy enables
the package helper boundary.

## Verification

- `npx tsc -b packages/broker/tsconfig.json --pretty false`: passed.
- Policy and contract-conformance suites: 10/10 passed, 0 failed, 0 skipped.
- `npm run lint`: passed for 619 tracked files.
- `git diff --check`: passed.

The existing Broker/Persistence test process remained undisturbed. This
closes policy-state representation only; no privileged capability is enabled
and no root helper installation or production signing is claimed.
