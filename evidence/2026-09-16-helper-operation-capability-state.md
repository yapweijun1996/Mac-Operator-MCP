# Privileged Helper operation-capability state evidence

Date: 2026-09-16
Source revision: `39cb147`
Host: physical Darwin arm64 (`yaps-Mac-mini.local`, Darwin 25.2.0)
Node: `v25.5.0`

## Decision

The Broker treats authenticated Helper transport availability and individual
Helper operation enablement as separate runtime facts. An enabled executor
must carry an explicit, duplicate-free allowlist of `service_control`,
`package_install`, and/or `power`; enabling transport without that list fails
closed. Broker planning and capability discovery call the same operation-level
support check, so an allowlisted service operation cannot cause package or
power capabilities to be advertised or admitted.

The operation allowlist is independent of principal scopes, target rules,
kill-switches, approvals, and Job leases. Those controls remain enforced by
the Broker and cannot be expanded by Helper arguments or transport state.

## Verification

- Focused Broker/Helper boundary suite: 102 total, 96 passed, 6 skipped, 0
  failed.
- Full repository regression: 892 total, 878 passed, 14 skipped, 0 failed.
- Typecheck, lint, and native build completed successfully.
- Capability discovery test enables only `service_control` in an injected
  authenticated executor; `mac_priv_service_control` is enabled while
  package-install and power report the stable `runtime_unavailable` reason and
  are absent from runtime-enabled capability names.
- Executor tests reject enabled construction without an explicit allowlist and
  reject an operation outside the allowlist before command dispatch.

The injected executor is test-only. No privileged Helper, service mutation,
package installation, power operation, or capability was enabled on the host.
The six focused and fourteen full-suite skips are opt-in real sandbox paths;
the host still lacks the descriptor-backed launcher required by the task
isolation boundary.

## Remaining gate

This closes the Helper transport-versus-operation capability-state gap. It does
not provide production Developer ID signing/notarization, root-helper
installation, VM boot/guest isolation, descriptor-backed task execution, or
real-Mac enablement evidence.
