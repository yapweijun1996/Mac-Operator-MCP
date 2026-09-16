# Capability runtime-state boundary evidence

Date: 2026-09-16
Source revision: `08c54d6`
Host: physical Darwin arm64 (`yaps-Mac-mini.local`, Darwin 25.2.0)
Node: `v25.5.0`

## Decision

The Broker is the final authority for capability state. A policy-enabled task
or privileged tool is not advertised as `enabled` unless its concrete runtime
boundary is available at the Broker instance:

- `mac_task_run` requires an available isolated task runner.
- `mac_priv_service_control`, `mac_priv_package_install`, and
  `mac_priv_power` require an available authenticated privileged Helper.

The stable discovery reason for a policy-enabled capability whose runtime
boundary is absent is `runtime_unavailable`. Scope, kill-switch, and target
authorization checks remain independent and take precedence for a requesting
principal. Service readback uses the same Broker-owned runtime gate, so startup
metadata cannot advertise work that execution planning will reject.

## Verification

- Broker and service-startup boundary suite: 95 total, 89 passed, 6 skipped.
- Full repository regression: 891 total, 877 passed, 14 skipped, 0 failed.
- The regression includes a signed startup policy with `mac_task_run` enabled
  while the isolated runner is disabled; service readback correctly omits the
  task capability.
- The Broker capability test enables task and privileged policy entries with
  authorized targets while using the fail-closed default runtimes; both return
  `runtime_unavailable` and are absent from runtime-enabled capability names.

Skipped cases are opt-in real sandbox execution paths because this host lacks
the descriptor-backed launcher required by the repository boundary. No task,
privileged Helper, service, or capability was enabled on the host.

## Remaining gate

This closes only the policy-versus-runtime capability-state consistency gap.
It does not provide the missing descriptor launcher, VM boot/guest isolation,
production signed artifacts, or Helper installation evidence.
