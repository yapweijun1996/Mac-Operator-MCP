# Direct task execution enablement check

Date: 2026-10-01 (Asia/Kuala_Lumpur)
Historical status: BLOCKED at this checkpoint; direct `mac_task_run` was not enabled.

This report preserves the G1 investigation on the date above. Later V2
production acceptance is recorded in
[the V2 production report](2026-10-02-v2-production-gateway.md); this historical
check does not describe the current deployment.

## Deployment observed during this check

The running personal snapshot is `personal-20260925-g1a`, with the `g1`
grant profile and signed policy revision 1. The current protected files show
no `mac_task_run` tool enablement, no `mac.task.run` principal or Edge scope,
and no task-profile target rules. The personal supervisor constructs the
Broker without a task profile registry or task runner. The Broker therefore
uses an empty registry and `FailClosedTaskRunner`.

A policy-only edit would not make task execution available. The personal
startup also checks the exact G1 scope and tool set. Enabling a task requires
an agreed named profile, an actual isolation executor, consistent signed
policy and OAuth configuration, and a fresh task-authorized client grant.

## Verification and alternatives

- The existing targeted runner tests passed 3/3. The additional focused
  executor/isolation invocation passed 10 reported tests/file results, with
  no failures. These tests confirm admission and release behavior; they do
  not prove a runnable production task deployment.
- The current physical `probe-sandbox-boundary.mjs` passed allowed-root reads
  and writes, denied-root reads and writes, fork denial, absence of a detached
  child marker, and bounded output/timeouts. It cleaned up its temporary roots.
- The standalone Seatbelt runner is deliberately staging-only and supports
  a no-fork boundary. This is not acceptance for ordinary project test/build
  processes or a remedy for the separately recorded App Sandbox descendant
  escape.
- The Virtualization runner remains staging-only in current code and is not
  configured in the personal deployment. Prior guest-boot and stop canaries
  are development evidence, not an installed authenticated task execution
  service with accepted isolation/reset/recovery evidence.
- The root-helper route requires an installed protected helper and complete
  production release evidence. Current host readback reports zero valid
  signing identities; no Mac Operator root helper is installed in the checked
  system helper/LaunchDaemon locations. `sudo -n true` cannot acquire
  administrator authority because a password is required.

## Remaining dependency

Provide an accepted isolation executor and its host installation/authority
before enabling the corresponding named task profiles, task scopes and
signed policy. Do not promote the existing staging runners or remove
containment/release checks to report task execution as fixed.

No runtime configuration, signing material, installed executable, database,
policy, OAuth grant profile, or service process was changed during this check.
