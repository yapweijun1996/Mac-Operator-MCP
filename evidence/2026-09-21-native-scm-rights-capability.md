# Native SCM_RIGHTS Descriptor Handoff Capability Evidence

Date: 2026-09-21

Scope: MOP-045/MOP-086 native transport preparation for the future helper
handoff.

## Host probe

The macOS native peer adapter now exposes a separate
`getDescriptorHandoffCapability()` probe. It creates a local UNIX stream socket pair,
passes an already-open `/dev/null` descriptor with `SCM_RIGHTS`, checks the
marker bytes, reads the received descriptor identity, and explicitly sets and
reads back `FD_CLOEXEC` on the receiving side. The probe reports:

- `mechanism`: `darwin-scm-rights-v1`
- `available`: `true` on the physical Darwin host
- `fdTransfer`: `verified`
- `fdCloseOnExec`: `verified`
- `peerAuthentication`: `unproven`
- `immutableSelection`: `unproven`

The TypeScript capability parser is exact-shape and default-deny. The probe is
not consulted by `ProcessSupervisor` launch admission and cannot enable
`mac_task_run`.

## Verification

- Native addon build passed with `-Wall -Wextra -Werror`.
- The physical-host capability suite passed 3/3, including the live native
  self-test and malformed/incomplete capability negatives.
- The previous descriptor snapshot suite passed 5/5.
- The full repository regression passed 946/960 with 14 explicit skips and no
  failures.
- Documentation, verification-matrix, lint, and diff checks remain required
  after any later edits.

## Explicit non-claims

This proves only local ancillary-FD transport. The bounded one-shot stream
frame and authenticated receiver ordering are documented separately in
[`evidence/2026-09-21-native-descriptor-handoff-frame.md`](2026-09-21-native-descriptor-handoff-frame.md).
The runtime descriptor-execution probe is documented separately in
[`evidence/2026-09-21-native-descriptor-exec-probe.md`](2026-09-21-native-descriptor-exec-probe.md).
It does not prove a separately launched helper, authenticated production helper
identity, executable-fd launch, `fexecve`/`execveat`, immutable program
selection, remount resistance, sandbox isolation, or close-on-exec across an
actual child launch. The existing launch capability therefore remains
unavailable and task execution remains disabled.

## Rollback

Rollback removes the native probe/export, its TypeScript parser/tests, and this
evidence. No helper, launchd service, policy, OAuth scope, database, or host
configuration was changed.
