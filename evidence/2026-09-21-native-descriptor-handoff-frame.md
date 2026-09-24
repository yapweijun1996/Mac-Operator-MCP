# Native Descriptor Handoff Frame Evidence

Date: 2026-09-21

Scope: MOP-045/MOP-086 bounded Broker-to-helper handoff preparation after the
independent SCM_RIGHTS capability probe.

## Implemented boundary

The native adapter and Broker package now expose a separate, default-off
one-shot handoff boundary for an owner-authenticated UNIX `SOCK_STREAM`
connection. `DescriptorHandoffHelperReceiver` owns one authenticated receive
and deterministic FD cleanup, but it has no launch or task-admission authority:

- fixed 12-byte header: magic, version, descriptor count, reserved bytes, and
  network-order payload length;
- payload capped at 64 KiB and descriptors capped at four;
- one `SCM_RIGHTS` ancillary message with duplicate/count validation;
- receiver rejects control or payload truncation, malformed headers, trailing
  bytes, length mismatch, and unexpected descriptor counts;
- receiver applies and reads back `FD_CLOEXEC` on every received descriptor;
- sender transmits one frame and half-closes its write side, so the receiver
  reads an exact frame length rather than assuming a stream write is a message;
- TypeScript admission authenticates peer UID/GID/PID and optional PID
  start-time identity before calling the native frame receiver.
- a real spawned child-process fixture imports the receiver, authenticates its
  Broker parent, consumes the frame, and verifies the received FD's device and
  inode identity.
- an opt-in helper-side verifier parses the strict signed snapshot envelope,
  verifies its Ed25519 signature, and recomputes executable content plus
  executable/cwd metadata from the received descriptors before callback use.

The receiver returns only opaque payload bytes and descriptor integers. It does
not parse paths, argv, environment, filesystem roots, or task commands.

## Verification

- Native addon build passed with `-Wall -Wextra -Werror`.
- The physical-host capability suite passed 3/3.
- The physical-host receiver suite passed 3/3, including live descriptor
  identity preservation and authenticated peer ordering.
- The spawned/helper-receiver suite passed 4/4, including signed snapshot and
  FD identity verification, peer mismatch rejection, one-shot replay denial,
  deterministic cleanup, and a real cross-process handoff.
- The descriptor snapshot suite passed 5/5.
- Full repository regression passed 946/960 with 14 explicit skips and no
  failures.
- Documentation links, verification matrix, lint, and `git diff --check` all
  passed.

## Explicit non-claims

This proves a bounded one-shot stream frame, its local peer-authentication
ordering, and a cross-process receiver fixture. It does not prove a packaged
or separately installed production helper, authenticated production helper
artifact identity, immutable executable selection, `fexecve`/`execveat`,
atomic child launch, remount resistance, sandbox isolation, or task admission.
The runtime probe result is recorded in
[`evidence/2026-09-21-native-descriptor-exec-probe.md`](2026-09-21-native-descriptor-exec-probe.md).
The existing native process-launch capability remains unavailable and all task
execution paths remain disabled.

## 2026-09-23 rejection-cleanup addendum

Clang static analysis identified a cleanup path that consulted a moved-from
descriptor vector. The receiver now transfers the list by swap and gathers
delivered SCM_RIGHTS descriptors before rejecting malformed or over-limit
control data. Its fixed control buffer covers XNU's `UIPC_MAX_CMSG_FD` limit of
512 descriptors per mbuf; the handoff protocol remains limited to four.
On the current physical Darwin arm64 host, regression tests send a frame with
five descriptors and separately provide an expected-count mismatch; both are
denied and leave no additional matching descriptors open. The focused receiver
suite passes 6/6, the native addon builds with `-Wall -Wextra -Werror`, Clang
static analysis emits no warnings, and the full repository suite passes
1,172/1,187 with 15 skips and 0 failures.

The bound is based on the current XNU source's `UIPC_MAX_CMSG_FD` definition:
[Apple XNU Unix-domain socket implementation](https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/uipc_usrreq.c).
Apple's [`recvmsg(2)` documentation](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/recvmsg.2.html)
defines `MSG_CTRUNC` as discarded ancillary data; the physical regression
confirms why rejection must still clean up descriptors already delivered.

This remains handoff-frame evidence only. It does not prove production helper
installation, task admission, a general kernel isolation boundary, or
independent P0/P1 review.

## Rollback

Rollback removes the handoff frame exports, receiver wrapper/tests, and this
evidence. No helper, launchd service, policy, OAuth scope, database, or host
configuration was changed.
