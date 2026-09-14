# Mac-Operator-MCP Task Ledger

Status: Active
Version: 0.1
Last verified: 2026-09-15

Strict UTF-8 boundary addendum: source revision `1ce5bee` makes implemented
JSON protocol and protected configuration readers use fatal UTF-8 decoding.
Malformed bytes fail closed before JSON parsing or replay admission, including
Broker IPC, owner channels, helper, Keychain, guest, persistence, audit, and
Edge contract/configuration paths. Focused boundary tests pass 78/78, the
native canonical JSON probe passes 5/5 vectors, and the complete physical-
Darwin regression passes 587/587 with 0 skipped tests. This closes malformed
encoding handling only; full numeric canonicalization compatibility,
duplicate-key handling, and release acceptance remain open. Evidence:
`evidence/2026-09-15-strict-utf8-boundary.md`.

Strict JSON parser addendum: source revision `ecc3a98` adds bounded recursive
validation before `JSON.parse` at implemented trust boundaries. Duplicate
object keys (including escaped equivalents), unpaired UTF-16 surrogates,
malformed grammar, and trailing data now fail closed without replay admission
or mutation. Focused trust-boundary tests pass 49/49, the native canonical
JSON probe passes 5/5 vectors, and the complete physical-Darwin regression
passes 588/588 with 0 skipped tests. This closes duplicate-key and lone-
surrogate parser divergence; broader numeric canonicalization, runtime fuzzing,
and release acceptance remain open. Evidence:
`evidence/2026-09-15-strict-json-parser.md`.

Runtime strict-JSON addendum: source revision `0bcb354` routes implemented
child-adapter, Authority Control IPC, stored-result, Job metadata, audit, and
encrypted-backup evidence readers through `parseJsonStrict` before validation
or canonical hashing. Static schema loading and parser internals remain
separate trusted implementation inputs. Targeted runtime-reader tests pass
79/79; the complete physical-Darwin regression passes 592/592 with 0 skipped
tests. This closes runtime parser divergence at these readers only; broader
numeric canonicalization, fuzzing, and release acceptance remain open.
Evidence: `evidence/2026-09-15-runtime-strict-json-boundaries.md`.

Cross-runtime number addendum: source revision `c31f82a` compares each strict
JSON number token's lexical canonical form with Node's ECMAScript
`JSON.stringify` output. Precision-changing, underflowing, overflowing, and
oversized-exponent values fail closed before authentication or persistence.
Focused canonical JSON tests pass 5/5 and the complete physical-Darwin suite
passes 593/593 with 0 skipped tests. This closes the implemented numeric input
boundary; broader independent native vector coverage and release acceptance
remain open. Evidence:
`evidence/2026-09-15-cross-runtime-json-number-canonicalization.md`.

Capability-family capacity addendum: source revisions `db129b3` and `0b7d3b9` persist the
Broker-resolved capability families on each request and enforces independent
durable active-request quotas for read, write, process, network, GUI,
destructive, and privileged work inside the SQLite admission transaction.
Cross-handle tests prove that one saturated family does not block another;
unknown legacy markers are counted against every requested family and
malformed markers return `AUDIT_UNAVAILABLE` before replay persistence, even
for a family-less request. Focused Broker/persistence tests pass 123/123 with
6 explicit skips; the complete physical-Darwin suite passes 597/597 with 0
skipped tests. This closes
the durable family-capacity boundary only; adapter-specific semantic quotas,
kernel/disk/depth limits, and release acceptance remain open. Evidence:
`evidence/2026-09-15-capability-family-capacity.md`.

Durable request-capacity addendum: source revision `31e89f0` adds a durable
global and principal/session admission gate inside the SQLite write
transaction. Default caps are global 64 and per principal/session 8, with
hard maxima 256/64. Saturation fails with retryable `CONFLICT` before nonce or
request persistence; terminal and restart reconciliation release capacity.
Cross-handle tests prove this boundary. Full physical-Darwin regression passes
589/589 with 0 skipped tests. This closes only durable request admission
capacity; process/adapter-specific quotas, disk/depth budgets, and release
acceptance remain open. Evidence:
`evidence/2026-09-15-durable-request-capacity.md`.

Process-quota addendum: source revision `a135396` adds a Broker-owned
per-executable admission gate to the shared ProcessSupervisor. Active and
pending starts for one canonical executable share a default cap of 4, while
the Broker-wide pool remains bounded at 16. Focused ProcessSupervisor tests
pass 26/26; the complete physical-Darwin regression passes 592/592 with 0
skipped tests. This closes the shared per-executable process quota only;
adapter-specific semantic quotas, disk/depth budgets, and release acceptance
remain open. Evidence: `evidence/2026-09-15-process-quota-isolation.md`.

Broker session-concurrency addendum: source revisions `d185f12` and `9d92f0d` add bounded
request-age/clock-skew constructor validation and an in-process active-request
cap per authenticated principal/session (default 8, maximum 64). A saturated
session receives retryable `CONFLICT` before request persistence or audit, and
capacity is released on success or failure. Broker focused tests pass 78/78;
the native canonical JSON probe passes 5/5 vectors; the complete
physical-Darwin regression passes 585/585 with 0 skipped tests.
This closes only the local Broker budget boundary; cross-process quotas,
installed service packaging, and release acceptance remain open. Evidence:
`evidence/2026-09-15-broker-session-concurrency.md`.

Approval TTL-gate addendum: source revision `0ab3fc9` rejects a signed Approval
whose TTL has already elapsed before Approval or audit persistence. Approval
Authority/IPC tests pass 10/10 and the complete physical-Darwin regression
passes 583/583 with 0 skipped tests. This closes only source-level Approval
expiry admission; human approval UI, protected production issuer-key storage,
and unattended profile ownership remain open. Evidence:
`evidence/2026-09-15-approval-ttl-gate.md`.

Task isolation proof addendum: source revision `7a101d9` adds a required
`persistence: "isolated"` field to the Broker-owned `TaskIsolationProof` and
rejects missing or non-isolated claims before runner availability. Proof and
guest-startup fixtures pass, and the complete physical-Darwin regression
passes 582/582 with 0 skipped tests. This strengthens the contract only;
real persistence/credential/VM isolation evidence and `mac_task_run`
enablement remain blocked. Evidence:
`evidence/2026-09-15-task-persistence-proof.md`.

Approval issuance expiry-gate addendum: source revision `8552210` rejects a
current-expired signed Approval issuance nonce before persistence or audit.
Approval Authority/IPC tests pass 9/9 and the complete physical-Darwin
regression passes 582/582 with 0 skipped tests. This closes only the
source-level current-clock nonce boundary; human approval UI, protected
production issuer-key storage, and unattended profile ownership remain open.
Evidence: `evidence/2026-09-15-approval-expiry-gate.md`.

IPC expiry-gate addendum: source revision `6947608` rejects current-expired
Privileged Helper command/status requests before replay, authorization,
dispatch, or readback, and rejects current-expired Policy Signer nonces before
manager mutation. Focused Helper tests pass 9/9 and Policy Signer tests pass
2/2; the complete physical-Darwin regression passes 581/581 with 0 skipped
tests. This closes only source-level current-clock expiry admission; installed
helper provenance, production key distribution, and real privileged execution
remain open. Evidence: `evidence/2026-09-15-ipc-expiry-gates.md`.

Broker Status IPC error-proof addendum: source revision `ad3adc9` binds
structurally valid status requests to authenticated `AUTH_EXPIRED` and
`REPLAY_DENIED` failure responses before freshness/auth checks. Unknown fields
remain on the invalid-request fallback, and the candidate never reaches replay
admission or status execution. The focused Broker Status IPC test passes 1/1;
the complete physical-Darwin regression passes 581/581 with 0 skipped tests.
Evidence: `evidence/2026-09-15-broker-status-error-proof.md`.

Authority Control CLI and IPC error-proof addendum: source revisions
`447e4aa`, `f359360`, `5962efc`, and `032bf8f` add a
source-level `mac-operator-authority` entrypoint that exposes only bounded
switch readback, expected-state switch
changes, and identity revocation. It requires canonical protected paths,
restores the persisted active key through `AuthorityControlKeyManager`, uses
explicit mutation confirmation, and verifies mutations by authenticated
readback; guest-attestation key revocation is included. Focused tests pass
4/4, including a protected-file/authenticated-IPC round trip. Authority
Control IPC tests pass 3/3, including stable authenticated `AUTH_EXPIRED`
readback without admission, audit, or mutation side effects; the complete
physical-Darwin regression passes 581/581 with 0 skipped tests. Installed
launchd ownership, active process-tree termination, and
production operator-key distribution remain open. Evidence:
`evidence/2026-09-15-authority-control-cli.md`.

Privileged helper command-factory disposal addendum: the Broker-owned helper
command factory now owns a one-way disposal boundary, wipes its copied HMAC
key once, and fails closed with `CANCELLED` on every later command issuance;
repeated disposal is harmless. Focused privileged-helper tests pass 9/9 and
the complete physical-Darwin regression passes 576/576 with 0 skipped tests.
This closes factory key lifetime only; production operator-key distribution,
root helper installation, real privileged execution, and deployed kill-switch
readback remain open. Evidence:
`evidence/2026-09-15-privileged-helper-factory-disposal.md`.

Virtualization guest active-I/O drain addendum: the Native VM lifecycle now
tracks Broker-owned Virtio exchanges and closes them before stop/close. Late
connection callbacks observe the atomic closed state and close immediately;
tracked Objective-C references are released only after set removal. Native
build and focused VM-native tests pass 7/7; the complete physical-Darwin
regression passes 576/576 with 0 skipped tests. This strengthens active-work
shutdown but does not prove VM boot, guest isolation, attestation, or
`mac_task_run` enablement. Evidence:
`evidence/2026-09-15-virtualization-native-connection-drain.md`.

Virtualization guest native-handle fencing addendum: the Native
Virtualization.framework lifecycle no longer resurrects a closed handle when
retained async work completes. Its validity marker is atomic, and the serial
queue remains available until finalization so delayed callbacks fail closed
instead of dispatching through a null queue. Native build and focused
VM-native tests pass 7/7; the complete physical-Darwin regression passes
576/576 with 0 skipped tests. VM boot, guest isolation, production
attestation, and `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-native-handle-fencing.md`.

Local IPC shutdown-drain addendum: all Node owner-only/local UDS servers now
own an accepted-socket set and destroy those sockets before waiting for server
close, preventing idle peers from extending shutdown to the read timeout.
Cross-channel IPC tests pass 29/29 and the complete physical-Darwin regression
passes 575/575 with 0 skipped tests. Evidence:
`evidence/2026-09-15-local-ipc-shutdown-drain.md`.

Broker IPC framing addendum: the authenticated Broker socket rejects
non-whitespace trailing data before JSON parsing or request admission; the
same signed request retries successfully, so no replay or audit state is
consumed by the rejected frame. Focused Broker IPC tests pass 6/6 and the
complete physical-Darwin regression passes 574/574 with 0 skipped tests.
Evidence: `evidence/2026-09-15-local-ipc-framing-hardening.md`.

Approval IPC framing addendum: the owner-only approval channel enforces one
authenticated newline-delimited frame and rejects non-whitespace trailing data
before replay admission, approval persistence, or audit. A clean retry of the
same signed issuance succeeds after the rejection. Focused approval tests pass
8/8 and the complete physical-Darwin regression passes 574/574 with 0 skipped
tests. Evidence: `evidence/2026-09-15-local-ipc-framing-hardening.md`.

Approval issuer key lifecycle addendum: the Broker-owned approval authority
now wipes its defensive issuer HMAC-key copies on idempotent disposal and
fails closed on all later issuance or key addition. Approval authority and
owner-only IPC tests pass 8/8; build and diff checks pass. Evidence:
`evidence/2026-09-15-approval-key-lifecycle.md`.

Authority-control key lifecycle addendum: the Authority Control client owns a
copied HMAC key, wipes it on explicit disposal, and fails closed on all later
requests. Authority Control and Privileged Helper server cleanup now wipes
copied keys even if socket detachment raises. Focused Authority Control tests
pass 2/2, Privileged Helper IPC tests pass 9/9, and the complete
physical-Darwin regression passes 573/573 with 0 skipped tests. Evidence:
`evidence/2026-09-15-authority-control-key-lifecycle.md`.

Local IPC framing hardening addendum: Privileged Helper, Policy Signer, and
Broker Status channels now enforce one authenticated frame and reject
non-whitespace trailing data before replay or side effects; clients reject
trailing response frames, and the Policy Signer wipes its copied HMAC key on
close. The complete physical-Darwin regression passes
573/573 with 0 skipped tests. Evidence:
`evidence/2026-09-15-local-ipc-framing-hardening.md`.

Capability kill-switch readback addendum: capability discovery now reflects
both persisted runtime and signed-policy family kill-switches. Enabled
process capabilities become `disabled_by_kill_switch` when the process family
is disabled, and the regression covers both authority sources. The complete
physical-Darwin regression passes 572/572 with 0 skipped tests. Evidence:
`evidence/2026-09-15-capability-kill-switch-readback.md`.

Authority-control framing addendum: the owner-only IPC rejects non-whitespace
trailing bytes after its one newline-delimited command and performs no replay
admission, authority mutation, or audit for that frame. Focused IPC tests pass
2/2; the full physical-Darwin regression passes 571/571 with 0 skipped tests.
Evidence: `evidence/2026-09-15-authority-control-framing.md`.

Authority-control restart readback addendum: the owner-only IPC now has a
cross-restart regression that reads back persisted switch and revocation state
through a fresh authenticated client and confirms replay denial remains in
force. Focused IPC tests pass 2/2; the full physical-Darwin regression passes
571/571 with 0 skipped tests. Installed operator identity, active process
termination, and safe re-enable procedures remain open. Evidence:
`evidence/2026-09-15-authority-control-restart-readback.md`.

Guest transport shutdown hardening addendum: the host transport client tracks
active exchanges, aborts them on close, and rejects post-close sends or signed
success publication. Focused transport tests pass 15/15; the full
physical-Darwin regression passes 571/571 with 0 skipped tests. Evidence:
`evidence/2026-09-15-virtualization-guest-transport-close.md`.

Guest-agent shutdown hardening addendum: the guest protocol service now tracks
each admitted request with a Broker-owned abort controller, propagates caller
cancellation, aborts active work on close, and refuses to sign a success after
shutdown. Focused guest-agent tests pass 4/4; the full physical-Darwin
regression passes 571/571 with 0 skipped tests. This is protocol shutdown
evidence only; VM boot, guest isolation, and `mac_task_run` enablement remain
open. Evidence: `evidence/2026-09-15-virtualization-guest-agent.md`.

Guest bootstrap addendum: `VirtualizationGuestBootstrap` adds a disabled-by-
default, transport-independent guest protocol loop. It accepts a native
startup-owned connection source, admits exactly one bounded length-prefixed
frame, delegates to the authenticated guest agent, writes one bounded response,
rejects trailing data, and closes streams and key material deterministically.
Focused bootstrap tests pass 5/5; the full physical-Darwin regression passes
560/560 with 0 skipped tests. AF_VSOCK acceptance, bootable image, isolation,
attestation production, and `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-bootstrap.md`.

Virtio listener addendum: the native lifecycle artifact now provides a
startup-owned fixed-port `VZVirtioSocketListener` with bounded queued accepts,
finite asynchronous chunk I/O, connection-handle lifetime fencing, and
deterministic listener/VM draining. The TypeScript wrapper exposes the
transport-independent bootstrap source and cleans up a late connection after
accept cancellation. Focused VM/listener tests pass 6/6; the full
physical-Darwin regression passes 562/562 with 0 skipped tests. Guest-side
AF_VSOCK serving, bootable image, guest profile execution/isolation, attestation
production, and `mac_task_run` enablement remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-vsock-listener.md`.

Guest profile executor addendum: a startup-owned Guest manifest registry now
recomputes profile/task digests, denies shell executables and unsafe
environment entries, rechecks canonical targets, and passes only fixed
manifest material to a bounded process adapter. Terminal outcomes are kept in
a bounded status ledger with stable redacted summaries; active work is
cancelled before executor close can publish success; the concrete process
adapter remains evidence-gated. The host Broker redacts runner verification
summaries before publishing task success. Focused guest-executor tests pass 7/7; the
full physical-Darwin regression passes 569/569 with 0 skipped tests. Guest
isolation evidence, bootable image deployment, and `mac_task_run` enablement
remain open. Evidence:
`evidence/2026-09-15-virtualization-guest-executor.md`.

Startup composition addendum: an optional startup-only factory now wires the
native guest VM, serialized lifecycle, fixed virtio channel, optional
guest-initiated listener source, HMAC transport, durable replay guard, and
virtualization task runner into Broker service
startup. It validates the immutable image before construction, starts an
enabled guest before restart recovery, and drains it before store close. The
default path remains disabled and fail closed. Focused startup tests pass 3/3;
the full physical-Darwin regression passes 555/555 with 0 skipped tests. This
does not close the bootable-image, guest-serving, isolation, attestation, or
`mac_task_run` release gates. Evidence:
`evidence/2026-09-15-virtualization-guest-startup.md`.

Virtio connector addendum: commit `b8551d6` connects the native VM handle to a
bounded `VZVirtioSocketDevice` frame exchange and the existing authenticated
guest transport client. Connect/write/read deadlines, port and frame caps,
single-frame response parsing, trailing-data rejection, SIGPIPE protection,
callback-race cleanup, and generic native errors are implemented and tested.
Focused lifecycle/native/channel tests pass 10/10; the full physical-Darwin
regression passes 552/552 with 0 skipped tests. The host rejects the synthetic
VM configuration before creation, so guest serving, VM boot/isolation,
attestation production, and `mac_task_run` enablement remain blocked. Evidence:
`evidence/2026-09-15-virtualization-guest-virtio-connector.md`.

Native virtualization lifecycle addendum: commit `40f0461` connects the
Broker lifecycle state machine to a protected Objective-C++ N-API artifact.
It revalidates the startup-owned image, builds a read-only Virtualization
framework configuration without host network or directory sharing, exposes
asynchronous handle-only start/stop/status/close operations, and binds every
transition to an adapter-owned boot ID. The TypeScript adapter rechecks image
identity before every call and maps malformed or uncertain native outcomes
fail-closed. Focused lifecycle/adapter tests pass 9/9; full physical-Darwin
regression passes 551/551 with 0 skipped tests. The host rejected the
synthetic VM configuration before boot, so entitlement, bootable image, guest
serving/isolation, attestation production, and `mac_task_run` enablement remain
blocked. Evidence:
`evidence/2026-09-15-virtualization-guest-native-lifecycle.md`.

Virtualization lifecycle addendum: commit `042517a` adds the disabled,
Broker-owned VM lifecycle state machine. It serializes start/stop/status and
close, enforces caller cancellation and bounded deadlines, binds every result
to the immutable guest identity and boot ID, and leaves failed or ambiguous
operations in `unknown` until fresh status recovery. Focused tests pass 5/5;
the full physical-Darwin regression passes 547/547 with 0 skipped tests. This
does not boot a VM or close the guest isolation, virtio serving, attestation
production, or `mac_task_run` release gates. Evidence:
`evidence/2026-09-15-virtualization-guest-lifecycle.md`.

Guest-agent protocol addendum: commit `c8a856e` adds a bounded
`VirtualizationGuestAgent` service for the future native guest channel. It
performs HMAC/freshness/profile/guest-identity verification and replay admission
before guest execution, binds signed task and status responses to their
admitted requests, enforces frame budgets, and keeps host paths, commands, and
credentials out of the executor surface. Focused tests pass 3/3 and the full
physical-Darwin regression passes 542/542 with 0 skipped tests. This advances
the guest protocol boundary only; VM lifecycle, bootable image deployment,
guest isolation, native serving integration, and `mac_task_run` enablement
remain blocked. Evidence:
`evidence/2026-09-15-virtualization-guest-agent.md`.

Native Virtualization guest-preflight addendum: commit `7de8385` adds a
protected, artifact-validated `virtualization_guest.node` N-API seam. Its
startup-only image readback binds canonical owner-only device/inode/size/SHA-256
identity, creates a read-only Virtualization.framework disk attachment, and
confirms no host network or directory-sharing devices are configured. Focused
tests pass 2/2 and the full physical-Darwin regression passes 539/539 with 0
skipped tests. This advances MOP-086/MOP-010 native boundary evidence only;
the artifact does not boot a VM or provide guest execution, attestation
production, isolation proof, or `mac_task_run` enablement. Evidence:
`evidence/2026-09-15-native-virtualization-guest-preflight.md`.

Canonical JSON wire-profile addendum: commits `7860a00`, `a26a188`, `1aa0eea`,
and `ae2e9eb` export
the versioned `jcs-utf8-v1` profile, exact UTF-8 byte helper, and a bounded
read-only native Swift standard-library probe. Five fixed digest vectors pass
2/2 focused TypeScript tests, 5/5 Swift readback, and the 537/537 full Darwin
regression with 0 skipped tests; the protected C++ N-API artifact also passes
the five digest readbacks and its 1 MiB cap check. This advances `MOP-012`
serialization compatibility but does not
close production Swift/C++ adapter integration, corruption, retention, VM
isolation, or accepted persistence design.

Guest-attestation keyring addendum: commits `73148a6`, `db83881`, and `c56aa0a` add a startup-only
Broker manager for protected Ed25519 public-key configuration. Owner-only
canonical files are opened with `O_NOFOLLOW`, device/inode and digest bound,
size limited, and rejected on duplicate paths, weak modes, replacement, or
non-Ed25519 content. BrokerStore schema version `8` persists an independent
revisioned activation/rollback history and `guest_attestation_key` revocation
kind; verifier construction checks revocation dynamically. Focused
persistence/keyring tests pass 50/50 and full physical-Darwin regression passes
533/533. Guest private signing keys remain outside the host; native producer,
Keychain distribution, VM boot/isolation, and capability enablement remain
blocked. The policy, policy-signer, and guest verification loaders also reject
private-key material before constructing trusted public keys. Packaged startup
restores an optional dataRoot-bound trust set before listeners or recovery.
Evidence:
`evidence/2026-09-15-virtualization-guest-attestation-keyring.md`.

Authority-lifecycle addendum: commit `d0c96be` adds a deterministic
BrokerStore state-machine regression with 16 seeds and 72 authority/job
actions per seed. It covers independent kill switches, principal/session and
upstream revocation, expected-state conflicts, queued/running cancellation,
terminal completion, and restart reconciliation while checking cross-principal
isolation, monotonic revisions, and terminal-state immutability. The focused
persistence suite passes 46/46 and the full physical-Darwin regression passes
527/527. Evidence:
`evidence/2026-09-15-authority-state-machine.md`.

Signed guest-provenance addendum: commit `84da3e0` extracts the Virtualization
guest attestation contract and adds a versioned Ed25519 envelope covering key,
algorithm, freshness, payload digest, and complete claims. Startup-trusted key
validity/revocation and bounded lifetime are enforced; a configured
`VirtualizationTaskRunner` verifier rechecks provenance before dispatch and
restart status lookup. Focused attestation/runner tests pass 15/15 and the
full physical-Darwin regression passes 527/527. Native attestation production,
Keychain key distribution, VM boot, guest isolation, and production enablement
remain blocked. Evidence:
`evidence/2026-09-15-virtualization-guest-attestation.md`.

Guest-image binding addendum: commits `846eca5` and `81faff0` add a protected
startup-owned image preflight and make its digest/runtime/device/inode/size
identity a required `VirtualizationTaskRunner` gate. The Broker rechecks the
image before dispatch and restart recovery; content replacement is denied
before executor invocation. Focused runner/image tests pass 15/15 and the
full physical-Darwin regression passes 527/527. Native signed-attestation
production, VM boot, isolation, and production enablement remain blocked.

Virtualization channel addendum: commits `521eecc` and `4592cad` add a
disabled-by-default Broker-side Unix-socket channel for the future native
guest adapter. It verifies owner-only socket target/device/inode identity,
native UID/GID/PID peer credentials with optional PID/start-time binding, and
parses exactly one bounded frame only after peer authorization. Physical
Darwin focused channel tests pass 4/4 and the full regression passes 527/527.
This is transport evidence only; native guest serving, VM boot, guest
isolation, and `mac_task_run` enablement remain blocked by MOP-086/MOP-045.

Strict-exit addendum: the governed sandbox task path sets a Broker-owned
`requireCleanExitProof` flag. `ProcessSupervisor` performs a final native
descendant snapshot after child close and keeps the result `UNKNOWN_OUTCOME`
on observer uncertainty, truncation, PID replacement, or unresolved
descendants. Focused process-supervisor/sandbox tests pass 29/32 with three
explicit Darwin-boundary skips; full real sandbox/Keychain regression passes
475/476 with one explicit skip. This does not prove kernel-held process or
remount isolation, post-snapshot detached-descendant prevention, credential
contents, or task enablement. Evidence:
`evidence/2026-09-14-post-snapshot-exit-proof.md`.

Keyed-audit addendum: `BrokerStore` can bind its audit tail to an explicit
owner-only 0600 sidecar with a memory-only HMAC key; a dedicated Keychain
source factory binds that key to the Broker executable ACL. The Broker
publishes only after SQLite commit and fails closed on missing, stale, forged,
or key-mismatched readback.
Focused persistence tests pass 43/43. This does not claim an external
immutable log, production Keychain anchor provisioning, cross-process sidecar
locking, or packaged enablement. Evidence:
`evidence/2026-09-14-keyed-audit-anchor.md`.

Process-identity exit-window addendum: short-lived children now retain the
bounded native PID/start-time retry after close, without synthetic identity or
unowned registration. Evidence:
`evidence/2026-09-14-process-identity-exit-window.md`.

Virtualization.framework candidate addendum: the current Darwin SDK exposes
the framework surface and the native probe links it without booting a VM while
reporting host support and rejecting a guest-less configuration; a
disabled `VirtualizationTaskRunner` seam now
requires externally reviewed guest image digest/runtime evidence plus a
matching native-adapter identity at dispatch. Identity mismatch, absent guest
evidence, unavailable adapter, and adapter failure all fail closed or remain
`UNKNOWN_OUTCOME`; this does not enable `mac_task_run`.
Evidence: `evidence/2026-09-14-virtualization-framework-sdk.md`.

Startup-authority addendum: the Supervisor rechecks close/cancellation state
after ownership sampling and before active-run registration, draining a child
and returning `CANCELLED` when authority is lost in that window. Evidence:
`evidence/2026-09-14-process-supervisor-startup-authority.md`.

Process-identity startup addendum: native PID/start-time capture retries for a
bounded 100ms after spawn, including a child that exits while the process table
settles, and never synthesizes an identity. Evidence:
`evidence/2026-09-14-process-identity-startup-retry.md`.

Task-crash mapping addendum: an observed child signal is retained as
`UNKNOWN_OUTCOME` at the task boundary so writes-local work cannot be reported
successful without post-crash attribution; a real Broker integration confirms
the Request and Job remain unresolved. Evidence:
`evidence/2026-09-14-task-crash-unknown.md`.

Process-crash addendum: an observed child termination signal is now classified
as `EXECUTION_FAILED` even when `exitCode` is null, preventing false-success
task readback. Evidence:
`evidence/2026-09-14-process-supervisor-crash-attribution.md`.

Real Broker network addendum: an opt-in Darwin integration verifies a signed
task can reach only its profile-owned loopback TCP destination and return
verified readback. Evidence:
`evidence/2026-09-14-real-broker-task-network.md`.

Task-volume identity addendum: the experimental runner double-reads and
rechecks native volume identity for every authorized task root, failing closed
on a changed root or volume before publishing a result. Evidence:
`evidence/2026-09-14-task-volume-identity.md`.

Process-supervisor startup-abort addendum: startup ownership persistence
failure now force-terminates the detached process group and waits for bounded
native root/descendant drain before returning; an unproven drain is reported as
retryable `UNKNOWN_OUTCOME`. Evidence:
`evidence/2026-09-14-process-supervisor-startup-abort.md`.

Task credential-policy addendum: versioned TaskProfiles explicitly declare
`credentialPolicy: none`; registry, sandbox renderer, and isolation-proof
admission reject unsupported credential-bearing values. Evidence:
`evidence/2026-09-14-task-credential-policy.md`.

Real process-kill-switch addendum: an opt-in Darwin integration flips the
durable `process` switch during a running task, verifies process-group drain,
and keeps the Job `unknown` after `CANCELLED`. Evidence:
`evidence/2026-09-14-real-broker-task-kill-switch.md`.

Real active-revocation addendum: an opt-in Darwin integration revokes a
session during a running `/bin/sleep` task, verifies process-group drain, and
keeps the Broker Job `unknown` after returning `CANCELLED`. Evidence:
`evidence/2026-09-14-real-broker-task-revocation.md`.

Real Edge-revocation addendum: an opt-in Darwin integration revokes the
authenticated Edge identity during a running `/bin/sleep` task, verifies
process-group drain, and keeps the Broker Job `unknown` after returning
`CANCELLED`. Evidence:
`evidence/2026-09-14-real-broker-task-edge-revocation.md`.

Real Broker task-path addendum: an opt-in Darwin integration now proves the
signed `mac_task_run` request can traverse Broker admission, single-use
approval, Job linkage, the experimental `SandboxExecTaskRunner`, and verified
readback. The default policy remains disabled; production execution is still
blocked by MOP-086. Evidence:
`evidence/2026-09-14-real-broker-task-path.md`.

Keychain ACL addendum: the native credential boundary now uses the file-based
Keychain model required by launchd daemons. Provisioning binds a canonical
protected Broker executable through `SecAccess` ACL, readback checks the exact
trusted-application identity before secret access, and digest-bound retirement
uses the exact item reference. The protected loader now requires 21 native
exports, including ACL inspection and retirement. Real host evidence covers
wrong-executable denial and cleanup; production signing/provenance and
installed rotation remain open. Evidence:
`evidence/2026-09-14-keychain-acl.md`.

Production-signature addendum: Broker and Edge install plans now default to a
strict Developer ID identity gate requiring the exact component identifier,
TeamIdentifier, and CDHash; explicit ad-hoc development plans cannot enable
capabilities. Focused install-plan tests pass 21/21. Developer ID artifact,
notarization, and persistent launchd evidence remain open. Evidence:
`evidence/2026-09-14-production-signature-gate.md`.

Task credential-proof addendum: `TaskIsolationProof` now requires a
mechanism-bound credential-isolation value for sandbox-exec or virtualization;
generic `credentials: isolated` claims are insufficient. Mechanism mismatch is
rejected before child dispatch. Focused runner/sandbox tests pass 18/21 with
three explicit Darwin skips. Production credential-store isolation remains
open. Evidence:
`evidence/2026-09-14-task-credential-isolation-proof.md`.

Persistence operations addendum: `PERSISTENCE_CUTOVER.md` records the forward
migration, encrypted-backup restore, authority freeze, UNKNOWN-job handling,
rollback, and final readback procedure. It is host/operator documentation and
does not imply an installed service cutover.

Status values: `DONE`, `IN_PROGRESS`, `PLANNED`, `BLOCKED`. Completion requires repository evidence. Current implementation, test, and working-tree state is owned by `PROGRESS.md`; this ledger records task status and acceptance evidence. `BLOCKED` is reserved for an evidenced unmet prerequisite, not merely future-phase placement. Every blocked task records `blocked_by`, `unblock_condition`, and `expected_evidence`.

Privileged-helper source-composition addendum: commit `1405b99` adds an
independent-source composition boundary for launchd, native process, plist,
runtime, and signature readback. It rejects service identity, state, type,
PID, argv, plist-path, and process-identity substitution before readiness.
Real root installation remains open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper executor addendum: commit `56ab0ca` forces the host-only
lifecycle executor to accept raw readback sources and compose the final
readback internally, preventing a preassembled-readback bypass. Root-owned
installation remains open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper host-adapter addendum: commit `a3d7765` wires bounded
`launchctl print`, native PID/start-time capture, descriptor plist reading, and
strict `codesign` verify/details parsing into the observer factory. Runtime
metadata remains helper-owned input; no root service is installed. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper observer addendum: commit `30b69df` re-reads launchd,
PID/start-time, and plist identities before composition and rejects replacement
during collection. The observer fixture covers success and PID-swap failure;
real root installation remains open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper plist addendum: commit `d3efae1` requires the exact
root-domain plist path, rendered byte count, SHA-256, and descriptor
device/inode identity in helper readback; descriptor-backed reads reject
target swaps and tampering. Root-owned installation and real helper readback
remain open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper identity addendum: commit `cc103a7` requires a positive
launchd PID and matching native PID/start-time identity in every helper
readback; missing, null, mismatched, or non-positive values fail closed. This
remains a contract-only hardening change; root-owned installation and real
helper readback remain open. Evidence:
`evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Privileged-helper readback addendum: commit `8fd5814` carries the exact native
helper `ProgramArguments` vector into the root-domain LaunchDaemon readback and
rejects missing, reordered, or substituted arguments. This is a contract-only
hardening change; root-owned installation and real helper readback remain open.
Evidence: `evidence/2026-09-13-privileged-helper-readback-arguments.md`.

Installer readback addendum: commit `6da24f6` requires a positive launchd PID
and matching native PID/start-time identity in every post-bootstrap Broker
readback. The host composition layer must obtain that identity from the native
observer; installed LaunchAgent/bootstrap and final real-service evidence remain
open. Evidence: `evidence/2026-09-13-installed-readback-identity.md`.

Verified launchd readback addendum: commit `4cb4e1a` adds
`composeMacOsInstallReadback`, binding the bounded launchd service identity,
running state, LaunchAgent type, PID, program, and plist path to the native
process identity before Broker/signature validation. It remains a non-installing
host composition boundary; real LaunchAgent bootstrap and final service evidence
remain open. Evidence: `evidence/2026-09-13-installed-readback-identity.md`.

Final plist readback addendum: commit `70ca1e9` requires descriptor-backed
plist identity and SHA-256 content matching the rendered plan, with canonical
`/var`/`/private/var` path handling and tamper/truncation rejection. Real
LaunchAgent bootstrap and installed-service evidence remain open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

Exact-arguments readback addendum: commit `9d90138` parses bounded launchd
arguments and requires the exact planned Node binary plus Broker entrypoint;
missing or substituted arguments fail closed. Generic system-service readback
remains compatible when launchd omits arguments. Real LaunchAgent bootstrap and
installed-service evidence remain open. Evidence:
`evidence/2026-09-13-installed-readback-identity.md`.

Live launchd readback addendum: a reversible physical-macOS smoke bootstrapped
and booted out a unique temporary user LaunchAgent running only `/bin/sleep`.
The production readback adapter parsed the live service and exposed a real
macOS transient `state = xpcproxy`; that value is now normalized to
`launching` without claiming `running`. The separate service inspector applies
the same conservative mapping to `loaded`. Strict Edge/helper readiness still
requires `running` plus native PID/start-time identity. Focused launchd tests
pass 7/7 and the full real-sandbox suite passes 420/420. This does not close
signed production artifacts, installed Broker/Edge handshake, or real-package
upgrade/rollback/uninstall evidence. Evidence:
`evidence/2026-09-14-live-launchd-readback.md`.

The Edge identity capture path now retries only the observed `xpcproxy`
bootstrap state within a five-second global deadline. A second reversible live
LaunchAgent smoke captured a positive PID/start-time identity through that
path, then booted the service out and confirmed absence; stopped/malformed
states remain terminal failures. This strengthens startup readback but does
not claim an installed Broker/Edge service.

The Broker instance-lock boundary additionally has a real non-cooperating
process test: a child holds the owner-only lock, the parent is denied with
`ALREADY_ACTIVE`, and reclamation succeeds only after native PID/start-time
observation proves the child stale. Focused lock tests pass 5/5. This does not
claim launchd singleton enforcement or remount durability. Evidence:
`evidence/2026-09-14-service-instance-lock-process.md`.

Current-host sandbox addendum: `MOPS_REAL_SANDBOX=1 npm test` passed 430/430
with one explicit non-sandbox skip on the Darwin arm64 host. Environment and
protected-surface denial, single-process fork/setsid and external-network
denial, selected loopback allowlisting, and active process-group cancellation
all ran successfully. This strengthens MOP-086 evidence but leaves its
deprecated-`sandbox-exec` production decision, post-snapshot descendants,
remounts, credential contents, and `mac_task_run` enablement open. Evidence:
`evidence/2026-09-14-real-sandbox-regression.md`.

Current runner-binding addendum: `TaskRunner` now declares the exact host
sandbox mechanism alongside `TaskIsolationProof`. Broker admission and task
dispatch reject missing or mismatched declarations before consuming approval or
launching a child process; `mac_task_run` remains disabled.

Install-plan readback hardening is committed locally. The host-only install
plan now has a physical-Mac package smoke that calls the
real executor with only independent launchd, native PID/start-time, plist,
Broker-status, and signature sources. It waits through transient `launching`,
double-reads mutable identities, starts a temporary zero-capability Broker
under a user LaunchAgent, and completes exact uninstall with final absence.
The package uses ad-hoc signing and the host observer now supports a distinct,
HMAC-authenticated Broker status socket with native peer credentials and
durable replay rejection. The recorded package smoke still used its historical
owner-only fixture; Developer ID, production artifact provenance,
upgrade/rollback, remote Edge, and helper installation remain open. Evidence:
`evidence/2026-09-14-live-install-plan.md` and
`evidence/2026-09-14-broker-status-ipc.md`.

The real Broker startup assembly now has a physical-host smoke: a temporary
user LaunchAgent supplied the native PID/start-time identity, signed policy and
Edge-key activations were restored from a temporary BrokerStore, and the
native Broker socket started with zero enabled capabilities and mode `0600`.
Close removed the socket and cleanup booted out the temporary service. This is
startup-assembly evidence, not installed-package, Edge request-exchange,
Developer ID, or privileged-helper evidence. Evidence:
`evidence/2026-09-14-live-broker-startup.md`.

Packaging-shape addendum: the repository now carries a reviewable Edge
LaunchAgent template beside the Broker template. The deployment notes bind
Edge launchd identity/readback before Broker startup and keep the Broker status
socket as a separate authenticated operator/readback channel. A static
template regression rejects shell, environment, user, and privileged fields;
this does not claim persistent installation or signing provenance.

## P0 — Foundation

- `MOP-001` — `DONE` — Git repository, npm workspace/package baseline, developer commands, dependency lockfile, ignore rules, and a least-privilege macOS CI definition exist. First remote CI execution remains verification evidence rather than bootstrap scope.
- `MOP-002` — `DONE` — Materialized and synchronized GOAL, DESIGN, SPEC, EPIC, ROADMAP, TASK, PROGRESS, and GOAL_PROMPT with repository-state, consistency, whitespace, task-ID, and prompt-length checks.
- `MOP-003` — `DONE` — Accepted TypeScript/Node 24+ for Edge/Broker/shared contracts; Swift remains available for native adapters/helper. Package direction and prototype evidence are recorded in ADR-0001.
- `MOP-004` — `IN_PROGRESS` — Versioned request/result/failure/principal/scope types, signed policy schemas, and a shared stable failure schema exist. A versioned `schemas/ledger-records.schema.json` now machine-validates bounded Request, Approval, Job, and Audit record envelopes, including typed privileged payloads and rejection of raw authority fields; persistence runtime validation remains the implementation authority. Host-only SQLite backup/restore/retention primitives now add owner-only atomic encrypted publication, AES-256-GCM authentication, audit-chain/SQLite integrity checks, fresh-target restore refusal, numeric timestamp retention, and symlink/ownership/mode/size/target-swap guards; missing or mismatched Broker-owned key sources and legacy plaintext backup names fail closed. BrokerStore now records and enforces monotonic SQLite schema version `8`, applies a versioned forward-only migration registry transactionally, preserves legacy data, rejects future markers and inconsistent registry identities, and defines rollback as restore-from-encrypted-backup only. Schema version 6 adds the durable virtualization-guest replay ledger; schema version 7 adds bounded guest request metadata used for restart status reconciliation and clears it after verified terminal readback; schema version 8 adds independently persisted guest-attestation key configuration and its dedicated revocation kind. Packaged Broker startup additionally claims a persisted singleton runtime fence so stale writers fail closed after service takeover. The macOS Keychain source now has a real physical ACL readback and digest-bound retirement path; focused migration/credential/ACL tests pass on the recorded host. Mutation-state invariants, disk-exhaustion behavior, production code-signing/Keychain identity, and final ADR acceptance remain incomplete.
- MOP-004 schema clarification: source revision `db129b3` adds schema version `9`
  for durable request capability-family markers. Version `8` remains the
  guest-attestation key configuration migration; the current BrokerStore
  runtime and migration registry are at version `9`.
- `MOP-005` — `DONE` — Materialized the locked capability taxonomy, lifecycle, catalog, standard, and all 44 KB tool contracts with unique provenance, deterministic mandatory fields, and canonical delivery-wave naming. Upstream KB writeback is tracked separately in `KB_SYNC.md`.
- `MOP-006` — `DONE` — Created the initial threat model for remote client, Edge, IPC, Broker, adapters, child processes, GUI, helper, audit, policy, and secret stores, with verification targets.
- `MOP-007` — `IN_PROGRESS` — Strict typecheck, build, Node test, AJV contract validation, dependency audit, unit/integration/adversarial foundation tests, a dependency-free tracked-file style/lint check, and a least-privilege macOS CI workflow exist. First remote CI evidence remains pending.
- `MOP-008` — `IN_PROGRESS` — Established the initial evidence and verification matrix; machine enforcement and real evidence remain pending the test baseline.

## P0 — Architecture closure

- `MOP-080` — `IN_PROGRESS` — Freeze exact scope, principal, session, parameterized-target, wildcard, inheritance, and revocation semantics. Depends on ADR-0002 and ADR-0004 acceptance.
- `MOP-081` — `IN_PROGRESS` — Exact Edge/key identity, signed key metadata, protected/exclusive key provisioning, revoke-before-retire deletion, overlapping rotation, validity windows, key-specific revocation, request/response policy-key binding, replay persistence, forged-socket response rejection, macOS UID/GID/PID peer verification, optional native PID/start-time peer identity binding, legacy revocation migration, a BrokerStore-backed monotonic activation/restore guard, and a native public-`Socket({ fd })` IPC candidate are implemented and tested. Edge key metadata now has an owner-only versioned loader requiring an explicit `file` or `keychain` source, an expected secret-byte digest, protected config target readback, BrokerStore revocation preflight, and a BrokerStore-backed monotonic activation/restore manager with exact restart matching and audited activation; the owner-only Authority Control channel now has a dedicated `authority_key` source/loader with digest, validity, audited activation, exact restore, revocation, and host uninstall client assembly. The Edge request factory has matching protected-file and opt-in native peer-authenticated Keychain delivery factories using a fresh challenge, strict bounded messages, replay rejection, fixed service/account startup binding, response digest checks, and no environment-variable or MCP-argument fallback. The Edge IPC client checks the owner-only socket parent and revalidates socket device/inode identity after connect before sending request bytes. LaunchAgent startup now restores the exact active key config before launchd PID/start-time capture and native runtime construction, injecting the restored keyring through a Broker factory; unactivated, changed, or cross-Edge config fails before `launchctl` readback. Overlapping source-backed rotation remains startup/configuration-only without installed hot reload. The protected native adapter loader rejects non-canonical/symlinked, writable, foreign-owned, oversized, changed, or incomplete `.node` artifacts before use, binds Node's cached module to the first artifact's device/inode/size/digest, requires all 19 production native exports including non-interactive Keychain read/provisioning, checks compiled N-API compatibility with the active runtime, and is the only production consumer path for filesystem, process, network, and process-tree adapters. The macOS native build now fails closed if `/usr/bin/codesign --verify --strict` cannot validate the emitted adapter, but the observed artifact remains ad-hoc signed only. The Broker now validates request-age/clock-skew constructor limits and bounds active work per principal/session (default 8, maximum 64), rejecting saturated sessions before durable admission; focused Broker and physical-Darwin regressions pass. Developer ID code identity/provenance, notarization, Node/runtime version pinning beyond N-API compatibility, Edge PID lifecycle packaging, Keychain ACL review, live-item rotation/deletion, physical-erasure limits, cross-process/global quotas, broader numeric canonicalization, and general corruption/migration handling remain open. Evidence: `evidence/2026-09-13-edge-key-source-rotation.md`, `evidence/2026-09-13-edge-keychain-delivery.md`, `evidence/2026-09-13-authority-key-activation.md`, `evidence/2026-09-15-broker-session-concurrency.md`, and `evidence/2026-09-15-strict-json-parser.md`.
- Durable request-capacity clarification: source revision `31e89f0` now closes
  the shared BrokerStore global and principal/session admission boundary that
  was previously described as open in the MOP-081 summary. Remaining quota
  work is process/adapter-specific enforcement, disk/depth budgets, and
  production service evidence.
- Durable capability-family clarification: source revision `db129b3` extends
  the request ledger to schema version `9` and closes the cross-handle durable
  family-capacity boundary for read, write, process, network, GUI, destructive,
  and privileged work. Remaining quota work is adapter-specific semantic
  enforcement plus kernel/disk/depth limits and production service evidence.
- `MOP-082` — `IN_PROGRESS` — Broker-owned single-use approval records bind approver/requester, tool/contract, normalized target, arguments digest, policy version, approval class, attended mode and TTL. Exact consumption is atomic with request intent; substitution, expiry, revocation, exhaustion, competing use, missing approval, and pre-dispatch invalidation tests pass. A separately authenticated issuer prototype now binds issuer/key identity, signed payload, preview digest, issuance nonce, attended/unattended policy, and decision/completion provenance before persistence. Owner-only issuer-key file loading/provisioning and a separate durable `approval_key` revocation kind pass revoke-before-retire tests. A versioned owner-only metadata config atomically rotates and reloads non-secret key paths with revision/digest readback; BrokerStore activation history now rejects rollback and startup restore requires the exact persisted identity. Protected Keychain/cross-process storage, human approval UI/channel, unattended profile ownership, privileged approval, active-work semantics and ADR acceptance remain.
- `MOP-083` — `IN_PROGRESS` — SQLite Request records atomically bind nonce admission, request/payload identity, lifecycle, decisions, approval-backed mutation intent, completion, and restart-safe recovery to audit evidence. Single-use Approval records and Job records persist their bounded identities and state. `admitApprovedJob` atomically binds future-request approval/intent/idempotency/new-job creation with idempotent reuse and conflict rollback, while `admitApprovedJobAfterDecision` atomically binds the already-authorized task path's approval consumption, intent audit, and queued Job linkage with owner/target/payload/timestamp preconditions. Fault-injected rollback proves the post-decision path leaves no partial approval, intent, or Job; restart reconciliation fails an authorized-but-not-intented request closed without consuming approval. Generic authority switches and revocations now persist redacted intent/completion audit pairs in the same transaction as the authority change and queued-job cancellation, and the separate Authority Control IPC durably admits its request/nonce before applying only bounded switch/revocation operations. Job execution now persists owner/token/expiry/heartbeat leases and fences stale terminal commits. Virtualization guest task admission now persists a bounded signed-request descriptor after replay admission; startup recovery performs a fresh authority-checked status lookup and only promotes a restart-unknown Job after verified terminal readback, otherwise retaining `UNKNOWN`. Host-only `backupTo`, `restoreBackup`, and `pruneBackups` measure source/destination capacity before writing, provide atomic owner-only encrypted `.sqlite.enc` snapshots, AES-256-GCM authentication, SQLite/audit-chain verification, fresh-target restore, numeric retention, and fail-closed symlink/ownership/mode/size/target-swap/key-source checks. Crash recovery removes stale hidden backup and WAL/SHM sidecar temporaries, simulated `ENOSPC` and insufficient-capacity preflight return retryable `AUDIT_UNAVAILABLE`, and a two-process writer test preserves the audit chain with a bounded SQLite busy timeout. Process-tree ownership, real kernel/disk exhaustion, explicit single-owner service policy, and ADR-0005 acceptance remain.
- `MOP-084` — `DONE` — Contract envelope and per-tool functional `input_schema`/`output_schema` objects are complete for all 44 tools. Envelope validation, functional schema compilation, semantic review, authority-surface review, and catalog parity pass. The mandatory audit taxonomy, structured postcondition field, and `tool_delivery_wave` migration are closed. This documentation/schema closure does not implement runtime behavior or close `MOP-004` or `MOP-080..083`.
- `MOP-085` — `IN_PROGRESS` — Maintain Requirement -> Threat -> Task -> Test -> Evidence -> Release Gate traceability. Depends on test IDs from `MOP-007` and contracts from `MOP-084`.
- `MOP-086` — `IN_PROGRESS` — Initial real-macOS sandbox probe is recorded in `SANDBOX_RESEARCH.md` and `evidence/2026-09-12-sandbox-research.json`. Commit `2e6cd57` adds a disabled-by-default `SandboxExecTaskRunner` and Broker-owned deny-default profile renderer: resolved profiles default to `processTreePolicy: single_process` without `process-fork`; `owned_group` profiles may render the explicit fork rule but the runner now refuses to enable them even with an external proof until a separate process-tree decision is accepted. `TaskIsolationProof` binds the explicit sandbox mechanism and selected process-tree policy and rejects proof reuse across variants. The opt-in host smoke reads/writes an allowed temporary root, denies `/private/etc/passwd`, a root-contained `.env`, an outside-file symlink, and existing `.ssh`, `.docker`, Chrome, Safari, Mail, Messages, and Keychains surfaces plus `/var/run/docker.sock` readability, without opening their contents; it filters controller/`HOME`/SSH-agent/AWS_PROFILE environment canaries, allows only a selected loopback `tcp` destination, denies an unlisted loopback port and external curl DNS/network access, rejects a Bash child-launch attempt, and maps active `/bin/sleep` cancellation to detached process-group termination. Source `01a26ba` adds a real-Mac Perl hostile-descendant fixture: `fork()`/`setsid()`/marker-write returns `fork-denied` under `single_process`, with no marker left behind; focused sandbox checks now include volume-identity target-swap coverage and pass 10/10, while the full `MOPS_REAL_SANDBOX=1` suite passes 446/447 with one explicit skip. The new shared environment policy rejects task-profile `PATH`, `NODE_OPTIONS`, dynamic-loader, interpreter-startup, temp-directory, and arbitrary Git/Docker configuration keys; fixed adapters retain only exact explicit non-secret keys. The experimental runner now captures and rechecks native root volume identity around each task, refusing to publish a result after a root/volume change; this is a readback guard, not a kernel-held mount namespace. Filesystem/symlink, executable-allowlist, network-deny, fake credential-canary, and Broker launch file-descriptor behavior remain partial evidence; real credential/Docker/persistence isolation, owned-group or post-snapshot `setsid` ownership, descendants created after the last persisted snapshot, in-syscall remount resistance, external allowlisted networking, and UDP behavior remain open. A disabled Broker `ProcessSupervisor` plus named `TaskProfileRegistry` prove explicit profile-owned executable/cwd/args/environment/stdio budgets, non-inherited descriptor canary behavior, bounded detached process-group drain/readback, shared live adapter ownership, exact PID/start-time recovery for a live root plus an observed detached descendant after BrokerStore reopen, and conservative `UNKNOWN` handling when an empty post-exit snapshot cannot prove absence; `SandboxExecTaskRunner.close()` and `Broker.close()` now forward that boundary. Broker admission additionally requires a versioned profile-matched `TaskIsolationProof` covering the explicit sandbox mechanism, sandbox, filesystem, network, credentials, process-tree, and selected process-tree policy guarantees; the fail-closed `mac_task_run` Job/approval handler remains unwired to a production runner. Still blocks `MOP-043`, `MOP-045`, and `mac_task_run` enablement.
- `MOP-087` — `IN_PROGRESS` — Complete README navigation and testing, configuration, deployment, operations, incident, rollback, and kill-switch runbooks. Verified commands depend on runtime and packaging work.
- `MOP-088` — `DONE` — Resolved the two repo representation conflicts, recorded decision/rationale/migration/evidence, and prepared `KB_SYNC.md` for owner-reviewed upstream writeback. This documentation-only task does not mutate KB-MCP.

Authority-control note: generic runtime switches and revocations now append redacted hash-linked `intent`/`completion` audit pairs in the same persistence transaction as the authority change and queued-job cancellation. A separate owner-only, native-peer/HMAC/replay-bound Authority Control IPC now admits only switch and revocation commands and carries its request ID into those audit pairs. Its operator key is selected by a protected, digest-bound, monotonic activation manager with a dedicated revocation kind and exact restart restore, and the uninstall coordinator constructs its client from that manager. This does not close active process-tree termination, installed startup, or operator recovery evidence.

IPC ownership addendum: source revision `44cae6a` now probes configured Unix
socket paths before stale cleanup, rejects active listeners without unlinking
them, binds generic close cleanup to device/inode identity with a temporary
symlink barrier, limits native cleanup to the recorded listener identity, and
preflights the Broker socket before startup Job recovery. Repository-level
tests pass; installed launchd singleton enforcement and physical crash/remount
readback remain open.

Startup serialization addendum: source revision `0c34c65` adds an owner-only
runtime-root instance lock with exact PID/start-time identity. It is acquired
before socket preflight, BrokerStore access, and restart reconciliation;
duplicate live owners are rejected and stale locks are reclaimed only after
proof of owner death or PID reuse. Normal and failed startup cleanup paths
release the lock after resource disposal. Launchd install/bootstrap and
non-cooperating-process lock evidence remain open.

## P1 — Local Broker vertical slice

- `MOP-010` — `IN_PROGRESS` — Broker core plus local `mac_health`, `mac_capabilities`, `mac_policy_explain`, `mac_system_summary`, `mac_process_list`, `mac_process_inspect`, `mac_network_status`, `mac_service_status`, `mac_log_tail`, exact-target `mac_git_status`/`mac_git_branch_list`/`mac_git_log`, `mac_stat_path`, bounded `mac_read_file`, descriptor-backed `mac_hash_file`, bounded descriptor-backed `mac_list_directory`, bounded `mac_directory_tree`, metadata-only `mac_find_files`, metadata-only `mac_recent_files`, bounded secret-filtered `mac_search_text`, bounded `mac_project_discover`, bounded `mac_project_summary`, and bounded `mac_storage_analysis` handlers exist and pass tests. A fail-closed `LocalBrokerRuntime` now orders Broker IPC before operator channels, rolls back partial startup, retains failed cleanup for explicit recovery, and `createMacOsNativeBrokerRuntime` binds that lifecycle to the native Broker channel. The launchd startup assembly now restores the protected Authority key and places its separate native-peer channel under the same lifecycle. Installed launchd lifecycle, operator startup, listener ABI pinning, and production enablement remain open.
- `MOP-011` — `IN_PROGRESS` — Mode-`0600` Unix IPC, macOS `getpeereid`/`LOCAL_PEERPID`, optional native PID/start-time identity binding, domain-separated request/response HMAC authentication, and a shared native accept path for Broker, policy-signer, and approval channels that hands descriptors through public `Socket({ fd })` pass prototype tests, including OS identity denial and rejection of a replacement socket using another key. Separate spawned Broker and Edge package-process fixtures now complete a signed request/response across native UDS under the captured Edge PID/start-time identity and verify the Broker response proof. A bounded read-only launchd readback adapter and real system-service smoke are also present. The fixed Broker service entrypoint restores exact persisted Policy/Edge-key activation before native listener construction and wipes loaded Edge keys on close. Production key lifecycle, native packaging/code identity, Edge PID lifecycle wiring, and installed transport selection remain open under ADR-0002.
- `MOP-012` — `IN_PROGRESS` — Timestamp/session expiry, canonical payload binding, atomic nonce/request admission, persistent replay denial, terminal request lookup, and restart replay/reconciliation tests exist. Corruption, canonicalization cross-runtime, retention, and accepted persistence design remain open.
- MOP-012 clarification: the atomic admission boundary now includes durable
  global and principal/session active-request limits; corruption, broader
  numeric canonicalization, retention, and the accepted persistence design
  remain open.
- `MOP-013` — `IN_PROGRESS` — Ed25519-signed policy loading, Broker-owned principal grants, exact typed target rules, deny-over-allow, default deny, immutable request snapshots, durable activation/rollback, policy-version binding, filesystem-root authorization, and unimplemented-tool enable rejection pass tests. The signer lifecycle now has a versioned owner-only metadata file, per-key public-key digests, bounded overlap/validity windows, monotonic activation and restart restore, audited durable key revocation, and a separate owner-only UDS operator channel with HMAC authentication, OS peer verification, replay persistence, reload, rollback, and revoke commands; it is not exposed through the MCP Edge. Installed startup wiring, native caller/process identity packaging, Keychain distribution, and the complete filesystem policy matrix remain open.
- `MOP-014` — `IN_PROGRESS` — A non-executing `mac_policy_explain` handler reports allow/deny, normalized query target, required/missing scopes, reason codes, and policy version. Path queries are mapped to Broker-owned signed root identities before authorization; remaining target types depend on MOP-013.
- `MOP-015` — `IN_PROGRESS` — Broker-owned request states commit atomically with decision, mutation-intent, and completion audit records; recursive redaction, a SHA-256 event chain, startup tamper rejection, and transactional policy intent/completion are implemented as prototype behavior. The packaged Broker startup now requires a keyed 0600 audit-tail sidecar and loads its HMAC source through the executable-bound Keychain factory, failing closed on missing or forged readback; the sidecar read/publication path now has an owner-only atomic sibling lock with target-identity recheck on release. Crash/outage injection, retention, access control, production Keychain provisioning/rotation, stale-lock operator recovery, external rollback detection, and ADR-0005 acceptance remain open.
- `MOP-016` — `IN_PROGRESS` — Persistent global/capability-family switches plus principal/session/Edge revocation checks exist. Filesystem workers poll active authority, request termination, revalidate before returning success, and audit active revocation as `CANCELLED`; mutation writes now keep the Job `UNKNOWN` when a mutations kill switch trips before completion persistence. Disabling global/mutations/process/network switches now transactionally cancels applicable queued Jobs, and principal/session revocation does the same with conservative cancellation for identities whose queued-job provenance is not yet persisted. A separate owner-only Authority Control IPC enforces native peer identity, HMAC authentication, durable replay denial, strict operation allowlists, and expected-state switch preconditions. The host-only uninstall path now binds to its authenticated client with response proof, socket identity revalidation, bounded transport, and switch/revocation readback. A deterministic 16-seed authority/job state-machine regression checks queued/running/terminal/restart invariants and cross-principal isolation. Active process-tree termination, restart behavior, protected key distribution, installed startup, and operator recovery controls remain open.
- `MOP-017` — `IN_PROGRESS` — Bounded filesystem workers implement concurrency admission, per-tool deadline, active cancellation polling, termination requests, output caps, and post-result authority revalidation. Fixtures cover a real multi-root filesystem worker request, fixed-capacity overlap rejection, cancellation capacity release only after worker exit, an abrupt worker crash after a committed write that preserves an `UNKNOWN` Job while releasing capacity only after the exit event, explicit executor shutdown that terminates active workers and rejects new work, and a real `Broker.handle` stale-completion attempt rejected after a second `BrokerStore` reopen reconciles the Job to `UNKNOWN`. Packaged Broker startup now enables a persisted singleton runtime fence; after a second instance claims the next generation, stale writers fail closed with `CONFLICT` inside their SQLite transaction. Broker admission rechecks authority immediately before starting a queued Job, while the Job Ledger persists queued cancellation, idempotency, and execution owner/token/expiry/heartbeat leases. The disabled ProcessSupervisor now binds the macOS root PID and descendants to start-time identities, counts pending starts against shared capacity, waits for pending startup cleanup during close, requires the native root process-group ID to match the detached PID, rechecks that group identity before treating the root as alive, signals verified descendants in addition to the detached process group, suppresses group signalling when the root identity is unavailable, and fails closed when the native observer is unavailable; it waits for group and tracked-descendant disappearance before reporting observed termination, holds capacity while unresolved work is reaped, rejects new work after close, drains the shared Broker-owned OS process authority plus active task-runner process groups during live Broker shutdown, and supports explicit restart recovery using persisted exact PID/start-time snapshots while retaining UNKNOWN Job state; an observed detached descendant is recovered after root exit without relying on group membership, and an empty post-exit snapshot remains UNKNOWN rather than claiming absence. The validated `sandbox-exec` single-process path now persists a Broker-owned no-fork proof and may report `PROCESS_ABSENT` after a dead root only when no descendants were recorded and the original group is gone; generic descendant trees, post-snapshot `setsid` escape resistance, unknown-outcome recovery, and old-process OS ownership remain.
- Process-quota clarification: `ProcessSupervisor` now counts active and
  pending starts per canonical executable in addition to the Broker-wide pool;
  a saturated executable fails with retryable `CONFLICT` while another
  executable may still use available global capacity. Adapter-specific
  semantic quotas and kernel-level resource limits remain separate work.
- `MOP-018` — `IN_PROGRESS` — Descriptor-backed bounded regular-file metadata, content-read, full-file `mac_hash_file`, bounded `mac_list_directory`, and depth/entry-bounded `mac_directory_tree` slices have canonical target binding, independent root policy, final-symlink/special-file denial, single-link enforcement where content is opened, local-volume restriction, plan-captured root volume identity, native `f_fsid`/filesystem-type checks, canonical secret checks before I/O, post-operation identity stability, strict encoding/digest handling, protected-entry filtering, and audit identity. Physical/removable remount evidence, configurable secret corpus, syscall timeout/cancellation, packaging, and release evidence remain.
- `MOP-019` — `IN_PROGRESS` — Bounded local success and adversarial metadata/content-read cases pass on the real Mac; a dedicated read-only host probe now records bounded system/network/process facts and `/System/Library` metadata/list/tree readback without active probes, content reads, credential access, or mutation. Clean-revision, installed-service, full filesystem/secret, and production policy evidence remain. Evidence: `evidence/2026-09-13-l0-l1-host-readback.md`.

## P2 — Remote Edge

- `MOP-020` — `IN_PROGRESS` — MCP SDK v2 initialize/modern protocol handling, Broker-filtered tool discovery, `mac_health` routing, stable Broker failure mapping, strict HTTPS Edge configuration, bounded connection budgets, and a real local HTTPS boundary probe are implemented and tested. A fixed packaged Edge service entrypoint now loads a strict owner-only, root-bound startup document, assembles the protected TLS/key/contract/JWT/IPC boundary, requires listener host/port readback, and wipes in-memory key material on close. A real RS256-authenticated MCP client now completes pinned `2026-07-28` discovery and reaches `mac_health` through the signed, peer-checked local Broker UDS; bearer material is absent from Broker audit rows. Pagination/notification behavior, separate packaged processes, remote deployment, and production key distribution remain. Evidence: `evidence/2026-09-13-governed-edge-service-entrypoint.md`.
- `MOP-021` — `IN_PROGRESS` — The MCP Edge validates signed JWT access tokens with pinned issuer/resource/audience, explicit asymmetric algorithms, bounded local/remote JWKS retrieval, controlled unknown-`kid` refresh cooldown, short token age, required identity claims, internal issuer-ID projection, known-scope filtering, and a fail-closed revocation callback. Startup also requires the configured OAuth issuer to match metadata and rejects non-HTTPS authorization/token endpoints. Local HTTPS tests verify bearer challenge/route ordering, metadata mismatch denial, official-client discovery, and in-process JWKS key rotation using a signed JWT; external issuer issuance/discovery, issuer-to-internal-ID operational mapping, live rotation/propagation latency, and remote client interoperability remain open; the local fixed-window rate limiter is tracked under MOP-023.
- `MOP-021` security addendum — Protected TLS certificate and private-key loading is implemented with owner-only regular-file checks, `O_NOFOLLOW`, canonical paths, bounded sizes, and device/inode stability readback. The fixed Edge startup loader additionally rejects weak/symlinked config, root escapes, and non-canonical target parents before constructing HTTPS. Remote issuer deployment, certificate rotation, Keychain storage, and installed Edge startup remain open.
- `MOP-022` — `IN_PROGRESS` — `EdgeRequestFactory` constructs canonical signed Broker requests with contract/protocol versions, policy audience/version, principal projection, timestamp, nonce, and key identity; `BrokerIpcClient` verifies the response proof against the exact request/result. The service-owned factory now exposes explicit disposal that wipes its HMAC key on shutdown. Cross-runtime canonicalization, protected production key distribution, and rotation/compatibility evidence remain.
- `MOP-023` — `IN_PROGRESS` — Implemented a bounded in-memory fixed-window Edge limiter after Bearer verification, keyed by verifier-provided client/principal identity, with fixed request/window/key budgets and `Retry-After` responses; Broker-filtered discovery is bounded. Shared multi-instance limits, durable counters, and real-client load evidence remain.
- `MOP-024` — `IN_PROGRESS` — Broker session/principal/Edge/key revocation and request/session expiry pass local tests; the JWT verifier accepts a host-owned revocation callback keyed by issuer/subject/session/jti. External issuer revocation, refresh/session lifecycle, propagation latency, and active-work behavior remain open.
- `MOP-025` — `PLANNED` — Select authenticated HTTPS/tunnel deployment and verify a real client end to end.

## P3 — L0/L1 inspection

- `MOP-030` — `IN_PROGRESS` — Implemented bounded `mac_system_summary` with sanitized host facts and optional load, local-interface-only `mac_network_status` with inferred connectivity, plus descriptor-verified, metadata-only `mac_storage_analysis` with capacity facts, ranked consumers, and fixed traversal budgets. The real Mac host probe now verifies system facts and interface state with listener enumeration/active probing disabled; listener ABI pinning, physical real-volume remount behavior, and release evidence remain.
- `MOP-031` — `IN_PROGRESS` — Implemented bounded native `mac_process_list` and `mac_process_inspect` with independent `mac.process.read` scope, process target authorization, numeric owner redaction, executable identity, CPU/memory bounds, parent/child PID bounds, sort/limit/PID validation, and no argv/environment exposure. The real Mac host probe verifies bounded inventory and current-process readback; network listener remains intentionally unavailable, while service status, allowlisted log inspection, exact-target Git status/branch/log/diff inspection, and the independent `mac.app.read` app inventory boundary are implemented through fixed adapters.
- `MOP-032` — `IN_PROGRESS` — Descriptor-backed `mac_stat_path`, bounded `mac_list_directory`, bounded `mac_directory_tree`, and metadata-only `mac_recent_files` are implemented with signed roots, canonical readback, plan/native volume-identity binding, same-volume containment, deny-zone revalidation, protected-entry filtering, fixed traversal/result limits, Broker-bound time windows, and audit identity. A real `/System/Library` metadata/list/tree probe now verifies canonical host readback with content reads disabled; physical remount and broader release evidence remain.
- `MOP-033` — `IN_PROGRESS` — Implemented bounded metadata-only `mac_find_files` and bounded secret-filtered `mac_search_text` over explicitly authorized roots with independent `mac.files.search` scope, per-root target authorization, descriptor-backed traversal, protected-entry/secret-content filtering, fixed entry/depth/result/text-byte budgets, worker cancellation, and strict result validation. `mac_log_tail` now preserves and redacts a supervisor-confirmed bounded output prefix on `OUTPUT_LIMIT`, reports explicit truncation, and fails closed on unresolved process outcomes. Packaging and release evidence remain.
- `MOP-034` — `IN_PROGRESS` — The bounded safe-file-read, full-file hash, descriptor-backed directory-list, depth/entry-bounded directory-tree, metadata-only file-discovery, and bounded content-search handlers are implemented. Binary policy expansion, secret controls, and broader read behavior remain.
- `MOP-035` — `IN_PROGRESS` — Implemented bounded metadata-only `mac_project_discover` and `mac_project_summary` with allowlisted marker types, safe manifest/language inference, bounded traversal/tree output, protected-entry filtering, dependency-directory pruning, per-root/root authorization, worker cancellation, strict result validation, and explicit VCS branch/dirty omission warnings. Packaging and release evidence remain.
- `MOP-036` — `IN_PROGRESS` — Traversal, root/target symlink, deny-inside-allow alias, root `/`, metadata/hash/content-read/list/tree target-change, content-read intermediate-symlink target-swap, protected directory-entry filtering, bounded depth/entry truncation, multiply-linked inode denial, post-authorization mutation, concurrent create-only target/symlink-swap, Unix-domain-socket generic-tool, FIFO/non-blocking pseudo-device, observed character/block-device, bounded pressure-budget, and real multi-root worker-capacity tests pass. Lexical case-alias rejection, NFKC-normalized Unicode search identity, and plan/native volume-identity guards are covered by adversarial fixtures. Physical remount identity, cross-volume normalization policy, broader device/pseudo-filesystem coverage, production-scale resource exhaustion, and kernel-blocked I/O recovery remain.
- `MOP-037` — `IN_PROGRESS` — Broker-mandatory F0/F1 path rules cover representative SSH, GPG, cloud, Docker, Kubernetes, Keychain, Mail, Messages, Safari, Chrome, Photos, dot-env, GitHub CLI, browser, and containerized Apple data paths; returned byte ranges are denied on representative private-key/token/credential signatures without audit leakage. Evidence redaction now covers protected paths with spaces, `/private/var/root`, Bearer/Basic credentials, and JWT-shaped values. Configurable classification, split-range signatures, false-positive corpus, and broader no-secret-output regressions remain. Evidence: `evidence/2026-09-13-secret-zone-redaction.md`.

## P4 — L2 developer operations

- `MOP-040` — `IN_PROGRESS` — Implemented governed Git status, diff, log, and branch metadata through exact project-root authorization, fixed `/usr/bin/git` commands, repository integration rejection, literal path/revision validation, bounded outputs, secret redaction, identity readback, and schema/conformance tests. Git log now preserves complete records from a supervisor-confirmed bounded prefix while rejecting unverified termination. A disabled-by-default controlled Git write prototype now adds explicit-path staging and local commit through Broker-owned Jobs, approval binding, fixed no-hook/no-network commands, staged-diff/HEAD/index/status readback, and fail-closed unknown-outcome handling. A real opt-in Broker task integration now exercises a profile-owned loopback TCP allowlist through the sandbox runner; external destinations and broader network release evidence remain open. Network operations remain excluded; real-Mac repository evidence and write-gate closure remain open.
- `MOP-041` — `IN_PROGRESS` — Implemented bounded `mac_package_inspect` with independent `mac.package.read` scope, exact project-root authorization, descriptor-backed manifest/lock identity checks, npm/pnpm/yarn/pip/uv/poetry/Brewfile parsing, protected-content denial, cancellation/timeout checks, and no package-manager script execution. Outdated registry reads remain disabled until an allowlisted registry profile and network-scope binding are released.
- `MOP-042` — `IN_PROGRESS` — Implemented fixed local-only Docker status, object inspection, and bounded container logs through a Broker-owned adapter with exact `mac.docker.read` targets, a canonical Docker Desktop executable allowlist, fixed arguments, bounded parsing, environment/mount/log redaction, cancellation, and no raw socket proxy. A real Mac daemon readback observed local Docker version `29.1.3` without listing containers/images; object/log compatibility, storage readback, and independent raw-socket negative tests remain.
- `MOP-043` — `BLOCKED` — Implemented the named-profile validation boundary and Broker-owned `mac_task_run` admission/Job lifecycle; versioned profiles now explicitly declare `credentialPolicy: none`, and an opt-in Darwin integration proves signed-request admission, single-use approval, Job linkage, experimental sandbox dispatch, and verified readback, but production execution remains disabled. `blocked_by: MOP-086`; `unblock_condition: per-tool functional schemas remain complete and sandbox/credential-isolation evidence passes`; `expected_evidence: hostile task-profile PoC, resource-bound tests, and L2 release-gate evidence (VT-SBX-01, VT-SBX-02)`.
- `MOP-044` — `IN_PROGRESS` — Owner-bound `mac_job_status` and `mac_job_cancel` handlers, bounded output, durable cancellation intent, queued cancellation, terminal idempotency, lease-fenced terminal transitions, and restart reconciliation are implemented and schema-tested. Opt-in Darwin integrations now verify session revocation, Edge revocation, and the durable `process` kill switch during real running tasks; each drains the process group and leaves the Job `unknown` after `CANCELLED`. Broader restart/crash and production process-tree evidence remains gated by MOP-086.
- `MOP-045` — `BLOCKED` — Prove child processes cannot access Edge/Broker/controller credentials or exceed filesystem/network policy. The handler accepts only a Broker-owned runner and records unknown outcomes when runner evidence or active authority is not trusted; no production child-process runner is enabled. `blocked_by: MOP-086`; `unblock_condition: real-Mac hostile sandbox PoC passes or task capability is restricted/removed`; `expected_evidence: credential canary, filesystem, network, process, Docker, and persistence isolation evidence (VT-SBX-01, VT-SBX-02)`.
- `MOP-046` — `IN_PROGRESS` — Implemented a disabled `mac_write_file_atomic` Broker/native prototype with independent write-root policy, exact approval binding, secret-content denial, descriptor identity checks, atomic same-directory rename, expected hash/create-only preconditions, explicit idempotency key, Broker Job Ledger linkage/status lookup, restart-to-`UNKNOWN` recovery, readback verification, and focused tests. Write jobs now persist only a bounded non-secret descriptor, including the exact generated temporary filename, and `mac_job_status` probes `matches`/`mismatch`/`unavailable` postconditions without inferring success. An explicit host-startup recovery hook now selects only restart-reconciled unknown write Jobs and cleans one recorded temporary artifact with descriptor-relative identity checks, audited intent/completion, and no prefix scan; legacy descriptors without a temporary name remain untouched. Real `WorkerFilesystemExecutor` pre-commit, post-rename, and test-only post-commit worker-crash failures now prove Broker preserves the Job as `UNKNOWN`; a Broker completion-failure simulation, deterministic fault-test-only `ENOSPC` cleanup before temporary write/`fsync` and after rename before parent `fsync`, a test-only fault-instrumented native `SIGKILL` boundary at selected syscalls, and final authority revalidation when the mutations kill switch trips confirm a committed atomic target cannot be published as an unauthorized success and remains inspectable as `UNKNOWN`. A 500-iteration hostile fixture now exercises concurrent create and symlink replacement; `RENAME_EXCL`/identity checks prevent replacement of the attacker target, while outside content remains unchanged. `mac_apply_patch` now adds a separate disabled-by-default textual patch path with independent `mac.files.write` + `mac.project.write` scopes, approval/Job/audit binding, expected-base hashing, bounded relative targets, secret denial, identity-bound atomic writes, rollback, and structured readback; focused Broker and filesystem tests pass. Release remains gated by physical remount/durability, prior-worker/process ownership proof, broader partial-mutation coverage, and final readback evidence (`MOP-013, MOP-015, MOP-017, MOP-082, MOP-083`; VT-FS-01, VT-FS-02, VT-APR-01, VT-AUD-01, VT-REL-01).
- `MOP-047` — `IN_PROGRESS` — Implemented a disabled-by-default controlled Git staging/local-commit prototype. Broker admission binds the exact project target, arguments, approval, mutation intent, idempotency key, and generic Job lease; staging accepts only bounded explicit literal paths after canonical/symlink/secret checks, and commit binds an optional staged-diff hash precondition. Fixed `/usr/bin/git` commands disable hooks, fsmonitor, optional locks, signing, and network integrations; no push/reset/remote command surface exists. Staged diff hash, HEAD/parent, index-empty, working-tree, target identity, redaction, and unknown-outcome readbacks are enforced by tests, including a real temporary repository run. Release remains gated by MOP-046 write-gate closure, broader crash/concurrency/remount/actor-attribution coverage, and final readback (VT-GIT-01, VT-REL-01, VT-AUD-01, VT-DOS-01).

## P5 — L3/L4 applications and GUI

- `MOP-050` — `IN_PROGRESS` — Implemented the read-only `mac_app_list` inventory slice, disabled-by-default `mac_app_open` launch and `mac_app_focus` focus slices, the first read-only `mac_ui_observe` Accessibility snapshot boundary, and a disabled-by-default snapshot-bound `mac_ui_action` slice. Inventory/launch/focus use stable `bundle:<bundle_id>` identities; launch and focus require exact target authorization, `trusted_gui` approval, Broker Job leases, fixed `/usr/bin/open -b` or Broker-owned JXA, bounded timeout/output, and launch/focus readback. UI observation requires an independent `mac.ui.observe` scope, `window:bundle:<bundle_id>` target rule, GUI kill-switch coverage, fixed Broker-owned JXA, empty environment, bounded node output, secure-label masking, and opaque window/element references. UI actions require `mac.ui.control`, exact parent app-window authority, a 30-second owner/session-bound snapshot, GUI approval, exact role/label/index matching, and before/after Accessibility reobservation. Document/URL launch, structured automation, typing, and broader GUI actions remain planned or disabled.
- `MOP-051` — `PLANNED` — Implement structured AppleScript/JXA/Shortcuts adapters without raw script input.
- `MOP-052` — `IN_PROGRESS` — Implemented bounded read-only Accessibility-tree observation with permission-denied fail-closed behavior, secure-node masking, redacted labels, and opaque window/element identity derivation. The observation now feeds an owner/session-bound 30-second snapshot registry, and action adapters reobserve exact window/index/role/label identity before completion. Permission-granted real-app evidence remains open.
- `MOP-053` — `IN_PROGRESS` — Implemented disabled-by-default `mac_ui_action` for the fixed allowlist `press`, `select`, `increment`, `decrement`, `show_menu`, and `focus`. It requires a fresh owned snapshot, exact parent app-window authority, `trusted_gui` approval, a Broker Job ID, fixed Broker-owned JXA, stale/sensitive/secure-target denial, and verified post-action reobservation. Credential typing and broader GUI mutation remain blocked by `MOP-054`; real permission-granted, focus-race, and adversarial app evidence remain open.
- `MOP-054` — `IN_PROGRESS` — Added a conservative sensitive UI deny policy for SecurityAgent, Keychain Access, System Settings, loginwindow, security/privacy/password/credential/sign-in window hints and returned titles; secure Accessibility nodes remain masked and labels are redacted. Clipboard, cross-app data, broader credential-surface classification, and permission-granted adversarial evidence remain open.
- `MOP-055` — `PLANNED` — Verify macOS permission-denied, revoked-permission, stale-target, and real-app workflows.

## P6 — L5 privileged helper

- `MOP-060` — `IN_PROGRESS` — Added the proposed separately authenticated helper protocol: owner-only peer-authenticated IPC, HMAC command/response binding, durable request/nonce replay rejection, fixed `service_control`/`package_install`/`power` operation names, Broker argument digests, approval/intent identity, bounded redacted evidence, and fail-closed postcondition validation. Added a Broker-owned factory that signs only matching explicit-approval, intent-linked running Jobs and rechecks target, payload, policy, principal/session, kill switches, and revocation before signing. A dedicated protected `helper_key` manager now binds explicit file/Keychain source, digest, validity, monotonic activation, exact restore, revocation, and disposal before constructing the factory or helper server; both helper HMAC owners defensively wipe key copies and recheck active key authority. Already-constructed factory/server paths now fence helper-key expiry and activation replacement without restart. An independent helper runtime now restores the exact activation, requires native peer identity, rejects Broker/control socket reuse, and owns serialized start/close rollback. A separate root-domain package plan now fixes native-only launchd argv, signature identity, socket separation, Broker peer binding, disabled capabilities, and rollback/readback invariants. Helper startup can derive the caller from the exact Broker LaunchAgent readback and bind native PID/start-time identity; a real macOS cross-process test rejects a spawned caller spoof before request parsing. No helper operation is enabled; signed artifact provenance, real root-domain host evidence, and independent review remain open under ADR-0009 and VT-PRIV-01.
- `MOP-061` — `BLOCKED` — Added a non-executing root-domain helper package plan with native-only argv, exact code-signature identity, root-owned plist actions, protected helper-root/key/socket paths, Broker peer UID/GID binding, and exact upgrade/rollback/uninstall commands plus readback rejection for enabled capabilities. Helper startup now derives the Broker caller from the exact per-user `gui/<uid>/com.mac-operator.broker` LaunchAgent readback and binds PID/start-time identity before constructing the helper. A real macOS temporary bundle smoke test executes the fixed ad-hoc `codesign` verification command and reads back the exact helper identifier; the package also has a double-`lstat` root-owned preflight and a host-only, explicitly confirmed descriptor-relative plist apply/upgrade/rollback/uninstall primitive with identity-bound restoration. A real cross-process native IPC test now proves the bound Broker caller is accepted while a second spawned caller is dropped before parsing, and plist apply verifies the real current process UID before any filesystem access. A host-only dry-run execution contract and gated executor now bind exact service-revision preconditions, fixed command/file order, final readback, and operation-specific recovery steps; non-root callers fail before command or readback access. These do not prove Developer ID provenance, successful root-owned execution, or real root-domain readback. `blocked_by: MOP-003, MOP-081, ADR-0007`; `unblock_condition: runtime, IPC identity, package/signing, launch ownership, and credential-cleanup decisions are accepted`; `expected_evidence: Developer ID signature and provenance, install/upgrade/rollback, helper mismatch, uninstall, caller identity, caller-spoof, and real root-domain readback tests (VT-PRIV-01, VT-OPS-01)`.
- `MOP-062` — `BLOCKED` — Implement approved service control with preconditions and postconditions. `blocked_by: MOP-060, MOP-061`; `unblock_condition: authenticated helper protocol and service allowlist are released`; `expected_evidence: allowlist, precondition, service-state readback, audit, rollback, and bypass tests (VT-PRIV-01)`.
- `MOP-063` — `BLOCKED` — Implement approved package installation with exact identity/version policy. `blocked_by: MOP-060, MOP-061`; `unblock_condition: authenticated helper, package source policy, and version allowlist are released`; `expected_evidence: package identity/version, source, approval, installed-version, rollback, and bypass tests (VT-PRIV-01)`.
- `MOP-064` — `BLOCKED` — Implement reboot/shutdown with explicit policy and verified audit intent. `blocked_by: MOP-060, MOP-061, MOP-082, MOP-083`; `unblock_condition: helper auth, privileged approval, durable audit intent, and handoff semantics are released`; `expected_evidence: accepted/scheduled handoff, policy denial, audit-intent, cancellation/reconciliation, and recovery tests (VT-PRIV-01, VT-AUD-01)`.

## P7 — Hardening and release

- `MOP-070` — `IN_PROGRESS` — Added deterministic bounded security-fuzz regression coverage in `packages/broker/src/security-fuzz.test.ts` for request/guest authentication mutations, replay IDs/nonces, strict extra-field and authority-shaped inputs, traversal/protected-zone paths, secret and prompt-injection-shaped content, output/resource budgets, canonical JSON rejection, deny-overrides-allow, and projected-scope expansion attempts. Commit `d0c96be` adds a 16-seed authority/job state-machine campaign covering independent switches, revocation, cancellation, terminal immutability, revision monotonicity, and restart reconciliation; the full physical-Darwin suite passes 527/527. Broader schema/property fuzzing, long-running campaigns, policy-downgrade exploration, kernel/resource-exhaustion evidence, and independent review remain open.
- `MOP-071` — `IN_PROGRESS` — Verify crash, restart, partial mutation, audit outage, credential rotation, and kill-switch recovery. Audit-anchor outage, stopped-service exact lock recovery, and persisted Broker runtime fencing now have focused persistence/Darwin evidence; crashed-process/old-worker ownership, credential rotation, partial-mutation durability, and installed operator recovery remain open.
- `MOP-072` — `IN_PROGRESS` — Added source-level launchd plist rendering, reviewed Edge/Broker LaunchAgent templates, signal-aware Broker/Edge service lifecycles, bounded startup readback, fixed packaged Broker and HTTPS Edge entrypoints with owner-only root-bound startup configuration, component-specific `buildMacOsEdgeInstallPlan`/`buildMacOsInstallPlan` boundaries and Edge/Broker readback composition, host-only install-plan executors requiring exact operation confirmation and existing-service preconditions, fixed bounded `codesign`/`launchctl` argv, exact previous-revision preconditions, rollback/uninstall actions, post-bootstrap identity validation, double-`lstat` owner/mode/symlink/device/inode checks, and temporary-root-tested descriptor-relative atomic plist install/upgrade/rollback/uninstall. Read-only launchd metadata parsing and an opt-in Darwin smoke of separate real Edge/Broker LaunchAgents now verify exact arguments, Edge TLS readiness, native/status socket ownership, HMAC Broker readback, PID identity, empty capabilities, and post-bootout absence. The Edge entrypoint has local listener readback and remote JWKS configuration, while the uninstall coordinator binds to the real owner-only Authority Control client with authenticated readback and exact Edge revocation. A real macOS temporary ad-hoc artifact smoke test executes the plan's fixed signature verification command. Developer ID signing/notarization, production artifact identity, unattended installer authorization, remote OAuth/JWKS, Keychain ACLs, production upgrade/rollback, observability, retention, and final operator runbooks remain.
- `MOP-073` — `PLANNED` — Perform independent security and architecture review; resolve all reproducible P0/P1 findings.
- `MOP-074` — `PLANNED` — Produce exact-revision release candidate and real-client/real-Mac evidence.

### Privileged helper status addendum (`2240870`, hardened in `86a99ca`)

`MOP-060`/`MOP-061` now include a helper-owned read-only status IPC slice. It
uses a separate HMAC domain, native peer authorization, durable replay
admission, fixed status/readback schemas, socket identity fencing, and active
helper-key authority checks. The status source is explicit and is not exposed
as an MCP tool; no privileged operation or root-domain service is enabled.
Verification: 398 tests (395 passed, 3 opt-in sandbox tests skipped),
typecheck, contract verification, audit, and diff checks pass. Evidence:
`evidence/2026-09-13-privileged-helper-status-ipc.md`.

`MOP-086` host-evidence addendum: source revision `a8d9007` passed the full
`MOPS_REAL_SANDBOX=1 npm test` run at 398/398 and the focused sandbox suite at
9/9 on the Mac mini host. This strengthens, but does not close, the sandbox
gate; real credential/Docker/persistence isolation, remount identity,
owned-group/post-snapshot process ownership, UDP, external allowlisted
networking, and production packaging remain open.

Latest MOP-086 exit-proof addendum: governed tasks now request a final native
descendant snapshot after child close and retain `UNKNOWN_OUTCOME` when the
observer is unavailable, truncated, replaced, or non-empty. The current full
real sandbox/Keychain regression is 475/476 with one explicit skip. This is an
observation guard only; post-snapshot detached descendants, remount identity,
credential-store isolation, and production task enablement remain open.

Latest Virtualization seam addendum: the disabled `VirtualizationTaskRunner`
now requires a digest-bound native guest attestation tied to the immutable
guest identity, resolved sandbox profile, external evidence reference,
guest-private filesystem, profile-bound network, unavailable host credentials,
and guest-owned process tree/policy. Commit `84da3e0` additionally defines a
versioned Ed25519 envelope with startup-trusted key validity/revocation and
freshness checks; a configured runner revalidates the signed claims before
dispatch and recovery. SDK presence, guest-less configuration validation, and
this structural/signature check still do not prove VM boot, entitlement,
credential isolation, or production enablement. Evidence:
`evidence/2026-09-15-virtualization-guest-attestation.md`.

Latest exit-event addendum: strict task proof now begins at child `exit`,
records process-group survival before stream `close`, and performs a second
native descendant sample after one bounded poll interval. A Darwin
fork-and-detach fixture that keeps the output pipe open remains
`UNKNOWN_OUTCOME`; focused process-supervisor tests pass 20/20 and the full
real sandbox/Keychain regression passes 477/478 with one explicit skip. This
closes the close-event reparenting race but not post-window descendants,
remount resistance, credential isolation, or production task enablement.
Evidence:
`evidence/2026-09-14-exit-observation-window.md`.

Latest restart-recovery addendum: when a persisted task root has exited and
its previously observed descendants are gone, the Broker no longer reports
`PROCESS_ABSENT`. A persisted snapshot is not a complete post-exit census, so
descendants created after the last observation could have escaped into another
process group; recovery now remains `UNKNOWN_OUTCOME` with no termination
claim. The Darwin regression and full real sandbox/Keychain run pass 21/21
focused process-supervisor tests and 478/479 tests with one explicit install
skip. Evidence:
`evidence/2026-09-14-restart-descendant-absence.md`.

Latest audit-outage addendum: a held owner-only audit-anchor lock now proves
the post-commit publication failure boundary. The audit append returns
retryable `AUDIT_UNAVAILABLE` after SQLite has committed, the same BrokerStore
freezes further writes, the sidecar remains at its previous tail, and the next
BrokerStore startup rejects the mismatch. The focused persistence suite passes
41/41. Evidence:
`evidence/2026-09-14-audit-anchor-publication-outage.md`.

Latest packaged-startup addendum: the compiled Broker service entrypoint now
requires the owner-controlled audit-anchor path and fixed Keychain
service/account/key-id configuration, loads the HMAC source through the
executable-bound ACL, and verifies the sidecar before readiness. The
service-startup suite passes 3/3. The real temporary LaunchAgent smoke with
`MOPS_REAL_INSTALL=1 MOPS_REAL_KEYCHAIN=1` passes 1/1 and cleans up the exact
temporary Keychain item and both labels. Production Developer ID provisioning,
persistent installation, cross-process locking, and external rollback-
resistant anchoring remain open. Evidence:
`evidence/2026-09-14-packaged-audit-anchor-startup.md`.

Latest audit-lock addendum: `AuditAnchorManager` now holds an owner-only
atomic sibling lock across sidecar read, validation, publication, and
directory `fsync`, then rechecks device/inode identity before release. A
pre-existing lock is never auto-reclaimed and fails closed for authenticated
operator recovery. The focused audit-anchor plus persistence suite passes
44/44. This closes the local sidecar race but leaves stale-lock recovery,
external immutable anchoring, production Keychain rotation, and Developer ID
installation open. Evidence:
`evidence/2026-09-14-audit-anchor-lock.md`.

Audit-lock recovery addendum: `recoverAuditAnchorLock` is now a host-only
stopped-service boundary. It requires the exact owner-only lock device/inode
from operator readback and uses the existing Darwin native descriptor-relative
`unlinkat` + parent `fsync` path with removal readback; startup never applies
age/PID-based cleanup. Focused recovery tests pass 3/3. This remains a
recovery primitive rather than external immutable anchoring or installed
operator authentication. Evidence:
`evidence/2026-09-14-audit-anchor-lock-recovery.md`.

Latest controller-secret-zone addendum: Broker-owned sandbox profiles now
deny `.codex` and `.openai` controller-state directories alongside SSH, cloud,
Docker, browser, Mail, Messages, and Keychain zones. The real
`MOPS_REAL_SANDBOX=1` sandbox/task-runner readback passes 21/21 and confirms
those surfaces are denied without opening contents. This strengthens the
credential-surface boundary but does not prove real credential-content
isolation or production `sandbox-exec` enablement. Evidence:
`evidence/2026-09-14-sandbox-controller-secret-zones.md`.

`MOP-061` signature addendum: source revision `46a3167` requires the exact
helper identifier, Developer ID TeamIdentifier, and CDHash in the root-domain
package plan and final codesign readback. Missing fields fail closed before
filesystem or launchd actions. Developer ID signing/notarization, installation,
live readback, and independent review remain blocked. Evidence:
`evidence/2026-09-13-helper-signature-gate.md`.

`MOP-061` observer addendum: source revision `3b24604` wires the authenticated
helper socket/key status client into the package observer and rejects a missing
runtime source. The integration test completes a real local signed status
exchange through the production-shaped observer. Root installation and live
launchd evidence remain blocked. Evidence:
`evidence/2026-09-13-helper-observer-ipc-integration.md`.

Source revision `a1bd63c` additionally verifies that an already-created
key-manager server rejects status reads immediately after helper-key revocation;
the latest default suite is 400 tests with 397 passed and 3 sandbox tests
skipped.

Source revision `6d6087d` adds the bounded Broker-side client for already-signed
helper commands. It authenticates complete responses and maps transport loss
to retryable `UNKNOWN_OUTCOME`; no privileged adapter or root service is
enabled. Evidence: `evidence/2026-09-13-helper-command-client.md`.

The helper Job executor slice adds a disabled-by-default Broker Job executor above the
client. It renews the Job lease, enforces command-to-Job identity binding,
rechecks authority before/after dispatch, redacts validated helper evidence,
and persists conservative `UNKNOWN_OUTCOME` for unresolved execution. The
executor is not wired to an MCP tool, and helper installation/root launchd
remain blocked. Evidence: `evidence/2026-09-13-helper-job-executor.md`.

The Broker owns the seam through an optional `privilegedHelperExecutor`
dependency and `executePrivilegedHelperJob()`; the default constructor injects
the disabled implementation and performs no privileged dispatch.

The helper command boundary also persists a strict typed payload descriptor and
includes it in the signed envelope. Only Broker-owned service, package, and
power descriptors can cross the helper boundary; raw shell text, executable
paths, environments, credentials, and arbitrary maps remain unrepresentable.
Target, operation, secret-policy, and canonical digest checks run at Job
creation and command validation. This is still disabled and does not unblock
the privileged capability rows.

`MOP-017` process-tree identity addendum: ProcessSupervisor now treats a
changed start-time for an already tracked descendant PID as a target-swap
failure, stops descendant signalling, and preserves unresolved work as
`UNKNOWN`. The deterministic regression is covered; OS PID-reuse timing and
post-snapshot descendant escapes remain open. Evidence:
`evidence/2026-09-14-process-pid-reuse.md`.

## Immediate next steps

1. Close `MOP-080` through `MOP-083` before implementing authority-sensitive handlers.
2. Establish test IDs and automated matrix checks through `MOP-007` and `MOP-085`.
3. Execute `MOP-086` before implementing or enabling `mac_task_run`.
4. Decide `MOP-003` and create the runtime/package baseline.
5. Review the `KB_SYNC.md` writeback manifest before any upstream KB mutation.
6. Implement the local Broker vertical slice before selecting production remote transport.

The Virtualization guest bridge now has a disabled protocol-only seam in
`virtualization-guest-transport.ts`. It is implemented/tested as an
HMAC-authenticated, request/response-bound contract with bounded output and a
BrokerStore-backed replay guard that survives restart. It remains `PLANNED`
for production enablement until a native VM adapter, host/guest credential and
filesystem/network evidence, cancellation/readback proof, and signing are
available. Evidence: `evidence/2026-09-14-virtualization-guest-transport.md`.

Latest guest recovery addendum: commit `c2a7888` adds a separate
HMAC-authenticated status lookup bound to the original task request and a
Broker-owned authority callback. It provides a tested recovery protocol but
now persists the admitted request identity in schema version `7` and
reconciles restart-unknown guest Jobs only through a fresh, authority-checked
status lookup. Only a signed, verified terminal result can close the Job;
unavailable or uncertain status leaves it `UNKNOWN`. This still does not serve
status from a native guest, boot a VM, or enable `mac_task_run`; the capability
remains `PLANNED` for production.

## Definition of Done

A task is `DONE` only when implementation, focused verification, affected regression and security checks, real-Mac evidence where relevant, documentation updates, and final repository readback are complete. Code existence alone is insufficient.

## Related documents

See `EPIC.md`, `ROADMAP.md`, `PROGRESS.md`, `VERIFICATION.md`, and `docs/adr/README.md`.
