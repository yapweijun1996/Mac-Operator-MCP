# ADR-0006: Child-Process Sandbox

Status: Proposed
Date: 2026-09-12
Tasks: MOP-086, MOP-043, MOP-045

## Context

`mac_task_run` executes project-controlled code. A named profile limits entry arguments but does not make the repository script trustworthy. The project must prove what macOS can enforce for filesystem, network, environment, process, credential, and persistence isolation.

## Decision rule

No sandbox technology is selected by documentation alone. Complete `SANDBOX_RESEARCH.md`, run real-Mac adversarial PoCs, and record unsupported guarantees. If credential isolation cannot be proven, restrict or remove the affected task capability.

The decision remains open pending that research and evidence; this ADR is not accepted and does not authorize `mac_task_run`.

Initial host evidence is recorded in `SANDBOX_RESEARCH.md` and [`evidence/2026-09-12-sandbox-research.json`](../../evidence/2026-09-12-sandbox-research.json). It demonstrates partial filesystem, symlink, executable-allowlist, and network-deny behavior from deprecated `sandbox-exec`, but also demonstrates inherited environment visibility and that sandbox-only parent termination leaves a child alive. A separate disabled `ProcessSupervisor` prototype proves explicit process-group cleanup in controlled tests, but does not select a production sandbox or authorize `mac_task_run`.

## Candidate areas

Evaluate macOS sandbox profiles and current platform support, dedicated users, containers or lightweight VMs, process wrappers, endpoint/security controls, filesystem ACLs, Keychain access groups, network filtering, and combinations. Do not treat environment filtering alone as credential isolation.

### 2026-09-24 process-boundary candidate review

The latest physical escape changes which candidates are credible:

| Candidate | Documented boundary | Assessment for double-fork/`setsid` |
|---|---|---|
| launchd process-group cleanup | `AbandonProcessGroup=false` kills remaining processes with the job's same process-group ID. | Rejected as sufficient containment: the hostile child creates a new session/process group and is already observed to survive the helper. |
| Endpoint Security | The public event catalogue has `NOTIFY_FORK`; its authorization events include `AUTH_EXEC`, but no `AUTH_FORK`. | Cannot deny a bare fork at the fork boundary. It also requires Apple's Endpoint Security entitlement and a signed system extension; activation can require owner approval. Notifications may help observation but are not containment. |
| Nested Seatbelt | The installed SDK marks `sandbox_init` unsupported/deprecated and says a second profile is ignored when the process is already sandboxed. | Rejected as an App Sandbox helper layering fix. The separate `sandbox-exec` no-fork runner remains experimental and deprecated. |
| One Virtualization guest per task | The host controls VM start/stop and can require the VM to reach `stopped` before completing teardown. | Preferred candidate for arbitrary untrusted code because a stopped guest cannot continue executing descendants. Still unproven on this host: no valid guest has booted and no hostile escape canary has run inside one. |

Keep fixed host operations in explicit Broker adapters. Route untrusted repository
code only through a disposable guest with bounded, staged inputs and outputs;
do not mount host credential areas or give the guest direct network access by
default. A stop timeout, identity mismatch, Broker crash, or uncertain VM state
must remain `UNKNOWN_OUTCOME` and quarantine subsequent task admission. This is
a candidate direction, not an accepted sandbox or a capability enablement.
Evidence and primary sources:
[`process-containment candidate audit`](../../evidence/2026-09-24-process-containment-candidate-audit.md),
[Apple launchd process-group semantics](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5),
[Apple Endpoint Security event catalogue](https://developer.apple.com/documentation/endpointsecurity/es_event_type_t),
[Apple Endpoint Security entitlement](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client),
[Apple System Extensions](https://developer.apple.com/documentation/systemextensions), and
[Apple Virtualization VM stop API](https://developer.apple.com/documentation/virtualization/vzvirtualmachine/stop%28completionhandler%3A%29).

## Acceptance evidence

A hostile fixture must fail to read controller and user credentials, escape allowed roots, reach denied network targets, detach unowned processes, access Docker/root-equivalent interfaces, persist launch items, or survive cancellation. Results must identify exact macOS/hardware/runtime versions.

The Broker admission contract additionally requires a versioned, profile-matched `TaskIsolationProof` that names the exact sandbox mechanism and attests to the sandbox, filesystem, network, credential, and process-tree dimensions. Binding the mechanism prevents evidence from being reused across `sandbox-exec`, App Sandbox, or Virtualization implementations. This gate prevents a runner's generic `available` flag from being treated as proof; it does not accept self-attestation as release evidence, and the default runner remains disabled until host evidence is independently reviewed.

The `TaskRunner` interface also declares its host mechanism. Broker admission
and dispatch require that declaration to match the proof before approval is
consumed or a child process is launched; an absent or mismatched declaration
fails closed.

### 2026-09-23 process-tree evidence update

The physical macOS arm64 double-fork/`setsid` fixture escaped the App Sandbox
helper's observed process group and remained alive after the task returned
`UNKNOWN_OUTCOME`. The probe killed the exact PID/start-time identity only
after the task response, so this is evidence of a containment failure, not a
successful cleanup boundary. The `AppSandboxTaskRunner` therefore remains
staging-only, and its proof records process-tree handling as `observer-only`;
it may not claim that App Sandbox process events own or terminate every task
descendant. The fixture and result are recorded in
[`evidence/2026-09-23-app-sandbox-executor-rerun.md`](../../evidence/2026-09-23-app-sandbox-executor-rerun.md).

Apple documents that child processes inherit their parent's App Sandbox and
recommends XPC services over child processes for privilege separation. That
does not establish task-scoped descendant termination. The experimental
`sandbox-exec` runner has a separate physical no-fork result, but remains
staging-only because the interface is deprecated. Continue toward a
supported OS-enforced task boundary (currently the per-task Virtualization
candidate) and keep public `mac_task_run` disabled until its hostile-descendant
and hard-stop evidence passes on the physical host. Sources:
[Apple App Sandbox inheritance](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html),
[Apple XPC privilege separation guidance](https://developer.apple.com/documentation/security/protecting-user-data-with-app-sandbox).

## Experimental implementation addendum

Commit `41e83c0` implements a narrow `SandboxExecTaskRunner` behind explicit
opt-in and host-evidence gates. It renders deny-default policy from the
resolved `TaskProfile` and delegates bounded execution to `ProcessSupervisor`.
Resolved profiles default to a single-process policy that omits
`process-fork`; an explicit owned process-group policy remains a separate,
unevidenced extension. The runner does not accept raw SBPL, caller-selected
executables, or non-loopback network destinations; loopback allowlists are
rendered as exact `localhost:port` rules.
`TaskIsolationProof` binds the `sandbox-exec` mechanism and process-tree policy
to the resolved profile so proofs cannot be replayed across policy variants or
future isolation runners.
The real-host smoke is recorded in
[`evidence/2026-09-13-sandbox-profile-runner.md`](../../evidence/2026-09-13-sandbox-profile-runner.md)
and remains partial. The runner is not wired into the production Broker
capability state, and this ADR remains proposed.

Commit `17d10e2` adds a shared Broker argument-secret gate before any task
profile or child-process dispatch. Fixed profile arguments, the combined
fixed-plus-requested task arguments, and the final `ProcessSupervisor` spawn
boundary reject credential-bearing option names and known token signatures,
because argv is observable through the host process table. This narrows one
credential-leak path but is not arbitrary secret detection, sandbox isolation,
or evidence that would authorize `mac_task_run`.

The physical Darwin descriptor-exec probe is recorded in
[`evidence/2026-09-15-darwin-descriptor-exec-boundary.md`](../../evidence/2026-09-15-darwin-descriptor-exec-boundary.md).
The installed SDK has no public `fexecve`/`execveat` or executable-file-
descriptor `posix_spawn` operation, and `/dev/fd/N` execution is denied by the
host. Consequently, canonical path revalidation is explicitly a compensating
control rather than atomic executable selection. This ADR must not be accepted
until a supported descriptor primitive or an immutable, code-signed executable
snapshot is proven on the target host.

The runtime native probe is recorded in
[`evidence/2026-09-21-native-descriptor-exec-probe.md`](../../evidence/2026-09-21-native-descriptor-exec-probe.md).
On the current physical host, `fexecve` and `execveat` are absent, so the
probe remains `unproven` and does not alter the existing launch gate. The
additional fixed `O_EXEC` plus `/dev/fd/<fd>` experiment can open the binary
but fails to execute it, so it is not a supported fallback on this host. A
future host where a fixed `/usr/bin/true` probe passes would still require an
independent all-child executable proof, immutable selection proof, and
close-on-exec proof before any task launch could be enabled.

The fixed-adapter path now has a separate `darwin-system-published-executable-v1`
boundary. It permits pathname launch only when the executable and every
canonical ancestor are root-owned, non-symlink, and not group/other writable,
the target has no setuid/setgid bits, and the Broker is unprivileged. This
blocks unprivileged same-user
replacement for Broker-owned fixed commands such as `/bin/launchctl`; it does
not authorize user-owned binaries, repository scripts, or generic
`mac_task_run`. The user-domain service-control candidate may use this path
only with explicit operator acceptance and remains outside public policy. The
descriptor-backed task gate is unchanged.

Commit `b228089` adds a Broker-owned descriptor launcher seam to
`ProcessSupervisor`. Descriptor-required admission now requires both the
attested host capability and a concrete launcher adapter; capability metadata
without the adapter returns `POLICY_DENIED`, and pathname `spawn` is never a
fallback. Commit `537bb37` also validates the native adapter's result as a
ChildProcess-like handle before output capture, process identity observation,
or cleanup. These changes close the latent fallback and malformed-return
boundaries only; they do not provide the native descriptor primitive or change
the disabled `mac_task_run` gate.

Commit `2c2b10d` makes that seam descriptor-bound: after Broker path validation,
the supervisor opens the executable with `O_NOFOLLOW`, rechecks complete
descriptor metadata, and passes only a borrowed FD to the adapter. The adapter
must consume or duplicate the FD before returning and receives no executable
pathname. This removes a pathname-reopen ambiguity but remains a contract
boundary only; native atomic execution, close-on-exec, immutable snapshots,
remount resistance, and production task enablement are still unproven.

Commit `d8f0202` extends the descriptor-bound seam to the working directory:
the supervisor opens and validates both executable and cwd descriptors and
passes neither pathname to the adapter. This removes the corresponding cwd
reopen ambiguity, while native descriptor execution, close-on-exec, immutable
selection, remount resistance, and production task enablement remain unproven.

The task-profile resolver now captures the observed SHA-256 content identity of
each canonical profile-owned executable and carries it into the frozen resolved
process request. A signed profile may additionally declare the expected digest;
the resolver rejects a mismatch before a runner is selected. This strengthens
the future helper/snapshot handoff and closes a profile-to-process identity gap,
but it remains a pathname/content revalidation control rather than atomic
descriptor execution or an immutable snapshot. Evidence:
[`evidence/2026-09-21-task-profile-executable-digest.md`](../../evidence/2026-09-21-task-profile-executable-digest.md).

The disabled-by-default `DescriptorSnapshotRegistry` now provides the next
handoff seam. It retains Broker-opened executable and cwd descriptors behind a
one-shot opaque reference and signs only plan digests plus descriptor identity
digests with a short-lived Ed25519 attestation. The future helper callback sees
borrowed FDs and the attestation, never a pathname, argv, environment, or
filesystem root. Its identity check is deliberately labelled
`revalidation-only`; native immutable selection and close-on-exec remain
separate host capability gates. Evidence:
[`evidence/2026-09-21-descriptor-snapshot-helper-attestation.md`](../../evidence/2026-09-21-descriptor-snapshot-helper-attestation.md).

The native adapter separately self-tests local `SCM_RIGHTS` transfer and
receiving-side `FD_CLOEXEC` setup. The disabled-by-default receiver adds a
bounded one-shot stream frame and authenticates UID/GID/PID plus optional
start-time identity before reading it. This remains a transport and ordering
boundary only; immutable executable selection, production helper packaging, and
actual helper launch remain separate release gates. Evidence:
[`evidence/2026-09-21-native-scm-rights-capability.md`](../../evidence/2026-09-21-native-scm-rights-capability.md).
[`evidence/2026-09-21-native-descriptor-handoff-frame.md`](../../evidence/2026-09-21-native-descriptor-handoff-frame.md).

The Broker now also contains a separate, disabled-by-default root-helper
snapshot adapter and native transport/server seam. It accepts only a complete
host capability proving FD identity, immutable selection, root-owned private
snapshot ownership, close-on-exec, and native peer/HMAC helper authentication.
It verifies the short-lived signed plan's argument/environment digests before
dispatch and passes no executable or cwd pathname. Incomplete evidence,
transport failure, or unobserved termination fails closed; no pathname or
system-published fallback is used. The physical host is non-root, so the
transport probe rejects startup with `POLICY_DENIED`; production helper
installation, immutable launch, and task enablement remain unproven.
Evidence:
[`evidence/2026-09-21-root-helper-snapshot-contract.md`](../../evidence/2026-09-21-root-helper-snapshot-contract.md).
[`evidence/2026-09-21-root-helper-snapshot-transport.md`](../../evidence/2026-09-21-root-helper-snapshot-transport.md).

## App Sandbox candidate boundary

The physical host now has a separately signed App Sandbox probe with the
`com.apple.security.app-sandbox` entitlement. On macOS 26.2 arm64, the probe
successfully writes inside its OS-owned container, is denied a read outside
that container, and its fixed `/usr/bin/touch` child is also denied an outside
write. This is the first current-host evidence for a supported macOS sandbox
mechanism; it does not promote the deprecated `sandbox-exec` runner.

The probe is intentionally not a public task capability. The Broker now has a
disabled-by-default `AppSandboxTaskRunner` seam and a native executor candidate
wired through the startup assembly seam. A physical round-trip proves the
distinct App Sandbox audience, Ed25519 attestation, request/response HMACs,
SCM_RIGHTS handoff, native helper identity, authenticated process events,
fixed `/bin/sh` interpreter selection, script materialization, and container
readback. The helper uses fixed system-published `/usr/bin/touch` from the
script because macOS 26.2 returns `EPERM` for executing a freshly materialized
arbitrary binary from the container. This is a compatibility finding, not a
generic executor claim. The current candidate now materializes authorized
regular files through native root-bound listing/read operations into a private
per-run container, rejects symlinks and unsupported entries under fixed
budgets, passes only the staged cwd descriptor, and transfers helper HMAC/key
configuration through unlinked close-on-exec descriptors. A physical fixture
verifies staged read/write, outside-root read denial, and absence of the old
path-based control files. A production implementation must still resolve the
executable-selection strategy, use a bounded protocol for admission/result/
status recovery, bind the helper identity and signed artifact, and prove
hostile network, credential, persistence, and process-tree behavior. Ad-hoc
signing proves host behavior only; Developer ID, notarization, launch identity,
rollback, and readback remain open.
Evidence:
[`evidence/2026-09-22-app-sandbox-boundary.md`](../../evidence/2026-09-22-app-sandbox-boundary.md).

A separate disabled-by-default `BrokerNetworkProxy` candidate now provides a
loopback-only TCP exchange seam with a digest-bound destination/limit policy,
bounded request and response bytes, cancellation, timeout, and secret-shaped
content rejection. It is intentionally not connected to the App Sandbox task
child or public MCP surface: granting the helper's broad network entitlement
would not prove an allowlist. Positive task networking still requires a
child-facing authenticated protocol and independent host evidence.

Commits `d68176b` and `28007cf` harden the virtualization startup seam's
shutdown recovery: `VirtualizationGuestRuntimeImpl` clears a rejected close
promise and remains retryable when transport, task-runner, or lifecycle
shutdown fails. While an explicit close retry is pending, new start/stop work
is fenced and lifecycle status recovery remains available. The runtime is
marked closed only after all shutdown steps succeed. This prevents an
unconfirmed VM transition from becoming a permanent local terminal state, but
does not provide VM boot or guest isolation evidence and does not authorize
`mac_task_run`.

Commit `5aa7d2e` binds signed guest-attestation lifetime to the configured
Ed25519 key validity window: the assertion cannot be issued before key
activation or expire after key retirement. This is an additional provenance
check only; it does not provide a native attestation producer, protected key
distribution, VM boot/isolation evidence, or authorization for
`mac_task_run`.

Commit `3245482` hardens the guest profile executor shutdown boundary. It
fences new guest work, aborts active adapters, drains all active executions
even when adapter cleanup fails, and permits an explicit retry of the failed
cleanup without reopening execution. This protects lifecycle recovery only; it
does not constitute VM boot, guest isolation, or production task enablement
evidence.

## Virtualization.framework candidate seam

The current Darwin host exposes the `Virtualization.framework` headers and
module through the Command Line Tools macOS 26.2 SDK. This is SDK availability
only; no VM image, guest boot, or isolation guarantee is inferred from it. The
host probe is recorded in
[`evidence/2026-09-14-virtualization-framework-sdk.md`](../../evidence/2026-09-14-virtualization-framework-sdk.md).
The checked-in native Objective-C probe links the framework and constructs a
`VZVirtualMachineConfiguration` without booting a VM; Swift compilation remains
unverified because the installed Command Line Tools compiler reports an
SDK/interface-version mismatch.

The 2026-09-23 physical-host audit confirms framework support only: the
guest-less configuration is intentionally invalid, no VM boot was attempted,
and no local boot image was found. The active Node host is ad-hoc signed with
no entitlements. Apple requires `com.apple.security.virtualization` for VM
creation and guest-specific boot inputs. Since the N-API bridge runs inside its
Node host, any future entitlement belongs on the unprivileged Broker host
executable; it must not be added to the privileged root helper. This is a
boundary decision, not a claim that entitlement validation or guest boot has
passed. Evidence and source links:
[`evidence/2026-09-23-virtualization-host-prerequisites.md`](../../evidence/2026-09-23-virtualization-host-prerequisites.md).

The native VM-creation path now queries the current process's effective
virtualization entitlement through Security.framework before native image
identity inspection and VM configuration. TypeScript performs the same
preflight after its protected image readback and before native creation, and
maps missing/unreadable entitlement to `POLICY_DENIED`; native creation
independently denies bypass attempts. This makes the entitlement a runtime
authorization prerequisite, not a caller-controlled flag. It does not
establish that the shipped Broker signature carries the entitlement, nor does
it constitute a valid-guest boot or isolation result.

This change adds a disabled-by-default `VirtualizationTaskRunner` seam.
It accepts only a native-adapter executor, requires an externally reviewed
guest image SHA-256/runtime identity in `TaskIsolationProof`, compares that
identity again immediately before dispatch, and maps an adapter failure to
retryable `UNKNOWN_OUTCOME`. It never accepts a caller image path and does not
pretend that an injected test executor is production isolation evidence. A
future Swift/native adapter must own VM lifecycle, guest transport, process
limits, credential isolation, and guest postcondition readback before this
runner can be enabled.

The seam also requires a digest-bound `VirtualizationGuestAttestation` from the
native adapter. Its claims are bound to the guest identity, resolved profile,
external evidence reference, guest-private filesystem, profile-bound network,
unavailable host credentials, and guest-owned process tree/policy; the runner checks
the attestation both at construction and immediately before dispatch. This is a
fail-closed adapter contract, not independent host evidence or capability
enablement.

Commit `84da3e0` adds an optional signed-provenance gate around that contract.
`VirtualizationGuestAttestationVerifier` accepts only a startup-trusted Ed25519
key set, binds the key ID, algorithm, validity window, payload digest, and full
claims in one canonical signed envelope, and checks key revocation plus claim
freshness. When configured on `VirtualizationTaskRunner`, the signed envelope
must match the native adapter's digest-bound claims at construction and is
revalidated before dispatch and restart status recovery. This improves
provenance authenticity but does not claim Keychain key distribution, a native
attestation producer, VM boot, guest isolation, or release enablement.

The future native bridge also has a separate authenticated transport contract
in `virtualization-guest-transport.ts`. Domain-separated HMAC proofs bind
requests to a guest identity, profile/task digests, nonce, freshness window,
and bounded budgets; responses bind the complete request digest and carry only
bounded output marked as Broker-redacted. The BrokerStore-backed replay guard
now persists request IDs and nonces across restart; the in-memory guard remains
test-only. `VirtualizationGuestTransportClient` enforces the same admission
before a bounded frame exchange and maps timeout, cancellation, malformed
responses, and transport loss to stable Broker errors. Evidence is recorded in
[`evidence/2026-09-14-virtualization-guest-transport.md`](../../evidence/2026-09-14-virtualization-guest-transport.md).

The client also defines a separate authenticated status lookup for recovery
after transport loss. Each lookup has a fresh replay-protected identity and is
bound to the original task request ID, nonce, digest, and guest identity; a
Broker-owned authority callback is mandatory before sending it. This is a
protocol and adapter boundary only. Broker Job reconciliation, native guest
status serving, VM boot, and independent isolation evidence remain required
before this ADR can be accepted or `mac_task_run` enabled.

The Broker now persists the admitted request identity and bounded guest
descriptor in schema version `7` and exposes a host-startup recovery hook. It
selects only restart-unknown Jobs, rechecks current policy/switch/revocation
authority, and asks the TaskRunner for a fresh status response bound to the
original request. Only an authenticated, signed, verified terminal response
can close the Job; uncertain or unavailable responses remain `UNKNOWN`. This
closes the Broker-side Job boundary but does not provide a native guest status
server or VM isolation evidence.

The 2026-09-15 host probe was rerun on the physical Darwin arm64 host and
returned framework support with the expected invalid guest-less configuration;
it did not boot or fetch a VM. Evidence is recorded in
[`evidence/2026-09-15-virtualization-framework-probe.md`](../../evidence/2026-09-15-virtualization-framework-probe.md).

The Broker now has a separate disabled-by-default Unix-socket channel for a
future native guest adapter. Commits `521eecc` and `4592cad` bind the
startup-owned socket target to owner-only path/device/inode readback, verify
the connected adapter through native UID/GID/PID peer credentials and optional
PID/start-time identity, and parse exactly one bounded length-prefixed frame
only after peer authentication. Timeout, cancellation, output overflow,
trailing data, symlinked targets, and post-send transport loss fail closed or
remain `UNKNOWN_OUTCOME`. Evidence is recorded in
[`evidence/2026-09-15-virtualization-guest-channel.md`](../../evidence/2026-09-15-virtualization-guest-channel.md).
This closes only the Broker-side local channel; it does not provide the native
guest server, VM boot, attestation, isolation evidence, or capability
enablement required to accept this ADR.

The host image preflight is now part of the `VirtualizationTaskRunner` gate.
Commits `846eca5` and `81faff0` require a startup-owned owner-only image,
match its digest/runtime/device/inode/size to the isolation proof and native
executor, and re-hash/recheck it before every dispatch and restart status
lookup. Replacement content is denied before the executor is called. Evidence
is recorded in
[`evidence/2026-09-15-virtualization-guest-image-preflight.md`](../../evidence/2026-09-15-virtualization-guest-image-preflight.md).
Signed guest provenance verification is now implemented in a separate
fail-closed gate, but this still provides no native attestation producer,
Keychain key distribution, VM boot, or guest isolation evidence, so the runner
remains disabled by default.

The host-side trust set is now loaded by the startup-only
`VirtualizationGuestAttestationKeyManager` (commit `73148a6`). Schema version
`8` persists its active payload digest and historical revisions independently
from policy, Edge, authority, and helper keys. Protected public-key files are
opened with `O_NOFOLLOW` after owner/mode/size/device/inode checks and are
Ed25519- and digest-bound; activation, exact restart restore, audited rollback,
and the dedicated `guest_attestation_key` revocation kind are covered by
focused tests. This protects the verification boundary but does not provision
or distribute guest private signing keys and does not change the disabled
runtime/VM release gate.

Revision `d276615` adds a plain-data representation check at the signed guest
attestation verifier boundary. The envelope, claims, and nested guest
identity reject inherited, accessor, hidden, and symbolic values before
canonical digest or Ed25519 verification. This prevents JavaScript object
semantics from changing provenance claims, but it is parser hardening only;
it does not provide a native attestation producer, protect guest private-key
distribution, boot a VM, prove isolation, or enable `mac_task_run`.

Commit `7de8385` adds a separate protected `virtualization_guest.node` native
artifact. Its startup-only N-API entry point revalidates a canonical
owner-only image through a bounded descriptor, binds device/inode/size/SHA-256
identity, and creates a read-only `VZDiskImageStorageDeviceAttachment` with no
network or directory-sharing devices. It reports configuration metadata but
never boots a VM. Focused native tests pass 2/2 and the full physical-Darwin
regression passes 539/539 with 0 skipped tests. This is a native preflight
boundary only; a bootable production image, guest server, signed attestation
producer, isolation proof, and release enablement remain required before this
ADR can be accepted.

Commit `c8a856e` adds `VirtualizationGuestAgent`, a guest-side protocol service
that verifies HMAC/freshness/identity/profile bindings and replay admission,
then signs only request-bound task or status responses under strict frame
budgets. Its executor API carries no host path, raw command, or credential. The
service is ready to be hosted by the native virtio adapter, but it does not
create or boot a VM, install a guest image, or provide independent isolation
evidence; this ADR remains proposed and the production task capability remains
disabled.

## Broker-owned lifecycle boundary

Commit `042517a` adds `VirtualizationGuestVmLifecycle`, a disabled-by-default
state machine that owns the future adapter's start, stop, status, cancellation,
timeout, close, and recovery semantics. Operations are serialized to prevent
lifecycle races; immutable guest identity and boot ID are checked on every
adapter result; and a timeout, cancellation, identity mismatch, or adapter
failure moves the state to `unknown` until a fresh bounded status readback
recovers it. The close path drains an active VM through the guarded stop path
and rejects new work after closure.

Focused lifecycle tests pass 5/5 and the full physical-Darwin regression passes
547/547 with 0 skipped tests. The controller is only a Broker/native-adapter
seam. It does not boot a VM, serve virtio, produce attestation, or provide
independent filesystem, network, credential, or process isolation; this ADR
remains proposed and `mac_task_run` remains disabled. Evidence is recorded in
[`evidence/2026-09-15-virtualization-guest-lifecycle.md`](../../evidence/2026-09-15-virtualization-guest-lifecycle.md).

## Native lifecycle adapter

Commit `40f0461` connects that Broker boundary to a separate Objective-C++
N-API artifact linked against the host `Virtualization.framework`. The
startup-only constructor revalidates the canonical owner-only image and its
device/inode/size/SHA-256 identity, creates a read-only block attachment, and
configures no host network or directory sharing. It adds one virtio-socket
device for the future guest agent, then exposes asynchronous, handle-bound
start/stop/status/close operations. Every start returns an adapter-owned boot
ID; status maps intermediate and framework-error states to `unknown`; close
refuses to discard a machine that is not stopped. The TypeScript adapter
rechecks the image before each operation and does not accept MCP paths or
commands.

The artifact compiles and passes strict local code-signature verification, but
the current host rejects the synthetic configuration before VM creation. The
focused lifecycle/adapter tests pass 9/9 and the full physical-Darwin
regression passes 551/551 with 0 skipped tests. This is an actual native
Virtualization.framework boundary, not VM boot or isolation evidence; a
Developer ID-signed entitled runtime, bootable reviewed image, virtio guest
server, signed attestation producer, and independent isolation proof are still
required before this ADR can be accepted or `mac_task_run` enabled. Evidence:
[`evidence/2026-09-15-virtualization-guest-native-lifecycle.md`](../../evidence/2026-09-15-virtualization-guest-native-lifecycle.md).

Commit `ea85237` closes a timeout-overlap gap in the Broker-owned lifecycle:
when a native start, stop, or status promise outlives its caller-visible
deadline or cancellation, the unresolved operation remains fenced and later
transitions fail closed with retryable `UNKNOWN_OUTCOME` until it settles.
This preserves serialized VM mutation even when an adapter does not honor
`AbortSignal`; it does not turn the timeout into proof of a stopped VM. The
focused lifecycle tests and current physical-Darwin regression are recorded in
[`evidence/2026-09-15-virtualization-guest-lifecycle-timeout-fence.md`](../../evidence/2026-09-15-virtualization-guest-lifecycle-timeout-fence.md).

Commits `e00554c`, `f74e485`, and `a08d2a5` make the image publication boundary
explicit.
The enabled native adapter accepts only a `system-published` image whose
canonical file and every ancestor are root-owned, non-symlink paths with no
group/other write bits; both startup and native paths reject a root Broker, and
the native `ValidateImage` path repeats this check
immediately before pathname attachment. Broker-owned images remain valid for
protocol/test fixtures but fail closed before native loading. This blocks
unprivileged same-user replacement across the framework pathname window,
including writable-grandparent directory renames, while root rotation and the
absence of an atomic descriptor attachment API remain open. The image/native
suites pass 12/12 and the non-overlapping package regression passes 508 total
(502 pass, 6 skipped, 0 fail). Evidence:
[`evidence/2026-09-15-system-published-guest-image.md`](../../evidence/2026-09-15-system-published-guest-image.md).

## Virtio-socket connector

Commit `b8551d6` adds a bounded native `exchangeGuestFrame` operation over
`VZVirtioSocketDevice.connectToPort` and the corresponding
`NativeVirtualizationGuestChannel` adapter. The operation accepts only a
Broker-owned VM handle, a startup-configured guest port, and a bounded frame;
it uses one monotonic connect/write/read deadline, a four-byte length prefix,
strict response and trailing-data checks, SIGPIPE protection, and cleanup for
success, failure, timeout, and callback races. The existing
`VirtualizationGuestTransportClient` remains responsible for HMAC, freshness,
replay admission, request/response binding, redaction, and status recovery.

Focused lifecycle/native/channel tests pass 10/10 and the full physical-Darwin
regression passes 552/552 with 0 skipped tests. The current host rejects the
synthetic VM configuration before creation, so no guest server or connection
was exercised; this is a native framing/connector boundary, not VM boot,
guest isolation, attestation production, or release enablement. Evidence:
[`evidence/2026-09-15-virtualization-guest-virtio-connector.md`](../../evidence/2026-09-15-virtualization-guest-virtio-connector.md).

## Guest profile manifest executor

The Guest-side execution seam now includes a startup-owned
`VirtualizationGuestTaskProfileRegistry` and `VirtualizationGuestProfileExecutor`.
The registry recomputes the canonical profile/task digests shared with the
Broker, rejects shell executables and unsafe environment keys, denies broad
protected roots, rechecks canonical executable/cwd/filesystem targets before
dispatch, and never accepts paths or commands from the authenticated request.
The executor keeps a bounded terminal ledger for fresh status recovery and
maps adapter failures to stable redacted result summaries. A concrete
`VirtualizationGuestProcessExecutor` uses the existing bounded
`ProcessSupervisor`, but remains unavailable until explicit enablement and
independent guest isolation evidence are accepted. This is manifest-binding
and executor semantics evidence only; it does not claim a bootable image,
guest isolation, attestation production, or `mac_task_run` enablement. Evidence:
[`evidence/2026-09-15-virtualization-guest-executor.md`](../../evidence/2026-09-15-virtualization-guest-executor.md).

## App Sandbox Broker network channel candidate

The App Sandbox executor now contains a disabled-by-default, independently
gated network candidate. For a probe-approved allowlist, the Broker creates a
per-run Unix socket channel and passes only one endpoint through the
authenticated descriptor handoff. The native helper gives the fixed `/bin/sh`
child FD 7 plus a run-bound token; the child does not receive a network
entitlement or raw network socket. The Broker validates strict framed JSON,
canonical base64, bounded request/response/timeout budgets, token binding,
single-use request IDs, and the digest-bound loopback destination before
opening the numeric loopback connection.

On the physical macOS 26.2 arm64 host, the positive probe verified the exact
allowlisted fixture response and direct child `/dev/tcp` denial in the same run.
This is transport-boundary evidence only. The helper is ad-hoc signed, the
network evidence gate is not accepted by production startup, and Developer ID,
notarization, installed identity readback, rollback/recovery, and public
`mac_task_run` enablement remain separate release gates. Evidence:
[`evidence/2026-09-22-app-sandbox-network-proxy.md`](../../evidence/2026-09-22-app-sandbox-network-proxy.md).

## Fixed-script Seatbelt rerun

The experimental `SandboxExecTaskRunner` now has a narrow Broker-resolved
script mode. The registry snapshots strict UTF-8 source and its SHA-256; the
runner rechecks the digest and passes source through bounded stdin to
`/bin/sh -s --`, never through argv or a script pathname. On the current
physical host, `/bin/sh` reads the protected `/private/var/select/sh` selector
and dispatches to root-owned `/bin/bash`; the rendered profile permits only
that fixed system implementation while continuing to deny `process-fork`.
A harmless script succeeds and a hostile subshell receives
`fork: Operation not permitted` with no child marker. This strengthens only
the Seatbelt staging evidence. The runner remains staging-only because the
API is deprecated, and it does not repair the App Sandbox double-fork escape
or authorize `mac_task_run`. Evidence:
[`evidence/2026-09-23-seatbelt-script-runner.md`](../../evidence/2026-09-23-seatbelt-script-runner.md).

The expanded physical probe also verified task-root write/read, denial of
sibling-root and synthetic `.env` reads, absence of `HOME` and `SSH_AUTH_SOCK`,
and denial of direct loopback access. The installed SDK header states that
`sandbox_init` is deprecated and ignores a new profile with an error when the
current process is already sandboxed; nested Seatbelt is therefore not a
supported repair for the App Sandbox helper's process boundary. This does not
alter the separate App Sandbox double-fork/`setsid` failure or any release
gate.
