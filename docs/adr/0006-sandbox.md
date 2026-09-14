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

## Acceptance evidence

A hostile fixture must fail to read controller and user credentials, escape allowed roots, reach denied network targets, detach unowned processes, access Docker/root-equivalent interfaces, persist launch items, or survive cancellation. Results must identify exact macOS/hardware/runtime versions.

The Broker admission contract additionally requires a versioned, profile-matched `TaskIsolationProof` that names the exact sandbox mechanism and attests to the sandbox, filesystem, network, credential, and process-tree dimensions. Binding the mechanism prevents evidence from being reused across `sandbox-exec`, App Sandbox, or Virtualization implementations. This gate prevents a runner's generic `available` flag from being treated as proof; it does not accept self-attestation as release evidence, and the default runner remains disabled until host evidence is independently reviewed.

The `TaskRunner` interface also declares its host mechanism. Broker admission
and dispatch require that declaration to match the proof before approval is
consumed or a child process is launched; an absent or mismatched declaration
fails closed.

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
