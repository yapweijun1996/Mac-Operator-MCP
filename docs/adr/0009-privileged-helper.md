# ADR-0009: Separately Authenticated Privileged Helper Boundary

- Status: Proposed
- Date: 2026-09-13
- Affected tasks: MOP-060, MOP-061, MOP-062, MOP-063, MOP-064
- Verification: VT-PRIV-01, VT-COMP-01

## Decision

Privileged operations must cross a separate helper IPC channel. The unprivileged Broker remains the final authority and sends a Broker-generated, HMAC-authenticated command over an owner-only Unix socket. The helper authenticates the OS peer before parsing, validates a versioned command envelope, admits each request and nonce exactly once through a durable replay ledger, and dispatches only the fixed operation names `service_control`, `package_install`, and `power`. A Broker-owned authority callback is mandatory and is checked before dispatch, during cancellation polling, and before response publication; a revoked or expired active operation cannot be returned as success.

The command carries only the normalized target, the digest of Broker-validated arguments, the active policy version, approval identity, and mutation-intent identity. It never carries shell text, executable paths, arbitrary arguments, filesystem roots, or credential material. Responses are bound to the complete command digest, bounded to flat redacted evidence, and require an allowlisted postcondition status before success is accepted.

Revision `54fe71a` hardens the nested helper boundary: command payloads,
execution results, verification records, evidence, and nested failures must
be plain data records before canonicalization or redaction. This preserves the
allowlisted payload/result contract for direct in-process callers as well as
JSON frames; it does not enable helper installation or privileged execution.

The repository currently provides the protocol, peer/authentication boundary, durable nonce adapter, bounded response validation, explicit handler-map validation, a Broker-owned command factory that binds signed commands to persisted approved running Jobs, and a fail-closed default adapter. No real root process, privileged command, package installer, service mutation, reboot, launchd registration, signing, or production enablement is included.

Revision `ee6d37b` additionally binds the shared contract version into the
HMAC-protected helper command. The parser and Broker factory reject a stale or
mismatched contract before replay admission or dispatch; this improves local
compatibility evidence without accepting the helper or enabling privileged
operations.

Revision `d91d406` adds a dedicated protected helper-key configuration. Exactly
one explicit file or Keychain source is active at a time, secret bytes are
bound to a digest and validity window, `helper_key` revocation is checked
before loading, and BrokerStore records audited monotonic activation with
exact restart restore. The command factory and helper IPC server defensively
copy and wipe HMAC keys; constructed paths recheck key-specific revocation
before issuing or authorizing work. This improves key custody evidence but does not
enable a helper adapter or establish a separate privileged process.

Revision `12a1ac3` adds an independent helper runtime assembly boundary. It
restores the exact activated helper key before construction, requires an
explicit native peer process identity, forbids reuse of the Broker/control
socket paths, and owns serialized start/close rollback. Its default adapter
remains fail-closed; this is lifecycle wiring only and does not launch a root
process or enable a privileged operation.

Revision `e0c1e17` adds a separate, non-executing root-domain package plan. The
plan fixes the system LaunchDaemon identity, native-only argv, exact helper
signature identifier, root-owned plist actions, protected helper-root/key/
socket paths, Broker peer UID/GID binding, and exact rollback/readback
invariants. It rejects capability advertisement and enabled adapters. This is
not installation, signing, caller-provenance approval, or acceptance of a
root process.

Revision `7af182e` adds a caller-capture startup entrypoint. It accepts only
the exact per-user Broker LaunchAgent identity, runs a bounded empty-environment
`launchctl print`, and binds the returned PID to native PID/start-time identity
before helper construction. The helper still refuses to start without that
identity; this is caller-authentication evidence, not installed launchd or
root-domain evidence.

Revision `4bdcf94` adds a real macOS temporary-bundle smoke test for the fixed
ad-hoc `codesign --verify --strict --deep` command and exact helper identifier
readback. It intentionally does not claim Developer ID provenance,
notarization, installation, or root-domain execution.

Revision `7f8f285` adds a read-only helper package filesystem preflight. It
double-checks `lstat` identity, rejects symlinks, foreign ownership, unsafe
modes, unexpected types, and device/inode changes, and requires owner-only
helper-key/plist files plus an owner-executable helper. It remains a preflight
primitive; descriptor-relative installation and real root-domain readback are
not yet enabled.

Revision `72a3284` fences already-constructed helper key owners when the
dedicated key is revoked, its active revision/digest is replaced, or its
validity window expires. The factory checks before issuing; the IPC server
checks before replay admission and authority/dispatch. This remains disabled
helper lifecycle evidence and does not enable privileged operations.

Revision `4afbe75` adds a host-only plist apply primitive for the helper
package. It requires explicit operation confirmation and root ownership,
reuses the descriptor-relative native writer, binds target device/inode
preconditions, and restores content when upgrade/uninstall recovery fails. It
never invokes launchctl; successful root-owned installation and readback remain
open evidence.

Revision `7a4a788` adds a real macOS cross-process caller-spoof test. The test
captures the separately spawned Broker fixture's PID/start-time identity before
constructing the helper listener, confirms that bound caller traffic reaches
the parser, and confirms a second spawned caller is dropped before parsing.
The fixture uses a temporary socket only and does not install launchd or start
a root process.

Revision `c49ff5b` makes host-only plist apply verify the actual current process
UID in addition to the supplied root identity. A non-root caller that forges
`ownerUid: 0` is rejected before filesystem preflight or mutation.

Revision `c8dcb2c` removes caller-supplied filesystem inspector injection from
the helper apply boundary. Host-only helper plist mutation now always uses its
internal root filesystem policy, preventing a caller from swapping the writer
after the real-path preflight.

Revision `3d5d257` adds a dry-run helper package execution contract. It binds
the exact existing source revision and returns fixed install/upgrade/rollback/
uninstall steps plus final readback and operation-specific recovery steps. It
does not execute launchctl or perform root mutation.

Revision `eb9ee6a` adds the gated host executor for that contract. It defaults
to the bounded `ProcessSupervisor`, requires the actual current UID to be root
before command/filesystem/readback access, and performs fixed recovery after a
bootstrap or final-readback failure. Root-domain success remains unverified.

Revision `8fd5814` carries the normalized native helper `ProgramArguments` into
the root-domain LaunchDaemon readback and requires exact array equality with the
planned vector. This closes a substitution gap where a service could retain the
expected label/program while launching with a different argument vector; it
does not claim root-owned installation or live launchd evidence.

Revision `cc103a7` requires every non-uninstall helper readback to carry a
positive launchd PID and a matching native PID/start-time identity. A helper
cannot report readiness from a launchd state string alone, and PID reuse or a
missing native observer identity fails closed. Root-owned installation remains
unverified.

Revision `d3efae1` adds a descriptor-backed helper plist readback. The final
readback must match the exact planned path, rendered byte count, SHA-256, and
device/inode identity; the reader uses the internal protected filesystem
inspector and rejects caller-supplied path or inspector substitution.

Revision `1405b99` adds `composePrivilegedHelperPackageReadback`. The final
helper readback is now constructed only from raw launchd, native process,
descriptor-backed plist, helper-runtime, and signature sources. Exact service
ID, domain, LaunchDaemon type, running state, PID, argv, plist path, and
process-identity checks run before the planned fields are copied into the
validated result.

Revision `56ab0ca` makes the host-only lifecycle executor accept only those raw
sources and call the composition boundary itself. This prevents an executor
caller from bypassing independent source checks with a preassembled readback.

Revision `30b69df` adds an observer boundary that takes two launchd, process,
and plist identity snapshots and rejects replacement during collection before
composition. The boundary is host-only and injectable for tests; it does not
install or enable the helper.

Revision `a3d7765` adds the production-shaped host adapter: bounded
`launchctl print`, native PID/start-time capture, descriptor-backed plist
reading, and strict `codesign` verification/details parsing. Runtime metadata is
still supplied by the helper-owned runtime source and is never inferred from
launchd or request arguments.

Revision `2240870` (hardened in `86a99ca`) adds the helper-owned read-only status IPC. Status requests
use a distinct HMAC domain, strict fields, bounded timestamps, durable replay
admission, and the existing native peer policy. Responses are request-bound
proofs over a fixed runtime readback that requires native transport, a disabled
adapter, canonical distinct sockets, Broker UID/GID, bounded source/contract/
policy metadata, and no enabled capabilities. The host client fences socket
device/inode identity before and after the exchange. Runtime construction
exposes the status source and Broker authority gate, and the active key manager
applies expiry, revocation, and activation-identity fencing to that gate. This
remains read-only contract/test evidence; it does not install or enable the
helper.

Revision `46a3167` makes the root-domain package signature expectation
Developer ID-shaped: the exact helper identifier, ten-character TeamIdentifier,
and CDHash are all mandatory and must match final codesign readback. An ad-hoc
or partially bound artifact therefore fails before filesystem or launchd action.
This is a package gate only; it does not assert that a signed/notarized helper
artifact exists or authorize installation.

Revision `3b24604` wires the authenticated helper status socket/key client into
the production-shaped package observer. The observer now fails closed when no
runtime source is selected, while the callback form remains available only for
controlled host/test adapters. Package readiness still composes helper status
with independent launchd, process, plist, and signature readback sources.
Revision `a1bd63c` verifies that an already-created key-manager server fences
status reads immediately after helper-key revocation.

Revision `6d6087d` adds the Broker-side bounded client for already-signed helper
commands. It authenticates complete responses, fences socket identity, caps
transport, and maps connection loss to retryable `UNKNOWN_OUTCOME`; it cannot
create a command or elevate authority.

The helper Job executor boundary now sits above that client as a separate,
disabled-by-default Broker module. It renews the Job lease, checks the command
binding against the persisted Job, rechecks authority on both sides of the
helper call, and commits success only for a verified completed result. Accepted
but incomplete work, timeout, transport loss, malformed/uncertain execution,
or a post-dispatch authority change is persisted as `UNKNOWN_OUTCOME`. The
executor never owns helper key material; the injected client obtains a
short-lived key buffer and clears it after the bounded exchange. This remains
an integration primitive: `Broker.executePrivilegedHelperJob()` is the only
host seam and the default Broker constructor injects a disabled executor, so
no privileged MCP route or adapter is enabled.

The signed command now contains a Broker-persisted typed payload descriptor,
not only a digest. The descriptor is a strict union for service control,
package installation, and power handoff. Persistence rejects unknown fields,
secret-shaped values, unbounded strings, operation/target mismatches, and a
canonical digest mismatch. Command validation repeats the operation, target,
and digest checks, so a helper handler receives no shell text, executable path,
environment, credential, or arbitrary argument map. The descriptor column is
optional for legacy non-privileged Jobs and has an empty migration default.

Revision `91806ae` adds a reusable Broker-backed authority callback for the
helper IPC server. It resolves the original Request and Job through the
consumed Approval, verifies deterministic command and intent identities, and
rechecks switch, Edge/key, principal/session, approval, and Job cancellation
state on every helper authority poll. This makes the required runtime callback
an explicit implementation boundary; the default helper and policy remain
disabled until production helper provenance, signing, installation, and
adapter evidence are accepted.

Revision `2660bdf`, hardened in `becea16` and `1eea5cb`, and wired in
`d717525`, `b9d038a`, and `2c3e01d`, adds the independent helper-to-Broker authority-polling socket,
wipes copied keys on setup failure, and strictly validates failure bodies. Both peers require explicit
OS-peer authentication, request and
response proofs use direction-separated HMAC domains, and request IDs/nonces
are durably admitted without treating a repeated authority poll as a repeated
helper execution. The Broker endpoint invokes the final persisted authority
gate; the helper client fences socket identity, bounds transport, and clears
its key. Active operations poll before dispatch, during execution, and before
success publication, mapping post-dispatch authority loss to retryable
`UNKNOWN_OUTCOME`. Runtime startup rejects an enabled adapter without this
poller. This remains disabled-by-default implementation evidence, not root
helper release or privilege enablement.

Revision `e786002` adds `createPrivilegedHelperRuntimeFromKeyMaterial` for the
root-helper process. It loads a protected helper key config without opening
`BrokerStore`, performs local validity-window checks, and requires the
separately authenticated Broker authority poller for any enabled adapter.
The earlier BrokerStore-backed runtime factory remains a Broker-side
activation/compatibility path and is not the root-helper boundary. The root
helper still cannot decide revocation, rotation, Request, Approval, Job, or
kill-switch authority locally; those decisions remain on the Broker channel.

Revision `ee2c934` binds the root-domain package plan and helper status
readback to the Broker-owned authority socket. Package validation rejects
socket reuse and rejects placing this endpoint inside the root-owned helper
package; final readback must match the helper, Broker, and authority socket
identities exactly.

Revision `fe9d681` adds a separate readback source for the Broker-owned
authority socket. Host verification requires the expected Broker UID/GID,
owner-only mode, Unix-socket type, and stable device/inode/mode/ownership over
two reads; this endpoint is deliberately excluded from root-owned helper file
preflight.

Revision `a79d813` removes authority-poller injection from the root-helper
key-material factory. If an adapter is enabled, the factory constructs the
authenticated poller itself from the fixed authority socket and native Broker
peer policy; missing authority configuration fails closed. The general runtime
factory retains injection only for Broker-side compatibility and test seams.

Revision `2ce0945` makes helper runtime authority-poller cleanup idempotent
across listener startup failure, failed listener cleanup, close-before-start,
and ordinary close. Test revision `ccb248b` covers the failed-cleanup path.
Once the separately authenticated poller is disposed, the runtime refuses
restart so wiped key material cannot be reused. This preserves fail-closed
lifecycle semantics without changing the helper's disabled default or
enabling any privileged operation.

Revision `4bc0308` makes the no-`BrokerStore` root-helper key loader require an
explicit canonical helper executable path when the configured helper key uses
Keychain. The BrokerStore-backed compatibility loader continues to bind
Keychain access to the Broker executable. Root-helper Keychain access therefore
cannot silently fall back to the generic Node executable identity; omission is
rejected before Keychain access or key loading.

## Consequences and rollback

- A helper implementation cannot be enabled merely by supplying tool arguments; it must provide an explicit operation handler and an accepted isolation/packaging review.
- Replay state is separate from Edge and Broker request replay so a helper socket cannot be reused after restart.
- Helper failure, timeout, cancellation, or unverifiable postcondition must remain a stable failure or `UNKNOWN_OUTCOME`; the Broker must not infer privileged success from connection loss.
- A privileged command cannot be signed from a digest alone: a persisted,
  allowlisted descriptor must match the Job target and canonical payload digest.
- Rollback is to remove the helper channel and revoke the `privileged` kill switch/authority; the MCP Edge has no direct helper route.

## Open evidence

Caller identity provenance, separate helper/root-domain installation, Developer
ID code signing/notarization, approved Keychain ACLs, service/package/power
adapters, crash recovery, real-host caller-spoof/readback tests, and independent
P0/P1 review remain open. This ADR is not an acceptance of privileged capability.
