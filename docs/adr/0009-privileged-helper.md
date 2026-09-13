# ADR-0009: Separately Authenticated Privileged Helper Boundary

- Status: Proposed
- Date: 2026-09-13
- Affected tasks: MOP-060, MOP-061, MOP-062, MOP-063, MOP-064
- Verification: VT-PRIV-01, VT-COMP-01

## Decision

Privileged operations must cross a separate helper IPC channel. The unprivileged Broker remains the final authority and sends a Broker-generated, HMAC-authenticated command over an owner-only Unix socket. The helper authenticates the OS peer before parsing, validates a versioned command envelope, admits each request and nonce exactly once through a durable replay ledger, and dispatches only the fixed operation names `service_control`, `package_install`, and `power`. A Broker-owned authority callback is mandatory and is checked before dispatch, during cancellation polling, and before response publication; a revoked or expired active operation cannot be returned as success.

The command carries only the normalized target, the digest of Broker-validated arguments, the active policy version, approval identity, and mutation-intent identity. It never carries shell text, executable paths, arbitrary arguments, filesystem roots, or credential material. Responses are bound to the complete command digest, bounded to flat redacted evidence, and require an allowlisted postcondition status before success is accepted.

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

## Consequences and rollback

- A helper implementation cannot be enabled merely by supplying tool arguments; it must provide an explicit operation handler and an accepted isolation/packaging review.
- Replay state is separate from Edge and Broker request replay so a helper socket cannot be reused after restart.
- Helper failure, timeout, cancellation, or unverifiable postcondition must remain a stable failure or `UNKNOWN_OUTCOME`; the Broker must not infer privileged success from connection loss.
- Rollback is to remove the helper channel and revoke the `privileged` kill switch/authority; the MCP Edge has no direct helper route.

## Open evidence

Caller identity provenance, separate helper/root-domain installation, Developer
ID code signing/notarization, approved Keychain ACLs, service/package/power
adapters, crash recovery, real-host caller-spoof/readback tests, and independent
P0/P1 review remain open. This ADR is not an acceptance of privileged capability.
