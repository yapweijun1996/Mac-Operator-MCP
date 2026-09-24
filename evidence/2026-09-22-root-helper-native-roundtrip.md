# Root Helper Native Round-Trip Evidence

Date: 2026-09-22
Host: Darwin arm64 physical Mac, current process UID 501
Status: `implemented` as a disabled native transport candidate with probe-only bounded child execution; production root-helper execution remains unavailable

## Boundary

`packages/broker/native/root_helper_snapshot.cc` now provides a small native
executable candidate for the future root-helper snapshot package. The artifact
is built by `packages/broker/scripts/build-root-helper-snapshot.sh` and is
ad-hoc signed and strict-verified as
`packages/broker/dist/root_helper_snapshot`.

The `--self-test` mode uses a real Darwin `AF_UNIX` `SOCK_STREAM` socketpair. It
sends one bounded `MOPH` frame with one descriptor through `SCM_RIGHTS`, checks
the connected peer uid/gid and macOS `LOCAL_PEERPID` plus `proc_pidinfo`
start-time identity, receives the frame with a single absolute deadline,
rejects framing/truncation ambiguity, applies `FD_CLOEXEC` to the received
descriptor, and verifies the payload and descriptor state before cleanup.

The cross-process `scripts/probe-root-helper-native-auth.mjs` starts the native
candidate with an ephemeral owner-only file-backed key configuration. Native
code validates the canonical protected config/key files, key digest, and
validity window, then receives a signed JSON envelope and two descriptors over
a real Unix socket. After HMAC authentication, native code hashes the received
executable FD, materializes an owner-only private snapshot with `O_EXCL`,
`FD_CLOEXEC`, `fsync`, atomic rename, and post-rename metadata readback, then
removes the snapshot after the request completes. The execution variant loads a
fixed deny-default Seatbelt profile in the forked child, clears inherited
environment state, applies only the authenticated bounded environment, and
directly `execve`s a materialized project-built native helper in the same
PID/process group. It returns a bounded process result with observed exit and
output. A separate authority socket uses an independent key and native
peer/PID verification; native polls bind the signed request digest and verify
the HMAC response before dispatch and before publishing a result. A denied
post-execution poll becomes an authenticated `UNKNOWN_OUTCOME` response. The
native envelope gate also checks freshness, bounded request identity, the
attestation algorithm/validity window/signature encoding, and the payload
digest before descriptor materialization. It then loads a separate protected
owner-only Ed25519 public-key configuration, binds the configured key ID and
digest, canonicalizes the exact unsigned attestation envelope, and verifies
the signature through the macOS Security framework's native EdDSA verifier.
The probe uses a real Node Ed25519 signature, sends an expired envelope and
an HMAC-valid envelope with a mismatched payload digest, and sends an
HMAC-valid envelope signed by the wrong Ed25519 key; the native candidate
rejects all three before descriptor materialization. It also enforces the
same minimum request-id suffix length as the TypeScript contract and the
probe sends a short request-id negative case. The Broker verifier remains
authoritative. The
probe deliberately does not copy or execute an Apple system binary from a
snapshot path. The probe verifies the native HMAC-bound
`POLICY_DENIED` response with the shared TypeScript proof function and repeats
the exchange with a forged request proof. The valid exchange succeeds with
`snapshotMaterialization=verified`,
`execution=bounded_sandbox_child_verified`,
`authority_poll=native_peer_hmac_poll_verified`, and
`authority_revocation=revocation_fail_closed_verified`,
`freshness=stale_request_rejected`,
`attestation_digest=attestation_digest_rejected`,
`attestation_signature=attestation_signature_rejected`,
`request_id=malformed_request_id_rejected`; the forged exchange is
rejected without a response. The key files are disposable probe material and
are not a production key distribution path.

The executable deliberately has no production serve mode. `--self-test` and
the two disposable probe modes are the only accepted invocations; all other
invocations return `POLICY_DENIED`. The probe execution mode does not install a
LaunchDaemon or expose a public task scope.

The Broker-side root-helper capability now has an independent
`supported-production` sandbox gate and bounded sandbox evidence reference.
Generic host evidence cannot satisfy this field, and the probe's deprecated
`sandbox_init` use is deliberately not accepted as production evidence. The
protected runtime factory rejects enabled startup without this gate, while the
current non-root host remains unavailable.
The Broker-side capability also requires an independent native Ed25519
verification evidence reference. The native candidate now has a qualifying
local cryptographic verification probe, but the capability remains fail-closed
until the separate production sandbox, root-domain package, protected public
key configuration, and runtime readback gates are accepted.

## Verification

- `npm run build:native:root-helper-snapshot --workspace @mac-operator/broker` passed.
- The artifact passed ad-hoc `codesign --verify --strict`.
- `npm run probe:root-helper-native` passed with:
  `peerCredentials=verified`, `peerProcessIdentity=verified`,
  `frame=verified`, `fdTransfer=verified`, and `productionServe=disabled`.
- `npm run probe:root-helper-native-auth` passed with
  `request_hmac=authenticated_failure_response_verified` and
  `snapshot_materialization=verified`,
  `native_execution=bounded_sandbox_child_verified`, and
  `authority_poll=native_peer_hmac_poll_verified`,
  `authority_revocation=revocation_fail_closed_verified`,
  `freshness=stale_request_rejected`,
  `attestation_digest=attestation_digest_rejected`,
  `attestation_signature=attestation_signature_rejected`, and
  `request_id=malformed_request_id_rejected`, and
  `forged_hmac=forged_request_rejected`.
- The execution response verified `completed`/`SUCCEEDED`, exit code `0`,
  empty stderr, native self-test output, `terminationObserved=true`, and
  `processGroupId === processId`.
- The authority-loss case verified a second poll denial was returned as an
  authenticated retryable `UNKNOWN_OUTCOME`; no success response was emitted.
- The native probe loaded the key only through a canonical owner-only file
  config, checked its SHA-256 digest and active validity window, and did not
  receive raw key bytes through process arguments.
- The native Ed25519 provider accepted the valid Node-signed attestation and
  rejected an HMAC-valid envelope signed by a different Ed25519 key. The
  public key was loaded from a separate protected configuration; no private
  signing key entered the native process.
- The production invocation remains fail-closed with `POLICY_DENIED`.
- Four concurrent invocations of the native build script passed after the
  artifact publication was changed to compile, ad-hoc sign, and strict-verify
  in unique temporary files before an atomic rename; no temporary build files
  remained. The peer-credential, Virtualization guest, lifecycle, and native
  fault-fixture builders now use the same temporary-output publication pattern.

## Remaining gates

This evidence does not prove protected production key distribution, root-domain
owner enforcement, production child execution/isolation, authority
polling/cancellation integration with the installed Broker, crash/restart
recovery, Developer ID/notarization, LaunchDaemon installation, or public task
enablement. The Seatbelt API used here is the deprecated `sandbox_init` API
solely for a local probe; selecting and evidencing a supported production
sandbox mechanism remains a release gate enforced by the Broker-side capability
and runtime startup checks. The native provider is dynamically resolved and
fails closed when the required Security framework symbols or algorithm are not
available; deployment evidence must still bind the supported macOS version,
signed artifact, protected public-key configuration, and native readback. The
candidate must not be treated as a usable privileged adapter.

## Rollback

Rollback is removal of the native candidate, build script, package scripts,
probe command, tests/evidence references, and generated local artifact. No
LaunchDaemon, socket service, permission, policy, OAuth grant, database, or
credential store was changed.
