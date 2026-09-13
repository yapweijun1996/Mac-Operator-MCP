# ADR-0002: Principal Identity and Edge-to-Broker IPC

Status: Proposed
Date: 2026-09-12
Tasks: MOP-011, MOP-012, MOP-081

## Context

The Edge authenticates remote callers, while the Broker owns final host authorization. IPC must preserve a trustworthy principal and prevent forgery, replay, payload substitution, downgrade, and unauthorized Edge replacement.

## Required decision

Define principal ID and issuer, session identity and concurrency, Edge identity, local transport, authentication primitive, key creation/storage/rotation/revocation, canonical payload encoding, signature or MAC, nonce domain and persistence, request-age limit, clock-skew policy, schema negotiation, incompatible-version behavior, and Edge replacement detection.

## Constraints

- Principal and scopes come from validated transport context, not tool arguments.
- The signed/authenticated envelope binds principal, session, Edge identity, tool, contract version, canonical payload digest, request ID, timestamp, nonce, and policy audience.
- Broker checks revocation on admission and immediately before mutation.
- Restart cannot silently reopen accepted nonce or idempotency windows.
- Multiple sessions do not imply shared approval or target authority.

## Candidate mechanisms

Protected Unix-domain socket with OS peer credentials plus application-layer request authentication; or loopback transport with mutually authenticated application credentials. The final choice depends on runtime and packaging evidence.

## Prototype evidence

The current Broker prototype uses an owner-only Unix-domain socket plus HMAC-SHA-256 application authentication. The proof binds a deterministic JSON digest of protocol/contract versions, request ID, tool, arguments, immutable principal/session context, timestamp, nonce, policy audience/version, and Edge authentication key ID. SQLite uniqueness rejects nonce or request-ID reuse across Broker-store restart. Forged scope, changed payload, expired request/session, replay, and revoked-session tests pass.

Broker responses use a separate HMAC domain and bind the request payload digest, Edge key ID, protocol version, and complete result. The Edge checks socket ownership/mode and rejects unsigned, malformed, request-mismatched, or invalidly signed responses. A replaced owner-mode socket with a different key cannot forge success in the integration test.

The Broker also requires a macOS native peer-credential verifier before it reads request bytes. A minimal N-API adapter calls `getpeereid` and `getsockopt(LOCAL_PEERPID)`; Broker-owned configuration can constrain UID, GID, and exact PID. Real-Mac tests verify the observed current-process identity, reject an unlisted PID, and prove a denied connection produces no audit event. The current Node integration isolates access to the accepted socket's private `_handle.fd`; production acceptance requires pinned Node compatibility evidence or replacement with a public/native transport boundary.

The native transport candidate is now implemented at source revision `0cdb8f0`: native code creates and accepts the owner-only non-blocking UDS, performs peer lookup before parsing, and hands the accepted descriptor to Node through the public `Socket({ fd })` constructor. Local Mac mini evidence covers mode `0600`, denied-peer pre-parse behavior, unsafe-parent rejection, and a signed Broker round trip. This remains a candidate rather than a production decision until native module packaging/code signing, Node/runtime version pinning, Edge PID lifecycle binding, protected key distribution, and installed startup readback are complete. The legacy `BrokerIpcServer` compatibility path still uses the private descriptor verifier and must not be selected for production startup.

Revision `6683344` generalizes the candidate transport to the policy-signer and approval operator channels. Their HMAC/signed-command handlers receive only a socket already authorized by the native UID/GID/PID policy, while the old private-handle verifier remains an explicit compatibility path. Production acceptance still requires packaging/signing, Node/runtime pinning, caller PID lifecycle configuration, protected key distribution, and installed startup/readback evidence for all channel families.

Revision `f76e8a0` adds an explicit stronger peer policy containing the accepted
PID's native `startTimeMicros`. The native Broker and compatibility verifier
read the current process identity after peer credentials and reject a reused PID
before constructing a Node socket or parsing request bytes. PID-only policy
remains an explicit compatibility configuration; the installed Edge startup
must capture and configure the stronger identity policy before production
acceptance.

Revision `752f73a` closes the production assembly fallback: the
`createMacOsNativeBrokerRuntime` factory rejects a peer policy without the
stronger identity before constructing the native listener. Lower-level
compatibility constructors remain available for migration and tests, but the
production assembly cannot silently choose PID-only authorization.

Revision `cd84e37` adds a real cross-process Mac test. A separately spawned
Node Edge fixture is captured by PID/start time before the listener starts,
then accepted through the native UDS and reaches the bounded request handler.
This proves the identity binding is not merely same-process self-observation;
installed launchd startup and Edge restart handling remain open.

Revision `9c48359` adds the local Edge lifecycle response. The native listener
checks the captured identity before startup and on a bounded monitor; if the
Edge exits or the PID is replaced, it closes the listener and accepted sockets,
removes the socket path, and invokes the production runtime hook to durably
revoke the exact Edge in the Broker. This rejects new work and lets active
authority polling fail closed, but it does not claim installed launchd startup,
signed caller provenance, or remote revocation propagation.

Revision `f3fc18e` adds the startup capture boundary for an installed Edge
candidate. The Broker may read only an exact per-user `gui/<uid>/com.mac-operator.*`
service through bounded `launchctl print`, require its `running` state, and
capture the returned PID's native start time before constructing the listener.
The identity is then monitored by the native transport and is never accepted
from request arguments or environment variables. This closes the local
startup-assembly ambiguity but not live LaunchAgent installation/readback,
signed package provenance, or protected cross-process key distribution.

An Edge keyring supports overlapping validity windows for rotation. The Ed25519-signed policy separately authorizes exact `(edge_id, key_id, not_before, expires_at)` metadata, while secret bytes come only from protected local key files. A request must pass both signed-policy metadata and local-key validity. Key-specific revocation is persisted and overrides both. Rotation, unknown key, local expiry, signed-policy expiry, and old-key revocation tests pass.

Key-file lifecycle primitives use an owner-only non-symlink directory, exclusive `0600` creation, file and directory fsync, and an expected-digest precondition. Retirement refuses an Edge key until its exact identity is durably revoked, then uses a unique same-directory quarantine rename and unlink. APFS/SSD physical overwrite is outside this guarantee; cross-process delivery should move to an approved Keychain or packaging mechanism before production acceptance.

Revisions `ef5e336`, `44c16ad`, `be02907`, and `26cc667` add Security.framework
generic-password read and provisioning primitives for an exact
`com.mac-operator.*` service/account pair. Reads require a unique 32-byte item
and fail rather than presenting authentication UI to a background Broker.
Provisioning rejects duplicates, returns only a digest, binds
`kSecAttrAccessControl` to `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`,
and disables synchronizable replication. Approval issuer metadata can select
the source only with an explicit `keySource: "keychain"` entry; file-backed
entries remain compatible. These are explicit startup/operator operations, not
MCP capabilities; live-item ACL review, rotation/deletion, Edge-side delivery,
and cross-process distribution remain open.

Revisions `e9dd75e` and `7d91c8f` add the same explicit-source boundary to Edge
authentication-key metadata. The owner-only versioned config accepts either a
protected file source or the non-interactive Keychain source, binds an expected
secret-byte SHA-256 digest, rejects mixed metadata and target swaps, and
requires BrokerStore `edge_key` revocation preflight before building the
keyring. `EdgeAuthenticationKeyManager` persists audited monotonic
revision/digest activation and exact restart restore; overlapping validity
windows are the supported rotation shape. Request-time signed-policy validity
and key-specific revocation remain the final authority. The manager is
startup/configuration code only and does not imply installed hot reload or
cross-process secret distribution. The Edge request factory now provides a
matching protected-file loader bound to the same expected digest. A Keychain
source selected by the Broker still needs an approved Edge-side delivery
mechanism; no environment-variable or MCP-argument fallback is permitted.
The LaunchAgent startup assembly restores that exact active config before
launchd identity capture and native Broker construction, injecting the restored
keyring through a Broker factory; an unactivated or changed config fails before
`launchctl` readback, and a config containing another Edge identity is rejected
for this per-Edge runtime.
The Edge IPC client also checks its owner-only socket parent and revalidates
socket device/inode identity after connect before sending a signed request;
this complements, but does not replace, native peer identity and response HMAC
verification.

This is not an accepted production identity design. Native-module packaging/code identity, stable descriptor access, Edge PID lifecycle, key generation/distribution/secure deletion, signer/operator procedures, session concurrency, canonical JSON compatibility across runtimes, and general database migration/corruption policy remain open. The legacy revocation constraint migration is implemented and tested. Production enablement stays closed.

## Acceptance evidence

Forged peer, copied envelope, changed payload, expired timestamp, repeated nonce, revoked session, concurrent session, restart replay, version mismatch, and replaced-Edge tests must fail safely.
