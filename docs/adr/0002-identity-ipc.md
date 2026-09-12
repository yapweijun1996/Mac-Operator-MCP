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

An Edge keyring supports overlapping validity windows for rotation. The Ed25519-signed policy separately authorizes exact `(edge_id, key_id, not_before, expires_at)` metadata, while secret bytes come only from protected local key files. A request must pass both signed-policy metadata and local-key validity. Key-specific revocation is persisted and overrides both. Rotation, unknown key, local expiry, signed-policy expiry, and old-key revocation tests pass.

Key-file lifecycle primitives use an owner-only non-symlink directory, exclusive `0600` creation, file and directory fsync, and an expected-digest precondition. Retirement refuses an Edge key until its exact identity is durably revoked, then uses a unique same-directory quarantine rename and unlink. APFS/SSD physical overwrite is outside this guarantee; cross-process delivery should move to an approved Keychain or packaging mechanism before production acceptance.

This is not an accepted production identity design. Native-module packaging/code identity, stable descriptor access, Edge PID lifecycle, key generation/distribution/secure deletion, signer/operator procedures, session concurrency, canonical JSON compatibility across runtimes, and general database migration/corruption policy remain open. The legacy revocation constraint migration is implemented and tested. Production enablement stays closed.

## Acceptance evidence

Forged peer, copied envelope, changed payload, expired timestamp, repeated nonce, revoked session, concurrent session, restart replay, version mismatch, and replaced-Edge tests must fail safely.
