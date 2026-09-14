# Virtualization Guest Transport Boundary Evidence

Date: 2026-09-14
Scope: authenticated protocol contract and Broker-side executor wiring only;
no VM boot or production capability enablement

## Implemented boundary

`packages/broker/src/virtualization-guest-transport.ts` defines a versioned,
domain-separated HMAC-SHA-256 envelope for a future native guest bridge.
Requests bind the request ID, nonce, freshness window, immutable guest image
identity, sandbox profile and task digests, process-tree policy, timeout, and
output cap. They do not carry executable paths, working directories, raw
arguments, credentials, tokens, or arbitrary host paths.

Responses bind the complete request digest, request ID, nonce, guest identity,
bounded redacted output, result class, exit status, duration, and verification
status. Proof comparison is constant-time and all envelopes reject unknown
fields, malformed identities, stale/future timestamps, oversized output, and
wrong keys.

`InMemoryVirtualizationGuestReplayGuard` rejects a request ID or nonce after it
has been admitted and fails closed when its bounded capacity is exhausted. The
production-shaped `BrokerStoreVirtualizationGuestReplayGuard` uses schema
version 6's owner-controlled SQLite ledger and rejects the same request after a
Broker restart. The in-memory implementation remains process-local and is
test-only. The durable ledger is capped at 4,096 live rows and cleans expired
entries before admission; capacity exhaustion fails closed as
`AUDIT_UNAVAILABLE`. `VirtualizationGuestTransportClient` admits before sending a
bounded JSON frame, enforces a hard response-size limit even when a channel
ignores abort, maps timeout/cancellation/transport loss to stable errors, and
verifies the response against the admitted request.

`VirtualizationGuestTransportExecutor` is the Broker-side adapter from that
client to `VirtualizationTaskRunner`. It computes a separate policy digest and
exact-task digest from the already-resolved profile, sends only those digests,
the immutable guest identity, process-tree policy, and bounded timeout/output
budget, and never forwards executable paths, cwd, arguments, environment, or
credentials. It independently validates the response schema and guest
identity and refuses a `SUCCEEDED` result unless the guest reports verified
postcondition status. The executor remains explicitly unavailable unless its
host-evidence gate is set by a reviewed adapter.

The same client now exposes an authenticated status lookup for recovery after
transport loss. Each lookup receives a fresh request ID and nonce, is admitted
through the durable replay guard, and binds the original task request ID,
nonce, and digest. The signed status response repeats those identities and the
guest identity, carries the same bounded/redacted result shape, and is rejected
if any binding or proof changes. The lookup path requires an explicit
Broker-owned authority callback before a frame can leave the Broker; it cannot
be used as an execution or target-granting primitive.

## Verification

Focused task-runner plus transport tests pass 25/25, covering round-trip
authentication,
request tampering, wrong keys, nonce/request-ID replay, response binding,
guest mismatch, proof tampering, freshness, strict envelopes, output limits,
exclusion of raw host paths/credential-shaped fields, durable replay after
restart, bounded exchange, timeout, cancellation, transport loss, digest-only
executor mapping, guest identity mismatch, and unverified-success rejection.
The persistence regression plus the transport file passes 54/54 in the
focused combined run; status lookup authentication, original-task binding,
authority gating, and recovery response mapping are also covered. The complete
`MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
regression passes 506/506.

This evidence does not establish VM boot, entitlement/signing, guest
filesystem or network enforcement, host-credential isolation, process-tree
ownership, cancellation, postcondition readback, native guest execution, or
production capability enablement. `mac_task_run` remains disabled.

This does not yet prove that a native guest can serve status requests, that
Broker Jobs reconcile unknown outcomes through this API, or that a VM image
boots with the claimed filesystem, network, credential, and process isolation.
