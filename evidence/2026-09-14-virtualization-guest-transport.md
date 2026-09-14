# Virtualization Guest Transport Boundary Evidence

Date: 2026-09-14
Scope: authenticated protocol contract and replay tests only; no VM boot or
production capability enablement

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
test-only. `VirtualizationGuestTransportClient` admits before sending a
bounded JSON frame, enforces a hard response-size limit even when a channel
ignores abort, maps timeout/cancellation/transport loss to stable errors, and
verifies the response against the admitted request.

## Verification

Focused transport tests pass 10/10, covering round-trip authentication,
request tampering, wrong keys, nonce/request-ID replay, response binding,
guest mismatch, proof tampering, freshness, strict envelopes, output limits,
exclusion of raw host paths/credential-shaped fields, and durable replay after
restart, bounded exchange, timeout, cancellation, and transport loss. The
persistence regression plus the transport file passes 53/53 in the focused
combined run.

This evidence does not establish VM boot, entitlement/signing, guest
filesystem or network enforcement, host-credential isolation, process-tree
ownership, cancellation, postcondition readback, native guest execution, or
production capability enablement. `mac_task_run` remains disabled.
