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
has been admitted and fails closed when its bounded capacity is exhausted. It
is intentionally process-local. A production bridge must supply a
BrokerStore-backed implementation before restart-safe guest execution is
enabled; this module does not claim durable replay protection by itself.

## Verification

Focused transport tests pass 6/6, covering round-trip authentication,
request tampering, wrong keys, nonce/request-ID replay, response binding,
guest mismatch, proof tampering, freshness, strict envelopes, output limits,
and exclusion of raw host paths/credential-shaped fields.

This evidence does not establish VM boot, entitlement/signing, guest
filesystem or network enforcement, host-credential isolation, process-tree
ownership, cancellation, postcondition readback, durable replay admission, or
production capability enablement. `mac_task_run` remains disabled.
