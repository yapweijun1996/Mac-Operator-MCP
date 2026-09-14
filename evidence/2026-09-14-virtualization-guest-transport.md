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

## Broker Job recovery

After request verification and replay admission, the
`VirtualizationGuestTransportExecutor` reports the admitted request identity to
the Broker. `BrokerStore` persists only the request ID, nonce, request digest,
immutable guest identity, profile/task digests, and bounded timeout/output
budgets in `guest_metadata_json`. Schema version `7` adds this column through a
forward-only migration; no host path, executable, argument, environment,
credential, or raw output is stored.

On startup, `Broker.reconcileRestartedGuestTasks()` selects only
`mac_task_run` Jobs already marked `UNKNOWN` with `BROKER_RESTART` and guest
metadata. It checks the current policy version, enabled tool, global/process
kill switches, principal/session revocation, and exact persisted identity
before invoking the TaskRunner recovery boundary. The recovery boundary sends
a fresh status request bound to the original request identity. A signed,
verified terminal result is redacted and committed with an optimistic Job
revision check; unknown, unavailable, unverified, transport-uncertain, or
concurrent results remain `UNKNOWN`. Successful terminal recovery clears the
guest descriptor, and every attempt has redacted intent/completion audit
evidence.

## Verification

Focused task-runner plus transport tests pass, covering round-trip
authentication,
request tampering, wrong keys, nonce/request-ID replay, response binding,
guest mismatch, proof tampering, freshness, strict envelopes, output limits,
exclusion of raw host paths/credential-shaped fields, durable replay after
restart, bounded exchange, timeout, cancellation, transport loss, digest-only
executor mapping, guest identity mismatch, and unverified-success rejection.
The persistence, Broker, task-runner, and transport suites also cover status
lookup authentication, original-task binding, authority gating, request
admission persistence, restart metadata recovery, verified-terminal-only Job
promotion, and recovery response mapping. The complete
`MOPS_REAL_INSTALL=1 MOPS_REAL_SANDBOX=1 MOPS_REAL_KEYCHAIN=1 npm test`
regression passes 509/509. `npm run typecheck`, `npm run lint`,
`npm run verify:contracts`, `npm audit --omit=dev --audit-level=high`, and
`git diff --check` also pass.

This evidence does not establish VM boot, entitlement/signing, guest
filesystem or network enforcement, host-credential isolation, process-tree
ownership, cancellation, postcondition readback, native guest execution, or
production capability enablement. `mac_task_run` remains disabled.

This does not prove that a native guest can serve status requests, that a VM
image boots with the claimed filesystem, network, credential, and process
isolation, or that production `mac_task_run` enablement is safe. The recovery
implementation is a Broker-side protocol/Job boundary tested with injected
adapters; no native guest server or VM boot evidence exists.
