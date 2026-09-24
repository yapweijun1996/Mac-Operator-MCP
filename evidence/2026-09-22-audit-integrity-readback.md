# Authenticated Audit Integrity Summary Readback

Date: 2026-09-22

Status: implementation and focused boundary evidence; not external immutable
anchoring or final release acceptance.

## Decision

Host recovery and service-status callers receive only a bounded audit
integrity summary. Raw audit rows and persisted evidence remain inside the
BrokerStore boundary and are not added to the MCP or status response contract.

## Implemented controls

- `BrokerStore.auditIntegrityReadback()` re-verifies the complete SHA-256 audit
  chain before producing a readback.
- When configured, the method also verifies the owner-only keyed audit tail;
  after a publication outage or stale tail it returns `AUDIT_UNAVAILABLE`.
- The `mac-operator-audit-integrity-v1` summary contains only event count, tail
  sequence, tail digest, and keyed-anchor state. It contains no audit evidence,
  request arguments, secret-shaped values, or raw row fields.
- The existing authenticated Broker status IPC validates the exact summary
  shape and binds it to its existing HMAC response proof and native owner-peer
  boundary.
- Service startup wires the summary from the Broker-owned store. It is not
  selectable through MCP arguments or startup configuration.

## Verification

```text
npm run build && node --test --test-timeout=120000 \
  packages/broker/dist/audit-integrity-readback.test.js \
  packages/broker/dist/broker-status-ipc.test.js \
  packages/broker/dist/service-entrypoint.test.js \
  packages/broker/dist/persistence.test.js
```

Result: 70 tests passed, 0 failed, 0 skipped. The focused coverage proves
bounded non-sensitive readback, keyed-tail verification, fail-closed behavior
after a publication outage, exact status-shape validation, and service
readback binding.

## Remaining boundary

This is authenticated local host readback, not an external rollback-resistant
immutable audit anchor. The separate append-only retention guard now rejects
new writes at its event/byte bound without compaction; production export and
retention recovery, installed operator authentication, production Keychain
identity, and final release evidence remain open under `VT-AUD-02`.
