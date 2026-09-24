# Audit retention boundary evidence

Status: implementation evidence only. This does not close the production
acceptance gate for external immutable anchoring, installed operator
authentication, or protected release material.

## Boundary

`BrokerStore` now applies an append-only audit retention policy with both a
maximum event count and a maximum logical UTF-8 byte count. The default policy
is 100,000 events and 128 MiB of persisted audit text. A caller may provide a
stricter owner-controlled policy, within a bounded implementation maximum.

When either limit would be crossed, the next audit append fails with
`AUDIT_UNAVAILABLE` before the SQLite transaction can commit. Existing rows are
never silently deleted, compacted, or rewritten. On startup, persisted usage
is checked against the selected policy; an over-limit database fails closed.
This preserves the hash chain and makes retention recovery an explicit
operator/export/migration action.

The logical byte count covers every persisted textual audit field, including
redacted evidence and both hash links. It is a bounded storage accounting
measure, not a filesystem quota or an immutable external archive.

## Focused verification

```text
npm run build
node --test packages/broker/dist/audit-write-boundary.test.js
4 passed, 0 failed, 0 skipped
```

The focused tests cover: exact event-cap rejection with restart readback,
rollback-preserving rejection, startup rejection of a database over a newly
selected bound, and single-event byte-cap rejection.

## Remaining acceptance work

- external rollback-resistant immutable anchoring;
- production audit-event export/retention recovery procedure;
- installed operator authentication with a stable native process identity;
- production Keychain identity, Developer ID/notarization, persistent service
  lifecycle, Accessibility, and final owner acceptance evidence.
