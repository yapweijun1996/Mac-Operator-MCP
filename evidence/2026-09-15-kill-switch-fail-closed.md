# Mutation kill-switch fail-closed evidence

Date: 2026-09-15
Source revision: `fe6a187`

The mutation kill-switch boundary now uses a bounded known-read-only tool set.
When `mutations` is disabled, known read-only queued Jobs remain queued; every
other tool, including an unknown future tool name, is cancelled. This prevents
future mutation capabilities from accidentally bypassing the kill switch when
their tool list is not yet added to persistence code. The global switch still
cancels all queued Jobs.

Verification:

```text
npm run build
temporary BrokerStore smoke: read-only Job preserved; known-write and
unknown-future Jobs cancelled
```

The persistence regression includes the same unknown-tool assertion. The
non-overlapping package regression remains 546 total (540 passed, 6 skipped,
0 failed); the long-lived persistence test process was intentionally not
duplicated.
