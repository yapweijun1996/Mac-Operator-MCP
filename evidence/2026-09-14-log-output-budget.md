# Bounded log output evidence

Date: 2026-09-14
Host: Darwin arm64 development Mac
Scope: `mac_log_tail` bounded output and process-result handling

## Evidence

- `node --test packages/broker/dist/log-inspector.test.js` passed 4/4.
- `MOPS_REAL_SANDBOX=1 node --test --test-concurrency=1` over all compiled
  package tests passed 438 tests with zero failures and one explicit skip.
- The real system-source test exercised `/usr/bin/log` on the host; the
  injected boundary test exercised a supervisor-confirmed `OUTPUT_LIMIT`.

## Boundary covered

When the process supervisor terminates a log command after the fixed 512 KiB
output cap and reports `terminationObserved`, the adapter parses only the
captured bounded prefix, applies the normal secret redaction and malformed-line
filters, and returns `truncated: true` with a warning. This keeps the read-only
contract useful without treating incomplete output as complete.

An `UNKNOWN_OUTCOME` result is never parsed as data and maps to a retryable
stable failure. Other process failures remain execution failures.

## Not established

This evidence does not establish production log-source allowlisting beyond the
current `system`/`process/<name>` patterns, audit-store availability, or final
release enablement. The tool remains governed by its existing policy gate.
