# Bounded Git log output evidence

Date: 2026-09-14
Host: Darwin arm64 development Mac
Scope: `mac_git_log` bounded output and process-result handling

## Evidence

- `node --test packages/broker/dist/git-inspector.test.js` passed 17/17.
- The test set includes a real temporary repository stage/commit workflow and
  injected output-limit and termination-identity boundaries.
- `npm run lint` and `git diff --check` passed after the change.

## Boundary covered

The Git log adapter uses NUL-delimited records. When the process supervisor
reports a bounded `OUTPUT_LIMIT` with `terminationObserved`, complete records
from the captured prefix are returned, incomplete trailing data is omitted,
and `truncated: true` plus a fixed warning make the loss explicit. This keeps
the read-only result useful without presenting a partial record as complete.

An output-limit report without observed termination maps to retryable
`UNKNOWN_OUTCOME`; no partial bytes are treated as authoritative in that case.

## Not established

This evidence does not establish production Git capability enablement, remote
repository access, push/reset behavior, or final write-release gates.
