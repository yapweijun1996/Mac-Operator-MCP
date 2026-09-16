# Shell-history secret-zone boundary

- Date: 2026-09-16
- Source revision: `8974dcc`
- Scope: Broker filesystem content authorization and bounded log redaction

## Change

The Broker now denies common shell and REPL history files before any content
read. Covered names include Bash, Zsh, Fish, Node, Python, IRB, PostgreSQL,
SQLite, `less`, and `wget` history variants, including the dotted and
undotted names used by their normal macOS/Linux locations.

The same exact basename set is redacted when it appears in a user or root
path in bounded diagnostics. The rule is name-based and does not inspect or
return history contents.

## Verification

The focused `secret-policy` suite passes 9/9. The complete repository
regression passes 876/876 with 14 explicit skips (890 total), and lint/build
pass. The new cases cover Zsh, Fish, and Python history locations plus
redaction of a Zsh history path.

## Limit

This closes the fixed history-name gap only. It does not claim opaque-secret
detection, full credential-store isolation, or production task-runner
enablement; those remain governed by the existing `VT-SEC-01` and sandbox
release gates.
