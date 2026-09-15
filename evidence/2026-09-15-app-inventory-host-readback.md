# App Inventory Host Readback Evidence

Date: 2026-09-15

Source revision: `c4bf986`

Host: physical macOS arm64 development host

Command:

```text
node --test packages/broker/dist/app-inspector.test.js
4 tests, 4 passed, 0 failed, 0 skipped
```

The real-host case returned a bounded running-application inventory using the
fixed Broker-owned JXA adapter. Tests also confirm stable bundle identities,
filter/sort bounds, redaction, malformed-result rejection, and the fixed
`/usr/bin/osascript -l JavaScript` command boundary with empty environment.
No app paths, PIDs, arguments, environments, or GUI mutation were exposed.

This is read-only host evidence. App launch/focus, Accessibility permission and
tree observation, sensitive UI policy, action/type mutation, packaging, and
final GUI release gates remain open.
