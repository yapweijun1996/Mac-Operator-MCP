# ChatGPT R1 `mac_system_summary` Reconnect Blocker

Date: 2026-09-21
Profile: `R1` owner-only bounded read-only
Application: `Mac Operator MCP R1 Read Only`

## Result

ChatGPT selected the R1 application and accepted the request:

`Run mac_system_summary and report only the bounded system summary.`

Before the tool call, ChatGPT displayed a reconnect prompt stating that the
R1 connection had expired. The request therefore did not produce a visible
`mac_system_summary` result.

## Transport evidence

The live PM2 log recorded token refresh activity, including HTTP 400 responses,
but no MCP `tools/call` for this request. This is a client-side connection
renewal blocker for this test, not evidence of a `mac_system_summary` handler
failure.

No bearer token, password, private key, or other secret material is recorded
in this evidence note.
