# ChatGPT R1 `mac_system_summary` Acceptance

Date: 2026-09-21
Profile: `R1` (`Mac Operator MCP R1 Read Only`)
Client surface: ChatGPT composer using the connected primary account
Endpoint: `https://mac.yapweijun1996.com/mcp`

## Visible result

ChatGPT executed `mac_system_summary` and displayed the bounded result:

- macOS: Darwin 25.2.0
- Architecture: ARM64
- CPU: 10 cores
- Memory: 16 GB
- Uptime: 12 hours 44 minutes 41 seconds
- Load averages (1/5/15 minutes): 3.75 / 3.50 / 3.45

The response was produced by the R1 app after the owner completed a fresh
OAuth reconnect. No mutation, GUI action, privileged action, or system-content
read was requested.

## Service evidence

The PM2 log recorded the corresponding request sequence without recording
tokens or credentials:

- `/token`: HTTP 200
- `/oauth/status`: HTTP 200
- MCP `tools/call`: HTTP 200
- MCP protocol: `2026-07-28`

Conclusion: the R1 ChatGPT path is operational for `mac_system_summary` with
the bounded read-only contract. This evidence complements the earlier failed
expired-connection attempt recorded in
`evidence/2026-09-21-chatgpt-r1-system-summary-reconnect.md`.
