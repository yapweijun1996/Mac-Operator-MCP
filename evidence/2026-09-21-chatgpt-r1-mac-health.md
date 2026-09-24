# ChatGPT R1 `mac_health` Live Acceptance

Date: 2026-09-21
Profile: `R1` owner-only bounded read-only
Application: `Mac Operator MCP R1 Read Only`

## Result

ChatGPT selected the R1 application in a new Work conversation and executed:

`Run mac_health with include_components=false and report only the health summary.`

The visible ChatGPT result was:

`健康状态： Healthy（正常）。`

## Transport evidence

The live PM2 service log recorded the same request path as:

- `/token` completed with HTTP 200.
- `/oauth/status` completed with HTTP 200.
- MCP `tools/call` completed with HTTP 200.
- The `tools/call` used the pinned `2026-07-28` protocol and completed in
  approximately 3.2 seconds.

No bearer token, password, private key, or other secret material is recorded
in this evidence note.

## Acceptance conclusion

The R1 ChatGPT invocation path is operational for the simple `mac_health`
contract. The earlier `mac_capabilities` internal-error result is therefore
not evidence of a general OAuth, grant, discovery, or tool-call transport
failure. It remains a tool-specific compatibility investigation.
