# Real Mac user-domain LaunchAgent readback

- Date: 2026-09-21
- Host: physical macOS host, owner uid `501`
- Scope: MOP-104 / proposed `mac_service_control`
- Operation: read-only `launchctl print`; no service mutation

## Probe

`npm run probe:user-service-readback` uses the shared bounded launchd readback
parser and a fixed service identity derived only from the current non-root uid:
`gui/<uid>/com.yapweijun.pm2-health`. It does not accept a service id,
executable, plist path, shell string, or launchctl arguments from input.

The probe returned:

```json
{
  "schemaVersion": "0.1",
  "serviceId": "gui/501/com.yapweijun.pm2-health",
  "domain": "gui/501",
  "label": "com.yapweijun.pm2-health",
  "type": "LaunchAgent",
  "state": "stopped",
  "pid": null,
  "program": "/Users/yapweijun/.local/share/yap-runtime/node-v24.20.0-darwin-arm64/bin/node",
  "arguments": [
    "/Users/yapweijun/.local/share/yap-runtime/node-v24.20.0-darwin-arm64/bin/node",
    "/Users/yapweijun/Library/Application Support/cloudflare-tunnel-server/bin/pm2-health-check.js"
  ],
  "plistPath": "/Users/yapweijun/Library/LaunchAgents/com.yapweijun.pm2-health.plist",
  "lastExitCode": 0,
  "truncated": false
}
```

macOS printed the native state as `not running`; the shared parser normalized it
to the conservative stable state `stopped`. The readback confirms the requested
user domain, LaunchAgent type, exact program/argument identity, canonical plist
path, bounded exit code, and non-truncated output.

## Limits

This is readback evidence only. It does not prove source-revision binding,
approval, rollback, permission-failure handling, descriptor-backed mutation, or
public MCP enablement. The observed agent is not the Mac Operator service and
was not started, stopped, or restarted by the probe.
