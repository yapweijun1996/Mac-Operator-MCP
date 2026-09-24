# User-domain LaunchAgent readback rerun

- Date: 2026-09-22
- Host: physical macOS host, owner uid `501`
- Scope: MOP-104 / proposed `mac_service_control`
- Operation: read-only `launchctl print`; no service mutation

## Probe

`npm run probe:user-service-readback` was rerun after the current Broker build.
The probe uses the fixed owner-domain identity `gui/<uid>/com.yapweijun.pm2-health`
and accepts no service id, executable, plist path, shell string, or launchctl
arguments from input.

The observed bounded readback was:

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

The readback confirms the owner domain, LaunchAgent type, exact program and
argument identity, canonical plist path, bounded exit code, and non-truncated
output. macOS reported the service as not running; the shared parser
conservatively normalized it to `stopped`.

## Limits

This is readback evidence only. It does not prove source-revision binding,
approval, rollback, mutation, revocation, or public MCP enablement. No service
was started, stopped, restarted, installed, or removed.
