# macOS Seatbelt boundary probe

- Date: 2026-09-21
- Host: physical Darwin arm64 Mac mini
- Scope: direct observation of the fixed `sandbox-exec` read/write policy boundary
- Source: [`scripts/probe-sandbox-boundary.mjs`](../scripts/probe-sandbox-boundary.mjs)
- Reproduction: `npm run probe:sandbox`

## Result

The fixed probe created disposable temporary directories and ran only the
absolute `/bin/cat`, `/usr/bin/touch`, and `/usr/bin/sandbox-exec` executables.
It did not read credentials, repository content, or protected system content.

```json
{
  "mechanism": "sandbox-exec-seatbelt-v1",
  "read": { "allowed": true, "denied": true },
  "write": { "allowed": true, "denied": true },
  "raw": {
    "allowedReadExit": 0,
    "deniedReadExit": 1,
    "allowedWriteExit": 0,
    "deniedWriteExit": 1
  }
}
```

The allowed task root was readable and writable. A separate protected root was
denied for both read and write. Temporary directories were removed after the
probe.

## Limit

This is real host evidence for Seatbelt policy behavior only. It does not prove
Broker-owned executable selection, descriptor-backed launch, process-tree
ownership, credential isolation, restart recovery, or production task
enablement. The Broker therefore continues to keep `mac_task_run` disabled
until the independent executable-launch and complete isolation gates pass.
