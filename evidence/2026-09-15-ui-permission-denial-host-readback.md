# Accessibility Permission-Denial Host Readback

Date: 2026-09-15

Source revision: `960b065`

Host: physical macOS arm64 development host

Command:

```text
node --input-type=module - <<'NODE'
import { MacUiInspectorImpl } from './packages/broker/dist/ui-inspector.js';
const inspector = new MacUiInspectorImpl();
try {
  const result = await inspector.observe('bundle:com.apple.finder', undefined, 20,
    { timeoutMs: 5000, shouldCancel: () => false });
  console.log(JSON.stringify({ ok: true, nodeCount: result.nodes.length }));
} catch (error) {
  console.log(JSON.stringify({ ok: false, errorClass: error?.errorClass,
    message: error?.message }));
}
NODE
```

Observed result:

```text
{"ok":false,"errorClass":"POLICY_DENIED","message":"Accessibility permission is not granted"}
```

The fixed Broker-owned JXA/ProcessSupervisor path failed closed before any UI
nodes, labels, window titles, or other Accessibility content crossed the
boundary. This is permission-denied evidence only; permission-granted real-app
observation, focus races, GUI mutations, and production packaging remain open.
