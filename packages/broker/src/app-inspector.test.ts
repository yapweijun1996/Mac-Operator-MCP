import assert from "node:assert/strict";
import test from "node:test";
import { AppInventoryInspectorImpl, parseAppInventoryResult, validateAppListRequest } from "./app-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

function success(stdout: string): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout,
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: 1,
    processGroupId: 1,
    terminationObserved: true
  };
}

test("app inventory parser filters safely and sorts bundle IDs", () => {
  const result = parseAppInventoryResult(success(JSON.stringify([
    { app_id: "bundle:com.example.Zed", bundle_id: "com.example.Zed", name: "Zed", running: false, version: "1.0" },
    { app_id: "bundle:com.example.A", bundle_id: "com.example.A", name: "A", running: true },
    { app_id: "bundle:com.example.Zed", bundle_id: "com.example.Zed", name: "Zed", running: true, version: "1.0" }
  ])), false, true);
  assert.deepEqual(result.apps, [
    { appId: "bundle:com.example.A", bundleId: "com.example.A", name: "A", running: true },
    { appId: "bundle:com.example.Zed", bundleId: "com.example.Zed", name: "Zed", running: false, version: "1.0" }
  ]);
  assert.deepEqual(parseAppInventoryResult(success(JSON.stringify([
    { app_id: "bundle:com.example.A", bundle_id: "com.example.A", name: "A", running: true },
    { app_id: "bundle:com.example.Zed", bundle_id: "com.example.Zed", name: "Zed", running: false }
  ])), true, false).apps, [
    { appId: "bundle:com.example.A", bundleId: "com.example.A", name: "A", running: true }
  ]);
});

test("app inventory validates filters and rejects malformed metadata", () => {
  assert.doesNotThrow(() => validateAppListRequest(false, true));
  assert.throws(() => validateAppListRequest("yes" as unknown as boolean, true), /boolean/u);
  assert.throws(() => parseAppInventoryResult(success("{}")), /result limit/u);
  assert.throws(() => parseAppInventoryResult(success(JSON.stringify([
    { app_id: "bundle:../bad", bundle_id: "../bad", name: "bad", running: false }
  ]))), /malformed metadata/u);
});

test("app inventory uses a fixed Broker-owned JXA command boundary", async () => {
  let observed: { executable: string; args: readonly string[]; cwd: string; environment?: Readonly<Record<string, string>> } | undefined;
  const inspector = new AppInventoryInspectorImpl({
    run: async (request) => {
      observed = {
        executable: request.executable,
        args: request.args,
        cwd: request.cwd,
        ...(request.environment ? { environment: request.environment } : {})
      };
      return success(JSON.stringify([{ app_id: "bundle:com.example.App", bundle_id: "com.example.App", name: "Example", running: true }]));
    }
  });
  const result = await inspector.list(true, false, { timeoutMs: 5_000, shouldCancel: () => false });
  assert.equal(result.apps.length, 1);
  assert.equal(observed?.executable, "/usr/bin/osascript");
  assert.deepEqual(observed?.args.slice(0, 3), ["-l", "JavaScript", "-e"]);
  assert.match(observed?.args[3] ?? "", /NSWorkspace/u);
  assert.equal(observed?.cwd, "/");
  assert.deepEqual(observed?.environment, {});
});

test("app inventory returns bounded running apps from the real macOS host", async () => {
  const inspector = new AppInventoryInspectorImpl();
  const result = await inspector.list(true, false, { timeoutMs: 5_000, shouldCancel: () => false });
  assert.ok(result.apps.length <= 500);
  assert.equal(result.apps.every((app) => /^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u.test(app.appId)), true);
  assert.equal(result.apps.every((app) => /^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u.test(app.bundleId)), true);
  assert.equal(result.apps.every((app) => app.running), true);
});
