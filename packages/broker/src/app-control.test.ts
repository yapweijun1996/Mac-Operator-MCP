import assert from "node:assert/strict";
import test from "node:test";
import { AppControlInspectorImpl, appOpenExecutableForTesting, validateAppOpenRequest } from "./app-control.js";
import type { SafeAppInventory } from "./app-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

const success: ProcessExecutionResult = {
  state: "completed",
  resultClass: "SUCCEEDED",
  exitCode: 0,
  signal: null,
  stdout: "",
  stderr: "",
  truncated: false,
  durationMs: 1,
  processId: 1,
  processGroupId: 1,
  terminationObserved: true
};

function inventory(apps: SafeAppInventory["apps"]): SafeAppInventory {
  return { apps, warnings: [], truncated: false };
}

test("app open validates stable bundle identity and rejects unscoped targets", () => {
  assert.doesNotThrow(() => validateAppOpenRequest("bundle:com.example.Editor"));
  assert.throws(() => validateAppOpenRequest("com.example.Editor"), /stable bundle identity/u);
  assert.throws(() => validateAppOpenRequest("bundle:../bad"), /stable bundle identity/u);
  assert.throws(() => validateAppOpenRequest("bundle:com.example.Editor", "/tmp/file.txt"), /not enabled/u);
  assert.throws(() => validateAppOpenRequest("bundle:com.example.Editor", undefined, "https://example.test"), /not enabled/u);
});

test("app open uses fixed /usr/bin/open and verifies the running target", async () => {
  const observed: { executable: string; args: readonly string[]; cwd: string; environment?: Readonly<Record<string, string>> } = {
    executable: "",
    args: [],
    cwd: ""
  };
  let inventoryCalls = 0;
  const inspector = new AppControlInspectorImpl(
    {
      async list(runningOnly, includeInstalled) {
        inventoryCalls += 1;
        assert.equal(typeof runningOnly, "boolean");
        assert.equal(typeof includeInstalled, "boolean");
        return inventory(inventoryCalls === 1
          ? [{ appId: "bundle:com.example.Editor", bundleId: "com.example.Editor", name: "Editor", running: false }]
          : [{ appId: "bundle:com.example.Editor", bundleId: "com.example.Editor", name: "Editor", running: true }]);
      }
    },
    {
      async run(request) {
        observed.executable = request.executable;
        observed.args = request.args;
        observed.cwd = request.cwd;
        if (request.environment !== undefined) observed.environment = request.environment;
        return success;
      }
    }
  );
  const result = await inspector.open("bundle:com.example.Editor", undefined, undefined, { timeoutMs: 5_000, shouldCancel: () => false });
  assert.equal(result.state, "launched");
  assert.equal(result.verified, true);
  assert.equal(result.processId, null);
  assert.deepEqual(result.target, { kind: "app", reference: "bundle:com.example.Editor" });
  assert.equal(observed.executable, appOpenExecutableForTesting);
  assert.deepEqual(observed.args, ["-b", "com.example.Editor"]);
  assert.equal(observed.cwd, "/");
  assert.deepEqual(observed.environment, {});
});

test("app open reports already-running without launching a second time", async () => {
  let launchCalls = 0;
  const inspector = new AppControlInspectorImpl(
    {
      async list() {
        return inventory([{ appId: "bundle:com.example.Editor", bundleId: "com.example.Editor", name: "Editor", running: true }]);
      }
    },
    {
      async run() {
        launchCalls += 1;
        return success;
      }
    }
  );
  const result = await inspector.open("bundle:com.example.Editor", undefined, undefined, { timeoutMs: 5_000, shouldCancel: () => false });
  assert.equal(result.state, "already_running");
  assert.equal(launchCalls, 1);
});

test("app open fails closed when the identity is absent from inventory", async () => {
  let launchCalls = 0;
  const inspector = new AppControlInspectorImpl(
    { async list() { return inventory([]); } },
    { async run() { launchCalls += 1; return success; } }
  );
  await assert.rejects(
    inspector.open("bundle:com.example.Missing", undefined, undefined, { timeoutMs: 5_000, shouldCancel: () => false }),
    /not found in the bounded inventory/u
  );
  assert.equal(launchCalls, 0);
});
