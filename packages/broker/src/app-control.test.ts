import assert from "node:assert/strict";
import test from "node:test";
import { AppControlInspectorImpl, appFocusExecutableForTesting, appFocusScriptForTesting, appOpenExecutableForTesting, parseAppFocusResult, validateAppFocusRequest, validateAppOpenRequest } from "./app-control.js";
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

test("app open applies one global deadline across launch and reobservation", async () => {
  let listCalls = 0;
  const observedTimeouts: number[] = [];
  const inspector = new AppControlInspectorImpl(
    {
      async list(_runningOnly, _includeInstalled, control) {
        listCalls += 1;
        observedTimeouts.push(control.timeoutMs);
        return inventory([{ appId: "bundle:com.example.Editor", bundleId: "com.example.Editor", name: "Editor", running: false }]);
      }
    },
    {
      async run(request) {
        observedTimeouts.push(request.timeoutMs);
        return success;
      }
    }
  );
  await assert.rejects(
    inspector.open("bundle:com.example.Editor", undefined, undefined, { timeoutMs: 25, shouldCancel: () => false }),
    /timed out/u
  );
  assert.ok(listCalls > 1);
  assert.ok(observedTimeouts.every((timeout) => timeout >= 1 && timeout <= 25));
  assert.ok(observedTimeouts.length >= 2);
});

test("app focus validates stable app-window inputs and fixed focus command output", async () => {
  assert.doesNotThrow(() => validateAppFocusRequest("bundle:com.example.Editor", "Main"));
  assert.throws(() => validateAppFocusRequest("com.example.Editor"), /stable bundle identity/u);
  assert.throws(() => validateAppFocusRequest("bundle:com.example.Editor", "bad\nwindow"), /bounded visible text/u);
  const observed: { executable: string; args: readonly string[]; cwd: string; environment?: Readonly<Record<string, string>> } = {
    executable: "", args: [], cwd: ""
  };
  const inspector = new AppControlInspectorImpl({ async list() { return inventory([]); } }, {
    async run(request) {
      observed.executable = request.executable;
      observed.args = request.args;
      observed.cwd = request.cwd;
      if (request.environment !== undefined) observed.environment = request.environment;
      return successWithOutput(JSON.stringify({
        status: "ok", app_id: "bundle:com.example.Editor", window_index: 0,
        window_title: "Main", focused: true
      }));
    }
  });
  const result = await inspector.focus!("bundle:com.example.Editor", "Main", { timeoutMs: 5_000, shouldCancel: () => false });
  assert.equal(result.focused, true);
  assert.equal(result.verified, true);
  assert.match(result.windowId, /^window:[a-f0-9]{48}$/u);
  assert.equal(observed.executable, appFocusExecutableForTesting);
  assert.deepEqual(observed.args.slice(0, 3), ["-l", "JavaScript", "-e"]);
  assert.equal(observed.args[3], appFocusScriptForTesting);
  assert.deepEqual(observed.args.slice(-2), ["bundle:com.example.Editor", "Main"]);
  assert.equal(observed.cwd, "/");
  assert.deepEqual(observed.environment, {});
});

test("app focus rejects unverified, sensitive, and permission-denied outcomes", () => {
  assert.throws(() => parseAppFocusResult(successWithOutput(JSON.stringify({
    status: "ok", app_id: "bundle:com.example.Editor", window_index: 0,
    window_title: "Main", focused: true
  })), "bundle:com.apple.SecurityAgent"), /Sensitive application/u);
  assert.throws(() => parseAppFocusResult(successWithOutput(JSON.stringify({
    status: "ok", app_id: "bundle:com.example.Editor", window_index: 0,
    window_title: "Main", focused: false
  })), "bundle:com.example.Editor"), /malformed metadata/u);
  assert.throws(() => parseAppFocusResult(successWithOutput(JSON.stringify({
    status: "ok", app_id: "bundle:com.example.Editor", window_index: 0,
    window_title: "Password", focused: true
  })), "bundle:com.example.Editor"), /Sensitive application/u);
  assert.throws(() => parseAppFocusResult(successWithOutput(JSON.stringify({ status: "error", error: "accessibility_permission" })), "bundle:com.example.Editor"), /permission is not granted/u);
});

function successWithOutput(stdout: string): ProcessExecutionResult {
  return { ...success, stdout };
}
