import assert from "node:assert/strict";
import test from "node:test";
import { MacUiInspectorImpl, parseUiObserveResult, uiObserveExecutableForTesting, uiObserveScriptForTesting, validateUiObserveRequest } from "./ui-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

const appId = "bundle:com.example.Accessible";

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

test("Accessibility observation parser creates opaque fresh window and element identities", () => {
  const result = parseUiObserveResult(success(JSON.stringify({
    status: "ok",
    app_id: appId,
    window_index: 0,
    window_title: "Example",
    focused: true,
    nodes: [
      { index: 0, role: "AXWindow", label: "Example", enabled: true, focused: true, secure: false },
      { index: 1, role: "AXSecureTextField", label: "should-not-cross", enabled: true, focused: false, secure: true },
      { index: 2, role: "AXButton", label: "API token: sk-test-secret", enabled: true, focused: false, secure: false }
    ],
    truncated: false
  })), appId, 10);
  assert.match(result.windowId, /^window:[a-f0-9]{48}$/u);
  assert.match(result.nodes[0]!.elementRef, /^element:[a-f0-9]{48}$/u);
  assert.equal(result.nodes[1]!.secure, true);
  assert.equal(result.nodes[1]!.label, undefined);
  assert.equal(result.nodes[2]!.label, "API [REDACTED]");
  assert.deepEqual(result.warnings, ["Sensitive Accessibility labels were redacted"]);
});

test("Accessibility observation fails closed for permission, app, and window errors", () => {
  for (const [error, expected] of [
    ["accessibility_permission", "POLICY_DENIED"],
    ["app_not_running", "TARGET_NOT_FOUND"],
    ["window_not_found", "TARGET_NOT_FOUND"]
  ] as const) {
    assert.throws(
      () => parseUiObserveResult(success(JSON.stringify({ status: "error", error })), appId, 10),
      (caught: unknown) => caught instanceof Error && "errorClass" in caught && (caught as { errorClass: string }).errorClass === expected
    );
  }
});

test("Accessibility observation validates identity, hint, and node budgets", () => {
  assert.doesNotThrow(() => validateUiObserveRequest(appId, "Main", 200));
  assert.throws(() => validateUiObserveRequest("bundle:../bad", undefined, 1), /stable bundle identity/u);
  assert.throws(() => validateUiObserveRequest(appId, "bad\nwindow", 1), /bounded visible text/u);
  assert.throws(() => validateUiObserveRequest(appId, undefined, 2_001), /between 1 and 2000/u);
  assert.throws(() => parseUiObserveResult(success(JSON.stringify({
    status: "ok", app_id: appId, window_index: 0, window_title: "x", focused: false,
    nodes: [{ index: 1, role: "AXButton", label: "x", enabled: true, focused: false, secure: false }], truncated: false
  })), appId, 10), /malformed node metadata/u);
});

test("Accessibility observation uses a fixed Broker-owned JXA command boundary", async () => {
  let observed: { executable: string; args: readonly string[]; cwd: string; environment?: Readonly<Record<string, string>>; timeoutMs: number; outputCapBytes: number } | undefined;
  const inspector = new MacUiInspectorImpl({
    run: async (request) => {
      observed = {
        executable: request.executable,
        args: request.args,
        cwd: request.cwd,
        ...(request.environment ? { environment: request.environment } : {}),
        timeoutMs: request.timeoutMs,
        outputCapBytes: request.outputCapBytes
      };
      return success(JSON.stringify({ status: "ok", app_id: appId, window_index: 0, window_title: "Example", focused: true, nodes: [], truncated: false }));
    }
  });
  const result = await inspector.observe(appId, "Example", 25, { timeoutMs: 20_000, shouldCancel: () => false });
  assert.equal(result.focused, true);
  assert.equal(observed?.executable, uiObserveExecutableForTesting);
  assert.deepEqual(observed?.args.slice(0, 3), ["-l", "JavaScript", "-e"]);
  assert.equal(observed?.args[3], uiObserveScriptForTesting);
  assert.deepEqual(observed?.args.slice(-3), [appId, "Example", "25"]);
  assert.equal(observed?.cwd, "/");
  assert.deepEqual(observed?.environment, {});
  assert.equal(observed?.timeoutMs, 10_000);
  assert.equal(observed?.outputCapBytes, 524_288);
});
