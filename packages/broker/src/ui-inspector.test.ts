import assert from "node:assert/strict";
import test from "node:test";
import { MacUiInspectorImpl, UiSnapshotRegistry, opaqueElementId, opaqueWindowId, parseUiActionResult, parseUiObserveResult, uiActionExecutableForTesting, uiActionScriptForTesting, uiObserveExecutableForTesting, uiObserveScriptForTesting, validateSensitiveUiTarget, validateUiActionRequest, validateUiObserveRequest } from "./ui-inspector.js";
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

test("Accessibility observation denies sensitive applications, hints, and returned window titles", () => {
  assert.throws(() => validateSensitiveUiTarget("bundle:com.apple.SecurityAgent"), /Sensitive application/u);
  assert.throws(() => validateSensitiveUiTarget(appId, "Password"), /Sensitive application/u);
  assert.throws(() => parseUiObserveResult(success(JSON.stringify({
    status: "ok", app_id: "bundle:com.apple.SecurityAgent", window_index: 0, window_title: "Example", focused: false,
    nodes: [], truncated: false
  })), "bundle:com.apple.SecurityAgent", 10), /Sensitive application/u);
  assert.throws(() => parseUiObserveResult(success(JSON.stringify({
    status: "ok", app_id: appId, window_index: 0, window_title: "Sign in", focused: false,
    nodes: [], truncated: false
  })), appId, 10), /Sensitive application/u);
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

test("Accessibility action validates fixed command output and reobserved identity", async () => {
  const windowId = opaqueWindowId(appId, 0, "Example");
  const elementRef = opaqueElementId(windowId, 0, "AXButton", "Save", false);
  const snapshot = {
    elementRef,
    appId,
    windowId,
    windowIndex: 0,
    windowTitle: "Example",
    elementIndex: 0,
    role: "AXButton",
    label: "Save",
    enabled: true,
    focused: false,
    secure: false,
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    observedAtMs: 1_000
  } as const;
  let observed: { executable: string; args: readonly string[]; cwd: string; environment?: Readonly<Record<string, string>>; timeoutMs: number; outputCapBytes: number } | undefined;
  const inspector = new MacUiInspectorImpl({
    run: async (request) => {
      observed = { executable: request.executable, args: request.args, cwd: request.cwd, ...(request.environment ? { environment: request.environment } : {}), timeoutMs: request.timeoutMs, outputCapBytes: request.outputCapBytes };
      return success(JSON.stringify({ status: "ok", app_id: appId, window_index: 0, window_title: "Example", element_index: 0, role: "AXButton", enabled: true, focused: true, secure: false, accepted: true }));
    }
  });
  const result = await inspector.action!({ snapshot, action: "press" }, { timeoutMs: 20_000, shouldCancel: () => false });
  assert.equal(result.verified, true);
  assert.equal(result.reobserved.focused, true);
  assert.equal(observed?.executable, uiActionExecutableForTesting);
  assert.deepEqual(observed?.args.slice(0, 3), ["-l", "JavaScript", "-e"]);
  assert.equal(observed?.args[3], uiActionScriptForTesting);
  assert.deepEqual(observed?.args.slice(-7), [appId, "Example", "0", "0", "AXButton", "Save", "press"]);
  assert.equal(observed?.cwd, "/");
  assert.deepEqual(observed?.environment, {});
  assert.equal(observed?.timeoutMs, 10_000);
  assert.equal(observed?.outputCapBytes, 262_144);
  assert.ok(Buffer.byteLength(uiActionScriptForTesting, "utf8") <= 4_096);
});

test("Accessibility action rejects stale, secure, and malformed targets", () => {
  assert.throws(() => validateUiActionRequest("element:not-a-snapshot", "press"), /opaque Accessibility snapshot/u);
  assert.throws(() => validateUiActionRequest("element:0123456789abcdef0123456789abcdef0123456789abcdef", "type"), /allowlisted Accessibility action/u);
  const windowId = opaqueWindowId(appId, 0, "Example");
  const elementRef = opaqueElementId(windowId, 0, "AXButton", "Save", false);
  const snapshot = {
    elementRef, appId, windowId, windowIndex: 0, windowTitle: "Example", elementIndex: 0,
    role: "AXButton", label: "Save", enabled: true, focused: false, secure: false,
    ownerPrincipalId: "principal-1", ownerSessionId: "session-1", observedAtMs: 1_000
  };
  assert.throws(() => parseUiActionResult(success(JSON.stringify({ status: "ok", app_id: appId, window_index: 1, window_title: "Example", element_index: 0, role: "AXButton", enabled: true, focused: true, secure: false, accepted: true })), snapshot, "press"), /approved snapshot/u);
  const registry = new UiSnapshotRegistry();
  registry.recordObservation({ appId, windowId, windowIndex: 0, windowTitle: "Example", focused: true, nodes: [{ elementRef, role: "AXSecureTextField", enabled: true, focused: true, secure: true }], truncated: false, warnings: [] }, "principal-1", "session-1", 1_000);
  assert.throws(() => registry.resolve(elementRef, "principal-1", "session-1", 1_000), /Secure or redacted/u);
  assert.throws(() => registry.resolve(elementRef, "other", "session-1", 1_000), /not available/u);
  assert.throws(() => registry.resolve(elementRef, "principal-1", "session-1", 31_001), /stale/u);
});
