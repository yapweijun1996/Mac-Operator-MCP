import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { assertRetainedUiTargetMatches, MacUiInspectorImpl, UiSnapshotRegistry, guiVisionExecutableForTesting, opaqueElementId, opaqueWindowId, parseUiActionResult, parseUiObserveResult, parseUiScreenshotResult, parseUiTypeResult, uiActionExecutableForTesting, uiActionScriptForTesting, uiObserveExecutableForTesting, uiObserveScriptForTesting, uiTypeExecutableForTesting, uiTypeScriptForTesting, validateSensitiveUiTarget, validateUiActionRequest, validateUiObserveRequest, validateUiTypeRequest, validateUiVisualActionRequest } from "./ui-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

const appId = "bundle:com.example.Accessible";
const nativeIdentity = "485:1790918400000:46";

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
    ["app_not_frontmost", "PRECONDITION_FAILED"],
    ["window_not_found", "TARGET_NOT_FOUND"]
  ] as const) {
    assert.throws(
      () => parseUiObserveResult(success(JSON.stringify({ status: "error", error })), appId, 10),
      (caught: unknown) => caught instanceof Error && "errorClass" in caught && (caught as { errorClass: string }).errorClass === expected
    );
  }
});

test("native observation reports unavailable helper instead of an Accessibility denial", () => {
  const failed = { ...success(""), state: "failed" as const, resultClass: "EXECUTION_FAILED" as const,
    exitCode: 71, stderr: "Accessibility debug text with private window data" };
  assert.throws(() => parseUiObserveResult(failed, appId, 10, true),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED" &&
      error.message.startsWith("GUI_HELPER_UNAVAILABLE:") && !/Accessibility|private window/iu.test(error.message));
  assert.throws(() => parseUiObserveResult({ ...failed, exitCode: 74 }, appId, 10, true),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED" &&
      error.message.startsWith("GUI_LAUNCHER_TRANSPORT_FAILED:"));
  // Legacy osascript adapters retain their permission diagnostic compatibility.
  assert.throws(() => parseUiObserveResult({ ...failed, exitCode: 1 }, appId, 10),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED");
});

test("native observation preserves explicit Accessibility permission denial", () => {
  assert.throws(() => parseUiObserveResult(success(JSON.stringify({ status: "error", error: "accessibility_permission" })), appId, 10, true),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED" &&
      error.message.startsWith("ACCESSIBILITY_PERMISSION_REQUIRED:"));
});

test("capture_mode none observes bounded browser AX nodes without requiring Screen Recording", async () => {
  const requests: string[][] = [];
  const inspector = new MacUiInspectorImpl({ run: async request => {
    requests.push([...request.args]);
    assert.equal(request.args[0], "inspect");
    return success(JSON.stringify({ status: "ok", app_id: "bundle:com.google.Chrome", window_index: 0,
      window_identity: nativeIdentity, window_title: "Example Domain", focused: true,
      nodes: [{ index: 0, role: "AXButton", label: "Reload", enabled: true, focused: false, secure: false }], truncated: false }));
  } });
  const observed = await inspector.observe("bundle:com.google.Chrome", undefined, 10,
    { timeoutMs: 10_000, shouldCancel: () => false }, "none");
  assert.equal(observed.nativeWindowIdentity, nativeIdentity);
  assert.equal(observed.nodes.length, 1);
  assert.equal(observed.screenshot, undefined);
  assert.deepEqual(requests, [["inspect", "accessibility", "com.google.Chrome", "", "10"]]);
});

test("active_window observation independently diagnoses Screen Recording permission denial", async () => {
  const requests: string[][] = [];
  const inspector = new MacUiInspectorImpl({ run: async request => {
    requests.push([...request.args]);
    return success(JSON.stringify(request.args[0] === "inspect" ? {
      status: "ok", app_id: "bundle:com.google.Chrome", window_index: 0, window_identity: nativeIdentity,
      window_title: "Example Domain", focused: true, nodes: [], truncated: false
    } : { status: "error", error: "screen_recording_permission" }));
  } });
  await assert.rejects(inspector.observe("bundle:com.google.Chrome", undefined, 10,
    { timeoutMs: 10_000, shouldCancel: () => false }, "active_window"),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED" &&
      error.message.startsWith("SCREEN_RECORDING_PERMISSION_REQUIRED:") && !/Accessibility/iu.test(error.message));
  assert.deepEqual(requests, [["inspect", "visual", "com.google.Chrome", "", "10"],
    ["capture", "active_window", "com.google.Chrome", "Example Domain", nativeIdentity]]);
});

test("active_window screenshot classifies a production launcher identity failure", () => {
  const observed = parseUiObserveResult(success(JSON.stringify({ status: "ok", app_id: appId,
    window_index: 0, window_identity: nativeIdentity, window_title: "Example", focused: true, nodes: [], truncated: false })), appId, 10, true);
  assert.throws(() => parseUiScreenshotResult({ ...success(""), state: "failed", resultClass: "EXECUTION_FAILED", exitCode: 71 }, observed, "active_window"),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED" &&
      error.message.startsWith("GUI_HELPER_UNAVAILABLE:"));
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

test("Accessibility result validation rejects unstable authority fields", () => {
  const validObservation = {
    status: "ok",
    app_id: appId,
    window_index: 0,
    window_title: "Example",
    focused: false,
    nodes: [{ index: 0, role: "AXButton", label: "Save", enabled: true, focused: false, secure: false }],
    truncated: false
  };
  assert.throws(
    () => parseUiObserveResult(success(JSON.stringify({ ...validObservation, extra: "authority" })), appId, 10),
    /malformed metadata/u
  );
  assert.throws(
    () => parseUiObserveResult(success(JSON.stringify({
      ...validObservation,
      nodes: [{ ...validObservation.nodes[0], extra: "authority" }]
    })), appId, 10),
    /malformed node metadata/u
  );

  const validAction = {
    status: "ok",
    app_id: appId,
    window_index: 0,
    window_title: "Example",
    element_index: 0,
    role: "AXButton",
    enabled: true,
    focused: false,
    secure: false,
    accepted: true
  };
  const windowId = opaqueWindowId(appId, 0, "Example");
  const snapshot = {
    elementRef: opaqueElementId(windowId, 0, "AXButton", "Save", false),
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
  assert.throws(
    () => parseUiActionResult(success(JSON.stringify({ ...validAction, extra: "authority" })), snapshot, "press"),
    /malformed metadata/u
  );
  assert.throws(
    () => parseUiActionResult(success(JSON.stringify({ status: "error", error: "stale_target", extra: true })), snapshot, "press"),
    /malformed metadata/u
  );
});

test("Accessibility observation without screenshots uses the fixed TCC application boundary", async () => {
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
      return success(JSON.stringify({ status: "ok", app_id: appId, window_index: 0, window_identity: nativeIdentity, window_title: "Example", focused: true, nodes: [], truncated: false }));
    }
  });
  const result = await inspector.observe(appId, "Example", 25, { timeoutMs: 20_000, shouldCancel: () => false });
  assert.equal(result.focused, true);
  assert.equal(observed?.executable, guiVisionExecutableForTesting);
  assert.deepEqual(observed?.args, ["inspect", "accessibility", appId.slice(7), "Example", "25"]);
  assert.equal(result.nativeVisual, true);
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
      return success(JSON.stringify({ status: "ok", app_id: appId, window_index: 0, ...(request.executable === guiVisionExecutableForTesting ? { window_identity: nativeIdentity } : {}), window_title: "Example", element_index: 0, role: "AXButton", enabled: true, focused: true, secure: false, accepted: true }));
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
  observed = undefined;
  const nativeWindowId = opaqueWindowId(appId, 0, "Example", nativeIdentity);
  const native = { ...snapshot, nativeVisual: true, nativeWindowIdentity: nativeIdentity, windowId: nativeWindowId,
    elementRef: opaqueElementId(nativeWindowId, 0, snapshot.role, snapshot.label, false) };
  await inspector.action!({ snapshot: native, action: "focus" }, { timeoutMs: 20_000, shouldCancel: () => false });
  const nativeCommand = observed as { executable: string; args: readonly string[] } | undefined;
  assert.equal(nativeCommand?.executable, guiVisionExecutableForTesting);
  assert.deepEqual(nativeCommand?.args, ["ax_action", "accessibility", appId.slice(7), "Example", "0", "AXButton", "Save", "focus", nativeIdentity]);
  observed = undefined;
  await assert.rejects(inspector.action!({ snapshot: { ...native, secure: true }, action: "focus" },
    { timeoutMs: 20_000, shouldCancel: () => false }), /Secure or redacted/u);
  assert.equal(observed, undefined, "Secure AX targets must be rejected before native dispatch");
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

test("Accessibility type keeps bounded input off argv and verifies the focused postcondition", async () => {
  const windowId = opaqueWindowId(appId, 0, "Example");
  const elementRef = opaqueElementId(windowId, 0, "AXTextField", "Name", false);
  const snapshot = {
    elementRef, appId, windowId, windowIndex: 0, windowTitle: "Example", elementIndex: 0,
    role: "AXTextField", label: "Name", enabled: true, focused: false, secure: false,
    ownerPrincipalId: "principal-1", ownerSessionId: "session-1", observedAtMs: 1_000
  } as const;
  let observed: { executable: string; args: readonly string[]; stdin?: string; cwd: string } | undefined;
  const inspector = new MacUiInspectorImpl({
    run: async (request) => {
      observed = { executable: request.executable, args: request.args, ...(request.stdin !== undefined ? { stdin: request.stdin } : {}), cwd: request.cwd };
      return success(JSON.stringify({ status: "ok", app_id: appId, window_index: 0, window_title: "Example", element_index: 0, role: "AXTextField", characters_accepted: 5, keys_accepted: ["TAB"], submitted: false, focus_confirmed: true, secure: false }));
    }
  });
  const result = await inspector.type!({ snapshot, text: "Alice", keys: ["TAB"], submit: false }, { timeoutMs: 20_000, shouldCancel: () => false });
  assert.equal(result.verified, true);
  assert.equal(result.charactersAccepted, 5);
  assert.deepEqual(result.keysAccepted, ["TAB"]);
  assert.equal(observed?.executable, uiTypeExecutableForTesting);
  assert.deepEqual(observed?.args.slice(-6), [appId, "Example", "0", "0", "AXTextField", "Name"]);
  assert.equal(observed?.args.includes("Alice"), false);
  assert.equal(observed?.stdin, '{"keys":["TAB"],"submit":false,"text":"Alice"}');
  assert.equal(observed?.cwd, "/");
  assert.ok(Buffer.byteLength(uiTypeScriptForTesting, "utf8") <= 8_192);
});

test("Accessibility type rejects secret-like text, secure snapshots, and postcondition drift", () => {
  const elementRef = "element:0123456789abcdef0123456789abcdef0123456789abcdef";
  assert.throws(() => validateUiTypeRequest(elementRef, "password: hunter22"), /protected secret signature/u);
  assert.throws(() => validateUiTypeRequest(elementRef, "x", ["NOPE"]), /allowlisted key names/u);
  const windowId = opaqueWindowId(appId, 0, "Example");
  const snapshot = {
    elementRef: opaqueElementId(windowId, 0, "AXTextField", "Name", false), appId, windowId, windowIndex: 0, windowTitle: "Example", elementIndex: 0,
    role: "AXTextField", label: "Name", enabled: true, focused: false, secure: false,
    ownerPrincipalId: "principal-1", ownerSessionId: "session-1", observedAtMs: 1_000
  } as const;
  assert.throws(() => parseUiTypeResult(success(JSON.stringify({ status: "ok", app_id: appId, window_index: 0, window_title: "Example", element_index: 0, role: "AXTextField", characters_accepted: 4, keys_accepted: [], submitted: false, focus_confirmed: true, secure: false })), { snapshot, text: "Alice", keys: [], submit: false }), /postcondition/u);
});

test("visual observation returns a bounded JPEG and a session-owned action reference", async () => {
  const browserApp = "bundle:com.google.Chrome";
  const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8]), Buffer.alloc(100, 0), Buffer.from([0xff, 0xd9])]).toString("base64");
  const calls: { executable: string; args: readonly string[]; allowUserOwnedExecutable: boolean | undefined }[] = [];
  const inspector = new MacUiInspectorImpl({
    run: async request => {
      calls.push({ executable: request.executable, args: request.args, allowUserOwnedExecutable: request.allowUserOwnedExecutable });
      if (calls.length === 1) return success(JSON.stringify({
        status: "ok", app_id: browserApp, window_index: 0, window_identity: nativeIdentity, window_title: "Example Domain",
        focused: true, nodes: [{ index: 0, role: "AXWindow", label: "Example Domain", enabled: true, focused: true, secure: false }], truncated: false
      }));
      return success(JSON.stringify({
        status: "ok", mode: "active_window", app_id: browserApp, window_identity: nativeIdentity, window_title: "Example Domain",
        screen_width: 800, screen_height: 600, window_x: 0, window_y: 0,
        window_width: 800, window_height: 600, capture_width: 1600, capture_height: 1200,
        image_width: 1600, image_height: 1200, image_base64: jpeg
      }));
    }
  });
  const observed = await inspector.observe(browserApp, undefined, 10, { timeoutMs: 10_000, shouldCancel: () => false }, "active_window");
  assert.deepEqual(calls.map(call => call.allowUserOwnedExecutable), [true, true]);
  assert.equal(observed.screenshot?.base64, jpeg);
  assert.match(observed.visualRef ?? "", /^element:[a-f0-9]{48}$/u);
  assert.equal(calls[0]?.executable, guiVisionExecutableForTesting);
  assert.deepEqual(calls[0]?.args, ["inspect", "visual", "com.google.Chrome", "", "10"]);
  assert.equal(calls[1]?.executable, guiVisionExecutableForTesting);
  assert.deepEqual(calls[1]?.args, ["capture", "active_window", "com.google.Chrome", "Example Domain", nativeIdentity]);
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observed, "owner", "session", 1_000);
  assert.equal(registry.resolve(observed.visualRef!, "owner", "session", 1_001).role, "VisualWindow");
  assert.throws(() => registry.resolve(observed.visualRef!, "other", "session", 1_001), /not available/u);
  assert.throws(() => registry.resolve(observed.visualRef!, "owner", "session", 31_001), /stale/u);
});

test("truncated Accessibility-only observations do not create actionable element references", () => {
  const appId = "bundle:com.google.Chrome";
  const windowId = opaqueWindowId(appId, 0, "Example Domain");
  const elementRef = opaqueElementId(windowId, 0, "AXTextField", "Text input", false);
  const registry = new UiSnapshotRegistry();
  registry.recordObservation({ appId, windowId, windowIndex: 0, windowTitle: "Example Domain",
    focused: true, nodes: [{ elementRef, role: "AXTextField", label: "Text input",
      enabled: true, focused: true, secure: false }], truncated: true, warnings: [] },
  "owner", "session", 1_000);
  assert.throws(() => registry.resolve(elementRef, "owner", "session", 1_001), /not available/u);
});

test("visual typing uses the app-owned helper and keeps text on stdin", async () => {
  const appId = "bundle:com.google.Chrome";
  const windowId = opaqueWindowId(appId, 0, "Example Domain", nativeIdentity);
  const snapshot = {
    elementRef: opaqueElementId(windowId, 0, "AXTextField", "Text input", false),
    appId, windowId, windowIndex: 0, windowTitle: "Example Domain", elementIndex: 0,
    role: "AXTextField", label: "Text input", enabled: true, focused: true, secure: false,
    ownerPrincipalId: "owner", ownerSessionId: "session", observedAtMs: 1_000, nativeVisual: true, nativeWindowIdentity: nativeIdentity
  } as const;
  let command: { executable: string; args: readonly string[]; stdin: string | undefined } | undefined;
  const inspector = new MacUiInspectorImpl({ run: async request => {
    command = { executable: request.executable, args: request.args, stdin: request.stdin };
    return success(JSON.stringify({ status: "ok", app_id: appId, window_index: 0,
      window_identity: nativeIdentity, window_title: "Example Domain", element_index: 0, role: "AXTextField",
      characters_accepted: 4, keys_accepted: [], submitted: false,
      focus_confirmed: true, secure: false }));
  } });
  const typed = await inspector.type({ snapshot, text: "Test", keys: [], submit: false },
    { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(typed.charactersAccepted, 4);
  assert.equal(command?.executable, guiVisionExecutableForTesting);
  assert.deepEqual(command?.args, ["type", "visual", "com.google.Chrome", "Example Domain", "AXTextField", "Text input", nativeIdentity]);
  assert.equal(command?.stdin, '{"keys":[],"navigation":false,"submit":false,"text":"Test"}');
});

test("visual actions validate bounds and reject secure or mismatched readback", () => {
  const ref = "element:0123456789abcdef0123456789abcdef0123456789abcdef";
  assert.doesNotThrow(() => validateUiVisualActionRequest(ref, "click", { x: 100, y: 200 }));
  assert.doesNotThrow(() => validateUiVisualActionRequest(ref, "shortcut", { key: "COMMAND_L" }));
  assert.throws(() => validateUiVisualActionRequest(ref, "click", { x: -20001, y: 200 }), /bounded screen coordinates/u);
  assert.throws(() => validateUiVisualActionRequest(ref, "shortcut", { key: "COMMAND_Q" }), /not allowed/u);
  assert.throws(() => validateUiVisualActionRequest(ref, "wait", { waitMs: 2001 }), /at most two seconds/u);
  const observed = {
    appId: "bundle:com.google.Chrome", windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
    windowTitle: "Example Domain", focused: true, nodes: [], truncated: false, warnings: []
  };
  assert.throws(() => parseUiScreenshotResult(success(JSON.stringify({ status: "error", error: "other_window_visible" })), observed, "screen"), /window-boundary restriction/u);
});

test("visual click dispatch stays inside an observed browser window", async () => {
  const browserApp = "bundle:com.google.Chrome";
  const snapshot = {
    elementRef: "element:0123456789abcdef0123456789abcdef0123456789abcdef",
    appId: browserApp, windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
    windowIndex: 0, windowTitle: "Example Domain", elementIndex: -1, role: "VisualWindow",
    enabled: true, focused: true, secure: false, ownerPrincipalId: "owner", ownerSessionId: "session",
    observedAtMs: 1000, screenWidth: 800, screenHeight: 600,
    windowX: 0, windowY: 0, windowWidth: 800, windowHeight: 600
  } as const;
  let command: { executable: string; args: readonly string[] } | undefined;
  const inspector = new MacUiInspectorImpl({ run: async request => {
    command = { executable: request.executable, args: request.args };
    return success(JSON.stringify({ status: "ok", app_id: browserApp, window_title: "Example Domain",
      action: "click", accepted: true, focused: true }));
  } });
  const acted = await inspector.action({ snapshot, action: "click", options: { x: 200, y: 150 } },
    { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(acted.reobserved.role, "VisualWindow");
  assert.equal(command?.executable, guiVisionExecutableForTesting);
  assert.deepEqual(command?.args, ["action", "visual", "com.google.Chrome", "Example Domain", "click", "200", "150", "0", "0", "", "0", ""]);
  await assert.rejects(inspector.action({ snapshot, action: "click", options: { x: 801, y: 150 } },
    { timeoutMs: 10_000, shouldCancel: () => false }), /within the observed window/u);
});

test("focused typing selects only a fresh text field from the latest observation", () => {
  const browserApp = "bundle:com.google.Chrome";
  const oldWindow = opaqueWindowId(browserApp, 0, "Old");
  const newWindow = opaqueWindowId(browserApp, 0, "New");
  const registry = new UiSnapshotRegistry();
  registry.recordObservation({ appId: browserApp, windowId: oldWindow, windowIndex: 0, windowTitle: "Old",
    focused: true, nodes: [{ elementRef: opaqueElementId(oldWindow, 0, "AXTextField", "Search", false),
      role: "AXTextField", label: "Search", enabled: true, focused: true, secure: false }],
    truncated: false, warnings: [] }, "owner", "session", 1000);
  registry.recordObservation({ appId: browserApp, windowId: newWindow, windowIndex: 0, windowTitle: "New",
    focused: true, nodes: [{ elementRef: opaqueElementId(newWindow, 0, "AXButton", "Browse", false),
      role: "AXButton", label: "Browse", enabled: true, focused: true, secure: false }],
    truncated: false, warnings: [] }, "owner", "session", 2000);
  assert.throws(() => registry.resolveFocused("owner", "session", 2001), /focused text field/u);
  registry.recordObservation({ appId: browserApp, windowId: newWindow, windowIndex: 0, windowTitle: "New",
    focused: true, nodes: [{ elementRef: opaqueElementId(newWindow, 0, "AXTextField", "Address", false),
      role: "AXTextField", label: "Address", enabled: true, focused: true, secure: false }],
    truncated: false, warnings: [] }, "owner", "session", 3000);
  assert.equal(registry.resolveFocused("owner", "session", 3001).label, "Address");
  assert.throws(() => registry.resolveFocused("owner", "session", 33_001), /stale/u);
});

test("browser address input rejects executable and local URL schemes", async () => {
  const browserApp = "bundle:com.google.Chrome";
  const windowId = opaqueWindowId(browserApp, 0, "Example Domain");
  const snapshot = {
    elementRef: opaqueElementId(windowId, 0, "AXTextField", "Address and search bar", false),
    appId: browserApp, windowId, windowIndex: 0, windowTitle: "Example Domain", elementIndex: 0,
    role: "AXTextField", label: "Address and search bar", enabled: true, focused: true, secure: false,
    ownerPrincipalId: "owner", ownerSessionId: "session", observedAtMs: 1000
  } as const;
  let called = false;
  const inspector = new MacUiInspectorImpl({ run: async () => { called = true; throw new Error("unexpected execution"); } });
  for (const value of ["javascript:alert(1)", "file:///etc/passwd", "http://127.0.0.1:8080/"]) {
    await assert.rejects(inspector.type({ snapshot, text: value, keys: [], submit: false },
      { timeoutMs: 10_000, shouldCancel: () => false }), /HTTPS URL/u);
  }
  assert.equal(called, false);
});

test("ordinary application text fields do not inherit browser toolbar navigation authority", async () => {
  const ordinaryApp = "bundle:com.apple.TextEdit";
  const windowId = opaqueWindowId(ordinaryApp, 0, "Document", nativeIdentity);
  const snapshot = {
    elementRef: opaqueElementId(windowId, 0, "AXTextField", "Address", false), appId: ordinaryApp, windowId,
    windowIndex: 0, windowTitle: "Document", elementIndex: 0, role: "AXTextField", label: "Address",
    enabled: true, focused: true, secure: false, nativeVisual: true, nativeWindowIdentity: nativeIdentity,
    browserNavigation: true, ownerPrincipalId: "owner", ownerSessionId: "session", observedAtMs: 1000
  };
  const text = "file:///tmp/document";
  let input: string | undefined;
  const inspector = new MacUiInspectorImpl({ run: async request => {
    input = request.stdin;
    return success(JSON.stringify({ status: "ok", app_id: ordinaryApp, window_index: 0,
      window_title: "Document", window_identity: nativeIdentity, element_index: 0, role: "AXTextField",
      characters_accepted: text.length, keys_accepted: [], submitted: false, focus_confirmed: true, secure: false }));
  } });
  const typed = await inspector.type({ snapshot, text, keys: [], submit: false }, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(typed.charactersAccepted, text.length);
  assert.deepEqual(JSON.parse(input!), { text, keys: [], submit: false, navigation: false });
});

test("ordinary application window actions accept bounded global coordinates on secondary displays", async () => {
  const ordinaryApp = "bundle:com.apple.TextEdit";
  for (const windowX of [-1200, 1920]) {
    const snapshot = { elementRef: "element:0123456789abcdef0123456789abcdef0123456789abcdef",
      appId: ordinaryApp, windowId: opaqueWindowId(ordinaryApp, 0, "Document", nativeIdentity),
      windowIndex: 0, windowTitle: "Document", elementIndex: -1, role: "VisualWindow",
      enabled: true, focused: true, secure: false, nativeVisual: true, nativeWindowIdentity: nativeIdentity,
      ownerPrincipalId: "owner", ownerSessionId: "session", observedAtMs: 1000,
      screenWidth: 1440, screenHeight: 900, windowX, windowY: 30, windowWidth: 800, windowHeight: 600 };
    let args: readonly string[] | undefined;
    const inspector = new MacUiInspectorImpl({ run: async request => {
      args = request.args;
      return success(JSON.stringify({ status: "ok", app_id: ordinaryApp, window_title: "Document",
        window_identity: nativeIdentity, action: "click", accepted: true, focused: true }));
    } });
    await inspector.action({ snapshot, action: "click", options: { x: windowX + 100, y: 200 } },
      { timeoutMs: 10_000, shouldCancel: () => false });
    assert.equal(args?.[5], String(windowX + 100));
    args = undefined;
    await assert.rejects(inspector.action({ snapshot, action: "click", options: { x: windowX - 1, y: 200 } },
      { timeoutMs: 10_000, shouldCancel: () => false }), /within the observed window/u);
    assert.equal(args, undefined);
  }
  assert.doesNotThrow(() => validateUiVisualActionRequest("element:0123456789abcdef0123456789abcdef0123456789abcdef", "click", { x: -20_000, y: -20_000 }));
  assert.throws(() => validateUiVisualActionRequest("element:0123456789abcdef0123456789abcdef0123456789abcdef", "click", { x: -20_001, y: 0 }), /bounded screen coordinates/u);
});

test("ordinary application admission retains case-insensitive protected application exclusions", () => {
  assert.doesNotThrow(() => validateSensitiveUiTarget("bundle:com.apple.TextEdit", "Ordinary document"));
  for (const app of ["com.apple.SEcurityAGent", "COM.APPLE.KEYCHAINACCESS", "com.apple.SystemPreferences", "com.apple.loginwindow"]) {
    assert.throws(() => validateSensitiveUiTarget(`bundle:${app}`), /Sensitive application/u);
  }
});

test("native observation requires strict boolean truncation metadata", () => {
  const result = (truncated: unknown) => success(JSON.stringify({
    status: "ok", app_id: appId, window_index: 0, window_identity: nativeIdentity, window_title: "Example", focused: true, nodes: [], truncated
  }));
  for (const value of [false, true]) assert.equal(parseUiObserveResult(result(value), appId, 10, true).truncated, value);
  for (const value of [0, 1, 2, -1, "1", null]) {
    assert.throws(() => parseUiObserveResult(result(value), appId, 10, true), /malformed metadata/u);
  }
});

function approvalTestObservation() {
  const appId = "bundle:com.google.Chrome";
  return {
    appId, windowId: opaqueWindowId(appId, 0, "Web form"), windowIndex: 0,
    windowTitle: "Web form", focused: true, nodes: [], truncated: true, warnings: [],
    visualRef: "element:0123456789abcdef0123456789abcdef0123456789abcdef",
    screenshot: { mode: "active_window" as const, mimeType: "image/jpeg" as const, base64: "original-image",
      screenWidth: 800, screenHeight: 600, windowX: 10, windowY: 20, windowWidth: 600, windowHeight: 400,
      captureWidth: 600, captureHeight: 400, imageWidth: 600, imageHeight: 400 }
  };
}

test("approval retention preserves evidence and expiry without extending ordinary snapshots", () => {
  const observation = approvalTestObservation();
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observation, "owner", "session", 1000);
  assert.throws(() => registry.retainForApproval(observation.visualRef, "other", "session", 2000, 122000, "first-input"), /not available/u);
  registry.retainForApproval(observation.visualRef, "owner", "session", 2000, 122000, "first-input");
  const retained = registry.resolve(observation.visualRef, "owner", "session", 32000, "first-input");
  assert.equal(retained.observedAtMs, 1000);
  assert.equal(retained.revalidationRequired, true);
  registry.retainForApproval(observation.visualRef, "owner", "session", 32000, 152000, "first-input");
  registry.recordObservation({ ...observation, visualRef: "element:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }, "owner", "session", 40000);
  assert.equal(registry.resolve(observation.visualRef, "owner", "session", 80000, "first-input").approvalRetainUntilMs, 122000);
  assert.throws(() => registry.resolve(observation.visualRef, "other", "session", 80000, "first-input"), /not available/u);
  assert.throws(() => registry.resolve(observation.visualRef, "owner", "session", 122000, "first-input"), /stale/u);
});

test("retained visual click reobserves before dispatch and rejects changed pixels, geometry, or focus", async () => {
  const observation = approvalTestObservation();
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observation, "owner", "session", 1000);
  registry.retainForApproval(observation.visualRef, "owner", "session", 2000, 122000, "first-input");
  const snapshot = registry.resolve(observation.visualRef, "owner", "session", 32000, "first-input");
  let dispatches = 0;
  let fresh = observation;
  class ReobservingInspector extends MacUiInspectorImpl {
    override async observe() { return fresh; }
  }
  const inspector = new ReobservingInspector({ run: async () => {
    dispatches++;
    return success(JSON.stringify({ status: "ok", app_id: observation.appId, window_title: "Web form", action: "click", accepted: true, focused: true }));
  } });
  const execute = () => inspector.action({ snapshot, action: "click", options: { x: 100, y: 100 } }, { timeoutMs: 10000, shouldCancel: () => false });
  for (const changed of [
    { ...observation, focused: false },
    { ...observation, screenshot: { ...observation.screenshot, base64: "changed-image" } },
    { ...observation, screenshot: { ...observation.screenshot, windowX: 11 } }
  ]) {
    fresh = changed;
    await assert.rejects(execute(), /Approved UI target changed/u);
    assert.equal(dispatches, 0);
  }
  fresh = observation;
  assert.equal((await execute()).accepted, true);
  assert.equal(dispatches, 1);
});

test("retained typing refuses a changed focused field even when the screenshot matches", async () => {
  const base = approvalTestObservation();
  const node = { elementRef: opaqueElementId(base.windowId, 0, "AXTextField", "Text input", false),
    role: "AXTextField", label: "Text input", focused: true, enabled: true, secure: false };
  const observation = { ...base, nodes: [node] };
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observation, "owner", "session", 1000);
  registry.retainForApproval(node.elementRef, "owner", "session", 2000, 122000, "first-input");
  const snapshot = registry.resolve(node.elementRef, "owner", "session", 32000, "first-input");
  class ChangedFieldInspector extends MacUiInspectorImpl {
    override async observe() { return { ...observation, nodes: [{ ...node, secure: true }] }; }
  }
  const inspector = new ChangedFieldInspector({ run: async () => { throw new Error("Input must not be dispatched"); } });
  await assert.rejects(inspector.type({ snapshot, text: "Mac Operator test", keys: [], submit: false },
    { timeoutMs: 10000, shouldCancel: () => false }), /Approved focused input changed/u);
});

test("successive input approvals preserve old evidence while accepting a new observation", async () => {
  const base = approvalTestObservation();
  const node = { elementRef: opaqueElementId(base.windowId, 0, "AXTextField", "Text input", false),
    role: "AXTextField", label: "Text input", focused: true, enabled: true, secure: false };
  const first = { ...base, nodes: [node] };
  const second = { ...first, visualRef: "element:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    screenshot: { ...base.screenshot, base64: "after-first-input" } };
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(first, "owner", "session", 1000);
  registry.retainForApproval(node.elementRef, "owner", "session", 2000, 122000, "first-input");
  registry.recordObservation(second, "owner", "session", 10000);
  assert.equal(registry.resolve(node.elementRef, "owner", "session", 10001).observedAtMs, 10000);
  assert.equal(registry.resolveFocused("owner", "session", 10001).observedAtMs, 10000);
  const original = registry.resolve(node.elementRef, "owner", "session", 10001, "first-input");
  assert.equal(original.observedAtMs, 1000);
  assert.equal(registry.resolveFocused("owner", "session", 10001, "first-input").observedAtMs, 1000);
  assert.throws(() => assertRetainedUiTargetMatches(original, second), /target changed/u);
  registry.retainForApproval(node.elementRef, "owner", "session", 10001, 130001, "second-input");
  assertRetainedUiTargetMatches(registry.resolve(node.elementRef, "owner", "session", 10002, "second-input"), second);
  registry.releaseApproval("other", "session", "first-input");
  assert.equal(registry.resolve(node.elementRef, "owner", "session", 10002, "first-input").observedAtMs, 1000);
  registry.releaseApproval("owner", "session", "first-input");
  assert.equal(registry.resolve(node.elementRef, "owner", "session", 10002, "first-input").observedAtMs, 10000);
  assert.equal(registry.resolve(node.elementRef, "owner", "session", 10002, "second-input").revalidationRequired, true);
  // Repeating the same input after completion starts with the new evidence.
  registry.retainForApproval(node.elementRef, "owner", "session", 10003, 130003, "first-input");
  assertRetainedUiTargetMatches(registry.resolve(node.elementRef, "owner", "session", 10004, "first-input"), second);
});

test("retained visual revalidation waits for an exact caret phase and dispatches only once", async () => {
  const observation = approvalTestObservation();
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observation, "owner", "session", 1000);
  registry.retainForApproval(observation.visualRef, "owner", "session", 2000, 122000, "caret-input");
  const snapshot = registry.resolve(observation.visualRef, "owner", "session", 32000, "caret-input");
  let observations = 0;
  let dispatches = 0;
  class CaretInspector extends MacUiInspectorImpl {
    override async observe() {
      observations++;
      assert.equal(dispatches, 0);
      return observations < 3
        ? { ...observation, screenshot: { ...observation.screenshot, base64: "other-caret-phase" } }
        : observation;
    }
  }
  const inspector = new CaretInspector({ run: async () => {
    dispatches++;
    return success(JSON.stringify({ status: "ok", app_id: observation.appId, window_title: "Web form", action: "click", accepted: true, focused: true }));
  } });
  assert.equal((await inspector.action({ snapshot, action: "click", options: { x: 100, y: 100 } },
    { timeoutMs: 10000, shouldCancel: () => false })).accepted, true);
  assert.equal(observations, 3);
  assert.equal(dispatches, 1);
});

test("visual retries stay bounded and stop on identity changes, cancellation, or deadline", async () => {
  const observation = approvalTestObservation();
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observation, "owner", "session", 1000);
  registry.retainForApproval(observation.visualRef, "owner", "session", 2000, 122000, "bounded-input");
  const snapshot = registry.resolve(observation.visualRef, "owner", "session", 32000, "bounded-input");
  for (const scenario of ["pixels", "identity", "cancel", "timeout"]) {
    let observations = 0;
    class RetryInspector extends MacUiInspectorImpl {
      override async observe() {
        observations++;
        return { ...observation, focused: scenario !== "identity",
          screenshot: { ...observation.screenshot, base64: "changed-content" } };
      }
    }
    const inspector = new RetryInspector({ run: async () => { throw new Error("Changed evidence must never dispatch"); } });
    await assert.rejects(inspector.action({ snapshot, action: "click", options: { x: 100, y: 100 } },
      { timeoutMs: scenario === "timeout" ? 40 : 10000,
        shouldCancel: () => scenario === "cancel" && observations > 0 }),
      scenario === "cancel" ? /cancelled/u : scenario === "timeout" ? /timed out/u : /target changed/u);
    assert.equal(observations, scenario === "pixels" ? 4 : 1);
  }
});

test("screen capture failures distinguish geometry from sensitive window rules", () => {
  const observed = {
    appId: "bundle:com.google.Chrome", windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
    windowTitle: "Web form", focused: true, nodes: [], truncated: false, warnings: []
  };
  for (const [reason, message] of [
    ["screen_window_occluded", /window above the browser/u],
    ["screen_other_window_visible", /another visible window/u],
    ["sensitive_window_visible", /known sensitive application/u],
    ["target_denied", /screenshot contents were not inspected/u]
  ] as const) {
    assert.throws(() => parseUiScreenshotResult(success(JSON.stringify({ status: "error", error: reason })), observed, "screen"), message);
  }
});
