import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { MacUiInspectorImpl, UiSnapshotRegistry, opaqueElementId, opaqueWindowId, type SafeUiObservation } from "./ui-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";
import { DESKTOP_APP_ID } from "./desktop-ui.js";

const appId = "bundle:com.apple.TextEdit";
const identity = "485:1790918400000:46";
const windowId = opaqueWindowId(appId, 0, "Fixture", identity);
const elementRef = opaqueElementId(windowId, 1, "AXComboBox", "font size", false);
const observation: SafeUiObservation = {
  appId, windowId, windowIndex: 0, windowTitle: "Fixture", nativeWindowIdentity: identity, nativeVisual: true,
  focused: true, truncated: false, warnings: [],
  nodes: [
    { elementRef: opaqueElementId(windowId, 0, "AXWindow", "Fixture", false), role: "AXWindow", label: "Fixture", enabled: true, focused: false, secure: false },
    { elementRef, role: "AXComboBox", label: "font size", enabled: true, focused: false, secure: false }
  ],
  screenshot: { mode: "active_window", mimeType: "image/jpeg", base64: "fixture-pixels", screenWidth: 1200, screenHeight: 900,
    windowX: 100, windowY: 100, windowWidth: 800, windowHeight: 600, captureWidth: 800, captureHeight: 600, imageWidth: 800, imageHeight: 600 }
};
const control = { timeoutMs: 10000, shouldCancel: () => false };

function completed(value: unknown): ProcessExecutionResult {
  return { state: "completed", resultClass: "SUCCEEDED", exitCode: 0, signal: null, stdout: JSON.stringify(value), stderr: "",
    truncated: false, durationMs: 1, processId: 1, processGroupId: 1, terminationObserved: true };
}

function retained(observed: SafeUiObservation = observation, now = 1001) {
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observed, "owner", "session", 1000);
  registry.retainForApproval(elementRef, "owner", "session", now, now + 30000, "operation");
  return { registry, snapshot: registry.resolve(elementRef, "owner", "session", now, "operation") };
}

test("fresh retained non-focused toolbar target allows immediate and short-delay bounded actions", async () => {
  for (const now of [1001, 1200]) {
    const { snapshot } = retained(observation, now);
    let dispatches = 0;
    class Inspector extends MacUiInspectorImpl {
      override async observe() { return observation; }
    }
    const inspector = new Inspector({ run: async request => {
      dispatches++;
      assert.equal(request.args[0], "ax_action");
      assert.equal(request.args[4], "1");
      return completed({ status: "ok", app_id: appId, window_index: 0, window_title: "Fixture", window_identity: identity,
        element_index: 1, role: "AXComboBox", enabled: true, focused: true, secure: false, accepted: true });
    } });
    assert.equal((await inspector.action({ snapshot, action: "focus" }, control)).accepted, true);
    assert.equal(dispatches, 1);
  }
});

test("toolbar retention rejects changed app/window, disappeared/secure/disabled target and lost app focus before dispatch", async () => {
  const { snapshot } = retained();
  const target = observation.nodes[1]!;
  for (const changed of [
    { ...observation, appId: "bundle:com.google.Chrome" },
    { ...observation, windowId: opaqueWindowId(appId, 0, "Other", "485:1790918400000:47") },
    { ...observation, focused: false },
    { ...observation, nodes: observation.nodes.slice(0, 1) },
    { ...observation, nodes: [observation.nodes[0]!, { ...target, secure: true }] },
    { ...observation, nodes: [observation.nodes[0]!, { ...target, enabled: false }] }
  ]) {
    class Inspector extends MacUiInspectorImpl {
      override async observe() { return changed; }
    }
    const inspector = new Inspector({ run: async () => { throw new Error("Must not dispatch"); } });
    await assert.rejects(inspector.action({ snapshot, action: "focus" }, control),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "TARGET_NOT_FOUND");
  }
});

test("typing retains focused-input guard when ordinary toolbar actions do not require focus", async () => {
  const { snapshot } = retained();
  class Inspector extends MacUiInspectorImpl {
    override async observe() { return observation; }
  }
  const inspector = new Inspector({ run: async () => { throw new Error("Must not dispatch"); } });
  await assert.rejects(inspector.type({ snapshot, text: "MBA-MCP test", keys: [], submit: false }, control), /Approved focused input changed/u);
});

test("ordinary native AXTextArea typing passes its actual observed index to the native guard", async () => {
  const textRef = opaqueElementId(windowId, 1, "AXTextArea", "", false);
  const textObservation = { ...observation, nodes: [observation.nodes[0]!,
    { elementRef: textRef, role: "AXTextArea", enabled: true, focused: true, secure: false }] };
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(textObservation, "owner", "session", 1000);
  const snapshot = registry.resolve(textRef, "owner", "session", 1001);
  const inspector = new MacUiInspectorImpl({ run: async request => {
    assert.deepEqual(request.args, ["type", "visual", "com.apple.TextEdit", "Fixture", "AXTextArea", "", "1", identity]);
    return completed({ status: "ok", app_id: appId, window_index: 0, window_title: "Fixture", window_identity: identity,
      element_index: 1, role: "AXTextArea", characters_accepted: 12, keys_accepted: [], submitted: false, focus_confirmed: true, secure: false });
  } });
  const typed = await inspector.type({ snapshot, text: "MBA-MCP test", keys: [], submit: false }, control);
  assert.equal(typed.charactersAccepted, 12);
  assert.equal(typed.focusConfirmed, true);
});

test("reference expiry and principal/session ownership still fail closed", () => {
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observation, "owner", "session", 1000);
  for (const [owner, session, now] of [["other", "session", 1001], ["owner", "other", 1001], ["owner", "session", 31001]] as const) {
    assert.throws(() => registry.resolve(elementRef, owner, session, now),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "TARGET_NOT_FOUND");
  }
});

test("ordinary native AX GUI sessions tolerate changed caret pixels after exact identity and geometry revalidation", async () => {
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observation, "owner", "session", 1000);
  registry.retainForGuiSession(elementRef, "owner", "session", 1750, 31750, "session-focus", false);
  const snapshot = registry.resolve(elementRef, "owner", "session", 1750, "session-focus");
  assert.equal(snapshot.revalidationStrategy, "native_ax");
  let dispatches = 0;
  class Inspector extends MacUiInspectorImpl {
    override async observe() { return { ...observation, screenshot: { ...observation.screenshot!, base64: "different-caret-pixels" } }; }
  }
  const inspector = new Inspector({ run: async () => {
    dispatches++;
    return completed({ status: "ok", app_id: appId, window_index: 0, window_title: "Fixture", window_identity: identity,
      element_index: 1, role: "AXComboBox", enabled: true, focused: true, secure: false, accepted: true });
  } });
  assert.equal((await inspector.action({ snapshot, action: "focus", guiSessionAuthorized: true }, control)).accepted, true);
  assert.equal(dispatches, 1);
  assert.equal(snapshot.observedAtMs, 1000);
  assert.equal(snapshot.approvalRetainUntilMs, 31750);
});

test("native AX GUI session still rejects geometry, native identity, focus, secure and target changes without dispatch", async () => {
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observation, "owner", "session", 1000);
  registry.retainForGuiSession(elementRef, "owner", "session", 1001, 31001, "session-focus", false);
  const snapshot = registry.resolve(elementRef, "owner", "session", 1001, "session-focus");
  const target = observation.nodes[1]!;
  for (const changed of [
    { ...observation, screenshot: { ...observation.screenshot!, windowX: 101 } },
    { ...observation, screenshot: { ...observation.screenshot!, imageWidth: 799 } },
    { ...observation, nativeWindowIdentity: "485:1790918400000:47" },
    { ...observation, appId: "bundle:com.google.Chrome" },
    { ...observation, focused: false },
    { ...observation, nodes: observation.nodes.slice(0, 1) },
    { ...observation, nodes: [observation.nodes[0]!, { ...target, secure: true }] },
    { ...observation, nodes: [observation.nodes[0]!, { ...target, enabled: false }] }
  ]) {
    class Inspector extends MacUiInspectorImpl { override async observe() { return changed; } }
    await assert.rejects(new Inspector({ run: async () => { throw new Error("Must not dispatch"); } })
      .action({ snapshot, action: "focus", guiSessionAuthorized: true }, control),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "TARGET_NOT_FOUND");
  }
  await assert.rejects(new MacUiInspectorImpl({ run: async () => { throw new Error("Must not dispatch"); } })
    .action({ snapshot, action: "focus" }, { timeoutMs: 10000, shouldCancel: () => true }), /cancelled/u);
});

test("attended and sensitive AX approvals retain exact pixels, including pending approval during session authorization", async () => {
  for (const pending of [true, false]) {
    const registry = new UiSnapshotRegistry();
    registry.recordObservation(observation, "owner", "session", 1000);
    if (pending) registry.retainForApproval(elementRef, "owner", "session", 1001, 31001, "approval");
    registry.retainForGuiSession(elementRef, "owner", "session", 1002, 31002, "approval", !pending);
    const snapshot = registry.resolve(elementRef, "owner", "session", 1002, "approval");
    assert.equal(snapshot.revalidationStrategy, "screenshot");
    class Inspector extends MacUiInspectorImpl {
      override async observe() { return { ...observation, screenshot: { ...observation.screenshot!, base64: "changed-approved-context" } }; }
    }
    await assert.rejects(new Inspector({ run: async () => { throw new Error("Must not dispatch"); } })
      .action({ snapshot, action: "focus" }, control), /target changed/u);
  }
});

test("visual, desktop and legacy references never select native AX session revalidation", () => {
  const visualRef = "element:" + "9".repeat(48);
  const { nativeWindowIdentity: _identity, ...legacy } = observation;
  for (const [observed, reference] of [
    [{ ...observation, visualRef }, visualRef],
    [{ ...observation, appId: DESKTOP_APP_ID }, elementRef],
    [legacy, elementRef]
  ] as const) {
    const registry = new UiSnapshotRegistry();
    registry.recordObservation(observed, "owner", "session", 1000);
    registry.retainForGuiSession(reference, "owner", "session", 1001, 31001, "session", false);
    assert.equal(registry.resolve(reference, "owner", "session", 1001, "session").revalidationStrategy, "screenshot");
  }
});

test("historical GUI retention cannot authorize a current attended request or refresh its evidence", async () => {
  for (const attended of [false, true, "sensitive"] as const) {
    const registry = new UiSnapshotRegistry();
    registry.recordObservation(observation, "owner", "session", 1000);
    registry.retainForGuiSession(elementRef, "owner", "session", 1001, 31001, "operation", false);
    if (attended === true) registry.retainForApproval(elementRef, "owner", "session", 1200, 31200, "operation");
    if (attended === "sensitive") registry.retainForGuiSession(elementRef, "owner", "session", 1200, 31200, "operation", true);
    const snapshot = registry.resolve(elementRef, "owner", "session", 1200, "operation");
    assert.equal(snapshot.revalidationStrategy, attended ? "screenshot" : "native_ax");
    assert.equal(snapshot.observedAtMs, 1000);
    assert.equal(snapshot.approvalRetainUntilMs, 31001);
    assert.equal(snapshot.screenshotFingerprint, registry.resolve(elementRef, "owner", "session", 1200).screenshotFingerprint);
    class Inspector extends MacUiInspectorImpl {
      override async observe() { return { ...observation, screenshot: { ...observation.screenshot!, base64: "changed-approved-context" } }; }
    }
    await assert.rejects(new Inspector({ run: async () => { throw new Error("Must not dispatch"); } })
      .action({ snapshot, action: "focus", ...(attended === false ? {} : { guiSessionAuthorized: false }) }, control), /target changed/u);
  }
});
