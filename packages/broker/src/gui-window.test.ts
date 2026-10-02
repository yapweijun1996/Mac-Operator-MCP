import assert from "node:assert/strict";
import test from "node:test";
import { normalizeAppId, parseAppFocusResult } from "./app-control.js";
import { nativeWindowIdentity, throwGuiWindowError } from "./gui-window.js";
import { isBoundedBrowserNavigation, opaqueElementId, opaqueWindowId, parseUiObserveResult, parseUiScreenshotResult, parseUiTypeResult, UiSnapshotRegistry } from "./ui-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

const app = "bundle:com.google.Chrome", identity = "485:1790918400000:46";
function output(value: unknown): ProcessExecutionResult {
  return { state: "completed", resultClass: "SUCCEEDED", exitCode: 0, signal: null, stdout: JSON.stringify(value), stderr: "", truncated: false, durationMs: 1, processId: 1, processGroupId: 1, terminationObserved: true };
}
function observation(title = "Page - Google Chrome - YAP", windowIdentity = identity) {
  return parseUiObserveResult(output({ status: "ok", app_id: app, window_index: 0, window_title: title,
    window_identity: windowIdentity, focused: true, nodes: [{ index: 0, role: "AXTextField", label: "Address and search bar",
      enabled: true, focused: true, secure: false, browser_navigation: true }], truncated: false }), app, 10, true);
}

test("bare and prefixed Chrome selectors normalize to the same canonical application", () => {
  assert.equal(normalizeAppId("com.google.Chrome"), app);
  assert.equal(normalizeAppId(app), app);
  assert.throws(() => normalizeAppId("../com.google.Chrome"), /stable bundle/u);
});
test("verified focus and immediate native observation retain the same logical window", () => {
  const focused = parseAppFocusResult(output({ status: "ok", app_id: app, window_index: 0,
    window_title: "Page - Google Chrome - YAP", window_identity: identity, focused: true }), app);
  assert.equal(focused.windowId, observation().windowId);
  assert.equal(focused.verified, true);
});
test("browser title changes do not change window identity while process/window replacement does", () => {
  assert.equal(observation("Before").windowId, observation("After").windowId);
  assert.notEqual(observation().windowId, observation("Page", "485:1790918400000:47").windowId);
  assert.notEqual(observation().windowId, observation("Page", "485:1790918500000:46").windowId);
});
test("native observations reject missing identity and numeric focus fields", () => {
  const value = { status: "ok", app_id: app, window_index: 0, window_title: "Page", focused: true,
    nodes: [{ index: 0, role: "AXWindow", label: "Page", enabled: true, focused: 1, secure: false }], truncated: false };
  assert.throws(() => parseUiObserveResult(output({ ...value, window_identity: identity }), app, 10, true), /malformed node/u);
  assert.throws(() => parseUiObserveResult(output({ ...value, nodes: [] }), app, 10, true), /window identity/u);
  for (const value of ["", "0:1:46", "485:0:46", "485:1:0", "../../../46", 46]) assert.throws(() => nativeWindowIdentity({ window_identity: value }, true));
});
test("active window screenshot is correlated by native identity after focus", () => {
  const observed = observation();
  const jpeg = Buffer.concat([Buffer.from([255,216]), Buffer.alloc(100), Buffer.from([255,217])]).toString("base64");
  const capture = { status: "ok", mode: "active_window", app_id: app, window_title: "Renamed page",
    window_identity: identity, screen_width: 1440, screen_height: 900, window_x: 83, window_y: 30,
    window_width: 1200, window_height: 800, capture_width: 1200, capture_height: 800,
    image_width: 1200, image_height: 800, image_base64: jpeg };
  assert.equal(parseUiScreenshotResult(output(capture), observed, "active_window").base64, jpeg);
  assert.throws(() => parseUiScreenshotResult(output({ ...capture, window_identity: "485:1790918400000:47" }), observed, "active_window"), /window identity/u);
  assert.throws(() => parseUiScreenshotResult(output({ ...capture, window_title: "Password" }), observed, "active_window"), /Sensitive/u);
});
for (const [reason, expected] of [
  ["app_not_running", "TARGET_NOT_FOUND"], ["window_not_found", "TARGET_NOT_FOUND"],
  ["app_not_frontmost", "PRECONDITION_FAILED"], ["window_unavailable", "PRECONDITION_FAILED"],
  ["window_correlation_failed", "VERIFICATION_FAILED"], ["window_ambiguous", "VERIFICATION_FAILED"],
  ["ax_enumeration_failed", "VERIFICATION_FAILED"], ["accessibility_permission", "POLICY_DENIED"],
  ["screen_recording_permission", "POLICY_DENIED"], ["capture_failed", "EXECUTION_FAILED"]
]) test(`GUI failure ${reason} preserves its actual boundary`, () => {
  assert.throws(() => throwGuiWindowError(reason), error => error instanceof Error && "errorClass" in error && error.errorClass === expected);
});
test("reusable browser navigation requires native toolbar provenance and bounded HTTPS input", () => {
  const observed = observation();
  const registry = new UiSnapshotRegistry(); registry.recordObservation(observed, "owner", "session", 1000);
  const snapshot = registry.resolve(observed.nodes[0]!.elementRef, "owner", "session", 1001);
  const execution = { snapshot, text: "https://example.com/", keys: [], submit: true };
  assert.equal(isBoundedBrowserNavigation(execution), true);
  assert.equal(snapshot.nativeWindowIdentity, identity);
  for (const changed of [{ snapshot: { ...snapshot, browserNavigation: false } }, { snapshot: { ...snapshot, secure: true } },
    { text: "http://example.com" }, { text: "https://user:password@example.com" }, { text: "https://example.com/#fragment" },
    { text: "Post a message" }, { keys: ["TAB", "ENTER"] as const }]) assert.equal(isBoundedBrowserNavigation({ ...execution, ...changed }), false);
  assert.equal(opaqueElementId(opaqueWindowId(app, 0, "Page", identity), 0, "AXTextField", "Address and search bar", false), snapshot.elementRef);
});

test("navigation reports actual post-navigation focus only with verified native address readback", () => {
  const observed = observation();
  const registry = new UiSnapshotRegistry(); registry.recordObservation(observed, "owner", "session", 1000);
  const snapshot = registry.resolve(observed.nodes[0]!.elementRef, "owner", "session", 1001);
  const execution = { snapshot, text: "https://example.com/", keys: [], submit: true };
  const raw = { status: "ok", app_id: app, window_index: 0, window_title: observed.windowTitle,
    window_identity: identity, element_index: 0, role: snapshot.role, characters_accepted: execution.text.length,
    keys_accepted: [], submitted: true, focus_confirmed: true, secure: false };
  assert.throws(() => parseUiTypeResult(output(raw), execution), /navigation postcondition/u);
  const verified = { ...raw, navigation_verified: true, post_role: "AXWebArea" };
  assert.equal(parseUiTypeResult(output(verified), execution).reobserved.role, "AXWebArea");
  assert.throws(() => parseUiTypeResult(output({ ...verified, navigation_verified: false }), execution), /navigation postcondition/u);
  assert.throws(() => parseUiTypeResult(output(verified), { ...execution, snapshot: { ...snapshot, browserNavigation: false } }), /malformed/u);
});
