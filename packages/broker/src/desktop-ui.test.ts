import assert from "node:assert/strict";
import test from "node:test";
import { DESKTOP_APP_ID, desktopDeniedApplications, desktopManifest } from "./desktop-ui.js";
import { createDefaultPolicy } from "./default-policy.js";
import { MacUiInspectorImpl, UiSnapshotRegistry, parseUiObserveResult, type UiExecutionControl } from "./ui-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

const identity = `desktop:1:${"a".repeat(64)}:485:1790918400000`;
const control: UiExecutionControl = { timeoutMs: 10000, shouldCancel: () => false, desktopDeniedApps: ["com.example.denied"] };
const jpeg = Buffer.concat([Buffer.from([0xff, 0xd8]), Buffer.alloc(100), Buffer.from([0xff, 0xd9])]).toString("base64");
function success(value: object): ProcessExecutionResult {
  return { state: "completed", resultClass: "SUCCEEDED", exitCode: 0, signal: null, stdout: JSON.stringify(value), stderr: "",
    truncated: false, durationMs: 1, processId: 1, processGroupId: 1, terminationObserved: true };
}
const observation = { status: "ok", app_id: DESKTOP_APP_ID, window_identity: identity, window_index: 0,
  window_title: "Desktop", focused: true, nodes: [], truncated: false };

test("desktop manifests require signed domain authority and preserve all GUI application denies", () => {
  const base = createDefaultPolicy("edge-1", true, ["mac.ui.observe"], ["key-1"]);
  const rule = { ruleId: "desktop-observe", effect: "allow" as const, principalId: "principal-1", scope: "mac.ui.observe" as const,
    target: { kind: "app_window" as const, reference: "desktop" } };
  const denied = { ...rule, ruleId: "denied-app", effect: "deny" as const, target: { kind: "app_window" as const, reference: "window:bundle:com.example.Denied" } };
  const policy = { ...base, targetRules: [rule, denied] };
  assert.deepEqual(desktopDeniedApplications(policy, "principal-1", ["mac.ui.observe"]), ["com.example.denied"]);
  assert.throws(() => desktopDeniedApplications({ ...policy, targetRules: [{ ...rule, target: { kind: "app_window", reference: `window:${DESKTOP_APP_ID}` } }] }, "principal-1", ["mac.ui.observe"]), /explicit signed desktop/u);
  assert.throws(() => desktopDeniedApplications({ ...policy, targetRules: [rule, { ...rule, effect: "deny" }] }, "principal-1", ["mac.ui.observe"]), /denied by application policy/u);
  assert.throws(() => desktopManifest(undefined), /Broker-owned/u);
  assert.throws(() => desktopManifest(Array.from({ length: 129 }, (_, n) => `com.example.app${n}`)), /transport boundary/u);
  assert.throws(() => desktopManifest(Array.from({ length: 100 }, (_, n) => `com.example.${"x".repeat(50)}${n}`)), /transport boundary/u);
});

test("desktop identity cannot be substituted for an application window or vice versa", () => {
  assert.doesNotThrow(() => parseUiObserveResult(success(observation), DESKTOP_APP_ID, 40, true));
  assert.throws(() => parseUiObserveResult(success({ ...observation, app_id: "bundle:com.example.App" }), "bundle:com.example.App", 40, true), /identity does not match/u);
  assert.throws(() => parseUiObserveResult(success({ ...observation, window_identity: "485:1790918400000:46" }), DESKTOP_APP_ID, 40, true), /identity does not match/u);
  assert.throws(() => parseUiObserveResult(success({ ...observation, window_title: "Window" }), DESKTOP_APP_ID, 40, true), /unexpected AX/u);
});

test("desktop observation and input use a display-bound visual reference and Broker-only deny manifest", async () => {
  const calls: readonly string[][] = [];
  const recorded: string[][] = calls as string[][];
  const inspector = new MacUiInspectorImpl({ run: async request => {
    recorded.push([...request.args]);
    assert.equal(request.args.at(-1), '["com.example.denied"]');
    if (request.args[0] === "inspect") return success(observation);
    if (request.args[0] === "capture") return success({ status: "ok", mode: "screen", app_id: DESKTOP_APP_ID,
      window_identity: identity, window_title: "Desktop", screen_width: 800, screen_height: 600,
      window_x: -800, window_y: 0, window_width: 800, window_height: 600, capture_width: 800, capture_height: 600,
      image_width: 800, image_height: 600, image_base64: jpeg });
    if (request.args[0] === "action") return success({ status: "ok", app_id: DESKTOP_APP_ID, window_title: "Desktop",
      window_identity: identity, action: "move_pointer", accepted: true, focused: true });
    assert.equal(request.args[0], "type");
    assert.ok(!request.args.includes("Test"), "Typed content stays on stdin");
    return success({ status: "ok", app_id: DESKTOP_APP_ID, window_title: "Desktop", window_identity: identity,
      window_index: 0, element_index: -1, role: "VisualWindow", characters_accepted: 4, keys_accepted: [],
      submitted: false, focus_confirmed: true, secure: false });
  } });
  await assert.rejects(inspector.observe(DESKTOP_APP_ID, undefined, 40, { timeoutMs: 10000, shouldCancel: () => false }, "screen"), /Broker-owned/u);
  const observed = await inspector.observe(DESKTOP_APP_ID, "display:1", 40, control, "active_window");
  assert.equal(observed.screenshot?.mode, "screen");
  assert.equal(calls[1]?.[3], "display:1");
  const registry = new UiSnapshotRegistry();
  registry.recordObservation(observed, "owner", "session", 1000);
  const snapshot = registry.resolve(observed.visualRef!, "owner", "session", 1001);
  await inspector.action({ snapshot, action: "move_pointer", options: { x: -400, y: 300 } }, control);
  await assert.rejects(inspector.action({ snapshot, action: "move_pointer", options: { x: 0, y: 300 } }, control), /within the observed window/u);
  const typed = await inspector.type({ snapshot, text: "Test", keys: [], submit: false }, control);
  assert.equal(typed.charactersAccepted, 4);
  assert.throws(() => registry.resolve(observed.visualRef!, "owner", "different-session", 1001), /not available/u);
});
