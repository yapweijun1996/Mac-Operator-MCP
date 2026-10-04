import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore, guiSessionApprovalId } from "./persistence.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";
import { MacUiInspectorImpl, UiSnapshotRegistry, opaqueElementId, opaqueWindowId,
  type SafeUiObservation, type UiActionExecution, type UiExecutionControl, type UiTypeExecution } from "./ui-inspector.js";

const NOW = 1_700_000_000_000;
const APP = "bundle:com.apple.TextEdit";
const IDENTITY = "485:1790918400000:46";
type Tool = "mac_ui_action" | "mac_ui_type";

interface CaseOptions {
  tool: Tool;
  sessionAllowed: boolean;
  changedPixels: boolean;
  historicalSession?: boolean;
  attendedApproval?: boolean;
  pendingAttendedEvidence?: boolean;
  legacy?: boolean;
  visual?: boolean;
  submit?: boolean;
}

function completed(value: unknown): ProcessExecutionResult {
  return { state: "completed", resultClass: "SUCCEEDED", exitCode: 0, signal: null, stdout: JSON.stringify(value), stderr: "",
    truncated: false, durationMs: 1, processId: 1, processGroupId: 1, terminationObserved: true };
}

async function fixture(options: CaseOptions) {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-gui-session-revalidation-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32), registry = new UiSnapshotRegistry();
  const identity = options.legacy ? undefined : IDENTITY;
  const windowId = opaqueWindowId(APP, 0, "Fixture", identity);
  const textRef = opaqueElementId(windowId, 1, "AXTextArea", "Text input", false);
  const visualRef = `element:${"9".repeat(48)}`;
  const elementRef = options.visual ? visualRef : textRef;
  const observation: SafeUiObservation = {
    appId: APP, windowId, windowIndex: 0, windowTitle: "Fixture", focused: true,
    nativeVisual: true, ...(identity === undefined ? {} : { nativeWindowIdentity: identity }),
    nodes: [
      { elementRef: opaqueElementId(windowId, 0, "AXWindow", "Fixture", false), role: "AXWindow", label: "Fixture",
        enabled: true, focused: false, secure: false },
      { elementRef: textRef, role: "AXTextArea", label: "Text input", enabled: true, focused: true, secure: false }
    ],
    truncated: false, warnings: [], visualRef,
    screenshot: { mode: "active_window", mimeType: "image/jpeg", base64: "approved-pixels", screenWidth: 800, screenHeight: 600,
      windowX: 0, windowY: 0, windowWidth: 800, windowHeight: 600, captureWidth: 800, captureHeight: 600, imageWidth: 800, imageHeight: 600 }
  };
  registry.recordObservation(observation, "principal-1", "session-1", NOW);
  const argumentsValue = options.tool === "mac_ui_type"
    ? { element_ref: elementRef, text: "MBA-MCP test", keys: [], submit: options.submit ?? false }
    : options.visual
      ? { element_ref: elementRef, action: "click", x: 100, y: 100 }
      : { element_ref: elementRef, action: "focus" };
  const binding = sha256(canonicalJson({ tool: options.tool, arguments: argumentsValue }));
  if (options.historicalSession) registry.retainForGuiSession(elementRef, "principal-1", "session-1", NOW,
    NOW + 30000, binding, false);
  if (options.pendingAttendedEvidence) registry.retainForApproval(elementRef, "principal-1", "session-1", NOW,
    NOW + 30000, binding);
  const executions: { authorized: boolean | undefined; strategy: string | undefined }[] = [];
  const authorizations: (boolean | undefined)[] = [];
  let nativeDispatches = 0, observations = 0;
  class Inspector extends MacUiInspectorImpl {
    override async observe() {
      observations++;
      return options.changedPixels
        ? { ...observation, screenshot: { ...observation.screenshot!, base64: "changed-caret-or-context-pixels" } }
        : observation;
    }
    override async action(execution: UiActionExecution, control: UiExecutionControl) {
      executions.push({ authorized: execution.guiSessionAuthorized, strategy: execution.snapshot.revalidationStrategy });
      return super.action(execution, control);
    }
    override async type(execution: UiTypeExecution, control: UiExecutionControl) {
      executions.push({ authorized: execution.guiSessionAuthorized, strategy: execution.snapshot.revalidationStrategy });
      return super.type(execution, control);
    }
  }
  const inspector = new Inspector({ run: async request => {
    nativeDispatches++;
    assert.equal(request.args[0], options.tool === "mac_ui_type" ? "type" : "ax_action");
    const common = { status: "ok", app_id: APP, window_index: 0, window_title: "Fixture", window_identity: IDENTITY,
      element_index: 1, role: "AXTextArea", secure: false };
    return completed(options.tool === "mac_ui_type"
      ? { ...common, characters_accepted: 12, keys_accepted: [], submitted: options.submit ?? false, focus_confirmed: true }
      : { ...common, enabled: true, focused: true, accepted: true });
  } });
  const base = createDefaultPolicy("edge-1", true, ["mac.ui.control"], ["edge-key-1"], [], [], [], [], [], [], [APP]);
  const policy = { ...base, tools: new Map(base.tools).set(options.tool, { ...base.tools.get(options.tool)!, enabled: true }) };
  const request: UnsignedBrokerRequest = {
    protocolVersion: "0.1", contractVersion: "0.1", requestId: "gui-session-case", nonce: "gui-session-case-nonce",
    tool: options.tool, arguments: argumentsValue, timestampMs: NOW, policyAudience: "mac-operator-broker",
    policyVersion: policy.version, authenticationKeyId: "edge-key-1",
    principal: { principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer", audience: "mac-operator-broker",
      scopes: ["mac.ui.control"], issuedAtMs: NOW - 1000, expiresAtMs: NOW + 60000, edgeId: "edge-1" }
  };
  function issueApproval(approvalId: string) {
    store.issueApproval({ approvalId, approverPrincipalId: "operator-1", requestingPrincipalId: "principal-1",
      tool: options.tool, contractVersion: "0.1", targetKind: "ui_element", targetRef: `ui_element:${elementRef}`,
      payloadDigest: sha256(canonicalJson(argumentsValue)), policyVersion: policy.version, approvalClass: "trusted_gui",
      unattended: false, issuedAtMs: NOW, expiresAtMs: NOW + 30000, useLimit: 1 });
  }
  if (options.attendedApproval) issueApproval("approval:attended-gui-session-case");
  const broker = new Broker({ store, policy, now: () => NOW, ordinaryGuiApplications: true, uiInspector: inspector,
    uiSnapshotRegistry: registry,
    edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key,
      notBeforeMs: NOW - 60000, expiresAtMs: NOW + 60000 }]),
    async authorizeGuiSession(operation) {
      authorizations.push(operation.requiresExplicitApproval);
      assert.equal(operation.appId, APP);
      assert.equal(operation.sessionId, "session-1");
      if (!options.sessionAllowed) return false;
      issueApproval(guiSessionApprovalId(operation.requestId));
      return true;
    }
  });
  return {
    run: () => broker.handle(signRequest(request, key)), executions, authorizations,
    nativeDispatches: () => nativeDispatches, observations: () => observations,
    async close() { await broker.close(); store.close(); await rm(directory, { recursive: true, force: true }); }
  };
}

for (const tool of ["mac_ui_action", "mac_ui_type"] as const) {
  test(`${tool} forwards current successful GUI session authorization through native AX dispatch`, async () => {
    const context = await fixture({ tool, sessionAllowed: true, changedPixels: true });
    try {
      const result = await context.run();
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.deepEqual(context.executions, [{ authorized: true, strategy: "native_ax" }]);
      assert.deepEqual(context.authorizations, [false]);
      assert.equal(context.nativeDispatches(), 1);
      assert.equal(context.observations(), 1);
    } finally { await context.close(); }
  });

  test(`${tool} attended fallback never forwards historical GUI session authorization`, async () => {
    const context = await fixture({ tool, sessionAllowed: false, changedPixels: false,
      historicalSession: true, attendedApproval: true });
    try {
      const result = await context.run();
      assert.equal(result.ok, true, JSON.stringify(result));
      assert.deepEqual(context.executions, [{ authorized: undefined, strategy: "native_ax" }]);
      assert.deepEqual(context.authorizations, [false]);
      assert.equal(context.nativeDispatches(), 1);
    } finally { await context.close(); }
  });

  test(`${tool} revoked GUI session with historical native AX evidence rejects changed pixels before dispatch`, async () => {
    const context = await fixture({ tool, sessionAllowed: false, changedPixels: true,
      historicalSession: true, attendedApproval: true });
    try {
      const result = await context.run();
      assert.equal(result.result_class, "TARGET_NOT_FOUND", JSON.stringify(result));
      assert.deepEqual(context.executions, [{ authorized: undefined, strategy: "native_ax" }]);
      assert.equal(context.nativeDispatches(), 0);
      assert.ok(context.observations() > 0);
    } finally { await context.close(); }
  });
}

for (const [name, options] of [
  ["pending attended evidence", { tool: "mac_ui_action", pendingAttendedEvidence: true }],
  ["visual reference", { tool: "mac_ui_action", visual: true }],
  ["legacy reference", { tool: "mac_ui_action", legacy: true }],
  ["explicit submission", { tool: "mac_ui_type", submit: true }]
] as const) {
  test(`current GUI session keeps exact screenshot revalidation for ${name}`, async () => {
    const context = await fixture({ ...options, sessionAllowed: true, changedPixels: true });
    try {
      const result = await context.run();
      assert.equal(result.result_class, "TARGET_NOT_FOUND", JSON.stringify(result));
      assert.deepEqual(context.executions, [{ authorized: true, strategy: "screenshot" }]);
      assert.equal(context.nativeDispatches(), 0);
      assert.deepEqual(context.authorizations, [name === "explicit submission"]);
    } finally { await context.close(); }
  });
}
