import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type BrokerResult, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { ACCESSIBILITY_BOUND_GUI_TOOLS } from "./gui-readiness.js";
import type { GuiHelperReadiness, GuiHelperReadinessProbe } from "./gui-helper-readiness.js";
import { BrokerStore } from "./persistence.js";

const NOW = 1_700_000_000_000;
const scopes: Scope[] = ["mac.control.read", "mac.app.control", "mac.ui.observe", "mac.ui.control", "mac.terminal.exec"];
const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default as new (options: Record<string, unknown>) => {
  compile(schema: object): ((value: unknown) => boolean) & { errors?: unknown };
  errorsText(errors: unknown): string;
};
const addFormats = require("ajv-formats").default as (ajv: InstanceType<typeof Ajv2020>) => void;
const ajv = new Ajv2020({ strict: true, allErrors: true });
addFormats(ajv);
const contract = JSON.parse(await readFile(new URL("../../../tool-contracts/mac_capabilities.json", import.meta.url), "utf8")) as { output_schema: object };
const validateCapabilities = ajv.compile(contract.output_schema);

interface CapabilitiesData {
  capabilities: { name: string; enabled: boolean; reason: string }[];
  permissions: { name: string; granted: boolean; reason?: string }[];
}

async function fixture(probe: GuiHelperReadinessProbe, guiEnabled = true) {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-gui-helper-broker-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const base = createDefaultPolicy("edge-1", true, scopes, ["edge-key-1"], [], [], [], [], [], [], ["bundle:com.google.Chrome"]);
  const tools = new Map(base.tools);
  for (const tool of [...ACCESSIBILITY_BOUND_GUI_TOOLS, "mac_terminal_exec"]) {
    tools.set(tool, { ...tools.get(tool)!, enabled: tool === "mac_terminal_exec" || guiEnabled });
  }
  const policy = {
    ...base,
    tools,
    targetRules: [...base.targetRules, {
      ruleId: "owner-terminal", effect: "allow" as const, principalId: "principal-1",
      scope: "mac.terminal.exec" as const, target: { kind: "host" as const, reference: "owner-terminal" }
    }]
  };
  let observations = 0;
  const broker = new Broker({
    store, policy, guiHelperReadiness: probe, guiPublicEnablement: "production", now: () => NOW,
    edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key,
      notBeforeMs: NOW - 60_000, expiresAtMs: NOW + 60_000 }]),
    ownerTerminalExecutor: {
      available: true,
      async run() { throw new Error("Capability diagnostics must not execute terminal commands"); },
      async close() {}
    },
    authorizeOwnerTerminal: async () => true,
    uiInspector: { async observe(appId, _windowHint, _maxNodes, _control, captureMode) {
      observations += 1;
      assert.equal(captureMode, "none", "A denied screenshot request must not reach the GUI adapter");
      return {
        appId, windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef", windowTitle: "Example",
        focused: true, nodes: [], truncated: false, warnings: []
      };
    } }
  });
  let sequence = 0;
  const request = (tool: string, grantedScopes: readonly Scope[] = scopes, argumentsValue: Record<string, unknown> = {}): UnsignedBrokerRequest => {
    sequence += 1;
    return {
      protocolVersion: "0.1", contractVersion: "0.1", requestId: `gui-readiness-${sequence}`,
      tool, arguments: argumentsValue, principal: {
        principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer", audience: "mac-operator-broker",
        scopes: grantedScopes, issuedAtMs: NOW - 1000, expiresAtMs: NOW + 60_000, edgeId: "edge-1"
      },
      timestampMs: NOW, nonce: `gui-readiness-nonce-${sequence}`, policyAudience: "mac-operator-broker",
      policyVersion: policy.version, authenticationKeyId: "edge-key-1"
    };
  };
  return {
    broker, store, key, request,
    observations: () => observations,
    call: (tool: string, grantedScopes: readonly Scope[] = scopes, argumentsValue: Record<string, unknown> = {}) =>
      broker.handle(signRequest(request(tool, grantedScopes, argumentsValue), key)),
    async close() {
      await broker.close();
      store.close();
      await rm(directory, { recursive: true, force: true });
    }
  };
}

function capabilities(result: BrokerResult): CapabilitiesData {
  assert.equal(result.ok, true, JSON.stringify(result));
  assert.equal(validateCapabilities(result), true, ajv.errorsText(validateCapabilities.errors));
  assert.ok(result.ok);
  return result.data as CapabilitiesData;
}

function ready(overrides: Partial<GuiHelperReadiness> = {}): GuiHelperReadiness {
  return { installed: true, identity_valid: true, accessibility: true, screen_recording: true,
    transport: "launchservices", ...overrides };
}

const unavailableCases: { name: string; state: GuiHelperReadiness }[] = [
  { name: "missing helper", state: ready({ installed: false, identity_valid: false, accessibility: null,
    screen_recording: null, reason: "GUI_HELPER_UNAVAILABLE" }) },
  { name: "invalid helper identity", state: ready({ identity_valid: false, accessibility: null,
    screen_recording: null, reason: "GUI_HELPER_UNAVAILABLE" }) },
  { name: "Accessibility denied", state: ready({ accessibility: false, reason: "ACCESSIBILITY_PERMISSION_REQUIRED" }) },
  { name: "LaunchServices permission probe unavailable", state: ready({ accessibility: null,
    screen_recording: null, reason: "GUI_HELPER_PERMISSION_PROBE_FAILED" }) }
];

for (const { name, state } of unavailableCases) {
  test(`signed capabilities diagnose ${name} without disabling terminal or health`, async () => {
    let probes = 0;
    const context = await fixture({ async probe() { probes += 1; return state; } });
    try {
      const health = await context.call("mac_health");
      assert.ok(health.ok);
      assert.equal((health.data as { overall: string }).overall, "healthy");
      assert.equal(probes, 0);
      const data = capabilities(await context.call("mac_capabilities"));
      assert.equal(probes, 1);
      for (const tool of ACCESSIBILITY_BOUND_GUI_TOOLS) {
        const capability = data.capabilities.find(value => value.name === tool);
        assert.equal(capability?.enabled, false, tool);
        assert.equal(capability?.reason, state.reason, tool);
      }
      for (const tool of ["mac_health", "mac_terminal_exec"]) {
        assert.equal(data.capabilities.find(value => value.name === tool)?.enabled, true, tool);
      }
      assert.equal(data.permissions.find(value => value.name === "gui_helper_installed")?.granted, state.installed);
      assert.equal(data.permissions.find(value => value.name === "gui_helper_identity_valid")?.granted, state.identity_valid);
      assert.equal(data.permissions.find(value => value.name === "accessibility")?.granted, false);
      assert.ok((await context.call("mac_health")).ok);
      assert.equal(probes, 1);
    } finally { await context.close(); }
  });
}

test("signed capabilities independently diagnose both denied TCC permissions", async () => {
  const context = await fixture({ async probe() {
    return ready({ accessibility: false, screen_recording: false, reason: "ACCESSIBILITY_PERMISSION_REQUIRED" });
  } });
  try {
    const data = capabilities(await context.call("mac_capabilities"));
    assert.deepEqual(data.permissions.find(value => value.name === "accessibility"), {
      name: "accessibility", granted: false, reason: "ACCESSIBILITY_PERMISSION_REQUIRED"
    });
    assert.deepEqual(data.permissions.find(value => value.name === "screen_recording"), {
      name: "screen_recording", granted: false, reason: "SCREEN_RECORDING_PERMISSION_REQUIRED"
    });
    assert.deepEqual(data.permissions.find(value => value.name === "gui_helper_launchservices"), {
      name: "gui_helper_launchservices", granted: true, reason: "transport=launchservices"
    });
  } finally { await context.close(); }
});

test("AX-only readiness keeps GUI metadata capabilities enabled and reports screenshot permission separately", async () => {
  const context = await fixture({ async probe() { return ready({ screen_recording: false, reason: "SCREEN_RECORDING_PERMISSION_REQUIRED" }); } });
  try {
    const data = capabilities(await context.call("mac_capabilities"));
    for (const tool of ACCESSIBILITY_BOUND_GUI_TOOLS) {
      assert.equal(data.capabilities.find(value => value.name === tool)?.enabled, true, tool);
    }
    assert.equal(data.permissions.find(value => value.name === "accessibility")?.granted, true);
    assert.equal(data.permissions.find(value => value.name === "screen_recording")?.granted, false);
  } finally { await context.close(); }
});

test("full readiness preserves caller scope and GUI kill-switch enforcement", async () => {
  const context = await fixture({ async probe() { return ready(); } });
  try {
    const full = capabilities(await context.call("mac_capabilities"));
    assert.ok(full.permissions.every(permission => permission.granted));
    assert.equal(full.capabilities.find(value => value.name === "mac_ui_observe")?.enabled, true);
    const limited = capabilities(await context.call("mac_capabilities", ["mac.control.read"]));
    assert.equal(limited.capabilities.find(value => value.name === "mac_ui_observe")?.reason, "scope_not_granted");
    assert.equal(limited.capabilities.find(value => value.name === "mac_terminal_exec")?.reason, "scope_not_granted");
    context.store.setSwitch("gui", true, "test-readiness-gui-switch", NOW);
    const disabled = capabilities(await context.call("mac_capabilities"));
    assert.equal(disabled.capabilities.find(value => value.name === "mac_ui_observe")?.reason, "disabled_by_kill_switch");
    assert.equal(disabled.capabilities.find(value => value.name === "mac_terminal_exec")?.enabled, true);
  } finally { await context.close(); }
});

test("signed observation fails with a helper precondition before reaching the GUI adapter", async () => {
  const context = await fixture({ async probe() { return unavailableCases[0]!.state; } });
  try {
    const result = await context.call("mac_ui_observe", scopes, { app_id: "com.google.Chrome", capture_mode: "none" });
    assert.equal(result.result_class, "PRECONDITION_FAILED");
    assert.ok(!result.ok);
    assert.match(result.error.message, /^GUI_HELPER_UNAVAILABLE:/u);
    assert.equal(context.observations(), 0);
  } finally { await context.close(); }
});

test("missing GUI helper does not consume an existing bounded mutation approval", async () => {
  const context = await fixture({ async probe() { return unavailableCases[0]!.state; } });
  const argumentsValue = { app_id: "bundle:com.google.Chrome", window_hint: "Example" };
  try {
    context.store.issueApproval({
      approvalId: "approval:helper-unavailable", approverPrincipalId: "operator-1", requestingPrincipalId: "principal-1",
      tool: "mac_app_focus", contractVersion: "0.1", targetKind: "app_window", targetRef: "app_window:window:bundle:com.google.Chrome",
      payloadDigest: sha256(canonicalJson(argumentsValue)), policyVersion: "policy-0.1", approvalClass: "trusted_gui",
      unattended: false, issuedAtMs: NOW - 1000, expiresAtMs: NOW + 1000
    });
    const result = await context.call("mac_app_focus", scopes, argumentsValue);
    assert.equal(result.result_class, "PRECONDITION_FAILED");
    assert.equal(context.store.approvalRecord("approval:helper-unavailable")?.usedCount, 0);
  } finally { await context.close(); }
});

test("signed screenshot denial preserves successful AX-only observation", async () => {
  const context = await fixture({ async probe() { return ready({ screen_recording: false, reason: "SCREEN_RECORDING_PERMISSION_REQUIRED" }); } });
  try {
    const result = await context.call("mac_ui_observe", scopes, { app_id: "com.google.Chrome", capture_mode: "active_window" });
    assert.equal(result.result_class, "POLICY_DENIED");
    assert.ok(!result.ok);
    assert.match(result.error.message, /^SCREEN_RECORDING_PERMISSION_REQUIRED:/u);
    assert.equal(context.observations(), 0);
    const metadata = await context.call("mac_ui_observe", scopes, { app_id: "com.google.Chrome", capture_mode: "none" });
    assert.ok(metadata.ok, JSON.stringify(metadata));
    assert.equal(context.observations(), 1);
    assert.equal((metadata.data as { window_id: string }).window_id, "window:0123456789abcdef0123456789abcdef0123456789abcdef");
  } finally { await context.close(); }
});

test("readiness refresh recovers after helper installation and owner TCC consent", async () => {
  let state = unavailableCases[0]!.state;
  let probes = 0;
  const context = await fixture({ async probe() { probes += 1; return state; } });
  try {
    assert.equal(capabilities(await context.call("mac_capabilities")).capabilities.find(value => value.name === "mac_ui_observe")?.enabled, false);
    state = ready({ screen_recording: false, reason: "SCREEN_RECORDING_PERMISSION_REQUIRED" });
    const ax = capabilities(await context.call("mac_capabilities"));
    assert.equal(ax.capabilities.find(value => value.name === "mac_ui_observe")?.enabled, true);
    assert.equal(ax.permissions.find(value => value.name === "screen_recording")?.granted, false);
    state = ready();
    assert.ok(capabilities(await context.call("mac_capabilities")).permissions.every(permission => permission.granted));
    assert.equal(probes, 3);
  } finally { await context.close(); }
});

test("health remains available while production GUI readiness is pending", async () => {
  let entered!: () => void;
  let finish!: (state: GuiHelperReadiness) => void;
  const started = new Promise<void>(resolve => { entered = resolve; });
  const pending = new Promise<GuiHelperReadiness>(resolve => { finish = resolve; });
  const context = await fixture({ async probe() { entered(); return pending; } });
  try {
    const diagnostic = context.call("mac_capabilities");
    await started;
    const health = await context.call("mac_health");
    assert.ok(health.ok);
    assert.equal((health.data as { overall: string }).overall, "healthy");
    finish(ready());
    capabilities(await diagnostic);
  } finally { finish(ready()); await context.close(); }
});

test("authenticated capability diagnostics reject tampering before the GUI probe", async () => {
  let probes = 0;
  const context = await fixture({ async probe() { probes += 1; return ready(); } });
  try {
    const request = signRequest(context.request("mac_health"), context.key);
    const result = await context.broker.handle({ ...request, tool: "mac_capabilities" });
    assert.equal(result.result_class, "AUTH_INVALID");
    assert.equal(probes, 0);
  } finally { await context.close(); }
});


test("capability negotiation never launches GUI readiness when no GUI tool is enabled", async () => {
  let probes = 0;
  const context = await fixture({ async probe() { probes += 1; throw new Error("GUI probe must not run"); } }, false);
  try {
    const data = capabilities(await context.call("mac_capabilities"));
    assert.deepEqual(data.permissions, []);
    assert.equal(probes, 0);
    assert.equal(data.capabilities.find(value => value.name === "mac_health")?.enabled, true);
    assert.equal(data.capabilities.find(value => value.name === "mac_terminal_exec")?.enabled, true);
  } finally { await context.close(); }
});
