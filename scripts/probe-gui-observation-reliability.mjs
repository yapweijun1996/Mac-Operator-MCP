import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { createServer } from "node:http";
import { mkdir, mkdtemp, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";
import { ownedDocumentCleanupAcknowledged } from "./gui-fixture-acknowledgment.mjs";

const exec = promisify(execFile);
const prepareOnly = process.argv.includes("--prepare-only");
const enabled = process.env.MOPS_REAL_GUI === "1";
const onlyChrome = process.env.MOPS_REAL_GUI_ONLY_CHROME === "1";
const chromeEnabled = onlyChrome || process.env.MOPS_REAL_GUI_CHROME === "1";
const chromeCuaMode = process.env.MOPS_REAL_GUI_CHROME_CUA === "1";
const appleEventsAllowed = process.env.MOPS_REAL_GUI_APPLE_EVENTS === "1";
const attendedHandoffTimeoutMs = 300_000;
const results = [];
const limitations = [];
let directory, broker, store, fixturePid, commandPath, statePath, chromeWindowId, chromeServer;
let chromeCuaCleanup, textEditCuaCleanup;
let fixtureCleanupBlocked = false;
let calculatorOwned = false, calculatorStarted = false, calculatorProcess, calculatorUtility, screenshotUtility, bundleResolutionUtility, fixtureInventory, fixtureBundleId, textEditDocument, textEditFile, textEditWindowId;
let revision = 0;
const report = value => console.log(JSON.stringify(value));
const sha256 = value => createHash("sha256").update(value).digest("hex");
const safeError = error => ({ name: error?.name ?? "Error", message: String(error?.message ?? "Probe failed").slice(0, 512) });

async function screenshotMarker(observed, diagnostics = false) {
  assert(observed.app_id === "bundle:com.apple.TextEdit" && observed.window_title === basename(textEditFile) && observed.focused,
    "OCR input must be the exact owned TextEdit fixture window");
  assert(observed.screenshot?.mode === "active_window", "OCR requires a fresh authorized window capture");
  const input = Buffer.from(observed.screenshot.image_base64, "base64");
  assert(input.length > 0 && input.length <= 480_000, "OCR screenshot exceeds the bounded image budget");
  return new Promise((resolve, reject) => {
    const child = spawn(screenshotUtility, diagnostics ? ["--diagnostics"] : [], { stdio: ["pipe", "pipe", "pipe"], env: { PATH: "/usr/bin:/bin" } });
    let output = "", outputBytes = 0, settled = false;
    const finish = (error, value) => {
      if (settled) return;
      settled = true; clearTimeout(timer);
      if (error) reject(error); else resolve(value);
    };
    const timer = setTimeout(() => { child.kill("SIGKILL"); finish(new Error("Fixture screenshot OCR timed out")); }, 10_000);
    child.stdout.on("data", chunk => { outputBytes += chunk.length; if (outputBytes > 4096) { child.kill("SIGKILL"); finish(new Error("Fixture OCR exceeded its output budget")); } else output += chunk; });
    child.stderr.on("data", chunk => { outputBytes += chunk.length; if (outputBytes > 4096) { child.kill("SIGKILL"); finish(new Error("Fixture OCR exceeded its output budget")); } });
    child.on("error", error => finish(error));
    child.on("close", code => {
      if (settled) return;
      try {
        assert.equal(code, 0, "Fixture screenshot OCR failed");
        const result = JSON.parse(output);
        if (!diagnostics) assert.deepEqual(Object.keys(result), ["marker_present"]);
        assert.equal(typeof result.marker_present, "boolean");
        finish(undefined, diagnostics ? result : result.marker_present);
      } catch (error) { finish(error); }
    });
    child.stdin.on("error", () => { /* The bounded child close result remains authoritative. */ });
    child.stdin.end(input);
  });
}

async function calculatorIdentity() {
  const output = await exec(calculatorUtility, ["snapshot"], { timeout: 5000, killSignal: "SIGKILL", maxBuffer: 4096 });
  const value = JSON.parse(output.stdout);
  assert(!value.error, "Calculator process identity is unavailable or ambiguous");
  return value;
}
async function quitOwnedCalculator() {
  if (!calculatorOwned || !calculatorStarted || !calculatorProcess) return;
  const current = await calculatorIdentity();
  if (!current.running) { calculatorStarted = false; calculatorProcess = undefined; return; }
  assert(current.pid === calculatorProcess.pid && current.generation === calculatorProcess.generation,
    "Owned Calculator process identity changed; cleanup refused");
  const output = await exec(calculatorUtility, ["terminate", String(current.pid), current.generation],
    { timeout: 5000, killSignal: "SIGKILL", maxBuffer: 4096 });
  const result = JSON.parse(output.stdout);
  assert(result.generation_matched && result.stopped, "macOS did not confirm graceful termination of the owned Calculator process");
  calculatorStarted = false; calculatorProcess = undefined;
}

async function waitFor(description, read, predicate, timeoutMs = 10_000) {
  const deadline = Date.now() + timeoutMs;
  do {
    let value;
    try { value = await read(); } catch (error) { if (error?.code !== "ENOENT") throw error; }
    if (value !== undefined && predicate(value)) return value;
    await delay(Math.min(50, Math.max(1, deadline - Date.now())));
  } while (Date.now() < deadline);
  throw new Error(`Readiness timeout: ${description}`);
}

async function fixtureState() { return JSON.parse(await readFile(statePath, "utf8")); }
async function command(operation) {
  const expectedRevision = ++revision;
  await writeFile(`${commandPath}.next`, JSON.stringify({ revision: expectedRevision, operation }), { mode: 0o600 });
  await rename(`${commandPath}.next`, commandPath);
  return waitFor(`fixture command ${operation}`, fixtureState, state => state.revision === expectedRevision);
}

async function check(name, run) {
  try {
    const evidence = await run();
    results.push({ name, status: "passed", ...evidence });
  } catch (error) { results.push({ name, status: "failed", error: safeError(error) }); }
  report(results.at(-1));
}

async function buildFixture(runId) {
  const app = join(directory, "MBA-MCP Reliability Fixture.app");
  const contents = join(app, "Contents");
  await mkdir(join(contents, "MacOS"), { recursive: true });
  const bundleId = `dev.macoperator.gui-reliability.${runId}`;
  await writeFile(join(contents, "Info.plist"), `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>CFBundleIdentifier</key><string>${bundleId}</string>
<key>CFBundleName</key><string>MBA-MCP Reliability Fixture</string>
<key>CFBundleExecutable</key><string>fixture</string><key>CFBundlePackageType</key><string>APPL</string>
<key>NSHighResolutionCapable</key><true/></dict></plist>\n`);
  const source = fileURLToPath(new URL("./fixtures/gui-reliability-app.m", import.meta.url));
  await exec("/usr/bin/clang", ["-fobjc-arc", "-framework", "AppKit", source, "-o", join(contents, "MacOS", "fixture")],
    { timeout: 60_000, maxBuffer: 64_000 });
  await exec("/usr/bin/codesign", ["--force", "--sign", "-", app], { timeout: 10_000, maxBuffer: 16_384 });
  calculatorUtility = join(directory, "owned-calculator-process");
  await exec("/usr/bin/clang", ["-fobjc-arc", "-framework", "AppKit",
    fileURLToPath(new URL("./fixtures/gui-owned-calculator-process.m", import.meta.url)), "-o", calculatorUtility],
    { timeout: 60_000, maxBuffer: 64_000 });
  screenshotUtility = join(directory, "fixture-screenshot-check");
  await exec("/usr/bin/clang", ["-fobjc-arc", "-framework", "Foundation", "-framework", "Vision", "-framework", "ImageIO",
    fileURLToPath(new URL("./fixtures/gui-fixture-screenshot-check.m", import.meta.url)), "-o", screenshotUtility],
    { timeout: 60_000, maxBuffer: 64_000 });
  bundleResolutionUtility = join(directory, "fixture-bundle-resolution");
  await exec("/usr/bin/clang", ["-fobjc-arc", "-framework", "AppKit",
    fileURLToPath(new URL("./fixtures/gui-fixture-bundle-resolution.m", import.meta.url)), "-o", bundleResolutionUtility],
    { timeout: 60_000, maxBuffer: 64_000 });
  return { app, appId: `bundle:${bundleId}` };
}

async function main() {
  if (process.platform !== "darwin" || (!enabled && !prepareOnly)) {
    report({ status: "skipped", reason: process.platform !== "darwin" ? "macOS required" : "Set MOPS_REAL_GUI=1 for attended integration", failClosed: true });
    return;
  }
  assert(Number(process.versions.node.split(".")[0]) >= 24, "Use Node.js 24 or newer for the production process supervisor");
  directory = await mkdtemp(join(tmpdir(), "mba-mcp-gui-probe-"));
  const runId = randomBytes(6).toString("hex");
  const fixture = await buildFixture(runId);
  if (prepareOnly) { report({ status: "prepared", fixtureCompiled: true, calculatorUtilityCompiled: true, screenshotUtilityCompiled: true, bundleResolutionUtilityCompiled: true, uiExecuted: false }); return; }

  const { Broker } = await import("../packages/broker/dist/broker.js");
  const { BrokerStore, guiSessionApprovalId } = await import("../packages/broker/dist/persistence.js");
  const { createDefaultPolicy } = await import("../packages/broker/dist/default-policy.js");
  const { EdgeKeyring } = await import("../packages/broker/dist/edge-keyring.js");
  const { GuiProcessSupervisor, guiApplicationExecutable } = await import("../packages/broker/dist/gui-process-supervisor.js");
  const { MacUiInspectorImpl } = await import("../packages/broker/dist/ui-inspector.js");
  const { AppControlInspectorImpl } = await import("../packages/broker/dist/app-control.js");
  const { AppInventoryInspectorImpl } = await import("../packages/broker/dist/app-inspector.js");
  const { MacGuiHelperReadinessProbe } = await import("../packages/broker/dist/gui-helper-readiness.js");
  const { canonicalJson, sha256: contractSha256, signRequest } = await import("../packages/contracts/dist/index.js");
  const supervisor = new GuiProcessSupervisor();
  const readiness = new MacGuiHelperReadinessProbe(undefined, timeoutMs => supervisor.run({ executable: guiApplicationExecutable,
    args: ["permission"], cwd: "/", environment: {}, timeoutMs, outputCapBytes: 4096 }),
    { requireOrdinaryApplications: true, productionCapabilities: timeoutMs => supervisor.run({ executable: guiApplicationExecutable,
      args: ["capabilities"], cwd: "/", environment: {}, timeoutMs, outputCapBytes: 4096 }) });
  const ready = await readiness.probe();
  report({ name: "production_helper", ...ready, node: process.version,
    helper_sha256: sha256(await readFile(guiApplicationExecutable)) });
  assert(ready.installed && ready.identity_valid && ready.accessibility && ready.screen_recording && ready.ordinary_apps && ready.desktop_surfaces,
    `Production GUI prerequisite unavailable: ${ready.reason ?? "permission or capability missing"}`);

  const inventory = new AppInventoryInspectorImpl();
  fixtureInventory = inventory; fixtureBundleId = fixture.appId;
  const appControl = new AppControlInspectorImpl(inventory, supervisor);
  const control = { timeoutMs: 15_000, shouldCancel: () => false };
  const beforeCalculator = await calculatorIdentity();
  const beforeApps = await inventory.list(true, false, control);
  calculatorOwned = !beforeApps.truncated && !beforeCalculator.running && !beforeApps.apps.some(app => app.appId === "bundle:com.apple.calculator");
  report({ name: "calculator_initial_ownership", helper_running: beforeCalculator.running,
    inventory_running: beforeApps.apps.some(app => app.appId === "bundle:com.apple.calculator"),
    inventory_truncated: beforeApps.truncated, owned_cold_start_eligible: calculatorOwned });
  const appIds = onlyChrome ? ["bundle:com.google.Chrome"] : [fixture.appId, "bundle:com.apple.TextEdit", "bundle:com.apple.calculator",
    ...(chromeEnabled ? ["bundle:com.google.Chrome"] : [])];
  const scopes = ["mac.app.control", "mac.ui.observe", "mac.ui.control"];
  const base = createDefaultPolicy("edge-1", true, scopes, ["edge-key-1"], [], [], [], [], [], [], appIds);
  const policy = { ...base, tools: new Map(base.tools) };
  for (const name of ["mac_app_open", "mac_app_focus", "mac_ui_observe", "mac_ui_action", "mac_ui_type"])
    policy.tools.set(name, { ...policy.tools.get(name), enabled: true });
  const key = randomBytes(32), startedAt = Date.now();
  store = new BrokerStore(join(directory, "broker.sqlite"));
  const ordinaryAxRefs = new Set();
  let delegatedRequest;
  broker = new Broker({ store, policy,
    edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key,
      notBeforeMs: startedAt - 1000, expiresAtMs: startedAt + 3_600_000 }]),
    appInspector: inventory, appControlInspector: appControl, uiInspector: new MacUiInspectorImpl(supervisor),
    guiHelperReadiness: readiness, ordinaryGuiApplications: true,
    async authorizeGuiSession(operation) {
      if (!delegatedRequest || operation.requestId !== delegatedRequest.requestId || operation.requiresExplicitApproval ||
          operation.principalId !== "principal-1" || operation.sessionId !== `probe-${runId}` ||
          !appIds.includes(operation.appId) || operation.tool !== delegatedRequest.tool ||
          operation.payloadDigest !== contractSha256(canonicalJson(delegatedRequest.arguments)) ||
          operation.targetKind !== "ui_element" || operation.targetRef !== `ui_element:${delegatedRequest.arguments.element_ref}`) return false;
      store.issueApproval({ approvalId: guiSessionApprovalId(operation.requestId), approverPrincipalId: "operator-1",
        requestingPrincipalId: operation.principalId, tool: operation.tool, contractVersion: operation.contractVersion,
        targetKind: operation.targetKind, targetRef: operation.targetRef, payloadDigest: operation.payloadDigest,
        policyVersion: operation.policyVersion, approvalClass: "trusted_gui", unattended: false, useLimit: 1,
        issuedAtMs: Date.now(), expiresAtMs: Math.min(Date.now() + 30_000, operation.expiresAtMs) });
      return true;
    } });
  let requestCounter = 0;
  function request(tool, argumentsValue) {
    const now = Date.now(), id = `gui-probe-${runId}-${++requestCounter}`;
    return { protocolVersion: "0.1", contractVersion: "0.1", requestId: id, tool, arguments: argumentsValue,
      principal: { principalId: "principal-1", sessionId: `probe-${runId}`, issuer: "test-issuer", audience: "mac-operator-broker",
        scopes, issuedAtMs: now - 1000, expiresAtMs: startedAt + 3_600_000, edgeId: "edge-1" },
      timestampMs: now, nonce: `${id}-nonce`, policyAudience: "mac-operator-broker", policyVersion: policy.version,
      authenticationKeyId: "edge-key-1" };
  }
  async function call(tool, args, approved = true) {
    const ordinarySession = approved && ordinaryAxRefs.has(args.element_ref) &&
      (tool === "mac_ui_type" ? args.submit === false && !/[\r\n]/u.test(args.text ?? "") && !(args.keys ?? []).includes("ENTER")
        : tool === "mac_ui_action" && ["focus", "press", "select"].includes(args.action));
    if (approved && !ordinarySession && ["mac_ui_action", "mac_ui_type"].includes(tool)) {
      const preview = await broker.handle(signRequest(request(tool, args), key));
      assert(!preview.ok && preview.result_class === "POLICY_DENIED", `UI approval preview failed: ${JSON.stringify(preview)}`);
    }
    const req = request(tool, args);
    if (approved && !ordinarySession && tool !== "mac_ui_observe") {
      const targetKind = tool === "mac_app_open" ? "app" : tool === "mac_app_focus" ? "app_window" : "ui_element";
      const targetRef = targetKind === "app" ? `app:${args.app_id}` : targetKind === "app_window"
        ? `app_window:window:${args.app_id}` : `ui_element:${args.element_ref}`;
      store.issueApproval({ approvalId: `approval:${req.requestId}`, approverPrincipalId: "operator-1", requestingPrincipalId: "principal-1",
        tool, contractVersion: "0.1", targetKind, targetRef, payloadDigest: contractSha256(canonicalJson(args)),
        policyVersion: policy.version, approvalClass: "trusted_gui", unattended: false,
        issuedAtMs: Date.now(), expiresAtMs: Date.now() + 30_000 });
    }
    let result;
    delegatedRequest = ordinarySession ? req : undefined;
    try { result = await broker.handle(signRequest(req, key)); }
    finally { delegatedRequest = undefined; }
    if (tool === "mac_app_open" && args.app_id === "bundle:com.apple.calculator" && result.ok && calculatorOwned) {
      if (result.data.state === "launched") {
        calculatorProcess = await calculatorIdentity();
        assert(calculatorProcess.running, "Launched Calculator process identity could not be bound");
        calculatorStarted = true;
      } else if (!calculatorProcess) calculatorOwned = false;
    }
    if (tool === "mac_app_open" && args.app_id === "bundle:com.apple.calculator") report({ name: "calculator_open_ownership",
      result_class: result.result_class, open_state: result.data?.state ?? null, owned: calculatorOwned,
      exact_process_bound: Boolean(calculatorProcess), before_helper_running: beforeCalculator.running,
      before_inventory_running: beforeApps.apps.some(app => app.appId === "bundle:com.apple.calculator") });
    return result;
  }
  const success = result => { assert.equal(result.ok, true, JSON.stringify(result)); return result.data; };
  const denied = (result, classes) => { assert.equal(result.ok, false); assert(classes.includes(result.result_class), JSON.stringify(result)); return { result_class: result.result_class, error: result.error?.message }; };
  const observe = async (appId, windowHint, mode = "active_window") => {
    const observed = success(await call("mac_ui_observe",
      { app_id: appId, ...(windowHint ? { window_hint: windowHint } : {}), capture_mode: mode, max_nodes: 500 }));
    for (const target of observed.nodes) if (!target.secure && ["AXTextArea", "AXTextField", "AXComboBox", "AXCheckBox"].includes(target.role)) ordinaryAxRefs.add(target.element_ref);
    return observed;
  };
  const focus = async (appId, windowHint) => success(await call("mac_app_focus", { app_id: appId, ...(windowHint ? { window_hint: windowHint } : {}) }));
  const node = (observation, role, label) => { const found = observation.nodes.find(value => value.role === role && (label === undefined || value.label === label)); assert(found, `Fixture ${role} not observed`); return found; };
  const summary = observation => ({ app_id: observation.app_id, window_id: observation.window_id,
    focused: observation.focused, nodes: observation.nodes.length, screenshot_sha256: observation.screenshot ? sha256(Buffer.from(observation.screenshot.image_base64, "base64")) : null });

  if (onlyChrome) {
    assert(chromeCuaMode || appleEventsAllowed, "Chrome-only integration requires exact CUA owned-tab handoff or existing AppleEvents access");
    report({ name: "chrome_only_scope", status: "selected", gui_app_ids: appIds,
      reason: "Repeat only the authorized Chrome acceptance flow; previously verified TextEdit, Calculator, and fixture flows are not rerun" });
    await chromeChecks({ call, success, denied, observe, focus, node, summary, runId });
    report({ status: results.some(result => result.status === "failed") ? "failed" : "passed", mode: "chrome_only",
      checks: results.length, passed: results.filter(result => result.status === "passed").length,
      screenshots_persisted: false, persistent_policy_changed: false });
    if (results.some(result => result.status === "failed")) process.exitCode = 1;
    return;
  }

  statePath = join(directory, "fixture-state.json"); commandPath = join(directory, "fixture-command.json");
  await exec("/usr/bin/open", ["-n", fixture.app, "--args", statePath, commandPath], { timeout: 10_000, maxBuffer: 16_384 });
  const initialState = await waitFor("Cocoa fixture ready", fixtureState, state => state.ready && `bundle:${state.bundle_id}` === fixture.appId);
  fixturePid = initialState.pid;
  // Native focus rejects a locked desktop or authorization session before activation.
  await focus(fixture.appId, "MBA-MCP Fixture Primary");
  await check("fixture_explicit_path_setup_focus_observe", async () => {
    await focus(fixture.appId, "MBA-MCP Fixture Primary");
    return { setup: "explicit_owned_temporary_app_path", ...summary(await observe(fixture.appId)) };
  });
  const bundleResolution = JSON.parse((await exec(bundleResolutionUtility, [fixture.appId.slice(7), fixture.app],
    { timeout: 5000, killSignal: "SIGKILL", maxBuffer: 4096 })).stdout);
  const fixtureOpen = await call("mac_app_open", { app_id: fixture.appId });
  report({ name: "temporary_fixture_mac_app_open", status: fixtureOpen.ok ? "passed" : "skipped", result_class: fixtureOpen.result_class,
    required_acceptance_flow: false, reason: fixtureOpen.ok ? undefined : "Temporary bundle registration diagnostic; required Flow A is independently tested with TextEdit, Calculator, and authorized Chrome",
    open_state: fixtureOpen.data?.state ?? null, error: fixtureOpen.ok ? undefined : fixtureOpen.error, launchservices: bundleResolution });
  for (const delayMs of [0, 750]) await check(`fresh_toolbar_ref_${delayMs}ms`, async () => {
    await command("focus_text");
    const observed = await observe(fixture.appId);
    const combo = node(observed, "AXComboBox", "Font size");
    await delay(delayMs);
    const result = await call("mac_ui_action", { element_ref: combo.element_ref, action: "focus" });
    const data = success(result);
    return { before: { role: combo.role, focused: combo.focused, secure: combo.secure }, after: data.reobserved, result_class: result.result_class };
  });
  await check("ordinary_textarea_input", async () => {
    await command("clear_text"); await command("focus_text");
    const observed = await observe(fixture.appId);
    const text = node(observed, "AXTextArea", "Ordinary fixture text");
    const result = await call("mac_ui_type", { element_ref: text.element_ref, text: "MBA-MCP test", submit: false });
    const data = success(result);
    const after = await waitFor("typed fixture text", fixtureState, state => state.text === "MBA-MCP test");
    assert(data.characters_accepted > 0 && data.focus_confirmed);
    return { before: { focused: text.focused, secure: text.secure }, after: { text: after.text, characters_accepted: data.characters_accepted, focus_confirmed: data.focus_confirmed }, ...summary(await observe(fixture.appId)) };
  });
  for (const effect of ["unchanged", "changed"]) await check(`visual_checkbox_${effect}`, async () => {
    await command(`${effect}_checkbox`); await command("focus_window");
    const observed = await observe(fixture.appId), before = await fixtureState();
    assert.equal(before.checked, false);
    const result = await call("mac_ui_action", { element_ref: observed.visual_ref, action: "click", ...before.checkbox_point });
    const data = success(result);
    assert.equal(result.verification.dispatch_status, "verified");
    assert.equal(result.verification.postcondition_status, "unknown");
    const after = await waitFor("checkbox event processed", fixtureState,
      state => state.checkbox_activations > before.checkbox_activations && state.checked === (effect === "changed"));
    const reobserved = await observe(fixture.appId);
    assert.equal(observed.window_id, reobserved.window_id);
    assert(data.visual_ref && data.screenshot);
    return { before: { checked: before.checked, activations: before.checkbox_activations },
      after: { checked: after.checked, activations: after.checkbox_activations }, expected_postcondition_satisfied: after.checked,
      verification: result.verification, window_id: reobserved.window_id, screenshot_sha256: sha256(Buffer.from(data.screenshot.image_base64, "base64")) };
  });
  await check("secure_field_denied", async () => {
    await command("focus_secure");
    const observed = await observe(fixture.appId), secure = observed.nodes.find(value => value.secure && value.focused);
    assert(secure, "Focused secure fixture field must be observable as redacted secure metadata");
    return { layer: "broker_pre_dispatch_secure_ref_guard", native_type_dispatched: false,
      ...denied(await call("mac_ui_type", { element_ref: secure.element_ref, text: "public probe marker", submit: false }, false), ["SECRET_BOUNDARY_DENIED"]) };
  });
  await command("focus_text");
  await check("element_disappearance_denied", async () => {
    const before = await observe(fixture.appId), checkbox = node(before, "AXCheckBox", "Fixture checkbox");
    await command("hide_checkbox");
    const result = await call("mac_ui_action", { element_ref: checkbox.element_ref, action: "press" });
    await command("show_checkbox");
    return denied(result, ["TARGET_NOT_FOUND"]);
  });
  await check("cross_window_ref_denied", async () => {
    await focus(fixture.appId, "MBA-MCP Fixture Primary");
    const observed = await observe(fixture.appId), combo = node(observed, "AXComboBox", "Font size");
    await command("show_second"); await focus(fixture.appId, "MBA-MCP Fixture Secondary");
    const after = await observe(fixture.appId);
    assert.notEqual(after.window_id, observed.window_id);
    const result = await call("mac_ui_action", { element_ref: combo.element_ref, action: "focus" });
    await focus(fixture.appId, "MBA-MCP Fixture Primary");
    return { before_window: observed.window_id, after_window: after.window_id, ...denied(result, ["TARGET_NOT_FOUND", "PRECONDITION_FAILED"]) };
  });
  await check("cross_app_ref_and_nonfrontmost_denied", async () => {
    await focus(fixture.appId, "MBA-MCP Fixture Primary");
    const observed = await observe(fixture.appId), combo = node(observed, "AXComboBox", "Font size");
    success(await call("mac_app_open", { app_id: "bundle:com.apple.calculator" })); await focus("bundle:com.apple.calculator");
    const action = denied(await call("mac_ui_action", { element_ref: combo.element_ref, action: "focus" }), ["TARGET_NOT_FOUND", "PRECONDITION_FAILED"]);
    const nonfrontmost = denied(await call("mac_ui_observe", { app_id: fixture.appId, capture_mode: "none" }), ["PRECONDITION_FAILED"]);
    await focus(fixture.appId, "MBA-MCP Fixture Primary");
    return { action, nonfrontmost };
  });
  await check("unauthorized_screen_boundary_denied", async () => {
    // Calculator's visible window is outside this app_window capture authority.
    await focus(fixture.appId, "MBA-MCP Fixture Primary");
    return denied(await call("mac_ui_observe", { app_id: fixture.appId, capture_mode: "screen" }), ["SECRET_BOUNDARY_DENIED"]);
  });
  await check("expired_ref_denied", async () => {
    const observed = await observe(fixture.appId), combo = node(observed, "AXComboBox", "Font size");
    // This deliberately exercises the actual 30-second reference lifetime.
    await delay(30_100);
    return denied(await call("mac_ui_action", { element_ref: combo.element_ref, action: "focus" }, false), ["TARGET_NOT_FOUND"]);
  });

  if (calculatorOwned) for (let attempt = 1; attempt <= 3; attempt++) await check(`calculator_cold_start_${attempt}`, async () => {
    await quitOwnedCalculator();
    const opened = success(await call("mac_app_open", { app_id: "bundle:com.apple.calculator" }));
    assert.equal(opened.state, "launched");
    const focused = await focus("bundle:com.apple.calculator"), observed = await observe("bundle:com.apple.calculator");
    assert.equal(focused.window_id, observed.window_id);
    return { open_state: opened.state, ...summary(observed) };
  });
  else report({ name: "calculator_cold_start", status: "skipped", reason: "Preexisting Calculator is outside fixture cleanup ownership" });
  for (let attempt = 1; attempt <= 3; attempt++) await check(`calculator_already_running_${attempt}`, async () => {
    const opened = success(await call("mac_app_open", { app_id: "bundle:com.apple.calculator" }));
    assert.equal(opened.state, "already_running");
    await focus(fixture.appId, "MBA-MCP Fixture Primary");
    const focused = await focus("bundle:com.apple.calculator"), observed = await observe("bundle:com.apple.calculator");
    assert.equal(focused.window_id, observed.window_id);
    return { open_state: opened.state, activated_from_fixture_background: true, ...summary(observed) };
  });
  await quitOwnedCalculator();

  textEditFile = join(directory, `MBA-MCP Probe ${runId}.rtf`);
  // A real empty paragraph retains its 24-point insertion attributes; a bare
  // whitespace run can reopen with TextEdit's default 12-point typing style.
  await writeFile(textEditFile, "{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0 Helvetica;}}\\pard\\plain\\f0\\fs48\\par}\n");
  await check("textedit_open_focus_observe_type", async () => {
    const opened = success(await call("mac_app_open", { app_id: "bundle:com.apple.TextEdit" }));
    await exec("/usr/bin/open", ["-b", "com.apple.TextEdit", textEditFile], { timeout: 10_000, maxBuffer: 16_384 });
    textEditDocument = basename(textEditFile);
    await focus("bundle:com.apple.TextEdit", basename(textEditFile));
    const original = await observe("bundle:com.apple.TextEdit", basename(textEditFile));
    textEditWindowId = original.window_id;
    assert.equal(await screenshotMarker(original), false, "Empty owned TextEdit fixture must not contain the test marker");
    const fontSize = original.nodes.find(value => value.role === "AXComboBox" && /\bfont\s+size\b/iu.test(value.label ?? "") && value.enabled && !value.secure);
    assert(fontSize, "Owned rich TextEdit document must expose its ordinary font-size AXComboBox");
    const toolbar = success(await call("mac_ui_action", { element_ref: fontSize.element_ref, action: "focus" }));
    const afterToolbar = await observe("bundle:com.apple.TextEdit", basename(textEditFile));
    assert.equal(original.window_id, afterToolbar.window_id);
    const editor = afterToolbar.nodes.find(value => value.role === "AXTextArea" && value.enabled && !value.secure);
    assert(editor, "Owned TextEdit document editor disappeared after toolbar focus");
    success(await call("mac_ui_action", { element_ref: editor.element_ref, action: "focus" }));
    const observed = await observe("bundle:com.apple.TextEdit", basename(textEditFile)), text = observed.nodes.find(value => value.role === "AXTextArea" && value.focused && !value.secure);
    assert(text, "Owned TextEdit document needs a focused non-secure AXTextArea");
    const typed = success(await call("mac_ui_type", { element_ref: text.element_ref, text: "MBA-MCP test", submit: false }));
    assert(typed.characters_accepted > 0 && typed.focus_confirmed);
    let after, ocrObservations = 0;
    try {
      await waitFor("fresh TextEdit screenshot marker", async () => {
        after = await observe("bundle:com.apple.TextEdit", basename(textEditFile));
        assert.equal(observed.window_id, after.window_id);
        const present = await screenshotMarker(after); ocrObservations++;
        report({ name: "textedit_marker_readiness", observation: ocrObservations, marker_present: present,
          characters_accepted: typed.characters_accepted, focus_confirmed: typed.focus_confirmed,
          screenshot_sha256: sha256(Buffer.from(after.screenshot.image_base64, "base64")) });
        return present;
      }, present => present === true, 10_000);
    } catch (error) {
      if (after?.window_id === observed.window_id && after.screenshot) {
        try { report({ name: "textedit_marker_failure_diagnostics", window_id: after.window_id,
          characters_accepted: typed.characters_accepted, focus_confirmed: typed.focus_confirmed,
          screenshot_sha256: sha256(Buffer.from(after.screenshot.image_base64, "base64")),
          diagnostics: await screenshotMarker(after, true) }); }
        catch (diagnosticError) { report({ name: "textedit_marker_failure_diagnostics", error: safeError(diagnosticError) }); }
      }
      throw error;
    }
    let independentlyReadText;
    if (appleEventsAllowed) {
      const readback = await exec("/usr/bin/osascript", ["-e", `tell application id "com.apple.TextEdit" to get text of document ${JSON.stringify(basename(textEditFile))}`],
        { timeout: 5000, killSignal: "SIGKILL", maxBuffer: 4096 });
      assert.equal(readback.stdout.trim(), "MBA-MCP test"); independentlyReadText = readback.stdout.trim();
    }
    return { open_state: opened.state, characters_accepted: typed.characters_accepted, focus_confirmed: typed.focus_confirmed,
      toolbar_before: { role: fontSize.role, focused: fontSize.focused, secure: fontSize.secure }, toolbar_after: toolbar.reobserved,
      independent_readback: "fresh_authorized_screenshot_marker_ocr", marker_before: false, marker_after: true, ocr_observations: ocrObservations,
      ...(independentlyReadText === undefined ? {} : { independently_read_text: independentlyReadText }),
      ...summary(after) };
  });
  if (chromeEnabled && (appleEventsAllowed || chromeCuaMode)) await chromeChecks({ call, success, denied, observe, focus, node, summary, runId });
  else if (chromeEnabled) {
    limitations.push("Chrome fixture setup requires explicit CUA owned-tab delegation or separately established AppleEvents access");
    report({ name: "chrome", status: "blocked", reason: limitations.at(-1) });
  }
  else report({ name: "chrome", status: "skipped", reason: "Set MOPS_REAL_GUI_CHROME=1 after authorizing the dedicated local fixture window" });
  report({ name: "physical_protected_session_and_system_auth_dialog", status: "not_exercised",
    reason: "The probe does not lock the desktop or create real system authentication UI; native protected-session guards apply to every real GUI action" });
  report({ status: results.some(result => result.status === "failed") ? "failed" : limitations.length ? "limited" : "passed", checks: results.length, limitations,
    passed: results.filter(result => result.status === "passed").length, screenshots_persisted: false, persistent_policy_changed: false });
  if (results.some(result => result.status === "failed")) process.exitCode = 1;
}

async function chromeChecks({ call, success, denied, observe, focus, node, summary, runId }) {
  let browserState, ownedTab, tabClosed = false, textEditClosed = false;
  const title = `MBA-MCP Browser Probe ${runId}`;
  const pagePath = `/probe/${runId}`, stateEndpoint = `/state/${runId}`;
  const createdEndpoint = `/control/${runId}/tab-created`, closedEndpoint = `/control/${runId}/tab-closed`;
  const textEditClosedEndpoint = `/control/${runId}/textedit-closed`;
  const html = `<!doctype html><html><head><title>${title}</title></head><body style="font:20px system-ui;padding:40px">
<textarea aria-label="Ordinary fixture textarea" style="width:500px;height:160px"></textarea><p><label><input id="check" type="checkbox">Fixture checkbox</label></p>
<input type="password" aria-label="Protected fixture input"><script>
let checkboxActivations=0;
document.querySelector('#check').addEventListener('click',()=>{checkboxActivations++;});
function state(){const c=document.querySelector('#check'),r=c.getBoundingClientRect();fetch(${JSON.stringify(stateEndpoint)},{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({probe_id:${JSON.stringify(runId)},text:document.querySelector('textarea').value,checked:c.checked,checkbox_activations:checkboxActivations,page_focused:document.hasFocus(),visible:document.visibilityState==='visible',point:{x:screenX+(outerWidth-innerWidth)/2+r.x+r.width/2,y:screenY+outerHeight-innerHeight+r.y+r.height/2}})});}
addEventListener('input',state);addEventListener('change',state);addEventListener('resize',state);setInterval(state,100);state();
</script></body></html>`;
  let url;
  chromeServer = createServer((req, res) => {
    if (req.method === "GET" && req.url === pagePath) { res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" }); res.end(html); return; }
    if (req.method === "POST" && [stateEndpoint, createdEndpoint, closedEndpoint, textEditClosedEndpoint].includes(req.url)) {
      let body = "";
      req.setTimeout(3000, () => req.destroy());
      req.on("data", chunk => { body += chunk; if (body.length > 8192) req.destroy(); });
      req.on("end", () => {
        let accepted = false;
        try {
          const value = JSON.parse(body);
          if (chromeCuaMode && req.url === textEditClosedEndpoint && textEditDocument && ownedDocumentCleanupAcknowledged(value,
              { probe_id: runId, app_id: "bundle:com.apple.TextEdit", document_title: textEditDocument,
                document_path: textEditFile, window_id: textEditWindowId ?? null })) {
            textEditClosed = true; accepted = true;
          } else if (value.probe_id === runId && req.url === stateEndpoint && typeof value.text === "string" && value.text.length <= 1024 &&
              typeof value.checked === "boolean" && Number.isSafeInteger(value.checkbox_activations) && value.checkbox_activations >= 0 &&
              typeof value.page_focused === "boolean" && typeof value.visible === "boolean" &&
              Number.isFinite(value.point?.x) && Number.isFinite(value.point?.y)) {
            browserState = { text: value.text, checked: value.checked, checkbox_activations: value.checkbox_activations,
              page_focused: value.page_focused, visible: value.visible, point: value.point };
            accepted = true;
          } else if (chromeCuaMode && value.probe_id === runId && value.url === url && typeof value.tab_id === "string" &&
              value.tab_id.length > 0 && value.tab_id.length <= 128 && !/[\r\n]/u.test(value.tab_id)) {
            if (req.url === createdEndpoint && (!ownedTab || ownedTab.tab_id === value.tab_id)) {
              const windowTitle = typeof value.window_title === "string" && value.window_title.includes(title) &&
                value.window_title.length <= 256 && !/[\u0000-\u001f\u007f]/u.test(value.window_title) ? value.window_title : undefined;
              ownedTab = { probe_id: runId, tab_id: value.tab_id, url, ...(windowTitle ? { window_title: windowTitle } : {}) }; accepted = true;
            } else if (req.url === closedEndpoint && ownedTab?.tab_id === value.tab_id && value.closed === true) {
              tabClosed = true; accepted = true;
            }
          }
        } catch { /* Reject malformed owned-fixture telemetry and cleanup acknowledgments. */ }
        res.writeHead(accepted ? 204 : 400); res.end();
      });
      return;
    }
    res.writeHead(404); res.end();
  });
  await new Promise(resolve => chromeServer.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${chromeServer.address().port}`;
  url = `${origin}${pagePath}`;
  if (chromeCuaMode) textEditCuaCleanup = async () => {
    if (!textEditDocument) return;
    report({ name: "textedit_cua_owned_document_cleanup_requested", probe_id: runId, app_id: "bundle:com.apple.TextEdit",
      document_title: textEditDocument, document_path: textEditFile, window_id: textEditWindowId ?? null,
      acknowledge_url: `${origin}${textEditClosedEndpoint}`,
      required_evidence: "Root must close only this owned test document with CUA, discard only its unsaved public marker, and independently confirm the exact document window is absent before acknowledging closed=true and independently_confirmed_absent=true" });
    await waitFor("root-owned TextEdit document close acknowledgment", async () => textEditClosed, value => value === true, attendedHandoffTimeoutMs);
    report({ name: "owned_textedit_cleanup", status: "passed", method: "root_cua_exact_owned_document_close_acknowledged",
      probe_id: runId, document_title: textEditDocument, window_id: textEditWindowId ?? null, independently_confirmed_absent: true });
    textEditDocument = undefined;
  };
  if (chromeCuaMode) chromeCuaCleanup = async () => {
    if (!ownedTab) return;
    report({ name: "chrome_cua_owned_tab_cleanup_requested", ...ownedTab, title,
      acknowledge_url: `${origin}${closedEndpoint}`, required_evidence: "Root must close only the retained CUA-created tab and independently confirm it is absent before acknowledging closed=true" });
    await waitFor("root-owned Chrome tab close acknowledgment", async () => tabClosed, value => value === true, attendedHandoffTimeoutMs);
    report({ name: "owned_chrome_cleanup", status: "passed", method: "root_cua_exact_owned_tab_close_acknowledged", ...ownedTab });
  };
  await check("chrome_open_focus_observe_type_checkbox_secure", async () => {
    const opened = success(await call("mac_app_open", { app_id: "bundle:com.google.Chrome" }));
    if (chromeCuaMode) {
      report({ name: "chrome_cua_owned_tab_setup_requested", probe_id: runId, url, title,
        acknowledge_url: `${origin}${createdEndpoint}`, required_evidence: "Root must retain the newly created exact CUA tab ID and foreground only its known fixture page before acknowledging probe_id, tab_id, and url; optional window_title must be the exact owned native window title containing this probe title. CUA setup is outside MBA acceptance actions" });
      await waitFor("root-owned Chrome tab creation acknowledgment", async () => ownedTab, value => Boolean(value), attendedHandoffTimeoutMs);
    } else {
      const setup = await exec("/usr/bin/osascript", ["-e", `tell application id "com.google.Chrome"
set fixtureWindow to make new window
set URL of active tab of fixtureWindow to ${JSON.stringify(url)}
return id of fixtureWindow
end tell`], { timeout: 5000, killSignal: "SIGKILL", maxBuffer: 4096 });
      chromeWindowId = Number(setup.stdout.trim()); assert(Number.isSafeInteger(chromeWindowId));
    }
    await waitFor("Chrome fixture foreground and loaded", async () => browserState,
      state => state.text === "" && !state.checked && state.page_focused && state.visible);
    report({ name: "chrome_owned_fixture_readiness", page_focused: browserState.page_focused, visible: browserState.visible,
      text_empty: browserState.text === "", checked: browserState.checked });
    let exactTitle;
    for (const candidate of [...new Set([ownedTab?.window_title, title, `${title} - Google Chrome`].filter(Boolean))]) {
      const focused = await call("mac_app_focus", { app_id: "bundle:com.google.Chrome", window_hint: candidate });
      report({ name: "chrome_exact_title_focus_attempt", candidate, ok: focused.ok, result_class: focused.result_class,
        error: focused.error ?? null, window_title: focused.data?.window_title ?? null,
        window_id: focused.data?.window_id ?? null, focused: focused.data?.focused ?? null });
      if (focused.ok) { exactTitle = focused.data.window_title; break; }
      if (focused.result_class !== "TARGET_NOT_FOUND") success(focused);
    }
    assert(exactTitle?.includes(title), "Owned Chrome fixture window title did not resolve");
    const observed = await observe("bundle:com.google.Chrome", exactTitle), textarea = node(observed, "AXTextArea", "Ordinary fixture textarea");
    success(await call("mac_ui_action", { element_ref: textarea.element_ref, action: "focus" }));
    const fresh = await observe("bundle:com.google.Chrome", exactTitle), input = node(fresh, "AXTextArea", "Ordinary fixture textarea");
    const typed = success(await call("mac_ui_type", { element_ref: input.element_ref, text: "MBA-MCP test", submit: false }));
    assert(typed.characters_accepted > 0 && typed.focus_confirmed);
    await waitFor("Chrome textarea input", async () => browserState, state => state.text === "MBA-MCP test");
    const beforeFocus = await observe("bundle:com.google.Chrome", exactTitle), checkbox = node(beforeFocus, "AXCheckBox", "Fixture checkbox");
    success(await call("mac_ui_action", { element_ref: checkbox.element_ref, action: "focus" }));
    const before = await observe("bundle:com.google.Chrome", exactTitle), point = { x: Math.floor(browserState.point.x), y: Math.floor(browserState.point.y) };
    const beforeActivations = browserState.checkbox_activations;
    const clicked = await call("mac_ui_action", { element_ref: before.visual_ref, action: "click", ...point }); success(clicked);
    assert.equal(clicked.verification.dispatch_status, "verified"); assert.equal(clicked.verification.postcondition_status, "unknown");
    await waitFor("Chrome checkbox changed", async () => browserState, state => state.checked && state.checkbox_activations > beforeActivations);
    const after = await observe("bundle:com.google.Chrome", exactTitle), secure = after.nodes.find(value => value.secure);
    assert(secure, "Browser password field must be marked secure");
    const rejection = denied(await call("mac_ui_type", { element_ref: secure.element_ref, text: "public probe marker", submit: false }, false), ["SECRET_BOUNDARY_DENIED"]);
    return { setup: chromeCuaMode ? "root_cua_exact_owned_tab" : "existing_appleevents_owned_window", open_state: opened.state,
      characters_accepted: typed.characters_accepted, focus_confirmed: typed.focus_confirmed,
      independently_observed: { text: browserState.text, checked: browserState.checked, checkbox_activations: browserState.checkbox_activations },
      verification: clicked.verification, secure_rejection: { ...rejection, layer: "broker_pre_dispatch_secure_ref_guard", native_type_dispatched: false }, ...summary(after) };
  });
}

try { await main(); }
catch (error) { report({ status: "blocked", error: safeError(error), checks: results.length }); process.exitCode = 1; }
finally {
  if (chromeCuaCleanup) {
    try { await chromeCuaCleanup(); }
    catch (error) { report({ name: "owned_chrome_cleanup", status: "blocked", error: safeError(error) }); process.exitCode = 1; }
  }
  if (fixturePid) {
    try {
      await command("quit");
      await waitFor("unique fixture process exit", () => fixtureInventory.list(true, false, { timeoutMs: 3000, shouldCancel: () => false }),
        value => !value.truncated && !value.apps.some(app => app.appId === fixtureBundleId), 5000);
      report({ name: "owned_fixture_cleanup", status: "passed", command_acknowledged: true, process_exit_observed: true });
    }
    catch {
      // Address the unique temporary bundle, never a potentially reused PID.
      report({ name: "owned_fixture_cleanup", status: "blocked", reason: "Fixture command acknowledgment unavailable; no broader AppleEvents permission or detached PID kill was attempted" });
      fixtureCleanupBlocked = true;
      process.exitCode = 1;
    }
  }
  if (chromeWindowId) {
    try { await exec("/usr/bin/osascript", ["-e", `tell application id "com.google.Chrome" to close window id ${chromeWindowId}`], { timeout: 5000, killSignal: "SIGKILL", maxBuffer: 4096 }); }
    catch (error) { report({ name: "owned_chrome_cleanup", status: "blocked", error: safeError(error) }); process.exitCode = 1; }
  }
  if (textEditDocument) {
    try {
      if (textEditCuaCleanup) await textEditCuaCleanup();
      else {
        assert(appleEventsAllowed, "Existing AppleEvents access was not established; temporary TextEdit document cleanup is unverified");
        await exec("/usr/bin/osascript", ["-e", `tell application id "com.apple.TextEdit" to close document ${JSON.stringify(textEditDocument)} saving no`], { timeout: 5000, killSignal: "SIGKILL", maxBuffer: 4096 });
        textEditDocument = undefined;
      }
    }
    catch (error) { report({ name: "owned_textedit_cleanup", status: "failed", error: safeError(error) }); process.exitCode = 1; }
  }
  if (calculatorOwned && calculatorStarted) {
    try { await quitOwnedCalculator(); }
    catch (error) { report({ name: "owned_calculator_cleanup", status: "failed", error: safeError(error) }); process.exitCode = 1; }
  }
  if (chromeServer) {
    chromeServer.closeAllConnections();
    await new Promise(resolve => chromeServer.close(resolve));
  }
  await broker?.close(); store?.close();
  if (directory && fixtureCleanupBlocked) {
    report({ name: "fixture_artifacts_retained", status: "cleanup_required", path: directory,
      reason: "The owned fixture did not acknowledge quit; retain its command/state files for attended cleanup" });
  } else if (directory && textEditDocument) {
    for (const entry of await readdir(directory)) {
      const candidate = join(directory, entry);
      if (candidate !== textEditFile) await rm(candidate, { recursive: true, force: true });
    }
    report({ name: "temporary_document_retained", status: "cleanup_required", path: textEditFile,
      reason: "Close only the owned MBA-MCP Probe document locally, then remove its temporary file; existing user documents were preserved" });
  } else if (directory) await rm(directory, { recursive: true, force: true });
}
