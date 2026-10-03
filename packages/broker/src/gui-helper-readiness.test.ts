import assert from "node:assert/strict";
import test from "node:test";
import { MacGuiHelperReadinessProbe, guiReadinessPermissions } from "./gui-helper-readiness.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

function fixture(options: { missing?: boolean; directory?: boolean; executable?: boolean; bundleId?: string; signature?: boolean;
  accessibility?: unknown; screen?: unknown; exitCode?: number; malformed?: boolean } = {}) {
  const calls: string[] = [];
  const probe = new MacGuiHelperReadinessProbe({
    stat: async path => {
      calls.push(path);
      if (options.missing) throw new Error("ENOENT");
      return { isDirectory: () => options.directory !== false, isFile: () => options.executable !== false, mode: 0o755 };
    },
    inspect: async (executable, args, timeout) => {
      assert.ok(timeout > 0 && timeout <= 500);
      calls.push(executable);
      if (executable === "/usr/bin/codesign") {
        if (options.signature === false) throw new Error("invalid signature");
        return "";
      }
      if (args[1] === "Print CFBundleIdentifier") return options.bundleId ?? "dev.macoperator.personal.gui";
      if (args[1] === "Print CFBundlePackageType") return "APPL";
      return "gui_vision";
    },
    permission: async timeout => {
      calls.push("launchservices");
      assert.ok(timeout > 0 && timeout <= 2500);
      return { resultClass: options.exitCode ? "EXECUTION_FAILED" : "SUCCEEDED", exitCode: options.exitCode ?? 0,
        terminationObserved: true, truncated: false, stdout: options.malformed ? "{}" : JSON.stringify({ status: "ok",
          accessibility: options.accessibility ?? true, screen_recording: options.screen ?? true }) } as ProcessExecutionResult;
    }
  });
  return { probe, calls };
}

for (const [name, options] of [
  ["missing app", { missing: true }], ["non-bundle target", { directory: false }],
  ["missing executable", { executable: false }], ["invalid bundle ID", { bundleId: "invalid.bundle" }],
  ["invalid code signature", { signature: false }]
] as const) test(`GUI readiness fails closed for ${name}`, async () => {
  const { probe, calls } = fixture(options);
  const state = await probe.probe();
  assert.equal(state.identity_valid, false);
  assert.equal(state.accessibility, null);
  assert.equal(state.reason, "GUI_HELPER_UNAVAILABLE");
  assert.equal(calls.includes("launchservices"), false);
});

test("production launcher exit71 is unavailable, never an AX denial", async () => {
  const state = await fixture({ exitCode: 71 }).probe.probe();
  assert.equal(state.installed, true);
  assert.equal(state.identity_valid, false);
  assert.equal(state.reason, "GUI_HELPER_UNAVAILABLE");
});

test("AX and Screen Recording denials are independently diagnosed", async () => {
  const state = await fixture({ accessibility: false, screen: false }).probe.probe();
  assert.equal(state.installed, true);
  assert.equal(state.identity_valid, true);
  const permissions = guiReadinessPermissions(state);
  assert.equal(permissions.find(p => p.name === "accessibility")?.reason, "ACCESSIBILITY_PERMISSION_REQUIRED");
  assert.equal(permissions.find(p => p.name === "screen_recording")?.reason, "SCREEN_RECORDING_PERMISSION_REQUIRED");
  assert.equal(permissions.find(p => p.name === "gui_helper_launchservices")?.granted, true);
});

test("AX-only readiness preserves the screenshot permission distinction", async () => {
  const state = await fixture({ screen: false }).probe.probe();
  assert.equal(state.accessibility, true);
  assert.equal(state.screen_recording, false);
  assert.equal(state.reason, "SCREEN_RECORDING_PERMISSION_REQUIRED");
});

test("valid app permission readback is production LaunchServices evidence", async () => {
  const state = await fixture().probe.probe();
  assert.deepEqual(state, { installed: true, identity_valid: true, accessibility: true, screen_recording: true, transport: "launchservices" });
});

test("AX Carbon Boolean accepts only exact booleans or zero/one", async () => {
  for (const [input, expected] of [[0, false], [1, true], [false, false], [true, true]] as const) {
    assert.equal((await fixture({ accessibility: input }).probe.probe()).accessibility, expected);
  }
  for (const input of ["true", "1", 2, {}]) {
    assert.equal((await fixture({ accessibility: input }).probe.probe()).accessibility, null);
  }
});

test("malformed permission results remain unknown and fail closed", async () => {
  const state = await fixture({ malformed: true }).probe.probe();
  assert.equal(state.reason, "GUI_HELPER_PERMISSION_PROBE_FAILED");
  assert.equal(state.accessibility, null);
});

test("readiness re-probes after consent instead of caching denial", async () => {
  const options = { accessibility: false };
  const { probe } = fixture(options);
  assert.equal((await probe.probe()).accessibility, false);
  options.accessibility = true;
  assert.equal((await probe.probe()).accessibility, true);
});
