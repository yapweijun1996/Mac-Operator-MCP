import { BrokerError, canonicalJson, parseJsonStrict, sha256 } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { redactLogText } from "./secret-policy.js";
import type { AppExecutionControl, AppInventoryInspector, SafeAppInventory } from "./app-inspector.js";
import { opaqueWindowId, validateSensitiveUiTarget } from "./ui-inspector.js";

const OPEN_EXECUTABLE = "/usr/bin/open";
const OPEN_CWD = "/";
const MAX_OUTPUT_BYTES = 262_144;
const MAX_FOCUS_OUTPUT_BYTES = 131_072;
const MAX_TIMEOUT_MS = 30_000;
const MAX_POLL_ATTEMPTS = 20;
const POLL_INTERVAL_MS = 100;
const APP_ID_PATTERN = /^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u;
const MAX_WINDOW_HINT_LENGTH = 256;

/** Broker-owned focus adapter; callers cannot provide AppleScript/JXA code. */
const APP_FOCUS_SCRIPT = String.raw`
ObjC.import("Foundation"); ObjC.import("ApplicationServices");
const argv = (() => { try { return ObjC.unwrap($.NSProcessInfo.processInfo.arguments).map((value) => String(ObjC.unwrap(value))); } catch (_) { return []; } })();
const marker = argv.lastIndexOf("--"); const supplied = marker >= 0 ? argv.slice(marker + 1) : argv.slice(-2);
const appId = String(supplied[0] || ""); const windowHint = String(supplied[1] || ""); const bundleId = appId.startsWith("bundle:") ? appId.slice("bundle:".length) : "";
let emitted = null; const result = (value) => { emitted = value; }; const text = (call, fallback = "") => { try { const value = call(); return value === null || value === undefined ? fallback : String(value); } catch (_) { return fallback; } };
if (!/^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/.test(appId)) result({ status: "error", error: "invalid_app_identity" });
else if (!$.AXIsProcessTrusted()) result({ status: "error", error: "accessibility_permission" });
else { try { const systemEvents = Application("System Events"); let process = null; for (const candidate of systemEvents.processes()) { if (text(() => candidate.bundleIdentifier()) === bundleId) { process = candidate; break; } } if (!process) result({ status: "error", error: "app_not_running" }); else { const windows = (() => { try { return process.windows(); } catch (_) { return []; } })(); let selected = null; let selectedIndex = -1; for (let index = 0; index < windows.length; index += 1) { const candidate = windows[index]; const title = text(() => candidate.name()); const focused = Boolean((() => { try { return candidate.focused(); } catch (_) { return false; } })()); if ((windowHint.length > 0 && title === windowHint) || (windowHint.length === 0 && focused && selected === null)) { selected = candidate; selectedIndex = index; if (windowHint.length > 0) break; } } if (selected === null && windowHint.length === 0 && windows.length > 0) { selected = windows[0]; selectedIndex = 0; } if (selected === null) result({ status: "error", error: "window_not_found" }); else { process.frontmost = true; try { selected.focused = true; } catch (_) {} const title = text(() => selected.name()); const focused = Boolean((() => { try { return selected.focused(); } catch (_) { return false; } })()); result({ status: "ok", app_id: appId, window_index: selectedIndex, window_title: title, focused }); } } } catch (error) { const message = text(() => error && error.message); result({ status: "error", error: /not authorized|not permitted|assistive|accessibility|-1743/iu.test(message) ? "accessibility_permission" : "execution_failed" }); } }
JSON.stringify(emitted);
`.replace(/\s+/gu, " ").trim();

export interface SafeAppOpen {
  appId: string;
  state: "launched" | "already_running";
  processId: null;
  target: { kind: "app"; reference: string };
  verified: true;
  warnings: readonly string[];
  truncated: false;
}

export interface SafeAppFocus {
  appId: string;
  windowId: string;
  windowTitle?: string;
  focused: true;
  verified: true;
  warnings: readonly string[];
  truncated: false;
}

export interface AppControlInspector {
  open(appId: string, documentPath: string | undefined, url: string | undefined, control: AppExecutionControl): Promise<SafeAppOpen>;
  focus?(appId: string, windowHint: string | undefined, control: AppExecutionControl): Promise<SafeAppFocus>;
}

export class AppControlInspectorImpl implements AppControlInspector {
  private readonly supervisor: Pick<ProcessSupervisor, "run">;
  private readonly inventory: AppInventoryInspector;

  constructor(
    inventory: AppInventoryInspector,
    supervisor: Pick<ProcessSupervisor, "run"> = new ProcessSupervisor({ maxConcurrent: 1, allowedEnvironmentKeys: [] })
  ) {
    this.inventory = inventory;
    this.supervisor = supervisor;
  }

  async open(
    appId: string,
    documentPath: string | undefined,
    url: string | undefined,
    control: AppExecutionControl
  ): Promise<SafeAppOpen> {
    validateAppOpenRequest(appId, documentPath, url);
    const deadlineMs = Date.now() + Math.min(control.timeoutMs, MAX_TIMEOUT_MS);
    const boundedControl = (): AppExecutionControl => ({
      timeoutMs: Math.max(1, deadlineMs - Date.now()),
      shouldCancel: () => {
        try { return control.shouldCancel() || Date.now() >= deadlineMs; }
        catch { return true; }
      }
    });
    if (Date.now() >= deadlineMs) throw new BrokerError("TIMEOUT", "App launch timed out");
    const before = await this.inventory.list(false, true, boundedControl());
    const installed = before.apps.find((app) => app.appId === appId);
    if (!installed) throw new BrokerError("TARGET_NOT_FOUND", "App identity was not found in the bounded inventory");
    const alreadyRunning = installed.running;
    const bundleId = appId.slice("bundle:".length);
    if (Date.now() >= deadlineMs) throw new BrokerError("TIMEOUT", "App launch timed out");
    const result = await this.supervisor.run({
      executable: OPEN_EXECUTABLE,
      args: ["-b", bundleId],
      cwd: OPEN_CWD,
      environment: {},
      timeoutMs: Math.max(1, deadlineMs - Date.now()),
      outputCapBytes: MAX_OUTPUT_BYTES,
      shouldCancel: boundedControl().shouldCancel
    });
    assertOpenResult(result);
    const observed = await this.waitForRunningApp(appId, boundedControl, deadlineMs);
    if (!observed) throw new BrokerError("VERIFICATION_FAILED", "App launch state could not be verified");
    const warnings = [...before.warnings, ...observed.warnings];
    const redactedWarnings = warnings.map((warning) => redactLogText(warning).text).filter((warning) => warning.length > 0);
    return {
      appId,
      state: alreadyRunning ? "already_running" : "launched",
      processId: null,
      target: { kind: "app", reference: appId },
      verified: true,
      warnings: redactedWarnings,
      truncated: false
    };
  }

  async focus(appId: string, windowHint: string | undefined, control: AppExecutionControl): Promise<SafeAppFocus> {
    validateAppFocusRequest(appId, windowHint);
    validateSensitiveUiTarget(appId, windowHint);
    const result = await this.supervisor.run({
      executable: "/usr/bin/osascript",
      args: ["-l", "JavaScript", "-e", APP_FOCUS_SCRIPT, "--", appId, windowHint ?? ""],
      cwd: OPEN_CWD,
      environment: {},
      timeoutMs: Math.min(control.timeoutMs, 10_000),
      outputCapBytes: MAX_FOCUS_OUTPUT_BYTES,
      shouldCancel: control.shouldCancel
    });
    return parseAppFocusResult(result, appId);
  }

  private async waitForRunningApp(
    appId: string,
    control: () => AppExecutionControl,
    deadlineMs: number
  ): Promise<{ app: SafeAppInventory["apps"][number]; warnings: readonly string[] } | undefined> {
    for (let attempt = 0; attempt < MAX_POLL_ATTEMPTS; attempt += 1) {
      const bounded = control();
      if (bounded.shouldCancel()) {
        if (Date.now() >= deadlineMs) throw new BrokerError("TIMEOUT", "App launch timed out");
        throw new BrokerError("CANCELLED", "App launch was cancelled");
      }
      const inventory = await this.inventory.list(true, false, bounded);
      const observed = inventory.apps.find((app) => app.appId === appId && app.running);
      if (observed) return { app: observed, warnings: inventory.warnings };
      const remainingMs = deadlineMs - Date.now();
      if (remainingMs <= 0) throw new BrokerError("TIMEOUT", "App launch timed out");
      await new Promise<void>((resolve) => setTimeout(resolve, Math.min(POLL_INTERVAL_MS, remainingMs)));
    }
    if (Date.now() >= deadlineMs) throw new BrokerError("TIMEOUT", "App launch timed out");
    return undefined;
  }
}

export function validateAppOpenRequest(appId: unknown, documentPath?: unknown, url?: unknown): asserts appId is string {
  if (typeof appId !== "string" || !APP_ID_PATTERN.test(appId)) {
    throw new BrokerError("PRECONDITION_FAILED", "app_id must be a stable bundle identity");
  }
  if (documentPath !== undefined || url !== undefined) {
    throw new BrokerError("UNSUPPORTED_CAPABILITY", "Document and URL app-open targets are not enabled");
  }
}

export function validateAppFocusRequest(appId: unknown, windowHint?: unknown): asserts appId is string {
  if (typeof appId !== "string" || !APP_ID_PATTERN.test(appId)) {
    throw new BrokerError("PRECONDITION_FAILED", "app_id must be a stable bundle identity");
  }
  if (windowHint !== undefined && (typeof windowHint !== "string" || windowHint.length > MAX_WINDOW_HINT_LENGTH || /[\u0000-\u001f\u007f]/u.test(windowHint))) {
    throw new BrokerError("PRECONDITION_FAILED", "window_hint must be bounded visible text");
  }
}

export function parseAppFocusResult(result: ProcessExecutionResult, appId: string): SafeAppFocus {
  validateAppFocusRequest(appId);
  validateSensitiveUiTarget(appId);
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "App focus was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "App focus timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "App focus exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") {
    if (/not authorized|not permitted|assistive|accessibility|-1743/iu.test(result.stderr)) {
      throw new BrokerError("POLICY_DENIED", "Accessibility permission is not granted");
    }
    throw new BrokerError("EXECUTION_FAILED", "App focus failed");
  }
  let parsed: unknown;
  try { parsed = parseJsonStrict(result.stdout); } catch { throw new BrokerError("VERIFICATION_FAILED", "App focus returned malformed metadata"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new BrokerError("VERIFICATION_FAILED", "App focus returned malformed metadata");
  const record = parsed as Record<string, unknown>;
  if (record.status === "error") {
    switch (record.error) {
      case "accessibility_permission": throw new BrokerError("POLICY_DENIED", "Accessibility permission is not granted");
      case "app_not_running": throw new BrokerError("TARGET_NOT_FOUND", "The requested app is not running");
      case "window_not_found": throw new BrokerError("TARGET_NOT_FOUND", "The requested app window was not found");
      case "invalid_app_identity": throw new BrokerError("PRECONDITION_FAILED", "app_id must be a stable bundle identity");
      default: throw new BrokerError("EXECUTION_FAILED", "App focus failed");
    }
  }
  if (record.status !== "ok" || record.app_id !== appId ||
      !Number.isSafeInteger(record.window_index) || (record.window_index as number) < 0 || (record.window_index as number) >= 2_000 ||
      typeof record.window_title !== "string" || record.window_title.length > 512 || record.focused !== true) {
    throw new BrokerError("VERIFICATION_FAILED", "App focus returned malformed metadata");
  }
  const windowTitle = redactLogText(record.window_title.replace(/[\u0000-\u001f\u007f]/gu, "�").slice(0, 512));
  if (windowTitle.text.length > 0) validateSensitiveUiTarget(appId, windowTitle.text);
  const windowId = opaqueWindowId(appId, record.window_index as number, windowTitle.text);
  return {
    appId,
    windowId,
    ...(windowTitle.text.length > 0 ? { windowTitle: windowTitle.text } : {}),
    focused: true,
    verified: true,
    warnings: windowTitle.redacted ? ["Sensitive app-window metadata was redacted"] : [],
    truncated: false
  };
}

function assertOpenResult(result: ProcessExecutionResult): void {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "App launch was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "App launch timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "App launch exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") throw new BrokerError("EXECUTION_FAILED", "App launch failed");
}

export const appOpenExecutableForTesting = OPEN_EXECUTABLE;
export const appFocusExecutableForTesting = "/usr/bin/osascript";
export const appFocusScriptForTesting = APP_FOCUS_SCRIPT;
