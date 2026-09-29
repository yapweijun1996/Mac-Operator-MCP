import { GuiProcessSupervisor } from "./gui-process-supervisor.js";
import { BrokerError, canonicalJson, parseJsonStrict, sha256 } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { isPlainDataRecord } from "./plain-record.js";
import { redactLogText } from "./secret-policy.js";
import type { AppExecutionControl, AppInventoryInspector, SafeAppInventory } from "./app-inspector.js";
import { guiVisionExecutableForTesting, opaqueWindowId, validateSensitiveUiTarget } from "./ui-inspector.js";

const OPEN_EXECUTABLE = "/usr/bin/open";
const OPEN_CWD = "/";
const MAX_OUTPUT_BYTES = 262_144;
const MAX_FOCUS_OUTPUT_BYTES = 131_072;
const MAX_TIMEOUT_MS = 30_000;
const MAX_POLL_ATTEMPTS = 20;
const POLL_INTERVAL_MS = 100;
const APP_ID_PATTERN = /^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u;
const BARE_APP_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u;
const MAX_WINDOW_HINT_LENGTH = 256;

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
    supervisor: Pick<ProcessSupervisor, "run"> = new GuiProcessSupervisor()
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
      executable: guiVisionExecutableForTesting,
      allowUserOwnedExecutable: true,
      args: ["focus", "visual", appId.slice("bundle:".length), windowHint ?? ""],
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

export function normalizeAppId(value: unknown): string {
  if (typeof value !== "string") {
    throw new BrokerError("PRECONDITION_FAILED", "app_id must be a stable bundle identity");
  }
  const appId = value.startsWith("bundle:") ? value : `bundle:${value}`;
  if (!APP_ID_PATTERN.test(appId) || (!value.startsWith("bundle:") && !BARE_APP_ID_PATTERN.test(value))) {
    throw new BrokerError("PRECONDITION_FAILED", "app_id must be a stable bundle identity");
  }
  return appId;
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
  if (!isPlainDataRecord(parsed)) throw new BrokerError("VERIFICATION_FAILED", "App focus returned malformed metadata");
  const record = parsed as Record<string, unknown>;
  if (record.status === "error") {
    if (!hasExactFields(record, ["status", "error"])) throw new BrokerError("VERIFICATION_FAILED", "App focus returned malformed metadata");
    switch (record.error) {
      case "accessibility_permission": throw new BrokerError("POLICY_DENIED", "Accessibility permission is not granted");
      case "app_not_running": throw new BrokerError("TARGET_NOT_FOUND", "The requested app is not running");
      case "window_not_found": throw new BrokerError("TARGET_NOT_FOUND", "The requested app window was not found");
      case "invalid_app_identity": throw new BrokerError("PRECONDITION_FAILED", "app_id must be a stable bundle identity");
      default: throw new BrokerError("EXECUTION_FAILED", "App focus failed");
    }
  }
  if (!hasExactFields(record, ["status", "app_id", "window_index", "window_title", "focused"])) {
    throw new BrokerError("VERIFICATION_FAILED", "App focus returned malformed metadata");
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
export const appFocusExecutableForTesting = guiVisionExecutableForTesting;

function hasExactFields(value: Record<string, unknown>, required: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === required.length && required.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}
