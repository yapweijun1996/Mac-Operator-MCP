import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { redactLogText } from "./secret-policy.js";

const OSASCRIPT = "/usr/bin/osascript";
const UI_OBSERVE_CWD = "/";
const MAX_OUTPUT_BYTES = 524_288;
const MAX_TIMEOUT_MS = 10_000;
const MAX_NODES = 2_000;
const MAX_WINDOW_HINT_LENGTH = 256;
const MAX_LABEL_LENGTH = 512;
const MAX_ROLE_LENGTH = 128;
const APP_ID_PATTERN = /^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u;
const SENSITIVE_APP_BUNDLE_IDS = new Set([
  "com.apple.SecurityAgent",
  "com.apple.securityagent",
  "com.apple.KeychainAccess",
  "com.apple.keychainaccess",
  "com.apple.systempreferences",
  "com.apple.SystemPreferences",
  "com.apple.loginwindow"
]);
const SENSITIVE_UI_TEXT_PATTERN = /\b(?:password|passcode|credential|security|privacy|private\s+key|sign\s*in|log\s*in|two[- ]factor|verification\s+code)\b/iu;

/**
 * Broker-owned JXA. It accepts only positional identity/filter values supplied
 * by the adapter and never evaluates caller-provided code. Values and secure
 * element contents are intentionally not read from the Accessibility tree.
 */
const UI_OBSERVE_SCRIPT = String.raw`
ObjC.import("Foundation");
ObjC.import("ApplicationServices");

const argv = (() => {
  try { return ObjC.unwrap($.NSProcessInfo.processInfo.arguments).map((value) => String(ObjC.unwrap(value))); }
  catch (_) { return []; }
})();
const marker = argv.lastIndexOf("--");
const supplied = marker >= 0 ? argv.slice(marker + 1) : argv.slice(-3);
const appId = String(supplied[0] || "");
const windowHint = String(supplied[1] || "");
const requestedNodes = Math.max(1, Math.min(2000, Number.parseInt(String(supplied[2] || "200"), 10) || 200));
const bundleId = appId.startsWith("bundle:") ? appId.slice("bundle:".length) : "";

let emitted = null;
function result(value) { emitted = value; }
function safe(call, fallback) { try { const value = call(); return value === null || value === undefined ? fallback : value; } catch (_) { return fallback; } }
function text(call, fallback = "") {
  const value = safe(call, fallback);
  return typeof value === "string" ? value : String(value || fallback);
}

if (!/^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/.test(appId)) {
  result({ status: "error", error: "invalid_app_identity" });
} else if (!$.AXIsProcessTrusted()) {
  result({ status: "error", error: "accessibility_permission" });
} else {
  let process = null;
  try {
    const systemEvents = Application("System Events");
    for (const candidate of systemEvents.processes()) {
      if (text(() => candidate.bundleIdentifier(), "") === bundleId) {
        process = candidate;
        break;
      }
    }
    if (!process) {
      result({ status: "error", error: "app_not_running" });
    } else {
      const windows = safe(() => process.windows(), []);
      let selected = null;
      let selectedIndex = -1;
      for (let index = 0; index < windows.length; index += 1) {
        const candidate = windows[index];
        const title = text(() => candidate.name(), "");
        const focused = Boolean(safe(() => candidate.focused(), false));
        if ((windowHint.length > 0 && title === windowHint) ||
            (windowHint.length === 0 && focused && selected === null)) {
          selected = candidate;
          selectedIndex = index;
          if (windowHint.length > 0) break;
        }
      }
      if (selected === null && windowHint.length === 0 && windows.length > 0) {
        selected = windows[0];
        selectedIndex = 0;
      }
      if (selected === null) {
        result({ status: "error", error: "window_not_found" });
      } else {
        const title = text(() => selected.name(), "");
        const focused = Boolean(safe(() => selected.focused(), false));
        const nodes = [];
        const addNode = (element, fallbackRole) => {
          if (nodes.length >= requestedNodes) return;
          const role = text(() => element.role(), fallbackRole);
          const subrole = text(() => element.subrole(), "");
          const secure = /secure|password|credential|protected|security/iu.test(role + " " + subrole);
          const label = secure ? "" : text(() => element.description(), text(() => element.name(), ""));
          nodes.push({
            index: nodes.length,
            role: role || fallbackRole,
            label: secure ? "" : label,
            enabled: Boolean(safe(() => element.enabled(), false)),
            focused: Boolean(safe(() => element.focused(), false)),
            secure
          });
        };
        addNode(selected, "AXWindow");
        let descendants = [];
        try { descendants = selected.entireContents(); } catch (_) { descendants = []; }
        for (const element of descendants) {
          if (nodes.length >= requestedNodes) break;
          addNode(element, "AXUnknown");
        }
        result({
          status: "ok",
          app_id: appId,
          window_index: selectedIndex,
          window_title: title,
          focused,
          nodes,
          truncated: descendants.length + 1 > requestedNodes
        });
      }
    }
  } catch (error) {
    const message = text(() => error && error.message, "");
    result({ status: /not authorized|not permitted|assistive|accessibility|-1743/iu.test(message) ? "error" : "error", error: /not authorized|not permitted|assistive|accessibility|-1743/iu.test(message) ? "accessibility_permission" : "execution_failed" });
  }
}
JSON.stringify(emitted);
`.replace(/\s+/gu, " ").trim();

export interface UiExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface SafeUiNode {
  elementRef: string;
  role: string;
  label?: string;
  enabled: boolean;
  focused: boolean;
  secure: boolean;
}

export interface SafeUiObservation {
  appId: string;
  windowId: string;
  windowTitle?: string;
  focused: boolean;
  nodes: readonly SafeUiNode[];
  truncated: boolean;
  warnings: readonly string[];
}

export interface UiInspector {
  observe(appId: string, windowHint: string | undefined, maxNodes: number, control: UiExecutionControl): Promise<SafeUiObservation>;
}

export class MacUiInspectorImpl implements UiInspector {
  private readonly supervisor: Pick<ProcessSupervisor, "run">;

  constructor(supervisor: Pick<ProcessSupervisor, "run"> = new ProcessSupervisor({ maxConcurrent: 1, allowedEnvironmentKeys: [] })) {
    this.supervisor = supervisor;
  }

  async observe(appId: string, windowHint: string | undefined, maxNodes: number, control: UiExecutionControl): Promise<SafeUiObservation> {
    validateUiObserveRequest(appId, windowHint, maxNodes);
    validateSensitiveUiTarget(appId, windowHint);
    const result = await this.supervisor.run({
      executable: OSASCRIPT,
      args: ["-l", "JavaScript", "-e", UI_OBSERVE_SCRIPT, "--", appId, windowHint ?? "", String(maxNodes)],
      cwd: UI_OBSERVE_CWD,
      environment: {},
      timeoutMs: Math.min(control.timeoutMs, MAX_TIMEOUT_MS),
      outputCapBytes: MAX_OUTPUT_BYTES,
      shouldCancel: control.shouldCancel
    });
    return parseUiObserveResult(result, appId, maxNodes);
  }
}

export function validateUiObserveRequest(appId: unknown, windowHint?: unknown, maxNodes = 200): asserts appId is string {
  if (typeof appId !== "string" || !APP_ID_PATTERN.test(appId)) {
    throw new BrokerError("PRECONDITION_FAILED", "app_id must be a stable bundle identity");
  }
  if (windowHint !== undefined && (typeof windowHint !== "string" || windowHint.length > MAX_WINDOW_HINT_LENGTH || /[\u0000-\u001f\u007f]/u.test(windowHint))) {
    throw new BrokerError("PRECONDITION_FAILED", "window_hint must be bounded visible text");
  }
  if (!Number.isSafeInteger(maxNodes) || maxNodes < 1 || maxNodes > MAX_NODES) {
    throw new BrokerError("PRECONDITION_FAILED", "max_nodes must be an integer between 1 and 2000");
  }
}

export function validateSensitiveUiTarget(appId: string, windowHint?: string): void {
  const bundleId = appId.slice("bundle:".length);
  if (SENSITIVE_APP_BUNDLE_IDS.has(bundleId) || (windowHint !== undefined && SENSITIVE_UI_TEXT_PATTERN.test(windowHint))) {
    throw new BrokerError("SECRET_BOUNDARY_DENIED", "Sensitive application or security UI targets are not observable");
  }
}

export function parseUiObserveResult(result: ProcessExecutionResult, appId: string, maxNodes = 200): SafeUiObservation {
  validateUiObserveRequest(appId, undefined, maxNodes);
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Accessibility observation was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Accessibility observation timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Accessibility observation exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") {
    if (/not authorized|not permitted|assistive|accessibility|-1743/iu.test(result.stderr)) {
      throw new BrokerError("POLICY_DENIED", "Accessibility permission is not granted");
    }
    throw new BrokerError("EXECUTION_FAILED", "Accessibility observation failed");
  }
  let parsed: unknown;
  try { parsed = JSON.parse(result.stdout); } catch { throw new BrokerError("VERIFICATION_FAILED", "Accessibility observation returned malformed metadata"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new BrokerError("VERIFICATION_FAILED", "Accessibility observation returned malformed metadata");
  }
  const record = parsed as Record<string, unknown>;
  validateSensitiveUiTarget(appId);
  if (record.status === "error") {
    switch (record.error) {
      case "accessibility_permission": throw new BrokerError("POLICY_DENIED", "Accessibility permission is not granted");
      case "app_not_running": throw new BrokerError("TARGET_NOT_FOUND", "The requested app is not running");
      case "window_not_found": throw new BrokerError("TARGET_NOT_FOUND", "The requested app window was not found");
      case "invalid_app_identity": throw new BrokerError("PRECONDITION_FAILED", "app_id must be a stable bundle identity");
      default: throw new BrokerError("EXECUTION_FAILED", "Accessibility observation failed");
    }
  }
  if (record.status !== "ok" || record.app_id !== appId ||
      !Number.isSafeInteger(record.window_index) || (record.window_index as number) < 0 || (record.window_index as number) >= MAX_NODES ||
      typeof record.window_title !== "string" || record.window_title.length > MAX_LABEL_LENGTH ||
      typeof record.focused !== "boolean" || !Array.isArray(record.nodes) || record.nodes.length > maxNodes ||
      typeof record.truncated !== "boolean") {
    throw new BrokerError("VERIFICATION_FAILED", "Accessibility observation returned malformed metadata");
  }
  const windowTitle = sanitizeText(record.window_title, MAX_LABEL_LENGTH);
  if (SENSITIVE_UI_TEXT_PATTERN.test(windowTitle)) {
    throw new BrokerError("SECRET_BOUNDARY_DENIED", "Sensitive application or security UI targets are not observable");
  }
  const windowId = opaqueWindowId(appId, record.window_index as number, windowTitle);
  const warnings: string[] = [];
  let redacted = false;
  const nodes: SafeUiNode[] = [];
  for (const [index, value] of record.nodes.entries()) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new BrokerError("VERIFICATION_FAILED", "Accessibility observation returned malformed node metadata");
    }
    const node = value as Record<string, unknown>;
    if (!Number.isSafeInteger(node.index) || (node.index as number) !== index ||
        typeof node.role !== "string" || node.role.length < 1 || node.role.length > MAX_ROLE_LENGTH ||
        typeof node.label !== "string" || node.label.length > MAX_LABEL_LENGTH ||
        typeof node.enabled !== "boolean" || typeof node.focused !== "boolean" || typeof node.secure !== "boolean") {
      throw new BrokerError("VERIFICATION_FAILED", "Accessibility observation returned malformed node metadata");
    }
    const role = sanitizeText(node.role, MAX_ROLE_LENGTH);
    const labelResult = node.secure ? { text: "", redacted: node.label.length > 0 } : redactLogText(sanitizeText(node.label, MAX_LABEL_LENGTH));
    redacted ||= labelResult.redacted;
    const elementRef = `element:${sha256(canonicalJson({ windowId, index, role, label: labelResult.text, secure: node.secure })).slice(0, 48)}`;
    nodes.push({
      elementRef,
      role,
      ...(labelResult.text.length > 0 ? { label: labelResult.text } : {}),
      enabled: node.enabled,
      focused: node.focused,
      secure: node.secure
    });
  }
  if (redacted) warnings.push("Sensitive Accessibility labels were redacted");
  if (result.truncated || record.truncated) warnings.push("Accessibility output was limited by a fixed adapter budget");
  return {
    appId,
    windowId,
    ...(windowTitle.length > 0 ? { windowTitle } : {}),
    focused: record.focused,
    nodes,
    truncated: result.truncated || record.truncated,
    warnings
  };
}

function sanitizeText(value: string, maxLength: number): string {
  return value.replace(/[\u0000-\u001f\u007f]/gu, "�").slice(0, maxLength);
}

export function opaqueWindowId(appId: string, windowIndex: number, windowTitle: string): string {
  return `window:${sha256(canonicalJson({ appId, windowIndex, windowTitle })).slice(0, 48)}`;
}

export const uiObserveExecutableForTesting = OSASCRIPT;
export const uiObserveScriptForTesting = UI_OBSERVE_SCRIPT;
