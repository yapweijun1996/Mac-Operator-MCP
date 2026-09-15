import { BrokerError, canonicalJson, parseJsonStrict, sha256 } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { isPlainDataRecord } from "./plain-record.js";
import { assertContentDoesNotContainSecrets, redactLogText } from "./secret-policy.js";

const OSASCRIPT = "/usr/bin/osascript";
const UI_OBSERVE_CWD = "/";
const MAX_OUTPUT_BYTES = 524_288;
const MAX_TIMEOUT_MS = 10_000;
const MAX_NODES = 2_000;
const MAX_WINDOW_HINT_LENGTH = 256;
const MAX_LABEL_LENGTH = 512;
const MAX_ROLE_LENGTH = 128;
const UI_SNAPSHOT_TTL_MS = 30_000;
const MAX_UI_SNAPSHOTS = 2_048;
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

/** Broker-owned JXA for one allowlisted Accessibility action and readback. */
const UI_ACTION_SCRIPT = String.raw`
ObjC.import("Foundation"); ObjC.import("ApplicationServices");
const supplied = (() => { try { const a = ObjC.unwrap($.NSProcessInfo.processInfo.arguments).map((v) => String(ObjC.unwrap(v))); return a.slice(a.lastIndexOf("--") + 1); } catch (_) { return []; } })();
const appId = String(supplied[0] || ""); const windowTitle = String(supplied[1] || ""); const windowIndex = Number(supplied[2]); const elementIndex = Number(supplied[3]); const expectedRole = String(supplied[4] || ""); const expectedLabel = String(supplied[5] || ""); const action = String(supplied[6] || ""); const bundleId = appId.slice(7);
let emitted = null; const result = (value) => { emitted = value; }; const text = (call, fallback = "") => { try { const value = call(); return value == null ? fallback : String(value); } catch (_) { return fallback; } }; const safe = (call, fallback) => { try { return call() ?? fallback; } catch (_) { return fallback; } }; const secureRole = (role, subrole) => /secure|password|credential|protected|security/iu.test(role + " " + subrole);
const findTarget = () => { const se = Application("System Events"); let process = null; for (const candidate of se.processes()) { if (text(() => candidate.bundleIdentifier()) === bundleId) { process = candidate; break; } } if (!process) return { error: "app_not_running" }; const windows = safe(() => process.windows(), []); let selected = null; let selectedIndex = -1; for (let i = 0; i < windows.length; i += 1) { if (text(() => windows[i].name()) === windowTitle) { selected = windows[i]; selectedIndex = i; break; } } if (selected === null) return { error: "window_not_found" }; if (selectedIndex !== windowIndex) return { error: "stale_target" }; let found = null; let index = 0; const visit = (element) => { if (found !== null) return; const role = text(() => element.role(), "AXUnknown"); const secure = secureRole(role, text(() => element.subrole())); const label = secure ? "" : text(() => element.description(), text(() => element.name())); if (index === elementIndex && role === expectedRole && label === expectedLabel && !secure) found = { element, role, index, enabled: Boolean(safe(() => element.enabled(), false)), focused: Boolean(safe(() => element.focused(), false)) }; index += 1; }; visit(selected); for (const element of safe(() => selected.entireContents(), [])) { if (index > elementIndex || found !== null) break; visit(element); } return found === null ? { error: "stale_target" } : { windowIndex: selectedIndex, target: found }; };
if (!/^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/.test(appId) || windowTitle.length === 0 || !Number.isSafeInteger(windowIndex) || windowIndex < 0 || !Number.isSafeInteger(elementIndex) || elementIndex < 0) result({ status: "error", error: "invalid_target" }); else if (!$.AXIsProcessTrusted()) result({ status: "error", error: "accessibility_permission" }); else if (!["press", "select", "increment", "decrement", "show_menu", "focus"].includes(action)) result({ status: "error", error: "action_unsupported" }); else { try { const before = findTarget(); if (before.error) result({ status: "error", error: before.error }); else { const target = before.target.element; if (action === "focus") target.focused = true; else if (action === "select") target.selected = true; else target.performAction(({ press: "AXPress", increment: "AXIncrement", decrement: "AXDecrement", show_menu: "AXShowMenu" })[action]); const after = findTarget(); if (after.error) result({ status: "error", error: after.error }); else result({ status: "ok", app_id: appId, window_index: after.windowIndex, window_title: windowTitle, element_index: after.target.index, role: after.target.role, enabled: after.target.enabled, focused: after.target.focused, secure: false, accepted: true }); } } catch (error) { const message = text(() => error && error.message); result({ status: "error", error: /not authorized|not permitted|assistive|accessibility|-1743/iu.test(message) ? "accessibility_permission" : "execution_failed" }); } }
JSON.stringify(emitted);
`.replace(/\s+/gu, " ").trim();

/** Broker-owned JXA for bounded non-secure text/key input. Text arrives on
 * stdin so it never appears in argv, process listings, or persisted audit data. */
const UI_TYPE_SCRIPT = String.raw`
ObjC.import("Foundation"); ObjC.import("ApplicationServices");
const supplied = (() => { try { const a = ObjC.unwrap($.NSProcessInfo.processInfo.arguments).map((v) => String(ObjC.unwrap(v))); return a.slice(a.lastIndexOf("--") + 1); } catch (_) { return []; } })();
const appId = String(supplied[0] || ""); const windowTitle = String(supplied[1] || ""); const windowIndex = Number(supplied[2]); const elementIndex = Number(supplied[3]); const expectedRole = String(supplied[4] || ""); const expectedLabel = String(supplied[5] || "");
let input = null; try { const data = $.NSFileHandle.fileHandleWithStandardInput().readDataToEndOfFile(); input = JSON.parse($.NSString.alloc.initWithDataEncoding(data, $.NSUTF8StringEncoding).js); } catch (_) { input = null; }
let emitted = null; const result = (value) => { emitted = value; }; const text = (call, fallback = "") => { try { const value = call(); return value == null ? fallback : String(value); } catch (_) { return fallback; } }; const safe = (call, fallback) => { try { return call() ?? fallback; } catch (_) { return fallback; } }; const secureRole = (role, subrole) => /secure|password|credential|protected|security/iu.test(role + " " + subrole); const keyCodes = { ENTER: 36, TAB: 48, ESCAPE: 53, ARROW_UP: 126, ARROW_DOWN: 125, ARROW_LEFT: 123, ARROW_RIGHT: 124, HOME: 115, END: 119 }; const textRole = (role) => /AX(TextField|TextArea|SearchField|ComboBox)/u.test(role);
const findTarget = () => { const se = Application("System Events"); let process = null; const bundleId = appId.slice(7); for (const candidate of se.processes()) { if (text(() => candidate.bundleIdentifier()) === bundleId) { process = candidate; break; } } if (!process) return { error: "app_not_running" }; const windows = safe(() => process.windows(), []); const selected = windows[windowIndex]; if (!selected || text(() => selected.name()) !== windowTitle) return { error: "stale_target" }; let found = null; let index = 0; const visit = (element) => { if (found !== null) return; const role = text(() => element.role(), "AXUnknown"); const subrole = text(() => element.subrole(), ""); const secure = secureRole(role, subrole); const label = secure ? "" : text(() => element.description(), text(() => element.name())); if (index === elementIndex && role === expectedRole && label === expectedLabel && !secure) found = { element, role, index, focused: Boolean(safe(() => element.focused(), false)) }; index += 1; }; visit(selected); for (const element of safe(() => selected.entireContents(), [])) { if (index > elementIndex || found !== null) break; visit(element); } return found === null ? { error: "stale_target" } : { windowIndex, target: found }; };
const validKeys = ["ENTER", "TAB", "ESCAPE", "ARROW_UP", "ARROW_DOWN", "ARROW_LEFT", "ARROW_RIGHT", "HOME", "END"];
if (!/^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/.test(appId) || windowTitle.length === 0 || !Number.isSafeInteger(windowIndex) || windowIndex < 0 || !Number.isSafeInteger(elementIndex) || elementIndex < 0 || input === null || typeof input.text !== "string" || input.text.length > 10000 || input.text.includes("\0") || !Array.isArray(input.keys) || input.keys.length > 32 || input.keys.some((key) => !validKeys.includes(key)) || typeof input.submit !== "boolean") result({ status: "error", error: "invalid_input" }); else if (!$.AXIsProcessTrusted()) result({ status: "error", error: "accessibility_permission" }); else { try { const before = findTarget(); if (before.error) result({ status: "error", error: before.error }); else if (!textRole(before.target.role)) result({ status: "error", error: "target_unsupported" }); else { before.target.element.focused = true; const se = Application("System Events"); if (input.text.length > 0) se.keystroke(input.text); for (const key of input.keys) se.keyCode(keyCodes[key]); if (input.submit) se.keyCode(keyCodes.ENTER); const after = findTarget(); if (after.error) result({ status: "error", error: after.error }); else result({ status: "ok", app_id: appId, window_index: windowIndex, window_title: windowTitle, element_index: elementIndex, role: after.target.role, characters_accepted: input.text.length, keys_accepted: input.keys, submitted: input.submit, focus_confirmed: after.target.focused === true, secure: false }); } } catch (error) { const message = text(() => error && error.message); result({ status: "error", error: /not authorized|not permitted|assistive|accessibility|-1743/iu.test(message) ? "accessibility_permission" : "execution_failed" }); } }
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
  windowIndex?: number;
  windowTitle?: string;
  focused: boolean;
  nodes: readonly SafeUiNode[];
  truncated: boolean;
  warnings: readonly string[];
}

export type UiActionName = "press" | "select" | "increment" | "decrement" | "show_menu" | "focus";
export type UiInputKey = "ENTER" | "TAB" | "ESCAPE" | "ARROW_UP" | "ARROW_DOWN" | "ARROW_LEFT" | "ARROW_RIGHT" | "HOME" | "END";

export interface UiSnapshotRecord {
  elementRef: string;
  appId: string;
  windowId: string;
  windowIndex: number;
  windowTitle: string;
  elementIndex: number;
  role: string;
  label?: string;
  enabled: boolean;
  focused: boolean;
  secure: boolean;
  ownerPrincipalId: string;
  ownerSessionId: string;
  observedAtMs: number;
}

export interface UiActionExecution {
  snapshot: UiSnapshotRecord;
  action: UiActionName;
}

export interface SafeUiAction {
  elementRef: string;
  action: UiActionName;
  accepted: true;
  appId: string;
  windowId: string;
  reobserved: {
    role: string;
    enabled: boolean;
    focused: boolean;
    secure: false;
    state?: string;
  };
  warnings: readonly string[];
  truncated: false;
  verified: true;
}

export interface UiTypeExecution {
  snapshot: UiSnapshotRecord;
  text: string;
  keys: readonly UiInputKey[];
  submit: boolean;
}

export interface SafeUiType {
  elementRef: string;
  charactersAccepted: number;
  keysAccepted: readonly UiInputKey[];
  submitted: boolean;
  focusConfirmed: true;
  appId: string;
  windowId: string;
  reobserved: { role: string; focused: true; secure: false; state?: string };
  warnings: readonly string[];
  truncated: false;
  verified: true;
}

export interface UiInspector {
  observe(appId: string, windowHint: string | undefined, maxNodes: number, control: UiExecutionControl): Promise<SafeUiObservation>;
  action?(execution: UiActionExecution, control: UiExecutionControl): Promise<SafeUiAction>;
  type?(execution: UiTypeExecution, control: UiExecutionControl): Promise<SafeUiType>;
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

  async action(execution: UiActionExecution, control: UiExecutionControl): Promise<SafeUiAction> {
    const { snapshot, action } = execution;
    validateUiActionRequest(snapshot.elementRef, action);
    validateSensitiveUiTarget(snapshot.appId, snapshot.windowTitle);
    if (snapshot.secure || snapshot.label?.includes("[REDACTED]")) {
      throw new BrokerError("SECRET_BOUNDARY_DENIED", "Secure or redacted UI elements cannot be acted on");
    }
    const result = await this.supervisor.run({
      executable: OSASCRIPT,
      args: [
        "-l", "JavaScript", "-e", UI_ACTION_SCRIPT, "--",
        snapshot.appId,
        snapshot.windowTitle,
        String(snapshot.windowIndex),
        String(snapshot.elementIndex),
        snapshot.role,
        snapshot.label ?? "",
        action
      ],
      cwd: UI_OBSERVE_CWD,
      environment: {},
      timeoutMs: Math.min(control.timeoutMs, MAX_TIMEOUT_MS),
      outputCapBytes: 262_144,
      shouldCancel: control.shouldCancel
    });
    return parseUiActionResult(result, snapshot, action);
  }

  async type(execution: UiTypeExecution, control: UiExecutionControl): Promise<SafeUiType> {
    const { snapshot, text: inputText, keys, submit } = execution;
    validateUiTypeRequest(snapshot.elementRef, inputText, keys, submit);
    validateSensitiveUiTarget(snapshot.appId, snapshot.windowTitle);
    if (snapshot.secure || snapshot.label?.includes("[REDACTED]")) {
      throw new BrokerError("SECRET_BOUNDARY_DENIED", "Secure or redacted UI elements cannot receive input");
    }
    const result = await this.supervisor.run({
      executable: OSASCRIPT,
      args: ["-l", "JavaScript", "-e", UI_TYPE_SCRIPT, "--", snapshot.appId, snapshot.windowTitle,
        String(snapshot.windowIndex), String(snapshot.elementIndex), snapshot.role, snapshot.label ?? ""],
      stdin: canonicalJson({ text: inputText, keys: [...keys], submit }),
      cwd: UI_OBSERVE_CWD,
      environment: {},
      timeoutMs: Math.min(control.timeoutMs, MAX_TIMEOUT_MS),
      outputCapBytes: 262_144,
      shouldCancel: control.shouldCancel
    });
    return parseUiTypeResult(result, execution);
  }
}

export class UiSnapshotRegistry {
  private readonly snapshots = new Map<string, UiSnapshotRecord>();

  recordObservation(observation: SafeUiObservation, ownerPrincipalId: string, ownerSessionId: string, observedAtMs: number): void {
    const windowTitle = (observation.windowTitle ?? "").replace(/[\u0000-\u001f\u007f]/gu, "�").slice(0, MAX_LABEL_LENGTH);
    if (windowTitle.length === 0 || observation.truncated) return;
    validateSensitiveUiTarget(observation.appId, windowTitle);
    const windowIndex = observation.windowIndex ?? 0;
    for (const [elementIndex, node] of observation.nodes.entries()) {
      const labelResult = node.secure
        ? { text: "", redacted: node.label !== undefined }
        : node.label === undefined
          ? { text: "", redacted: false }
          : redactLogText(node.label.replace(/[\u0000-\u001f\u007f]/gu, "�").slice(0, MAX_LABEL_LENGTH));
      const record: UiSnapshotRecord = {
        elementRef: node.elementRef,
        appId: observation.appId,
        windowId: observation.windowId,
        windowIndex,
        windowTitle,
        elementIndex,
        role: node.role,
        ...(labelResult.text.length > 0 ? { label: labelResult.text } : labelResult.redacted ? { label: "[REDACTED]" } : {}),
        enabled: node.enabled,
        focused: node.focused,
        secure: node.secure,
        ownerPrincipalId,
        ownerSessionId,
        observedAtMs
      };
      this.snapshots.set(node.elementRef, record);
    }
    this.prune(observedAtMs);
  }

  resolve(elementRef: string, ownerPrincipalId: string, ownerSessionId: string, nowMs: number): UiSnapshotRecord {
    const snapshot = this.snapshots.get(elementRef);
    if (!snapshot || snapshot.ownerPrincipalId !== ownerPrincipalId || snapshot.ownerSessionId !== ownerSessionId) {
      throw new BrokerError("TARGET_NOT_FOUND", "UI element snapshot is not available");
    }
    if (nowMs < snapshot.observedAtMs || nowMs - snapshot.observedAtMs > UI_SNAPSHOT_TTL_MS) {
      this.snapshots.delete(elementRef);
      throw new BrokerError("TARGET_NOT_FOUND", "UI element snapshot is stale");
    }
    validateSensitiveUiTarget(snapshot.appId, snapshot.windowTitle);
    if (snapshot.secure || snapshot.label?.includes("[REDACTED]")) {
      throw new BrokerError("SECRET_BOUNDARY_DENIED", "Secure or redacted UI elements cannot be acted on");
    }
    return snapshot;
  }

  private prune(nowMs: number): void {
    for (const [elementRef, snapshot] of this.snapshots) {
      if (nowMs < snapshot.observedAtMs || nowMs - snapshot.observedAtMs > UI_SNAPSHOT_TTL_MS) this.snapshots.delete(elementRef);
    }
    while (this.snapshots.size > MAX_UI_SNAPSHOTS) {
      const oldest = this.snapshots.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.snapshots.delete(oldest);
    }
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

export function validateUiActionRequest(elementRef: unknown, action: unknown): asserts action is UiActionName {
  if (typeof elementRef !== "string" || !/^element:[a-f0-9]{48}$/u.test(elementRef)) {
    throw new BrokerError("PRECONDITION_FAILED", "element_ref must be an opaque Accessibility snapshot identity");
  }
  if (typeof action !== "string" || !["press", "select", "increment", "decrement", "show_menu", "focus"].includes(action)) {
    throw new BrokerError("PRECONDITION_FAILED", "action is not an allowlisted Accessibility action");
  }
}

export function validateUiTypeRequest(
  elementRef: unknown,
  text: unknown,
  keys: unknown = [],
  submit: unknown = false
): asserts text is string {
  if (typeof elementRef !== "string" || !/^element:[a-f0-9]{48}$/u.test(elementRef)) {
    throw new BrokerError("PRECONDITION_FAILED", "element_ref must be an opaque Accessibility snapshot identity");
  }
  if (typeof text !== "string" || text.length > 10_000 || text.includes("\0")) {
    throw new BrokerError("PRECONDITION_FAILED", "text must be a bounded string of at most 10000 characters");
  }
  assertContentDoesNotContainSecrets(Buffer.from(text, "utf8"));
  if (!Array.isArray(keys) || keys.length > 32 || keys.some((key) => typeof key !== "string" ||
      !["ENTER", "TAB", "ESCAPE", "ARROW_UP", "ARROW_DOWN", "ARROW_LEFT", "ARROW_RIGHT", "HOME", "END"].includes(key))) {
    throw new BrokerError("PRECONDITION_FAILED", "keys must contain at most 32 allowlisted key names");
  }
  if (typeof submit !== "boolean") throw new BrokerError("PRECONDITION_FAILED", "submit must be a boolean");
}

export function parseUiTypeResult(result: ProcessExecutionResult, execution: UiTypeExecution): SafeUiType {
  const { snapshot, text: inputText, keys, submit } = execution;
  validateUiTypeRequest(snapshot.elementRef, inputText, keys, submit);
  validateSensitiveUiTarget(snapshot.appId, snapshot.windowTitle);
  if (snapshot.secure || snapshot.label?.includes("[REDACTED]")) {
    throw new BrokerError("SECRET_BOUNDARY_DENIED", "Secure or redacted UI elements cannot receive input");
  }
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Accessibility input was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Accessibility input timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Accessibility input exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") {
    if (/not authorized|not permitted|assistive|accessibility|-1743/iu.test(result.stderr)) {
      throw new BrokerError("POLICY_DENIED", "Accessibility permission is not granted");
    }
    throw new BrokerError("EXECUTION_FAILED", "Accessibility input failed");
  }
  let parsed: unknown;
  try { parsed = parseJsonStrict(result.stdout); } catch { throw new BrokerError("VERIFICATION_FAILED", "Accessibility input returned malformed metadata"); }
  if (!isPlainDataRecord(parsed)) throw new BrokerError("VERIFICATION_FAILED", "Accessibility input returned malformed metadata");
  const record = parsed as Record<string, unknown>;
  if (record.status === "error") {
    if (!hasExactFields(record, ["status", "error"])) throw new BrokerError("VERIFICATION_FAILED", "Accessibility input returned malformed metadata");
    switch (record.error) {
      case "accessibility_permission": throw new BrokerError("POLICY_DENIED", "Accessibility permission is not granted");
      case "app_not_running":
      case "window_not_found":
      case "stale_target": throw new BrokerError("TARGET_NOT_FOUND", "UI element snapshot is stale");
      case "target_unsupported": throw new BrokerError("UNSUPPORTED_CAPABILITY", "Accessibility input target is not a text control");
      case "invalid_input": throw new BrokerError("PRECONDITION_FAILED", "Accessibility input metadata is malformed");
      default: throw new BrokerError("EXECUTION_FAILED", "Accessibility input failed");
    }
  }
  if (!hasExactFields(record, ["status", "app_id", "window_index", "window_title", "element_index", "role", "characters_accepted", "keys_accepted", "submitted", "focus_confirmed", "secure"])) {
    throw new BrokerError("VERIFICATION_FAILED", "Accessibility input returned malformed metadata");
  }
  if (record.status !== "ok" || record.app_id !== snapshot.appId || record.window_index !== snapshot.windowIndex ||
      record.window_title !== snapshot.windowTitle || record.element_index !== snapshot.elementIndex || record.role !== snapshot.role ||
      record.characters_accepted !== inputText.length || !Array.isArray(record.keys_accepted) ||
      record.keys_accepted.length !== keys.length || record.keys_accepted.some((key, index) => key !== keys[index]) ||
      record.submitted !== submit || record.focus_confirmed !== true || record.secure !== false) {
    throw new BrokerError("VERIFICATION_FAILED", "Accessibility input postcondition did not match the approved snapshot");
  }
  const windowId = opaqueWindowId(snapshot.appId, record.window_index as number, snapshot.windowTitle);
  if (windowId !== snapshot.windowId || opaqueElementId(windowId, snapshot.elementIndex, snapshot.role, snapshot.label ?? "", false) !== snapshot.elementRef) {
    throw new BrokerError("TARGET_NOT_FOUND", "UI element snapshot is stale");
  }
  return {
    elementRef: snapshot.elementRef,
    charactersAccepted: inputText.length,
    keysAccepted: [...keys],
    submitted: submit,
    focusConfirmed: true,
    appId: snapshot.appId,
    windowId,
    reobserved: { role: snapshot.role, focused: true, secure: false },
    warnings: [],
    truncated: false,
    verified: true
  };
}

export function parseUiActionResult(
  result: ProcessExecutionResult,
  snapshot: UiSnapshotRecord,
  action: UiActionName
): SafeUiAction {
  validateUiActionRequest(snapshot.elementRef, action);
  validateSensitiveUiTarget(snapshot.appId, snapshot.windowTitle);
  if (snapshot.secure || snapshot.label?.includes("[REDACTED]")) {
    throw new BrokerError("SECRET_BOUNDARY_DENIED", "Secure or redacted UI elements cannot be acted on");
  }
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Accessibility action was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Accessibility action timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Accessibility action exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") {
    if (/not authorized|not permitted|assistive|accessibility|-1743/iu.test(result.stderr)) {
      throw new BrokerError("POLICY_DENIED", "Accessibility permission is not granted");
    }
    throw new BrokerError("EXECUTION_FAILED", "Accessibility action failed");
  }
  let parsed: unknown;
  try { parsed = parseJsonStrict(result.stdout); } catch { throw new BrokerError("VERIFICATION_FAILED", "Accessibility action returned malformed metadata"); }
  if (!isPlainDataRecord(parsed)) throw new BrokerError("VERIFICATION_FAILED", "Accessibility action returned malformed metadata");
  const record = parsed as Record<string, unknown>;
  if (record.status === "error") {
    if (!hasExactFields(record, ["status", "error"])) throw new BrokerError("VERIFICATION_FAILED", "Accessibility action returned malformed metadata");
    switch (record.error) {
      case "accessibility_permission": throw new BrokerError("POLICY_DENIED", "Accessibility permission is not granted");
      case "app_not_running":
      case "window_not_found":
      case "stale_target": throw new BrokerError("TARGET_NOT_FOUND", "UI element snapshot is stale");
      case "secure_target": throw new BrokerError("SECRET_BOUNDARY_DENIED", "Secure UI elements cannot be acted on");
      case "action_unsupported": throw new BrokerError("UNSUPPORTED_CAPABILITY", "Accessibility action is not supported by the target");
      case "invalid_target": throw new BrokerError("PRECONDITION_FAILED", "UI action target metadata is malformed");
      default: throw new BrokerError("EXECUTION_FAILED", "Accessibility action failed");
    }
  }
  if (!hasExactFields(record, ["status", "app_id", "window_index", "window_title", "element_index", "role", "enabled", "focused", "secure", "accepted"])) {
    throw new BrokerError("VERIFICATION_FAILED", "Accessibility action returned malformed metadata");
  }
  if (record.status !== "ok" || record.app_id !== snapshot.appId ||
      record.window_index !== snapshot.windowIndex || record.window_title !== snapshot.windowTitle ||
      record.element_index !== snapshot.elementIndex || record.role !== snapshot.role ||
      typeof record.enabled !== "boolean" || typeof record.focused !== "boolean" ||
      record.secure !== false || record.accepted !== true) {
    throw new BrokerError("VERIFICATION_FAILED", "Accessibility action readback did not match the approved snapshot");
  }
  const windowId = opaqueWindowId(snapshot.appId, record.window_index as number, snapshot.windowTitle);
  if (windowId !== snapshot.windowId || opaqueElementId(windowId, snapshot.elementIndex, snapshot.role, snapshot.label ?? "", false) !== snapshot.elementRef) {
    throw new BrokerError("TARGET_NOT_FOUND", "UI element snapshot is stale");
  }
  return {
    elementRef: snapshot.elementRef,
    action,
    accepted: true,
    appId: snapshot.appId,
    windowId,
    reobserved: {
      role: snapshot.role,
      enabled: record.enabled as boolean,
      focused: record.focused as boolean,
      secure: false
    },
    warnings: [],
    truncated: false,
    verified: true
  };
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
  try { parsed = parseJsonStrict(result.stdout); } catch { throw new BrokerError("VERIFICATION_FAILED", "Accessibility observation returned malformed metadata"); }
  if (!isPlainDataRecord(parsed)) {
    throw new BrokerError("VERIFICATION_FAILED", "Accessibility observation returned malformed metadata");
  }
  const record = parsed as Record<string, unknown>;
  validateSensitiveUiTarget(appId);
  if (record.status === "error") {
    if (!hasExactFields(record, ["status", "error"])) throw new BrokerError("VERIFICATION_FAILED", "Accessibility observation returned malformed metadata");
    switch (record.error) {
      case "accessibility_permission": throw new BrokerError("POLICY_DENIED", "Accessibility permission is not granted");
      case "app_not_running": throw new BrokerError("TARGET_NOT_FOUND", "The requested app is not running");
      case "window_not_found": throw new BrokerError("TARGET_NOT_FOUND", "The requested app window was not found");
      case "invalid_app_identity": throw new BrokerError("PRECONDITION_FAILED", "app_id must be a stable bundle identity");
      default: throw new BrokerError("EXECUTION_FAILED", "Accessibility observation failed");
    }
  }
  if (!hasExactFields(record, ["status", "app_id", "window_index", "window_title", "focused", "nodes", "truncated"])) {
    throw new BrokerError("VERIFICATION_FAILED", "Accessibility observation returned malformed metadata");
  }
  if (record.status !== "ok" || record.app_id !== appId ||
      !Number.isSafeInteger(record.window_index) || (record.window_index as number) < 0 || (record.window_index as number) >= MAX_NODES ||
      typeof record.window_title !== "string" || record.window_title.length > MAX_LABEL_LENGTH ||
      typeof record.focused !== "boolean" || !isDenseArray(record.nodes, maxNodes) ||
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
    if (!isPlainDataRecord(value) || !hasExactFields(value, ["index", "role", "label", "enabled", "focused", "secure"])) {
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
    const elementRef = opaqueElementId(windowId, index, role, labelResult.text, node.secure);
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
    windowIndex: record.window_index as number,
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

export function opaqueElementId(windowId: string, elementIndex: number, role: string, label: string, secure: boolean): string {
  return `element:${sha256(canonicalJson({ windowId, index: elementIndex, role, label, secure })).slice(0, 48)}`;
}

export const uiObserveExecutableForTesting = OSASCRIPT;
export const uiObserveScriptForTesting = UI_OBSERVE_SCRIPT;
export const uiActionExecutableForTesting = OSASCRIPT;
export const uiActionScriptForTesting = UI_ACTION_SCRIPT;
export const uiTypeExecutableForTesting = OSASCRIPT;
export const uiTypeScriptForTesting = UI_TYPE_SCRIPT;

function hasExactFields(value: Record<string, unknown>, required: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === required.length && required.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function isDenseArray(value: unknown, maxLength: number): value is readonly unknown[] {
  if (!Array.isArray(value) || value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0) return false;
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== value.length + 1 || Object.keys(value).length !== value.length) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor)) return false;
  }
  return true;
}
