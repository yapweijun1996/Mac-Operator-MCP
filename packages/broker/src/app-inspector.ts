import { BrokerError, parseJsonStrict } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { redactLogText } from "./secret-policy.js";

const OSASCRIPT = "/usr/bin/osascript";
const APP_METADATA_CWD = "/";
const MAX_OUTPUT_BYTES = 262_144;
const MAX_APPS = 500;
const MAX_NAME_LENGTH = 256;
const MAX_VERSION_LENGTH = 128;
const BUNDLE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u;

/**
 * Broker-owned JXA. It accepts no caller-provided code, paths, or arguments.
 * The script returns only bundle metadata and running state; app bundle paths,
 * process arguments, and environment values never cross the adapter boundary.
 */
const APP_INVENTORY_SCRIPT = String.raw`
ObjC.import("Foundation");
ObjC.import("AppKit");

const MAX_APPS = 500;
const roots = ["/Applications", "/System/Applications", "/System/Library/CoreServices"];
const home = (() => { try { return ObjC.unwrap($.NSHomeDirectory()) || ""; } catch (_) { return ""; } })();
if (home.length > 0) roots.push(home + "/Applications");
const records = new Map();

function unwrap(value) {
  try {
    const result = ObjC.unwrap(value);
    return result === null || result === undefined ? "" : String(result);
  } catch (_) {
    return "";
  }
}

function bundleValue(bundle, key) {
  try { return unwrap(bundle.objectForInfoDictionaryKey($(key))); } catch (_) { return ""; }
}

function add(bundleId, name, version, running) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@+\\-]{0,255}$/.test(bundleId)) return;
  const existing = records.get(bundleId);
  records.set(bundleId, {
    app_id: "bundle:" + bundleId,
    bundle_id: bundleId,
    name: name.length > 0 ? name : bundleId,
    ...(version.length > 0 ? { version } : {}),
    running: Boolean(running || existing?.running)
  });
}

const fileManager = $.NSFileManager.defaultManager;
for (const root of roots) {
  let entries = [];
  try { entries = ObjC.unwrap(fileManager.contentsOfDirectoryAtPathError($(root), null)).map((value) => ObjC.unwrap(value)); } catch (_) { entries = []; }
  for (const entry of entries) {
    if (records.size >= MAX_APPS || !entry.endsWith(".app")) continue;
    try {
      const bundle = $.NSBundle.bundleWithPath($(root + "/" + entry));
      if (bundle) {
        const bundleId = bundleValue(bundle, "CFBundleIdentifier");
        const name = bundleValue(bundle, "CFBundleDisplayName") || bundleValue(bundle, "CFBundleName");
        const version = bundleValue(bundle, "CFBundleShortVersionString") || bundleValue(bundle, "CFBundleVersion");
        add(bundleId, name, version, false);
      }
    } catch (_) {}
  }
}

try {
  for (const app of $.NSWorkspace.sharedWorkspace.runningApplications.js) {
    if (records.size >= MAX_APPS && !records.has(unwrap(app.bundleIdentifier))) continue;
    const bundleId = unwrap(app.bundleIdentifier);
    const name = unwrap(app.localizedName);
    add(bundleId, name, "", true);
  }
} catch (_) {}

JSON.stringify(Array.from(records.values()).slice(0, MAX_APPS));
`;

export interface AppExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface SafeApp {
  appId: string;
  bundleId: string;
  name: string;
  running: boolean;
  version?: string;
}

export interface SafeAppInventory {
  apps: readonly SafeApp[];
  warnings: readonly string[];
  truncated: boolean;
}

export interface AppInventoryInspector {
  list(runningOnly: boolean, includeInstalled: boolean, control: AppExecutionControl): Promise<SafeAppInventory>;
}

export class AppInventoryInspectorImpl implements AppInventoryInspector {
  private readonly supervisor: Pick<ProcessSupervisor, "run">;

  constructor(supervisor: Pick<ProcessSupervisor, "run"> = new ProcessSupervisor({ maxConcurrent: 1, allowedEnvironmentKeys: [] })) {
    this.supervisor = supervisor;
  }

  async list(runningOnly: boolean, includeInstalled: boolean, control: AppExecutionControl): Promise<SafeAppInventory> {
    validateAppListRequest(runningOnly, includeInstalled);
    const result = await this.supervisor.run({
      executable: OSASCRIPT,
      args: ["-l", "JavaScript", "-e", APP_INVENTORY_SCRIPT],
      cwd: APP_METADATA_CWD,
      environment: {},
      timeoutMs: Math.min(control.timeoutMs, 10_000),
      outputCapBytes: MAX_OUTPUT_BYTES,
      shouldCancel: control.shouldCancel
    });
    return parseAppInventoryResult(result, runningOnly, includeInstalled);
  }
}

export function validateAppListRequest(runningOnly = false, includeInstalled = true): void {
  if (typeof runningOnly !== "boolean" || typeof includeInstalled !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "App inventory filters must be boolean");
  }
}

export function parseAppInventoryResult(result: ProcessExecutionResult, runningOnly = false, includeInstalled = true): SafeAppInventory {
  validateAppListRequest(runningOnly, includeInstalled);
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "App inventory was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "App inventory timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "App inventory exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") throw new BrokerError("EXECUTION_FAILED", "App inventory failed");
  let parsed: unknown;
  try { parsed = parseJsonStrict(result.stdout); } catch { throw new BrokerError("VERIFICATION_FAILED", "App inventory returned malformed metadata"); }
  if (!Array.isArray(parsed) || parsed.length > MAX_APPS) {
    throw new BrokerError("VERIFICATION_FAILED", "App inventory exceeded its result limit");
  }
  const apps: SafeApp[] = [];
  const seen = new Set<string>();
  const warnings: string[] = [];
  let redacted = false;
  for (const value of parsed) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
      throw new BrokerError("VERIFICATION_FAILED", "App inventory returned malformed metadata");
    }
    const record = value as Record<string, unknown>;
    const appId = record.app_id;
    const bundleId = record.bundle_id;
    const name = record.name;
    const running = record.running;
    const version = record.version;
    if (typeof appId !== "string" || !/^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u.test(appId) ||
        typeof bundleId !== "string" || !BUNDLE_ID_PATTERN.test(bundleId) ||
        appId !== `bundle:${bundleId}` || typeof name !== "string" || name.length < 1 || name.length > MAX_NAME_LENGTH ||
        typeof running !== "boolean" || (version !== undefined && (typeof version !== "string" || version.length > MAX_VERSION_LENGTH))) {
      throw new BrokerError("VERIFICATION_FAILED", "App inventory returned malformed metadata");
    }
    if (seen.has(appId)) continue;
    if (runningOnly && !running) continue;
    if (!includeInstalled && !running) continue;
    seen.add(appId);
    const redactedName = redactLogText(name);
    const safeName = redactedName.text.replace(/[\u0000-\u001f\u007f]/gu, "�").slice(0, MAX_NAME_LENGTH);
    if (safeName.length === 0) throw new BrokerError("VERIFICATION_FAILED", "App inventory returned an empty app name");
    redacted ||= redactedName.redacted || safeName !== name;
    const redactedVersion = typeof version === "string" ? redactLogText(version) : undefined;
    const safeVersion = redactedVersion?.text.replace(/[\u0000-\u001f\u007f]/gu, "�").slice(0, MAX_VERSION_LENGTH);
    redacted ||= redactedVersion?.redacted === true || (safeVersion !== undefined && safeVersion !== version);
    apps.push({
      appId,
      bundleId,
      name: safeName,
      running,
      ...(safeVersion !== undefined && safeVersion.length > 0 ? { version: safeVersion } : {})
    });
  }
  apps.sort((left, right) => left.bundleId.localeCompare(right.bundleId));
  if (redacted) warnings.push("Sensitive app metadata was redacted");
  if (result.truncated) warnings.push("App inventory output was limited by a fixed adapter budget");
  return { apps, warnings, truncated: result.truncated };
}

export const appInventoryScriptForTesting = APP_INVENTORY_SCRIPT;
