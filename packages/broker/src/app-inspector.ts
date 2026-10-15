import { BrokerError, parseJsonStrict } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { isPlainDataRecord } from "./plain-record.js";
import { redactLogText } from "./secret-policy.js";

const OSASCRIPT = "/usr/bin/osascript";
const APP_METADATA_CWD = "/";
const MAX_OUTPUT_BYTES = 262_144;
const MAX_APPS = 500;
const MAX_NAME_LENGTH = 256;
const MAX_VERSION_LENGTH = 128;
const BUNDLE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u;

/**
 * Broker-owned JXA. Validated boolean filters select fixed script variants;
 * callers cannot provide code or discovery paths.
 * The script returns only bundle metadata and running state; app bundle paths,
 * process arguments, and environment values never cross the adapter boundary.
 */
const APP_INVENTORY_SCRIPT = String.raw`
ObjC.import("Foundation");
ObjC.import("AppKit");

const MAX_APPS = 500;
const MAX_DIRECTORIES = 128;
const MAX_ENTRIES = 10000;
const MAX_DEPTH = 4;
const INCLUDE_INSTALLED = __INCLUDE_INSTALLED__;
const roots = ["/Applications", "/Applications/Utilities", "/System/Applications", "/System/Applications/Utilities", "/System/Library/CoreServices"];
const home = (() => { try { return ObjC.unwrap($.NSHomeDirectory()) || ""; } catch (_) { return ""; } })();
if (home.length > 0) roots.push(home + "/Applications", home + "/Applications/Utilities");
const records = new Map();
let truncated = false;

function unwrap(value) {
  try {
    const result = ObjC.unwrap(value);
    return result === null || result === undefined ? "" : String(result);
  } catch (_) {
    return "";
  }
}

function bundleValue(bundle, key) {
  try { return unwrap(bundle.objectForInfoDictionaryKey($(key))); } catch (_) { truncated = true; return ""; }
}

function add(bundleId, name, version, running) {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:@+\\-]{0,255}$/.test(bundleId)) return;
  const existing = records.get(bundleId);
  if (!existing && records.size >= MAX_APPS) { truncated = true; return; }
  const retainedVersion = existing?.version || version;
  records.set(bundleId, {
    app_id: "bundle:" + bundleId,
    bundle_id: bundleId,
    name: existing?.name || name || bundleId,
    ...(retainedVersion.length > 0 ? { version: retainedVersion } : {}),
    running: Boolean(running || existing?.running)
  });
}

const fileManager = $.NSFileManager.defaultManager;
const workspace = $.NSWorkspace.sharedWorkspace;
// Reserve capacity for running apps before adding installed-only identities.
try {
  for (const app of workspace.runningApplications.js) {
    add(unwrap(app.bundleIdentifier), unwrap(app.localizedName), "", true);
  }
} catch (_) { truncated = true; }

function directory(path) {
  try {
    if (!fileManager.fileExistsAtPath($(path))) return false;
    const attributes = fileManager.attributesOfItemAtPathError($(path), null);
    if (unwrap(attributes.objectForKey($.NSFileType)) !== unwrap($.NSFileTypeDirectory)) return false;
    // Reject links in the path, including root or intermediate components.
    return unwrap($(path).stringByResolvingSymlinksInPath) === path;
  } catch (_) { truncated = true; return false; }
}

if (INCLUDE_INSTALLED) {
  const pending = roots.map(path => ({ path, depth: 0 }));
  const scheduled = new Set(roots);
  let visitedEntries = 0;
  while (pending.length > 0) {
    const current = pending.shift();
    if (!directory(current.path)) continue;
    let entries;
    try { entries = ObjC.unwrap(fileManager.contentsOfDirectoryAtPathError($(current.path), null)).map(value => ObjC.unwrap(value)).sort(); }
    catch (_) { truncated = true; continue; }
    for (const entry of entries) {
      if (++visitedEntries > MAX_ENTRIES) { truncated = true; break; }
      if (typeof entry !== "string" || !entry || entry.startsWith(".") || /[\\/\x00]/.test(entry)) continue;
      const path = current.path + "/" + entry;
      if (!directory(path)) continue;
      if (entry.endsWith(".app")) {
        try {
          const bundle = $.NSBundle.bundleWithPath($(path));
          if (bundle) add(bundleValue(bundle, "CFBundleIdentifier"),
            bundleValue(bundle, "CFBundleDisplayName") || bundleValue(bundle, "CFBundleName"),
            bundleValue(bundle, "CFBundleShortVersionString") || bundleValue(bundle, "CFBundleVersion"), false);
        } catch (_) { truncated = true; }
        continue;
      }
      try { if (workspace.isFilePackageAtPath($(path))) continue; }
      catch (_) { truncated = true; continue; }
      if (scheduled.has(path)) continue;
      if (current.depth >= MAX_DEPTH || scheduled.size >= MAX_DIRECTORIES) { truncated = true; continue; }
      scheduled.add(path);
      pending.push({ path, depth: current.depth + 1 });
    }
    if (visitedEntries > MAX_ENTRIES) break;
  }
}

JSON.stringify({ apps: Array.from(records.values()), truncated });
`;

function inventoryScript(runningOnly: boolean, includeInstalled: boolean): string {
  return APP_INVENTORY_SCRIPT.replace("__INCLUDE_INSTALLED__", String(!runningOnly && includeInstalled));
}

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
      args: ["-l", "JavaScript", "-e", inventoryScript(runningOnly, includeInstalled)],
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
  let rows: unknown[];
  let semanticTruncation = false;
  // Accept the legacy array for existing internal adapters; the shipped script
  // always supplies explicit completeness evidence.
  if (Array.isArray(parsed)) rows = parsed;
  else if (isPlainDataRecord(parsed) && hasExactFields(parsed, ["apps", "truncated"]) &&
      Array.isArray(parsed.apps) && typeof parsed.truncated === "boolean") {
    rows = parsed.apps;
    semanticTruncation = parsed.truncated;
  } else throw new BrokerError("VERIFICATION_FAILED", "App inventory exceeded its result limit or returned malformed metadata");
  if (rows.length > MAX_APPS) throw new BrokerError("VERIFICATION_FAILED", "App inventory exceeded its result limit");
  const apps: SafeApp[] = [];
  const seen = new Set<string>();
  const warnings: string[] = [];
  let redacted = false;
  for (const value of rows) {
    if (!isPlainDataRecord(value) || !hasExactFields(value, ["app_id", "bundle_id", "name", "running"], ["version"])) {
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
  if (semanticTruncation) warnings.push("App inventory is incomplete because an application or discovery budget was reached, or metadata was unavailable");
  if (result.truncated) warnings.push("App inventory output was limited by a fixed adapter budget");
  return { apps, warnings, truncated: result.truncated || semanticTruncation };
}

export const appInventoryScriptForTesting = inventoryScript(false, true);

function hasExactFields(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) && keys.every((key) => allowed.has(key));
}
