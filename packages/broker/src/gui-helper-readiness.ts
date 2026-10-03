import { parseJsonStrict } from "@mac-operator/contracts";
import { execFile } from "node:child_process";
import { lstat } from "node:fs/promises";
import { dirname, join } from "node:path";
import { promisify } from "node:util";
import { isPlainDataRecord } from "./plain-record.js";
import { guiApplicationExecutable, GuiProcessSupervisor } from "./gui-process-supervisor.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";
import { guiLauncherFailureError } from "./gui-launcher-errors.js";

export interface GuiHelperReadiness {
  installed: boolean;
  identity_valid: boolean;
  accessibility: boolean | null;
  screen_recording: boolean | null;
  transport: "launchservices";
  ordinary_apps?: boolean | null;
  desktop_surfaces?: boolean | null;
  reason?: string;
}

export interface GuiHelperReadinessProbe { probe(): Promise<GuiHelperReadiness>; }

interface ReadinessDependencies {
  stat(path: string): Promise<{ isDirectory(): boolean; isFile(): boolean; mode: number }>;
  inspect(executable: string, args: readonly string[], timeoutMs: number): Promise<string>;
  permission(timeoutMs: number): Promise<ProcessExecutionResult>;
}

const exec = promisify(execFile);

/** Read-only checks use the fixed installed identity and the production launcher. */
export class MacGuiHelperReadinessProbe implements GuiHelperReadinessProbe {
  constructor(private readonly dependencies: ReadinessDependencies = {
    stat: path => lstat(path),
    inspect: async (executable, args, timeoutMs) => (await exec(executable, [...args], {
      timeout: timeoutMs, maxBuffer: 16384, shell: false, env: { PATH: "/usr/bin:/bin" }
    })).stdout,
    permission: timeoutMs => new GuiProcessSupervisor().run({
      executable: guiApplicationExecutable, args: ["permission"], cwd: "/", timeoutMs, outputCapBytes: 4096
    })
  }, private readonly productionPermission?: (timeoutMs: number) => Promise<ProcessExecutionResult>,
  private readonly options: { requireOrdinaryApplications?: boolean;
    productionCapabilities?: (timeoutMs: number) => Promise<ProcessExecutionResult> } = {}) {}

  async probe(): Promise<GuiHelperReadiness> {
    const deadline = Date.now() + 2500;
    const remaining = () => Math.max(1, deadline - Date.now());
    const inspect = (executable: string, args: readonly string[]) => this.dependencies.inspect(executable, args, Math.min(500, remaining()));
    const state: GuiHelperReadiness = { installed: false, identity_valid: false, accessibility: null,
      screen_recording: null, transport: "launchservices",
      ...(this.options.requireOrdinaryApplications ? { ordinary_apps: null, desktop_surfaces: null } : {}) };
    const app = dirname(dirname(dirname(guiApplicationExecutable)));
    try {
      if (!(await this.dependencies.stat(app)).isDirectory()) return { ...state, reason: "GUI_HELPER_UNAVAILABLE" };
      state.installed = true;
      for (const directory of [join(app, "Contents"), join(app, "Contents", "MacOS")]) {
        if (!(await this.dependencies.stat(directory)).isDirectory()) return { ...state, reason: "GUI_HELPER_UNAVAILABLE" };
      }
      if (!(await this.dependencies.stat(join(app, "Contents", "Info.plist"))).isFile()) return { ...state, reason: "GUI_HELPER_UNAVAILABLE" };
      const executable = await this.dependencies.stat(guiApplicationExecutable);
      if (!executable.isFile() || (executable.mode & 0o111) === 0) return { ...state, reason: "GUI_HELPER_UNAVAILABLE" };
      const plist = join(app, "Contents", "Info.plist");
      const bundleId = await inspect("/usr/libexec/PlistBuddy", ["-c", "Print CFBundleIdentifier", plist]);
      const packageType = await inspect("/usr/libexec/PlistBuddy", ["-c", "Print CFBundlePackageType", plist]);
      const bundleExecutable = await inspect("/usr/libexec/PlistBuddy", ["-c", "Print CFBundleExecutable", plist]);
      if (bundleId.trim() !== "dev.macoperator.personal.gui" || packageType.trim() !== "APPL" || bundleExecutable.trim() !== "gui_vision") {
        return { ...state, reason: "GUI_HELPER_UNAVAILABLE" };
      }
      await inspect("/usr/bin/codesign", ["--verify", "--strict", app]);
      state.identity_valid = true;
    } catch { return { ...state, reason: "GUI_HELPER_UNAVAILABLE" }; }
    try {
      const result = await (this.productionPermission ?? this.dependencies.permission)(remaining());
      const failure = guiLauncherFailureError(result);
      if (failure || result.resultClass !== "SUCCEEDED" || result.exitCode !== 0 || result.truncated || !result.terminationObserved) {
        if (result.exitCode === 71) state.identity_valid = false;
        return { ...state, reason: failure?.message.split(":")[0] ?? "GUI_HELPER_PERMISSION_PROBE_FAILED" };
      }
      if (Buffer.byteLength(result.stdout, "utf8") > 4096) return { ...state, reason: "GUI_HELPER_PERMISSION_PROBE_FAILED" };
      const value: unknown = parseJsonStrict(result.stdout);
      if (!isPlainDataRecord(value) || Object.keys(value).sort().join(",") !== "accessibility,screen_recording,status" ||
          value.status !== "ok" || ![false, true, 0, 1].includes(value.accessibility as boolean | number) || typeof value.screen_recording !== "boolean") {
        return { ...state, reason: "GUI_HELPER_PERMISSION_PROBE_FAILED" };
      }
      state.accessibility = value.accessibility === true || value.accessibility === 1;
      state.screen_recording = value.screen_recording;
      if (!state.accessibility) state.reason = "ACCESSIBILITY_PERMISSION_REQUIRED";
      else if (!value.screen_recording) state.reason = "SCREEN_RECORDING_PERMISSION_REQUIRED";
      if (this.options.requireOrdinaryApplications && state.accessibility) {
        try {
          const capabilities = await (this.options.productionCapabilities ?? (timeoutMs => new GuiProcessSupervisor().run({
            executable: guiApplicationExecutable, args: ["capabilities"], cwd: "/", timeoutMs, outputCapBytes: 4096
          })))(remaining());
          const failure = guiLauncherFailureError(capabilities);
          if (failure) throw failure;
          if (capabilities.resultClass !== "SUCCEEDED" || capabilities.exitCode !== 0 || !capabilities.terminationObserved ||
              capabilities.truncated || Buffer.byteLength(capabilities.stdout, "utf8") > 4096) {
            return { ...state, reason: "GUI_HELPER_CAPABILITY_PROBE_FAILED" };
          }
          const capabilityValue: unknown = parseJsonStrict(capabilities.stdout);
          state.ordinary_apps = isPlainDataRecord(capabilityValue) &&
              Object.keys(capabilityValue).sort().join(",") === "features,status,version" && capabilityValue.status === "ok" &&
              capabilityValue.version === "0.3" && isPlainDataRecord(capabilityValue.features) &&
              Object.keys(capabilityValue.features).sort().join(",") === "bounded_global_coordinates,desktop_surfaces,ordinary_apps" &&
              capabilityValue.features.ordinary_apps === true && capabilityValue.features.bounded_global_coordinates === true &&
              capabilityValue.features.desktop_surfaces === true;
          state.desktop_surfaces = state.ordinary_apps;
          if (!state.ordinary_apps) state.reason = "GUI_HELPER_UPGRADE_REQUIRED";
        } catch (error) {
          const reason = error instanceof Error ? error.message.split(":")[0] : undefined;
          if (reason === "GUI_HELPER_UNAVAILABLE") state.identity_valid = false;
          return { ...state, ordinary_apps: null, reason: reason && /^GUI_[A-Z_]+$/u.test(reason) ? reason : "GUI_HELPER_CAPABILITY_PROBE_FAILED" };
        }
      }
      return state;
    } catch (error) {
      // The launcher mapper throws before returning a result in the production supervisor.
      const reason = error instanceof Error ? error.message.split(":")[0] ?? "GUI_HELPER_PERMISSION_PROBE_FAILED" : "GUI_HELPER_PERMISSION_PROBE_FAILED";
      if (reason === "GUI_HELPER_UNAVAILABLE") state.identity_valid = false;
      return { ...state, reason: /^GUI_[A-Z_]+$/u.test(reason) ? reason : "GUI_HELPER_PERMISSION_PROBE_FAILED" };
    }
  }
}

export function guiReadinessPermissions(state: GuiHelperReadiness): { name: string; granted: boolean; reason: string }[] {
  const permissions = [
    { name: "gui_helper_installed", granted: state.installed },
    { name: "gui_helper_identity_valid", granted: state.identity_valid },
    { name: "gui_helper_launchservices", granted: state.accessibility !== null && state.screen_recording !== null },
    { name: "accessibility", granted: state.accessibility === true },
    { name: "screen_recording", granted: state.screen_recording === true }
  ];
  if (state.ordinary_apps !== undefined) permissions.push({ name: "gui_helper_ordinary_apps", granted: state.ordinary_apps === true });
  if (state.desktop_surfaces !== undefined) permissions.push({ name: "gui_helper_desktop_surfaces", granted: state.desktop_surfaces === true });
  return permissions.map(permission => {
    let reason = "verified";
    if (permission.name === "gui_helper_launchservices") reason = permission.granted ? "transport=launchservices" : state.reason ?? "GUI_HELPER_PERMISSION_PROBE_FAILED";
    else if (!permission.granted) {
      if (permission.name === "accessibility" && state.accessibility === false) reason = "ACCESSIBILITY_PERMISSION_REQUIRED";
      else if (permission.name === "screen_recording" && state.screen_recording === false) reason = "SCREEN_RECORDING_PERMISSION_REQUIRED";
      else if (permission.name === "gui_helper_ordinary_apps" || permission.name === "gui_helper_desktop_surfaces") reason = state.ordinary_apps === false
        ? "GUI_HELPER_UPGRADE_REQUIRED" : state.reason ?? "GUI_HELPER_CAPABILITY_PROBE_FAILED";
      else reason = state.reason ?? "GUI_HELPER_UNAVAILABLE";
    }
    return { ...permission, reason };
  });
}
