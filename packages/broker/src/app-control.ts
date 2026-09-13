import { BrokerError } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { redactLogText } from "./secret-policy.js";
import type { AppExecutionControl, AppInventoryInspector, SafeAppInventory } from "./app-inspector.js";

const OPEN_EXECUTABLE = "/usr/bin/open";
const OPEN_CWD = "/";
const MAX_OUTPUT_BYTES = 262_144;
const MAX_TIMEOUT_MS = 30_000;
const MAX_POLL_ATTEMPTS = 20;
const POLL_INTERVAL_MS = 100;
const APP_ID_PATTERN = /^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u;

export interface SafeAppOpen {
  appId: string;
  state: "launched" | "already_running";
  processId: null;
  target: { kind: "app"; reference: string };
  verified: true;
  warnings: readonly string[];
  truncated: false;
}

export interface AppControlInspector {
  open(appId: string, documentPath: string | undefined, url: string | undefined, control: AppExecutionControl): Promise<SafeAppOpen>;
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

function assertOpenResult(result: ProcessExecutionResult): void {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "App launch was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "App launch timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "App launch exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") throw new BrokerError("EXECUTION_FAILED", "App launch failed");
}

export const appOpenExecutableForTesting = OPEN_EXECUTABLE;
