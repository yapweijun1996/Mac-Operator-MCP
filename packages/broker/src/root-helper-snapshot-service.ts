import type { ServiceSignalSource } from "./service-entrypoint.js";
import {
  captureLaunchdBrokerProcessIdentity,
  type LaunchdHelperIdentityCommandExecutor
} from "./privileged-helper-runtime.js";
import { capturePeerProcessCredentials, capturePeerProcessIdentity, type PeerProcessIdentity } from "./peer-credentials.js";
import { ProcessSupervisor, type ProcessExecutionRequest, type ProcessExecutionResult } from "./process-supervisor.js";
import { LaunchdReadbackError, parseLaunchdJobReadback } from "./launchd-readback.js";
import {
  createRootHelperSnapshotRuntimeFromKeyMaterial,
  type RootHelperSnapshotRuntime,
  type RootHelperSnapshotRuntimeKeyMaterialOptions
} from "./root-helper-snapshot-runtime.js";

export type RootHelperSnapshotServiceState = "stopped" | "starting" | "running" | "stopping" | "failed";

export type RootHelperSnapshotServiceStartupErrorCode =
  | "BROKER_SERVICE_INVALID"
  | "BROKER_SERVICE_UNAVAILABLE"
  | "BROKER_PROCESS_NOT_RUNNING"
  | "BROKER_PROCESS_IDENTITY_UNAVAILABLE"
  | "ROOT_HELPER_RUNTIME_UNAVAILABLE";

const LAUNCHCTL_PATH = "/bin/launchctl" as const;
const LAUNCHCTL_TIMEOUT_MS = 5_000 as const;
const LAUNCHCTL_OUTPUT_CAP_BYTES = 131_072 as const;
const LAUNCHD_STARTUP_DEADLINE_MS = 5_000 as const;
const LAUNCHD_XPCPROXY_RETRY_DELAY_MS = 50 as const;
const ROOT_HELPER_SERVICE_PATTERN = /^system\/(com\.mac-operator\.root-helper-snapshot)$/u;

export class RootHelperSnapshotServiceStartupError extends Error {
  readonly code: RootHelperSnapshotServiceStartupErrorCode;

  constructor(code: RootHelperSnapshotServiceStartupErrorCode, message: string) {
    super(message);
    this.name = "RootHelperSnapshotServiceStartupError";
    this.code = code;
  }
}

export interface RootHelperSnapshotServiceMetadata {
  component: "mac-operator-root-helper-snapshot";
  sourceRevision: string;
  contractVersion: string;
  evidenceRef?: string;
}

export interface RootHelperSnapshotServiceReadback extends RootHelperSnapshotServiceMetadata {
  state: RootHelperSnapshotServiceState;
  runtimeState: RootHelperSnapshotRuntime["state"];
  nativeTransportRequired: true;
  available: boolean;
  capability: RootHelperSnapshotRuntime["capability"];
}

export interface RootHelperSnapshotServiceLaunchdOptions
  extends Omit<RootHelperSnapshotRuntimeKeyMaterialOptions, "peerPolicy"> {
  /** Exact per-user Broker LaunchAgent identity used by the root helper. */
  brokerServiceId: string;
  expectedBrokerUid: number;
  expectedBrokerGid?: number;
  commandExecutor?: LaunchdHelperIdentityCommandExecutor;
}

export interface LaunchdRootHelperIdentityCommandExecutor {
  run(command: ProcessExecutionRequest): Promise<ProcessExecutionResult>;
}

/**
 * Captures the exact root LaunchDaemon process identity used by the Broker's
 * authority listener. The launchd record supplies only the service binding;
 * native PID/start-time readback is the identity authority.
 */
export async function captureLaunchdRootHelperProcessIdentity(options: {
  rootHelperServiceId: string;
  commandExecutor?: LaunchdRootHelperIdentityCommandExecutor;
}): Promise<PeerProcessIdentity> {
  const serviceId = parseRootHelperServiceId(options.rootHelperServiceId);
  const executor = options.commandExecutor ?? new ProcessSupervisor({ allowedEnvironmentKeys: [] });
  const deadline = Date.now() + LAUNCHD_STARTUP_DEADLINE_MS;
  for (;;) {
    const remainingMs = deadline - Date.now();
    if (remainingMs <= 0) {
      throw new RootHelperSnapshotServiceStartupError("BROKER_SERVICE_UNAVAILABLE", "Root-helper launchd service did not reach running state");
    }
    let result: ProcessExecutionResult;
    try {
      result = await executor.run({
        executable: LAUNCHCTL_PATH,
        args: ["print", serviceId],
        cwd: "/",
        environment: {},
        timeoutMs: Math.min(LAUNCHCTL_TIMEOUT_MS, remainingMs),
        outputCapBytes: LAUNCHCTL_OUTPUT_CAP_BYTES
      });
    } catch {
      throw new RootHelperSnapshotServiceStartupError("BROKER_SERVICE_UNAVAILABLE", "Root-helper launchd readback failed");
    }
    try {
      const readback = parseLaunchdJobReadback(serviceId, result.stdout);
      if (result.resultClass !== "SUCCEEDED") {
        throw new RootHelperSnapshotServiceStartupError("BROKER_SERVICE_UNAVAILABLE", "Root-helper launchd service is unavailable");
      }
      if (readback.type !== "LaunchDaemon" || readback.state !== "running" || readback.pid === null) {
        throw new RootHelperSnapshotServiceStartupError("BROKER_PROCESS_NOT_RUNNING", "Root-helper launchd service is not running");
      }
      try {
        const credentials = capturePeerProcessCredentials(readback.pid);
        if (credentials.uid !== 0) {
          throw new RootHelperSnapshotServiceStartupError("BROKER_PROCESS_IDENTITY_UNAVAILABLE", "Root-helper process is not root-owned");
        }
        return capturePeerProcessIdentity(readback.pid);
      } catch {
        throw new RootHelperSnapshotServiceStartupError("BROKER_PROCESS_IDENTITY_UNAVAILABLE", "Root-helper process identity or root ownership readback failed");
      }
    } catch (error) {
      if (error instanceof RootHelperSnapshotServiceStartupError &&
          error.code === "BROKER_PROCESS_NOT_RUNNING" && isXpcProxyState(result.stdout)) {
        const delayMs = Math.min(LAUNCHD_XPCPROXY_RETRY_DELAY_MS, Math.max(0, deadline - Date.now()));
        if (delayMs > 0) {
          await new Promise<void>((resolve) => setTimeout(resolve, delayMs));
          continue;
        }
      }
      if (error instanceof RootHelperSnapshotServiceStartupError) throw error;
      if (error instanceof LaunchdReadbackError) {
        throw new RootHelperSnapshotServiceStartupError("BROKER_SERVICE_UNAVAILABLE", "Root-helper launchd readback identity is malformed");
      }
      throw new RootHelperSnapshotServiceStartupError("BROKER_SERVICE_UNAVAILABLE", "Root-helper launchd identity could not be captured");
    }
  }
}

/**
 * Root-helper startup assembly. The helper never opens BrokerStore: it binds
 * the exact Broker process through launchd readback plus native PID/start-time
 * identity, then loads protected key material and uses the Broker authority
 * poll channel before the snapshot runtime can become available.
 */
export async function createRootHelperSnapshotRuntimeForLaunchdBroker(
  options: RootHelperSnapshotServiceLaunchdOptions
): Promise<RootHelperSnapshotRuntime> {
  validateBrokerExpectation(options.expectedBrokerUid, options.expectedBrokerGid);
  let brokerIdentity: PeerProcessIdentity;
  try {
    brokerIdentity = await captureLaunchdBrokerProcessIdentity({
      brokerServiceId: options.brokerServiceId,
      expectedBrokerUid: options.expectedBrokerUid,
      ...(options.commandExecutor === undefined ? {} : { commandExecutor: options.commandExecutor })
    });
  } catch (error) {
    throw mapBrokerIdentityError(error);
  }

  try {
    return await createRootHelperSnapshotRuntimeFromKeyMaterial({
      ...options,
      peerPolicy: {
        expectedUid: options.expectedBrokerUid,
        ...(options.expectedBrokerGid === undefined ? {} : { expectedGid: options.expectedBrokerGid }),
        allowedProcessIdentity: brokerIdentity
      }
    });
  } catch (error) {
    if (error instanceof RootHelperSnapshotServiceStartupError) throw error;
    throw new RootHelperSnapshotServiceStartupError(
      "ROOT_HELPER_RUNTIME_UNAVAILABLE",
      error instanceof Error ? error.message : "Root-helper snapshot runtime could not be assembled"
    );
  }
}

/**
 * Owns the process-facing root-helper lifecycle. It is deliberately separate
 * from BrokerServiceEntrypoint because the root helper has a different state
 * owner, key source, and capability readback.
 */
export class RootHelperSnapshotServiceEntrypoint {
  private stateValue: RootHelperSnapshotServiceState = "stopped";
  private lifecycleQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly runtime: RootHelperSnapshotRuntime,
    private readonly metadata: RootHelperSnapshotServiceMetadata
  ) {
    if (!/^[0-9a-f]{7,64}$/u.test(metadata.sourceRevision)) {
      throw new Error("Root-helper snapshot source revision is invalid");
    }
    if (!/^v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u.test(metadata.contractVersion)) {
      throw new Error("Root-helper snapshot contract version is invalid");
    }
    if (metadata.evidenceRef !== undefined &&
        !/^[A-Za-z0-9._:/-]{1,256}$/u.test(metadata.evidenceRef)) {
      throw new Error("Root-helper snapshot evidence reference is invalid");
    }
    runtime.setStatusMetadata(metadata);
  }

  get state(): RootHelperSnapshotServiceState {
    return this.stateValue;
  }

  start(): Promise<void> {
    return this.enqueue(() => this.startInternal());
  }

  stop(): Promise<void> {
    return this.enqueue(() => this.stopInternal());
  }

  readback(): RootHelperSnapshotServiceReadback {
    return {
      ...this.metadata,
      state: this.stateValue,
      runtimeState: this.runtime.state,
      nativeTransportRequired: true,
      available: this.runtime.available,
      capability: this.runtime.capability
    };
  }

  async runUntilSignal(signals: ServiceSignalSource): Promise<void> {
    await this.start();
    await new Promise<void>((resolve, reject) => {
      let settled = false;
      const handleSignal = () => {
        if (settled) return;
        settled = true;
        signals.removeListener("SIGINT", handleSignal);
        signals.removeListener("SIGTERM", handleSignal);
        void this.stop().then(resolve, reject);
      };
      signals.on("SIGINT", handleSignal);
      signals.on("SIGTERM", handleSignal);
    });
  }

  private async startInternal(): Promise<void> {
    if (this.stateValue !== "stopped") {
      throw new Error(`Root-helper snapshot service cannot start from ${this.stateValue}`);
    }
    this.stateValue = "starting";
    try {
      await this.runtime.start();
      this.stateValue = "running";
    } catch (error) {
      this.stateValue = "failed";
      throw error;
    }
  }

  private async stopInternal(): Promise<void> {
    if (this.stateValue === "stopped") {
      await this.runtime.close();
      return;
    }
    this.stateValue = "stopping";
    try {
      await this.runtime.close();
      this.stateValue = "stopped";
    } catch (error) {
      this.stateValue = "failed";
      throw error;
    }
  }

  private enqueue(operation: () => Promise<void>): Promise<void> {
    const next = this.lifecycleQueue.then(operation, operation);
    this.lifecycleQueue = next.catch(() => undefined);
    return next;
  }
}

/**
 * Small launchd-facing wrapper used by a native/service host after it has
 * assembled the fixed runtime options. It does not read arguments or
 * environment variables, and it never installs or bootstraps launchd jobs.
 */
export async function runRootHelperSnapshotService(
  runtime: RootHelperSnapshotRuntime,
  metadata: RootHelperSnapshotServiceMetadata,
  signals: ServiceSignalSource
): Promise<void> {
  const service = new RootHelperSnapshotServiceEntrypoint(runtime, metadata);
  await service.runUntilSignal(signals);
}

function validateBrokerExpectation(uid: number, gid: number | undefined): void {
  if (!Number.isSafeInteger(uid) || uid < 1 || uid > 2_147_483_647 ||
      (gid !== undefined && (!Number.isSafeInteger(gid) || gid < 0 || gid > 2_147_483_647))) {
    throw new RootHelperSnapshotServiceStartupError(
      "BROKER_SERVICE_INVALID",
      "Root-helper snapshot Broker identity expectation is invalid"
    );
  }
}

function parseRootHelperServiceId(serviceId: string): string {
  if (typeof serviceId !== "string" || !ROOT_HELPER_SERVICE_PATTERN.test(serviceId)) {
    throw new RootHelperSnapshotServiceStartupError("BROKER_SERVICE_INVALID", "Root-helper launchd service identity is invalid");
  }
  return serviceId;
}

function isXpcProxyState(output: string): boolean {
  return /(?:^|\n)\tstate\s*=\s*xpcproxy\s*(?:\r?\n|$)/u.test(output);
}

function mapBrokerIdentityError(error: unknown): RootHelperSnapshotServiceStartupError {
  const code = error instanceof Error && "code" in error ? String((error as { code?: unknown }).code) : "";
  if (code === "INVALID_HELPER_SERVICE") {
    return new RootHelperSnapshotServiceStartupError("BROKER_SERVICE_INVALID", "Broker launchd service identity is invalid");
  }
  if (code === "HELPER_SERVICE_UNAVAILABLE") {
    return new RootHelperSnapshotServiceStartupError("BROKER_SERVICE_UNAVAILABLE", "Broker launchd service is unavailable");
  }
  if (code === "HELPER_PROCESS_NOT_RUNNING") {
    return new RootHelperSnapshotServiceStartupError("BROKER_PROCESS_NOT_RUNNING", "Broker launchd service is not running");
  }
  if (code === "HELPER_PROCESS_IDENTITY_UNAVAILABLE") {
    return new RootHelperSnapshotServiceStartupError("BROKER_PROCESS_IDENTITY_UNAVAILABLE", "Broker process identity readback failed");
  }
  return new RootHelperSnapshotServiceStartupError(
    "BROKER_SERVICE_UNAVAILABLE",
    error instanceof Error ? error.message : "Broker launchd identity could not be captured"
  );
}
