import type { LocalBrokerRuntime, LocalBrokerRuntimeState } from "./runtime.js";
import type { AuditIntegrityReadback } from "./audit-integrity.js";

export interface BrokerServiceMetadata {
  component: "mac-operator-broker";
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
}

export type BrokerServiceState = "stopped" | "starting" | "running" | "stopping" | "failed";

export interface BrokerServiceReadback extends BrokerServiceMetadata {
  state: BrokerServiceState;
  runtimeState: LocalBrokerRuntimeState;
  nativeTransportRequired: true;
  enabledCapabilities: readonly string[];
  /** Optional owner-only, non-sensitive audit integrity summary. */
  audit?: AuditIntegrityReadback;
}

export interface ServiceSignalSource {
  on(event: "SIGINT" | "SIGTERM", listener: () => void): unknown;
  removeListener(event: "SIGINT" | "SIGTERM", listener: () => void): unknown;
}

/**
 * Owns the process-facing lifecycle used by a future launchd entrypoint.
 * Startup and shutdown are delegated to LocalBrokerRuntime; no signal path
 * reports readiness unless the native runtime is actually running.
 */
export class BrokerServiceEntrypoint {
  private stateValue: BrokerServiceState = "stopped";
  /** Serialize service lifecycle transitions around the runtime boundary. */
  private lifecycleQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly runtime: LocalBrokerRuntime,
    private readonly metadata: BrokerServiceMetadata,
    private readonly enabledCapabilities: readonly string[] = [],
    private readonly readAudit?: () => AuditIntegrityReadback
  ) {
    if (!/^v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u.test(metadata.contractVersion)) {
      throw new Error("Broker service contract version is invalid");
    }
    if (!/^[0-9a-f]{7,64}$/u.test(metadata.sourceRevision)) {
      throw new Error("Broker service source revision is invalid");
    }
    if (!/^(?:policy-[1-9][0-9]*|\d+\.\d+(?:\.\d+)?(?:[-+].*)?)$/u.test(metadata.policyVersion)) {
      throw new Error("Broker service policy version is invalid");
    }
    if (enabledCapabilities.some((capability) => typeof capability !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(capability))) {
      throw new Error("Broker service capability readback is invalid");
    }
    if (readAudit !== undefined && typeof readAudit !== "function") {
      throw new Error("Broker service audit readback callback is invalid");
    }
  }

  get state(): BrokerServiceState {
    return this.stateValue;
  }

  start(): Promise<void> {
    return this.enqueueLifecycle(() => this.startInternal());
  }

  stop(): Promise<void> {
    return this.enqueueLifecycle(() => this.stopInternal());
  }

  private enqueueLifecycle(operation: () => Promise<void>): Promise<void> {
    const next = this.lifecycleQueue.then(operation, operation);
    this.lifecycleQueue = next.catch(() => undefined);
    return next;
  }

  private async startInternal(): Promise<void> {
    if (this.stateValue !== "stopped") throw new Error(`Broker service cannot start from ${this.stateValue}`);
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
    if (this.stateValue === "stopped") return;
    this.stateValue = "stopping";
    try {
      await this.runtime.close();
      this.stateValue = "stopped";
    } catch (error) {
      this.stateValue = "failed";
      throw error;
    }
  }

  readback(): BrokerServiceReadback {
    const readback: BrokerServiceReadback = {
      ...this.metadata,
      state: this.stateValue,
      runtimeState: this.runtime.state,
      nativeTransportRequired: true,
      enabledCapabilities: [...this.enabledCapabilities]
    };
    if (this.readAudit !== undefined) readback.audit = this.readAudit();
    return readback;
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
}
