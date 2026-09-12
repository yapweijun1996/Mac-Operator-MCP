import type { LocalBrokerRuntime, LocalBrokerRuntimeState } from "./runtime.js";

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

  constructor(
    private readonly runtime: LocalBrokerRuntime,
    private readonly metadata: BrokerServiceMetadata,
    private readonly enabledCapabilities: readonly string[] = []
  ) {
    if (!/^v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u.test(metadata.contractVersion)) {
      throw new Error("Broker service contract version is invalid");
    }
    if (!/^[0-9a-f]{7,64}$/u.test(metadata.sourceRevision)) {
      throw new Error("Broker service source revision is invalid");
    }
    if (!/^\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u.test(metadata.policyVersion)) {
      throw new Error("Broker service policy version is invalid");
    }
    if (enabledCapabilities.some((capability) => typeof capability !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(capability))) {
      throw new Error("Broker service capability readback is invalid");
    }
  }

  get state(): BrokerServiceState {
    return this.stateValue;
  }

  async start(): Promise<void> {
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

  async stop(): Promise<void> {
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
    return {
      ...this.metadata,
      state: this.stateValue,
      runtimeState: this.runtime.state,
      nativeTransportRequired: true,
      enabledCapabilities: [...this.enabledCapabilities]
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
}
