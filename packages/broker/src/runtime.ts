import type { Broker } from "./broker.js";
import { MacOsNativeBrokerIpcServer, type NativeBrokerIpcServerOptions } from "./native-ipc-server.js";

export interface RuntimeChannel {
  listen(): Promise<void>;
  close(): Promise<void>;
}

export type LocalBrokerRuntimeState = "stopped" | "starting" | "running" | "stopping" | "failed";

export interface LocalBrokerRuntimeOptions {
  brokerChannel: RuntimeChannel;
  operatorChannels?: readonly RuntimeChannel[];
}

export interface MacOsNativeBrokerRuntimeOptions extends Omit<NativeBrokerIpcServerOptions, "broker"> {
  broker: Broker;
  operatorChannels?: readonly RuntimeChannel[];
}

/**
 * Owns the local Broker process boundary without owning persistence.
 *
 * The Broker IPC channel is made ready before separate operator channels. A
 * partial startup is never left listening: channels that did start are closed
 * in reverse order and the runtime returns to `stopped`. Store and policy
 * ownership remain with the caller so packaging can choose their lifecycle
 * explicitly.
 */
export class LocalBrokerRuntime {
  private readonly channels: readonly RuntimeChannel[];
  private stateValue: LocalBrokerRuntimeState = "stopped";
  private activeChannels: RuntimeChannel[] = [];
  private operation: Promise<void> = Promise.resolve();

  constructor(options: LocalBrokerRuntimeOptions) {
    if (!options.brokerChannel || typeof options.brokerChannel.listen !== "function" || typeof options.brokerChannel.close !== "function") {
      throw new Error("Broker runtime requires a valid Broker channel");
    }
    const operatorChannels = [...(options.operatorChannels ?? [])];
    if (operatorChannels.some((channel) => !channel || typeof channel.listen !== "function" || typeof channel.close !== "function")) {
      throw new Error("Broker runtime requires valid operator channels");
    }
    const allChannels = [options.brokerChannel, ...operatorChannels];
    if (new Set(allChannels).size !== allChannels.length) {
      throw new Error("Broker runtime channels must be unique");
    }
    this.channels = allChannels;
  }

  get state(): LocalBrokerRuntimeState {
    return this.stateValue;
  }

  start(): Promise<void> {
    return this.enqueue(() => this.startInternal());
  }

  close(): Promise<void> {
    return this.enqueue(() => this.closeInternal());
  }

  private async startInternal(): Promise<void> {
    if (this.stateValue !== "stopped") throw new Error(`Broker runtime cannot start from ${this.stateValue}`);
    this.stateValue = "starting";
    const started: RuntimeChannel[] = [];
    this.activeChannels = started;
    try {
      for (const channel of this.channels) {
        await channel.listen();
        started.push(channel);
      }
      this.stateValue = "running";
    } catch (error) {
      try {
        await closeReverse(started);
        this.activeChannels = [];
        this.stateValue = "stopped";
      } catch (cleanupError) {
        this.stateValue = "failed";
        throw new AggregateError(
          [error, cleanupError],
          "Broker runtime startup failed and cleanup also failed"
        );
      }
      throw error;
    }
  }

  private async closeInternal(): Promise<void> {
    if (this.stateValue === "stopped") return;
    this.stateValue = "stopping";
    let firstError: unknown;
    try {
      await closeReverse(this.activeChannels, (channel) => channel.close());
      this.activeChannels = [];
    } catch (error) {
      firstError = error;
    } finally {
      this.stateValue = firstError === undefined ? "stopped" : "failed";
    }
    if (firstError !== undefined) throw firstError;
  }

  private enqueue(operation: () => Promise<void>): Promise<void> {
    const run = this.operation.catch(() => undefined).then(operation);
    this.operation = run;
    return run;
  }
}

/**
 * Production assembly boundary for the unprivileged macOS Broker process.
 *
 * This factory deliberately constructs the native UDS channel instead of the
 * legacy Node server. The generic lifecycle class still owns ordering and
 * rollback, while the factory makes transport selection explicit at the
 * packaging/startup boundary.
 */
export function createMacOsNativeBrokerRuntime(
  options: MacOsNativeBrokerRuntimeOptions
): { runtime: LocalBrokerRuntime; brokerChannel: MacOsNativeBrokerIpcServer } {
  const { operatorChannels, ...nativeOptions } = options;
  if (nativeOptions.peerPolicy.allowedProcessIdentity === undefined) {
    throw new Error("macOS native Broker runtime requires an explicit peer process identity");
  }
  const brokerChannel = new MacOsNativeBrokerIpcServer(nativeOptions);
  const runtime = new LocalBrokerRuntime({
    brokerChannel,
    ...(operatorChannels === undefined ? {} : { operatorChannels })
  });
  return { runtime, brokerChannel };
}

async function closeReverse(
  channels: readonly RuntimeChannel[],
  close: (channel: RuntimeChannel) => Promise<void> = (channel) => channel.close()
): Promise<void> {
  let firstError: unknown;
  for (const channel of [...channels].reverse()) {
    try {
      await close(channel);
    } catch (error) {
      firstError ??= error;
    }
  }
  if (firstError !== undefined) throw firstError;
}
