export interface RuntimeChannel {
  listen(): Promise<void>;
  close(): Promise<void>;
}

export type LocalBrokerRuntimeState = "stopped" | "starting" | "running" | "stopping";

export interface LocalBrokerRuntimeOptions {
  brokerChannel: RuntimeChannel;
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
    try {
      for (const channel of this.channels) {
        await channel.listen();
        started.push(channel);
      }
      this.stateValue = "running";
    } catch (error) {
      await closeReverse(started);
      this.stateValue = "stopped";
      throw error;
    }
  }

  private async closeInternal(): Promise<void> {
    if (this.stateValue === "stopped") return;
    this.stateValue = "stopping";
    let firstError: unknown;
    try {
      await closeReverse(this.channels, (channel) => channel.close());
    } catch (error) {
      firstError = error;
    } finally {
      this.stateValue = "stopped";
    }
    if (firstError !== undefined) throw firstError;
  }

  private enqueue(operation: () => Promise<void>): Promise<void> {
    const run = this.operation.catch(() => undefined).then(operation);
    this.operation = run;
    return run;
  }
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
