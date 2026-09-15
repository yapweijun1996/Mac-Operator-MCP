import { Worker } from "node:worker_threads";
import { BrokerError } from "@mac-operator/contracts";
import { parseProcessDetail, parseProcessInventory, type SafeProcessDetail, type SafeProcessInventory } from "./process-inspector.js";
import type { ProcessWorkerCommand, ProcessWorkerResult } from "./process-worker-protocol.js";
import { BoundedWorkerExecutor } from "./worker-executor.js";

export interface ProcessExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface ProcessExecutor {
  /** Stop accepting work and terminate owned worker threads during Broker shutdown. */
  close?(): Promise<void>;
  list(limit: number, sort: "cpu" | "memory" | "pid" | "name", control: ProcessExecutionControl): Promise<SafeProcessInventory>;
  inspect(pid: number, control: ProcessExecutionControl): Promise<SafeProcessDetail>;
}

export class WorkerProcessExecutor implements ProcessExecutor {
  private readonly executor: BoundedWorkerExecutor<ProcessWorkerCommand, ProcessWorkerResult>;

  constructor(maxConcurrent = 2) {
    this.executor = new BoundedWorkerExecutor(
      (command) => new Worker(new URL("./process-worker.js", import.meta.url), {
        workerData: command,
        argv: [],
        execArgv: [],
        env: {},
        resourceLimits: { maxOldGenerationSizeMb: 32, maxYoungGenerationSizeMb: 8, stackSizeMb: 2 },
        trackUnmanagedFds: true
      }),
      maxConcurrent
    );
  }

  close(): Promise<void> {
    return this.executor.close();
  }

  list(limit: number, sort: "cpu" | "memory" | "pid" | "name", control: ProcessExecutionControl): Promise<SafeProcessInventory> {
    return this.executor.run({ operation: "list", limit, sort }, control.timeoutMs, control.shouldCancel).then(validateProcessResult);
  }

  inspect(pid: number, control: ProcessExecutionControl): Promise<SafeProcessDetail> {
    return this.executor.run({ operation: "inspect", pid }, control.timeoutMs, control.shouldCancel).then(validateProcessDetail);
  }
}

export function validateProcessResult(value: ProcessWorkerResult): SafeProcessInventory {
  try {
    return parseProcessInventory(value);
  } catch {
    throw new BrokerError("EXECUTION_FAILED", "Process worker returned a malformed result");
  }
}

export function validateProcessDetail(value: ProcessWorkerResult): SafeProcessDetail {
  try {
    return parseProcessDetail(value);
  } catch {
    throw new BrokerError("EXECUTION_FAILED", "Process worker returned a malformed process detail");
  }
}
