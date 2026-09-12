import { Worker } from "node:worker_threads";
import { BrokerError } from "@mac-operator/contracts";
import type { SafeProcessInventory } from "./process-inspector.js";
import type { ProcessWorkerCommand, ProcessWorkerResult } from "./process-worker-protocol.js";
import { BoundedWorkerExecutor } from "./worker-executor.js";

export interface ProcessExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface ProcessExecutor {
  list(limit: number, sort: "cpu" | "memory" | "pid" | "name", control: ProcessExecutionControl): Promise<SafeProcessInventory>;
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

  list(limit: number, sort: "cpu" | "memory" | "pid" | "name", control: ProcessExecutionControl): Promise<SafeProcessInventory> {
    return this.executor.run({ limit, sort }, control.timeoutMs, control.shouldCancel).then(validateProcessResult);
  }
}

function validateProcessResult(value: ProcessWorkerResult): SafeProcessInventory {
  if (value === null || typeof value !== "object" || !Array.isArray(value.processes) || value.processes.length > 500 ||
      typeof value.truncated !== "boolean") {
    throw new BrokerError("EXECUTION_FAILED", "Process worker returned a malformed result");
  }
  for (const process of value.processes) {
    if (process === null || typeof process !== "object" ||
        !Number.isSafeInteger(process.pid) || process.pid < 1 || process.pid > 99_999_999 ||
        typeof process.name !== "string" || process.name.length < 1 || process.name.length > 256 ||
        process.name.includes("\0") ||
        typeof process.executable !== "string" || process.executable.length < 1 || process.executable.length > 4096 ||
        process.executable.includes("\0") ||
        typeof process.cpuPercent !== "number" || !Number.isFinite(process.cpuPercent) || process.cpuPercent < 0 || process.cpuPercent > 100 ||
        !Number.isSafeInteger(process.memoryBytes) || process.memoryBytes < 0 || process.memoryBytes > 1_000_000_000_000 ||
        typeof process.owner !== "string" || process.owner.length < 1 || process.owner.length > 256 ||
        process.owner.includes("\0") || !/^uid:[0-9]+$/.test(process.owner)) {
      throw new BrokerError("EXECUTION_FAILED", "Process worker returned a malformed result");
    }
  }
  return value;
}
