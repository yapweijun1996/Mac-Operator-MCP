import { parentPort, workerData } from "node:worker_threads";
import { BrokerError } from "@mac-operator/contracts";
import { inspectProcess, inspectProcesses } from "./process-inspector.js";
import type { ProcessWorkerCommand } from "./process-worker-protocol.js";
import type { WorkerResult } from "./worker-executor.js";

if (!parentPort) throw new Error("Process worker requires a parent port");

try {
  const command = workerData as ProcessWorkerCommand;
  const value = command.operation === "list"
    ? inspectProcesses(command.limit, command.sort)
    : inspectProcess(command.pid);
  parentPort.postMessage({ ok: true, value } satisfies WorkerResult<typeof value>);
} catch (error) {
  const brokerError = error instanceof BrokerError
    ? error
    : new BrokerError("EXECUTION_FAILED", "Process worker failed");
  parentPort.postMessage({
    ok: false,
    errorClass: brokerError.errorClass,
    message: brokerError.message
  } satisfies WorkerResult<never>);
}
