import type { SafeProcessDetail, SafeProcessInventory } from "./process-inspector.js";

export interface ProcessListWorkerCommand {
  operation: "list";
  limit: number;
  sort: "cpu" | "memory" | "pid" | "name";
}

export interface ProcessInspectWorkerCommand {
  operation: "inspect";
  pid: number;
}

export type ProcessWorkerCommand = ProcessListWorkerCommand | ProcessInspectWorkerCommand;
export type ProcessWorkerResult = SafeProcessInventory | SafeProcessDetail;
