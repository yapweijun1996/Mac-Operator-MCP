import type { SafeProcessInventory } from "./process-inspector.js";

export interface ProcessWorkerCommand {
  limit: number;
  sort: "cpu" | "memory" | "pid" | "name";
}

export type ProcessWorkerResult = SafeProcessInventory;
