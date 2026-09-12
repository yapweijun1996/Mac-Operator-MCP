import { createRequire } from "node:module";

export interface SafeProcessInfo {
  pid: number;
  name: string;
  executable: string;
  cpuPercent: number;
  memoryBytes: number;
  owner: string;
}

export interface SafeProcessInventory {
  processes: readonly SafeProcessInfo[];
  truncated: boolean;
}

interface NativeProcessAdapter {
  listProcesses(limit: number, sort: "cpu" | "memory" | "pid" | "name"): unknown;
}

const require = createRequire(import.meta.url);

export function inspectProcesses(limit: number, sort: "cpu" | "memory" | "pid" | "name"): SafeProcessInventory {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new Error("Process limit is outside the supported range");
  if (!["cpu", "memory", "pid", "name"].includes(sort)) throw new Error("Process sort is unsupported");
  const native = require("./peer_credentials.node") as NativeProcessAdapter;
  return parseNativeProcessInventory(native.listProcesses(limit, sort));
}

function parseNativeProcessInventory(value: unknown): SafeProcessInventory {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed native process inventory");
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.processes) || record.processes.length > 500 || typeof record.truncated !== "boolean") {
    throw new Error("Malformed native process inventory");
  }
  const processes: SafeProcessInfo[] = [];
  for (const value of record.processes) {
    if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed native process record");
    const process = value as Record<string, unknown>;
    if (!Number.isSafeInteger(process.pid) || (process.pid as number) < 1 || (process.pid as number) > 99_999_999 ||
        typeof process.name !== "string" || process.name.length < 1 || process.name.length > 256 || process.name.includes("\0") ||
        typeof process.executable !== "string" || process.executable.length < 1 || process.executable.length > 4096 || process.executable.includes("\0") ||
        typeof process.cpuPercent !== "number" || !Number.isFinite(process.cpuPercent) || process.cpuPercent < 0 || process.cpuPercent > 100 ||
        !Number.isSafeInteger(process.memoryBytes) || (process.memoryBytes as number) < 0 || (process.memoryBytes as number) > 1_000_000_000_000 ||
        typeof process.owner !== "string" || process.owner.length > 256 || process.owner.includes("\0")) {
      throw new Error("Malformed native process record");
    }
    processes.push({
      pid: process.pid as number,
      name: process.name,
      executable: process.executable,
      cpuPercent: process.cpuPercent,
      memoryBytes: process.memoryBytes as number,
      owner: process.owner
    });
  }
  return { processes, truncated: record.truncated };
}
