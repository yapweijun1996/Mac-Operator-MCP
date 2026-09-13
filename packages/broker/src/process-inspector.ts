import { loadNativePeerAdapter } from "./peer-credentials.js";

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

export interface SafeProcessDetail {
  pid: number;
  name: string;
  executable: string;
  state: "running" | "sleeping" | "stopped" | "zombie" | "unknown";
  cpuPercent: number;
  memoryBytes: number;
  parentPid: number | null;
  childPids: readonly number[];
  owner: string;
}

interface NativeProcessAdapter {
  listProcesses(limit: number, sort: "cpu" | "memory" | "pid" | "name"): unknown;
  inspectProcess(pid: number): unknown;
}

export function inspectProcesses(limit: number, sort: "cpu" | "memory" | "pid" | "name"): SafeProcessInventory {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new Error("Process limit is outside the supported range");
  if (!["cpu", "memory", "pid", "name"].includes(sort)) throw new Error("Process sort is unsupported");
  const native = loadNativePeerAdapter() as unknown as NativeProcessAdapter;
  return parseNativeProcessInventory(native.listProcesses(limit, sort));
}

export function inspectProcess(pid: number): SafeProcessDetail {
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 99_999_999) throw new Error("Process pid is outside the supported range");
  const native = loadNativePeerAdapter() as unknown as NativeProcessAdapter;
  return parseNativeProcessDetail(native.inspectProcess(pid));
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

function parseNativeProcessDetail(value: unknown): SafeProcessDetail {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("Malformed native process detail");
  const process = value as Record<string, unknown>;
  if (!Number.isSafeInteger(process.pid) || (process.pid as number) < 1 || (process.pid as number) > 99_999_999 ||
      typeof process.name !== "string" || process.name.length < 1 || process.name.length > 256 || process.name.includes("\0") ||
      typeof process.executable !== "string" || process.executable.length < 1 || process.executable.length > 4096 || process.executable.includes("\0") ||
      !["running", "sleeping", "stopped", "zombie", "unknown"].includes(process.state as string) ||
      typeof process.cpuPercent !== "number" || !Number.isFinite(process.cpuPercent) || process.cpuPercent < 0 || process.cpuPercent > 100 ||
      !Number.isSafeInteger(process.memoryBytes) || (process.memoryBytes as number) < 0 || (process.memoryBytes as number) > 1_000_000_000_000 ||
      (process.parentPid !== null && (!Number.isSafeInteger(process.parentPid) || (process.parentPid as number) < 1 || (process.parentPid as number) > 99_999_999)) ||
      !Array.isArray(process.childPids) || process.childPids.length > 256 ||
      typeof process.owner !== "string" || process.owner.length < 1 || process.owner.length > 256 || !/^uid:[0-9]+$/u.test(process.owner)) {
    throw new Error("Malformed native process detail");
  }
  const childPids = process.childPids.map((childPid) => {
    if (!Number.isSafeInteger(childPid) || (childPid as number) < 1 || (childPid as number) > 99_999_999) {
      throw new Error("Malformed native process child identity");
    }
    return childPid as number;
  });
  return {
    pid: process.pid as number,
    name: process.name,
    executable: process.executable,
    state: process.state as SafeProcessDetail["state"],
    cpuPercent: process.cpuPercent,
    memoryBytes: process.memoryBytes as number,
    parentPid: process.parentPid as number | null,
    childPids,
    owner: process.owner
  };
}
