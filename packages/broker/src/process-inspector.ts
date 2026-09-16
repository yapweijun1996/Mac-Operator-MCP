import { loadNativePeerAdapter, parsePeerProcessIdentity } from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";

const PROCESS_INFO_KEYS = new Set(["pid", "name", "executable", "cpuPercent", "memoryBytes", "owner"]);
const PROCESS_INVENTORY_KEYS = new Set(["processes", "truncated"]);
const PROCESS_DETAIL_KEYS = new Set(["pid", "name", "executable", "state", "cpuPercent", "memoryBytes", "parentPid", "childPids", "owner"]);

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
  getProcessIdentity(pid: number): unknown;
}

export function inspectProcesses(limit: number, sort: "cpu" | "memory" | "pid" | "name"): SafeProcessInventory {
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 500) throw new Error("Process limit is outside the supported range");
  if (!["cpu", "memory", "pid", "name"].includes(sort)) throw new Error("Process sort is unsupported");
  const native = loadNativePeerAdapter() as unknown as NativeProcessAdapter;
  return parseProcessInventory(native.listProcesses(limit, sort));
}

export function inspectProcess(pid: number): SafeProcessDetail {
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 99_999_999) throw new Error("Process pid is outside the supported range");
  const native = loadNativePeerAdapter() as unknown as NativeProcessAdapter;
  const before = parsePeerProcessIdentity(native.getProcessIdentity(pid));
  const detail = parseProcessDetail(native.inspectProcess(pid));
  const after = parsePeerProcessIdentity(native.getProcessIdentity(pid));
  assertStableProcessIdentity(pid, before, after);
  assertProcessDetailIdentity(pid, detail);
  return detail;
}

/**
 * The detail payload is an adapter result, not authority. Bind its PID to the
 * requested target before any caller can serialize or otherwise consume it.
 */
export function assertProcessDetailIdentity(
  requestedPid: number,
  detail: Pick<SafeProcessDetail, "pid">
): void {
  if (detail.pid !== requestedPid) throw new Error("Process identity changed during inspection");
}

/** Reject a PID reuse or target swap observed across one native inspection. */
export function assertStableProcessIdentity(
  requestedPid: number,
  before: { pid: number; startTimeMicros: number },
  after: { pid: number; startTimeMicros: number }
): void {
  if (before.pid !== requestedPid || after.pid !== requestedPid || before.startTimeMicros !== after.startTimeMicros) {
    throw new Error("Process identity changed during inspection");
  }
}

export function parseProcessInventory(value: unknown): SafeProcessInventory {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, PROCESS_INVENTORY_KEYS)) throw new Error("Malformed native process inventory");
  const record = value;
  if (!isDenseArray(record.processes, 500) || typeof record.truncated !== "boolean") {
    throw new Error("Malformed native process inventory");
  }
  const processes: SafeProcessInfo[] = [];
  for (const value of record.processes) {
    if (!isPlainDataRecord(value) || !hasExactKeys(value, PROCESS_INFO_KEYS)) throw new Error("Malformed native process record");
    const process = value;
    if (!Number.isSafeInteger(process.pid) || (process.pid as number) < 1 || (process.pid as number) > 99_999_999 ||
        typeof process.name !== "string" || process.name.length < 1 || process.name.length > 256 || process.name.includes("\0") ||
        typeof process.executable !== "string" || process.executable.length < 1 || process.executable.length > 4096 || process.executable.includes("\0") ||
        typeof process.cpuPercent !== "number" || !Number.isFinite(process.cpuPercent) || process.cpuPercent < 0 || process.cpuPercent > 100 ||
        !Number.isSafeInteger(process.memoryBytes) || (process.memoryBytes as number) < 0 || (process.memoryBytes as number) > 1_000_000_000_000 ||
        typeof process.owner !== "string" || process.owner.length < 1 || process.owner.length > 256 || process.owner.includes("\0") || !/^uid:[0-9]+$/u.test(process.owner)) {
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

export function parseProcessDetail(value: unknown): SafeProcessDetail {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, PROCESS_DETAIL_KEYS)) throw new Error("Malformed native process detail");
  const process = value;
  if (!Number.isSafeInteger(process.pid) || (process.pid as number) < 1 || (process.pid as number) > 99_999_999 ||
      typeof process.name !== "string" || process.name.length < 1 || process.name.length > 256 || process.name.includes("\0") ||
      typeof process.executable !== "string" || process.executable.length < 1 || process.executable.length > 4096 || process.executable.includes("\0") ||
      !["running", "sleeping", "stopped", "zombie", "unknown"].includes(process.state as string) ||
      typeof process.cpuPercent !== "number" || !Number.isFinite(process.cpuPercent) || process.cpuPercent < 0 || process.cpuPercent > 100 ||
      !Number.isSafeInteger(process.memoryBytes) || (process.memoryBytes as number) < 0 || (process.memoryBytes as number) > 1_000_000_000_000 ||
      (process.parentPid !== null && (!Number.isSafeInteger(process.parentPid) || (process.parentPid as number) < 1 || (process.parentPid as number) > 99_999_999)) ||
      !isDenseNumberArray(process.childPids, 256) ||
      typeof process.owner !== "string" || process.owner.length < 1 || process.owner.length > 256 || !/^uid:[0-9]+$/u.test(process.owner)) {
    throw new Error("Malformed native process detail");
  }
  const childPids = [...process.childPids];
  for (let index = 1; index < childPids.length; index += 1) {
    if (childPids[index - 1]! >= childPids[index]!) throw new Error("Malformed native process child identity");
  }
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

function hasExactKeys(value: Record<string, unknown>, expected: ReadonlySet<string>): boolean {
  const keys = Object.keys(value);
  return keys.length === expected.size && keys.every((key) => expected.has(key));
}

function isDenseNumberArray(value: unknown, maxLength: number): value is readonly number[] {
  if (!Array.isArray(value) || value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0 ||
      Object.keys(value).length !== value.length || Object.getOwnPropertyNames(value).length !== value.length + 1) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor) ||
        !Number.isSafeInteger(descriptor.value) || descriptor.value < 1 || descriptor.value > 99_999_999) return false;
  }
  return true;
}

function isDenseArray(value: unknown, maxLength: number): value is readonly unknown[] {
  if (!Array.isArray(value) || value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0 ||
      Object.keys(value).length !== value.length || Object.getOwnPropertyNames(value).length !== value.length + 1) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor)) return false;
  }
  return true;
}
