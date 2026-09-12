import { cpus, loadavg, machine, platform, release, totalmem, uptime, version } from "node:os";

export interface SystemSummary {
  osVersion: string;
  architecture: string;
  cpuCount: number;
  memoryBytes: number;
  uptimeSeconds: number;
  load?: { one: number; five: number; fifteen: number };
}

const MAX_CPU_COUNT = 256;
const MAX_MEMORY_BYTES = 1_000_000_000_000;
const MAX_UPTIME_SECONDS = 1_000_000_000;
const MAX_LOAD = 1_000_000;

/** Returns bounded host facts without reading credentials, paths, or user identity. */
export function inspectSystem(includeLoad: boolean): SystemSummary {
  const cpuCount = Math.max(1, Math.min(MAX_CPU_COUNT, cpus().length));
  const memoryBytes = Math.max(1, Math.min(MAX_MEMORY_BYTES, Math.floor(totalmem())));
  const uptimeSeconds = Math.max(0, Math.min(MAX_UPTIME_SECONDS, Math.floor(uptime())));
  const osVersion = boundedVersion(version() || `${platform()} ${release()}`);
  const result: SystemSummary = {
    osVersion,
    architecture: boundedVersion(machine() || platform()),
    cpuCount,
    memoryBytes,
    uptimeSeconds
  };
  if (includeLoad) {
    const [one = 0, five = 0, fifteen = 0] = loadavg();
    result.load = { one: boundedLoad(one), five: boundedLoad(five), fifteen: boundedLoad(fifteen) };
  }
  return result;
}

function boundedVersion(value: string): string {
  const normalized = value.replace(/[\u0000-\u001f\u007f]/gu, " ").trim();
  return normalized.slice(0, 128) || "unknown";
}

function boundedLoad(value: number): number {
  return Number.isFinite(value) ? Math.max(0, Math.min(MAX_LOAD, value)) : 0;
}
