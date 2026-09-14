import { lstatSync, realpathSync } from "node:fs";
import { BrokerError, parseJsonStrict } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult } from "./process-supervisor.js";
import { redactBoundedText, redactLogText } from "./secret-policy.js";

const DOCKER_EXECUTABLE_CANDIDATES = [
  "/Applications/Docker.app/Contents/Resources/bin/docker",
  "/opt/homebrew/bin/docker",
  "/usr/local/bin/docker",
  "/usr/bin/docker"
] as const;
const DOCKER_CWD = "/";
const DOCKER_HOST = "unix:///var/run/docker.sock";
const DOCKER_CONFIG = "/var/empty";
const DOCKER_HOME = "/var/empty";
const MAX_OUTPUT_BYTES = 1_048_576;
const MAX_STATUS_OUTPUT_BYTES = 524_288;
const MAX_TIMEOUT_MS = 15_000;
const MAX_ITEMS = 500;
const MAX_MOUNTS = 1_000;
const MAX_PORTS = 128;
const MAX_LOG_LINES = 5_000;
const MAX_LOG_LINE_BYTES = 8_192;
const OBJECT_ID_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;
const SAFE_ENVIRONMENT = {
  DOCKER_CONFIG,
  DOCKER_HOST,
  HOME: DOCKER_HOME
} as const;

export type DockerObjectType = "container" | "image" | "network" | "volume";

export interface DockerExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface SafeDockerContainer {
  id: string;
  name?: string;
  state: "running" | "exited" | "paused" | "created" | "unknown";
}

export interface SafeDockerImage {
  id: string;
  name?: string;
  tag?: string;
}

export interface SafeDockerStorage {
  usedBytes: number;
  availableBytes: number;
}

export interface SafeDockerStatus {
  daemon: { available: boolean; version?: string; context?: string };
  containers: readonly SafeDockerContainer[];
  images: readonly SafeDockerImage[];
  storage?: SafeDockerStorage;
  warnings: readonly string[];
  truncated: boolean;
}

export interface SafeDockerPort {
  protocol: "tcp" | "udp";
  containerPort: number;
  hostPort: number | null;
}

export interface SafeDockerMount {
  source?: string;
  target: string;
  readOnly: boolean;
}

export interface SafeDockerInspection {
  objectType: DockerObjectType;
  id: string;
  name: string;
  state: string;
  image: string;
  ports: readonly SafeDockerPort[];
  mounts: readonly SafeDockerMount[];
  warnings: readonly string[];
  truncated: boolean;
}

export interface SafeDockerLogEntry {
  timestamp: string | null;
  line: string;
}

export interface SafeDockerLogs {
  containerId: string;
  entries: readonly SafeDockerLogEntry[];
  truncated: boolean;
  warnings: readonly string[];
}

export interface DockerInspector {
  status(includeImages: boolean, includeStorage: boolean, control: DockerExecutionControl): Promise<SafeDockerStatus>;
  inspect(objectType: DockerObjectType, id: string, control: DockerExecutionControl): Promise<SafeDockerInspection>;
  logs(containerId: string, tail: number, sinceSeconds: number, control: DockerExecutionControl): Promise<SafeDockerLogs>;
}

export interface DockerInspectorOptions {
  supervisor?: Pick<ProcessSupervisor, "run">;
  executable?: string;
}

export class DockerInspectorImpl implements DockerInspector {
  private readonly supervisor: Pick<ProcessSupervisor, "run">;
  private readonly executable: string;

  constructor(options: DockerInspectorOptions = {}) {
    this.supervisor = options.supervisor ?? new ProcessSupervisor({
      maxConcurrent: 2,
      allowedEnvironmentKeys: Object.keys(SAFE_ENVIRONMENT)
    });
    this.executable = options.executable ?? resolveDockerExecutable();
  }

  async status(includeImages: boolean, includeStorage: boolean, control: DockerExecutionControl): Promise<SafeDockerStatus> {
    validateDockerStatusRequest(includeImages, includeStorage);
    const warnings: string[] = [];
    let version: ProcessExecutionResult;
    try {
      version = await this.run(["version", "--format", "{{.Server.Version}}"], control, MAX_STATUS_OUTPUT_BYTES);
    } catch (error) {
      if (error instanceof BrokerError && error.errorClass === "TARGET_NOT_FOUND") {
        return {
          daemon: { available: false },
          containers: [],
          images: [],
          warnings: ["Docker CLI is unavailable on this host"],
          truncated: false
        };
      }
      throw error;
    }
    throwForDockerProcess(version, "Docker version", true);
    if (version.resultClass !== "SUCCEEDED") {
      return {
        daemon: { available: false },
        containers: [],
        images: [],
        warnings: ["Docker daemon is unavailable or did not accept the fixed local request"],
        truncated: version.resultClass === "OUTPUT_LIMIT"
      };
    }
    const daemonVersion = boundedValue(version.stdout.trim(), 128);
    const containersResult = await this.run(["ps", "--all", "--no-trunc", "--format", "{{json .}}"], control, MAX_STATUS_OUTPUT_BYTES);
    throwForDockerProcess(containersResult, "Docker container listing", true);
    const containers = parseContainerLines(containersResult.stdout, warnings);
    let images: SafeDockerImage[] = [];
    let truncated = version.truncated || containersResult.truncated;
    if (containersResult.resultClass !== "SUCCEEDED" && containersResult.resultClass !== "OUTPUT_LIMIT") {
      warnings.push("Docker container listing failed and was omitted");
    }
    if (includeImages) {
      const imagesResult = await this.run(["images", "--no-trunc", "--format", "{{json .}}"], control, MAX_STATUS_OUTPUT_BYTES);
      throwForDockerProcess(imagesResult, "Docker image listing", true);
      images = parseImageLines(imagesResult.stdout, warnings);
      truncated ||= imagesResult.truncated;
      if (imagesResult.resultClass !== "SUCCEEDED" && imagesResult.resultClass !== "OUTPUT_LIMIT") {
        warnings.push("Docker image listing failed and was omitted");
      }
    }
    if (includeStorage) {
      warnings.push("Docker storage facts are unavailable until a fixed local volume readback is configured");
    }
    return {
      daemon: {
        available: true,
        ...(daemonVersion ? { version: daemonVersion } : {}),
        context: "local"
      },
      containers,
      images,
      warnings: uniqueWarnings(warnings),
      truncated
    };
  }

  async inspect(objectType: DockerObjectType, id: string, control: DockerExecutionControl): Promise<SafeDockerInspection> {
    validateDockerObjectRequest(objectType, id);
    const result = await this.run(["inspect", "--type", objectType, id], control, MAX_OUTPUT_BYTES);
    throwForDockerProcess(result, "Docker inspection");
    if (result.resultClass !== "SUCCEEDED") throw new BrokerError("EXECUTION_FAILED", "Docker inspection failed");
    return parseInspection(objectType, id, result.stdout, result.truncated);
  }

  async logs(containerId: string, tail: number, sinceSeconds: number, control: DockerExecutionControl): Promise<SafeDockerLogs> {
    validateDockerLogsRequest(containerId, tail, sinceSeconds);
    const args = ["logs", "--timestamps", "--tail", String(tail)];
    if (sinceSeconds > 0) args.push("--since", `${sinceSeconds}s`);
    args.push(containerId);
    const result = await this.run(args, control, MAX_OUTPUT_BYTES);
    throwForDockerProcess(result, "Docker logs", true);
    if (result.resultClass !== "SUCCEEDED" && result.resultClass !== "OUTPUT_LIMIT") {
      throw new BrokerError("EXECUTION_FAILED", "Docker logs failed");
    }
    return parseLogs(containerId, tail, result);
  }

  private async run(args: readonly string[], control: DockerExecutionControl, outputCapBytes: number): Promise<ProcessExecutionResult> {
    return this.supervisor.run({
      executable: this.executable,
      args,
      cwd: DOCKER_CWD,
      environment: SAFE_ENVIRONMENT,
      timeoutMs: Math.min(control.timeoutMs, MAX_TIMEOUT_MS),
      outputCapBytes,
      shouldCancel: control.shouldCancel
    });
  }
}

export function validateDockerStatusRequest(includeImages: boolean, includeStorage: boolean): void {
  if (typeof includeImages !== "boolean" || typeof includeStorage !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "Docker status flags must be booleans");
  }
}

export function validateDockerObjectRequest(objectType: DockerObjectType, id: string): void {
  if (!isDockerObjectType(objectType) || typeof id !== "string" || !OBJECT_ID_PATTERN.test(id) ||
      id.includes("..") || id.includes("\\") || id.includes("\0") || id.includes("\n")) {
    throw new BrokerError("PRECONDITION_FAILED", "Docker object target is outside the supported range");
  }
}

export function validateDockerLogsRequest(containerId: string, tail: number, sinceSeconds: number): void {
  if (typeof containerId !== "string" || !OBJECT_ID_PATTERN.test(containerId) ||
      !Number.isSafeInteger(tail) || tail < 1 || tail > MAX_LOG_LINES ||
      !Number.isSafeInteger(sinceSeconds) || sinceSeconds < 0 || sinceSeconds > 31_536_000) {
    throw new BrokerError("PRECONDITION_FAILED", "Docker log arguments are outside the supported range");
  }
}

function resolveDockerExecutable(): string {
  for (const candidate of DOCKER_EXECUTABLE_CANDIDATES) {
    try {
      const stat = lstatSync(candidate);
      if (stat.isFile() && (stat.mode & 0o111) !== 0 && realpathSync(candidate) === candidate) return candidate;
    } catch {
      // Continue through the fixed executable allowlist.
    }
  }
  return DOCKER_EXECUTABLE_CANDIDATES[0];
}

function parseContainerLines(output: string, warnings: string[]): SafeDockerContainer[] {
  const containers: SafeDockerContainer[] = [];
  for (const line of boundedLines(output, MAX_ITEMS)) {
    if (!line.trim()) continue;
    const value = parseJsonObject(line, warnings);
    const id = safeDockerId(value?.ID ?? value?.Id);
    if (!id) continue;
    const state = parseContainerState(value?.State);
    const name = boundedValue(value?.Names, 256);
    containers.push({ id, state, ...(name ? { name } : {}) });
  }
  if (boundedLines(output, MAX_ITEMS + 1).length > MAX_ITEMS) warnings.push("Docker container results were capped");
  return containers;
}

function parseImageLines(output: string, warnings: string[]): SafeDockerImage[] {
  const images: SafeDockerImage[] = [];
  for (const line of boundedLines(output, MAX_ITEMS)) {
    if (!line.trim()) continue;
    const value = parseJsonObject(line, warnings);
    const id = safeDockerId(value?.ID ?? value?.Id);
    if (!id) continue;
    const name = boundedValue(value?.Repository ?? value?.Name, 256);
    const tag = boundedValue(value?.Tag, 256);
    images.push({ id, ...(name ? { name } : {}), ...(tag ? { tag } : {}) });
  }
  if (boundedLines(output, MAX_ITEMS + 1).length > MAX_ITEMS) warnings.push("Docker image results were capped");
  return images;
}

function parseInspection(objectType: DockerObjectType, requestedId: string, output: string, truncated: boolean): SafeDockerInspection {
  let parsed: unknown;
  try { parsed = parseJsonStrict(output); } catch { throw new BrokerError("EXECUTION_FAILED", "Docker inspection returned malformed metadata"); }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !isRecord(parsed[0])) {
    throw new BrokerError("EXECUTION_FAILED", "Docker inspection returned an unexpected object shape");
  }
  const value = parsed[0];
  const warnings: string[] = [];
  const id = safeDockerId(value.Id ?? value.ID) ?? requestedId;
  const name = boundedValue(value.Name ?? value.Name, 256);
  const stateValue = isRecord(value.State) ? boundedValue(value.State.Status, 128) : "";
  const imageValue = isRecord(value.Config) ? boundedValue(value.Config.Image, 256) : "";
  const ports = objectType === "container" ? parsePorts(isRecord(value.NetworkSettings) ? value.NetworkSettings.Ports : undefined, warnings) : [];
  const mounts = objectType === "container" ? parseMounts(value.Mounts, warnings) : [];
  if (truncated) warnings.push("Docker inspection output was truncated by a fixed adapter budget");
  return {
    objectType,
    id,
    name,
    state: stateValue,
    image: imageValue,
    ports,
    mounts,
    warnings: uniqueWarnings(warnings),
    truncated
  };
}

function parseLogs(containerId: string, tail: number, result: ProcessExecutionResult): SafeDockerLogs {
  const entries: SafeDockerLogEntry[] = [];
  const warnings: string[] = [];
  for (const rawLine of result.stdout.split("\n")) {
    if (rawLine.length === 0) continue;
    const match = /^(\S+)\s(.*)$/u.exec(rawLine);
    const timestamp = match ? parseDockerTimestamp(match[1]!) : null;
    const rawMessage = match ? match[2]! : rawLine;
    const redacted = redactLogText(rawMessage);
    entries.push({ timestamp, line: redacted.text });
    if (redacted.redacted) warnings.push("Sensitive Docker log content was redacted");
  }
  const lineLimited = entries.length > tail;
  if (lineLimited) entries.splice(0, entries.length - tail);
  if (result.truncated) warnings.push("Docker log output was truncated by a fixed adapter budget");
  return {
    containerId,
    entries,
    truncated: result.truncated || lineLimited,
    warnings: uniqueWarnings(warnings)
  };
}

function throwForDockerProcess(result: ProcessExecutionResult, operation: string, allowOutputLimit = false): void {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", `${operation} was cancelled`);
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", `${operation} timed out`);
  if (result.resultClass === "UNKNOWN_OUTCOME") throw new BrokerError("UNKNOWN_OUTCOME", `${operation} ended with an unknown outcome`);
  if (result.resultClass === "OUTPUT_LIMIT" && !allowOutputLimit) throw new BrokerError("OUTPUT_LIMIT", `${operation} exceeded its output limit`);
}

function parsePorts(value: unknown, warnings: string[]): SafeDockerPort[] {
  if (!isRecord(value)) return [];
  const ports: SafeDockerPort[] = [];
  for (const [key, bindings] of Object.entries(value)) {
    const match = /^(\d+)\/(tcp|udp)$/u.exec(key);
    if (!match) continue;
    const containerPort = Number(match[1]);
    if (!Number.isSafeInteger(containerPort) || containerPort < 1 || containerPort > 65_535) continue;
    const items = Array.isArray(bindings) ? bindings : [];
    if (items.length === 0) {
      ports.push({ protocol: match[2] as "tcp" | "udp", containerPort, hostPort: null });
      continue;
    }
    for (const item of items.slice(0, MAX_PORTS - ports.length)) {
      const hostPort = isRecord(item) && typeof item.HostPort === "string" ? Number(item.HostPort) : null;
      ports.push({
        protocol: match[2] as "tcp" | "udp",
        containerPort,
        hostPort: hostPort !== null && Number.isSafeInteger(hostPort) && hostPort >= 1 && hostPort <= 65_535 ? hostPort : null
      });
    }
    if (ports.length >= MAX_PORTS) {
      warnings.push("Docker port bindings were capped");
      break;
    }
  }
  return ports;
}

function parseMounts(value: unknown, warnings: string[]): SafeDockerMount[] {
  if (!Array.isArray(value)) return [];
  const mounts: SafeDockerMount[] = [];
  for (const item of value.slice(0, MAX_MOUNTS)) {
    if (!isRecord(item) || typeof item.Destination !== "string") continue;
    const target = redactBoundedText(item.Destination, 4_096).text;
    const source = typeof item.Source === "string" ? redactBoundedText(item.Source, 4_096).text : undefined;
    const readOnly = item.RW === false || item.Mode === "ro";
    mounts.push({ target, ...(source ? { source } : {}), readOnly });
  }
  if (value.length > MAX_MOUNTS) warnings.push("Docker mounts were capped");
  return mounts;
}

function parseJsonObject(line: string, warnings: string[]): Record<string, unknown> | undefined {
  try {
    const parsed = parseJsonStrict(line) as unknown;
    if (isRecord(parsed)) return parsed;
  } catch {
    // A malformed line is omitted and does not cross the result boundary.
  }
  warnings.push("Some Docker metadata records were malformed and were omitted");
  return undefined;
}

function parseContainerState(value: unknown): SafeDockerContainer["state"] {
  if (typeof value !== "string") return "unknown";
  const normalized = value.toLowerCase();
  if (normalized === "running" || normalized === "exited" || normalized === "paused" || normalized === "created") return normalized;
  return "unknown";
}

function parseDockerTimestamp(value: string): string | null {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : new Date(parsed).toISOString();
}

function safeDockerId(value: unknown): string | undefined {
  return typeof value === "string" && OBJECT_ID_PATTERN.test(value) ? value : undefined;
}

function boundedValue(value: unknown, maxLength: number): string {
  if (typeof value !== "string") return "";
  return redactBoundedText(value, maxLength).text;
}

function boundedLines(value: string, maxLines: number): string[] {
  return value.split("\n").slice(0, maxLines);
}

function uniqueWarnings(warnings: readonly string[]): string[] {
  return [...new Set(warnings)].slice(0, 32);
}

function isDockerObjectType(value: unknown): value is DockerObjectType {
  return value === "container" || value === "image" || value === "network" || value === "volume";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
