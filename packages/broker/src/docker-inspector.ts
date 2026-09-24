import { lstatSync, realpathSync } from "node:fs";
import { BrokerError, parseJsonStrict } from "@mac-operator/contracts";
import { captureProcessPathIdentity, ProcessSupervisor, type DescriptorProcessSpawnAdapter, type ProcessExecutionResult } from "./process-supervisor.js";
import { isPlainDataRecord } from "./plain-record.js";
import { redactBoundedText, redactLogText } from "./secret-policy.js";

export const DOCKER_EXECUTABLE_CANDIDATES = [
  "/Applications/Docker.app/Contents/Resources/bin/docker",
  "/opt/homebrew/bin/docker",
  "/usr/local/bin/docker",
  "/usr/bin/docker"
] as const;
const DOCKER_CWD = "/";
const DOCKER_HOST = "unix:///var/run/docker.sock";
const DOCKER_CONFIG = "/var/empty";
const DOCKER_HOME = "/var/empty";
const CODESIGN_EXECUTABLE = "/usr/bin/codesign";
const CODE_SIGNATURE_TIMEOUT_MS = 5_000;
const CODE_SIGNATURE_OUTPUT_BYTES = 131_072;
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
const CONTAINER_RECORD_FIELDS = new Set([
  "ID", "Id", "Names", "State", "Image", "Command", "CreatedAt", "CreatedSince", "RunningFor",
  "Ports", "Status", "Labels", "LocalVolumes", "Mounts", "Networks", "Platform", "Size"
]);
const IMAGE_RECORD_FIELDS = new Set([
  "ID", "Id", "Repository", "Name", "Tag", "Digest", "CreatedAt", "CreatedSince", "Size",
  "SharedSize", "UniqueSize", "VirtualSize", "Containers"
]);

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
  /** Require a Broker-owned code-signature attestation before Docker calls. */
  requireCodeSignature?: boolean;
  /** Fixed expected identity for the Docker executable; never caller supplied. */
  codeSignatureExpectation?: DockerCodeSignatureExpectation;
}

/**
 * Construct the only process authority permitted for the production Docker
 * adapter. Docker is a host boundary, so a trusted path/content observation
 * is not sufficient: the supervisor must require a host-proven descriptor
 * launcher and must never fall back to pathname spawn.
 */
export function createDockerProcessSupervisor(options: {
  descriptorSpawnAdapter?: DescriptorProcessSpawnAdapter;
} = {}): ProcessSupervisor {
  return new ProcessSupervisor({
    maxConcurrent: 2,
    requireRootOwnedExecutable: true,
    trustedUserOwnedExecutablePaths: DOCKER_EXECUTABLE_CANDIDATES,
    requireDescriptorExecution: true,
    allowedEnvironmentKeys: Object.keys(SAFE_ENVIRONMENT),
    ...(options.descriptorSpawnAdapter === undefined ? {} : { descriptorSpawnAdapter: options.descriptorSpawnAdapter })
  });
}

export interface DockerCodeSignatureExpectation {
  identifier: string;
  teamIdentifier?: string;
  cdHash?: string;
}

/** Docker Inc's Developer ID identity observed on the supported Mac mini host. */
export const DOCKER_CODE_SIGNATURE_EXPECTATION: DockerCodeSignatureExpectation = Object.freeze({
  identifier: "docker",
  teamIdentifier: "9BNSXJN65R"
});

export class DockerInspectorImpl implements DockerInspector {
  private readonly supervisor: Pick<ProcessSupervisor, "run">;
  private readonly executable: string;
  private readonly requireCodeSignature: boolean;
  private readonly codeSignatureExpectation: DockerCodeSignatureExpectation;

  constructor(options: DockerInspectorOptions = {}) {
    this.supervisor = options.supervisor ?? new ProcessSupervisor({
      maxConcurrent: 2,
      allowedEnvironmentKeys: Object.keys(SAFE_ENVIRONMENT)
    });
    this.executable = options.executable ?? resolveDockerExecutable();
    this.requireCodeSignature = options.requireCodeSignature ?? false;
    this.codeSignatureExpectation = normalizeCodeSignatureExpectation(
      options.codeSignatureExpectation ?? DOCKER_CODE_SIGNATURE_EXPECTATION
    );
  }

  async status(includeImages: boolean, includeStorage: boolean, control: DockerExecutionControl): Promise<SafeDockerStatus> {
    validateDockerStatusRequest(includeImages, includeStorage);
    const expectedExecutableContentSha256 = await this.verifyCodeSignature(control);
    const warnings: string[] = [];
    let version: ProcessExecutionResult;
    try {
      version = await this.run(["version", "--format", "{{.Server.Version}}"], control, MAX_STATUS_OUTPUT_BYTES, expectedExecutableContentSha256);
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
    const containersResult = await this.run(["ps", "--all", "--no-trunc", "--format", "{{json .}}"], control, MAX_STATUS_OUTPUT_BYTES, expectedExecutableContentSha256);
    throwForDockerProcess(containersResult, "Docker container listing", true);
    const containers = parseContainerLines(containersResult.stdout, warnings);
    let images: SafeDockerImage[] = [];
    let truncated = version.truncated || containersResult.truncated;
    if (containersResult.resultClass !== "SUCCEEDED" && containersResult.resultClass !== "OUTPUT_LIMIT") {
      warnings.push("Docker container listing failed and was omitted");
    }
    if (includeImages) {
      const imagesResult = await this.run(["images", "--no-trunc", "--format", "{{json .}}"], control, MAX_STATUS_OUTPUT_BYTES, expectedExecutableContentSha256);
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
    const expectedExecutableContentSha256 = await this.verifyCodeSignature(control);
    const deadlineMs = Date.now() + Math.min(control.timeoutMs, MAX_TIMEOUT_MS);
    const first = await this.inspectOnce(objectType, id, control, deadlineMs, expectedExecutableContentSha256);
    if (DOCKER_HEX_ID_PATTERN.test(id)) return first;

    // Names are mutable aliases. Re-observe the canonical ID so a replacement
    // between name resolution and result publication cannot be returned as the
    // originally selected object. This remains a bounded observation fence,
    // not a kernel-held Docker object handle.
    const second = await this.inspectOnce(objectType, first.id, control, deadlineMs, expectedExecutableContentSha256);
    if (normalizeDockerName(first.name) !== normalizeDockerName(second.name)) {
      throw new BrokerError("CONFLICT", "Docker object identity changed during inspection");
    }
    return {
      ...second,
      warnings: uniqueWarnings([...first.warnings, ...second.warnings]),
      truncated: first.truncated || second.truncated
    };
  }

  async logs(containerId: string, tail: number, sinceSeconds: number, control: DockerExecutionControl): Promise<SafeDockerLogs> {
    validateDockerLogsRequest(containerId, tail, sinceSeconds);
    const expectedExecutableContentSha256 = await this.verifyCodeSignature(control);
    const args = ["logs", "--timestamps", "--tail", String(tail)];
    if (sinceSeconds > 0) args.push("--since", `${sinceSeconds}s`);
    args.push(containerId);
    const result = await this.run(args, control, MAX_OUTPUT_BYTES, expectedExecutableContentSha256);
    throwForDockerProcess(result, "Docker logs", true);
    if (result.resultClass !== "SUCCEEDED" && result.resultClass !== "OUTPUT_LIMIT") {
      throw new BrokerError("EXECUTION_FAILED", "Docker logs failed");
    }
    return parseLogs(containerId, tail, result);
  }

  private async run(
    args: readonly string[],
    control: DockerExecutionControl,
    outputCapBytes: number,
    expectedExecutableContentSha256?: string
  ): Promise<ProcessExecutionResult> {
    return this.supervisor.run({
      executable: this.executable,
      args,
      cwd: DOCKER_CWD,
      environment: SAFE_ENVIRONMENT,
      timeoutMs: Math.min(control.timeoutMs, MAX_TIMEOUT_MS),
      outputCapBytes,
      allowUserOwnedExecutable: true,
      ...(expectedExecutableContentSha256 === undefined ? {} : { expectedExecutableContentSha256 }),
      shouldCancel: control.shouldCancel
    });
  }

  /**
   * Verify the fixed Docker executable through the host's fixed codesign
   * utility. The result is intentionally not exposed to MCP callers; a
   * mismatch denies the adapter before any Docker daemon request is started.
   * This is a bounded observation fence, not a kernel-held executable handle.
   */
  private async verifyCodeSignature(control: DockerExecutionControl): Promise<string | undefined> {
    if (!this.requireCodeSignature) return undefined;
    const timeoutMs = Math.min(control.timeoutMs, CODE_SIGNATURE_TIMEOUT_MS);
    let expectedExecutableContentSha256: string | undefined;
    let verification: ProcessExecutionResult;
    let details: ProcessExecutionResult;
    try {
      const identity = await captureProcessPathIdentity(this.executable, "executable");
      expectedExecutableContentSha256 = identity.contentSha256;
      if (expectedExecutableContentSha256 === undefined) {
        throw new BrokerError("POLICY_DENIED", "Docker executable content identity is unavailable");
      }
      verification = await this.supervisor.run({
        executable: CODESIGN_EXECUTABLE,
        args: ["--verify", "--strict", "--deep", this.executable],
        cwd: DOCKER_CWD,
        environment: {},
        timeoutMs,
        outputCapBytes: CODE_SIGNATURE_OUTPUT_BYTES,
        shouldCancel: control.shouldCancel
      });
      if (verification.resultClass !== "SUCCEEDED" || verification.truncated) {
        throw new BrokerError("POLICY_DENIED", "Docker executable code signature is not trusted");
      }
      details = await this.supervisor.run({
        executable: CODESIGN_EXECUTABLE,
        args: ["-dv", "--verbose=4", this.executable],
        cwd: DOCKER_CWD,
        environment: {},
        timeoutMs,
        outputCapBytes: CODE_SIGNATURE_OUTPUT_BYTES,
        shouldCancel: control.shouldCancel
      });
    } catch (error) {
      if (error instanceof BrokerError && (error.errorClass === "CANCELLED" || error.errorClass === "TIMEOUT")) {
        throw error;
      }
      if (error instanceof BrokerError && error.errorClass === "POLICY_DENIED") throw error;
      throw new BrokerError("POLICY_DENIED", "Docker executable code signature is not trusted");
    }
    if (details.resultClass !== "SUCCEEDED" || details.truncated) {
      throw new BrokerError("POLICY_DENIED", "Docker executable code signature details are unavailable");
    }
    const output = `${details.stdout}\n${details.stderr}`;
    const identifier = readCodeSignatureField(output, "Identifier", /^[A-Za-z0-9._:-]{1,128}$/u);
    const teamIdentifier = readCodeSignatureField(output, "TeamIdentifier", /^[A-Z0-9]{5,32}$/u);
    const cdHash = readCodeSignatureField(output, "CDHash", /^[a-f0-9]{20,64}$/u);
    if (identifier !== this.codeSignatureExpectation.identifier ||
        (this.codeSignatureExpectation.teamIdentifier !== undefined && teamIdentifier !== this.codeSignatureExpectation.teamIdentifier) ||
        (this.codeSignatureExpectation.cdHash !== undefined && cdHash !== this.codeSignatureExpectation.cdHash)) {
      throw new BrokerError("POLICY_DENIED", "Docker executable code signature does not match the Broker trust policy");
    }
    return expectedExecutableContentSha256;
  }

  private async inspectOnce(
    objectType: DockerObjectType,
    id: string,
    control: DockerExecutionControl,
    deadlineMs: number,
    expectedExecutableContentSha256?: string
  ): Promise<SafeDockerInspection> {
    const remainingMs = Math.max(1, Math.min(deadlineMs - Date.now(), MAX_TIMEOUT_MS));
    const result = await this.run(["inspect", "--type", objectType, id], {
      timeoutMs: remainingMs,
      shouldCancel: control.shouldCancel
    }, MAX_OUTPUT_BYTES, expectedExecutableContentSha256);
    throwForDockerProcess(result, "Docker inspection");
    if (result.resultClass !== "SUCCEEDED") throw new BrokerError("EXECUTION_FAILED", "Docker inspection failed");
    return parseInspection(objectType, id, result.stdout, result.truncated);
  }
}

function normalizeCodeSignatureExpectation(value: DockerCodeSignatureExpectation): DockerCodeSignatureExpectation {
  if (value === null || typeof value !== "object" || typeof value.identifier !== "string" ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(value.identifier) ||
      (value.teamIdentifier !== undefined && (typeof value.teamIdentifier !== "string" || !/^[A-Z0-9]{5,32}$/u.test(value.teamIdentifier))) ||
      (value.cdHash !== undefined && (typeof value.cdHash !== "string" || !/^[a-f0-9]{20,64}$/u.test(value.cdHash)))) {
    throw new Error("Docker code-signature expectation is invalid");
  }
  return {
    identifier: value.identifier,
    ...(value.teamIdentifier === undefined ? {} : { teamIdentifier: value.teamIdentifier }),
    ...(value.cdHash === undefined ? {} : { cdHash: value.cdHash })
  };
}

function readCodeSignatureField(output: string, fieldName: string, pattern: RegExp): string | null {
  const matches = [...output.matchAll(new RegExp(`^${fieldName}=([^\\r\\n]+)$`, "gmu"))];
  if (matches.length === 0) return null;
  if (matches.length !== 1) throw new BrokerError("POLICY_DENIED", "Docker executable code signature details are ambiguous");
  const value = matches[0]?.[1]?.trim();
  if (value === undefined || !pattern.test(value)) {
    throw new BrokerError("POLICY_DENIED", "Docker executable code signature details are malformed");
  }
  return value;
}

export function validateDockerStatusRequest(includeImages: boolean, includeStorage: boolean): void {
  if (typeof includeImages !== "boolean" || typeof includeStorage !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "Docker status flags must be booleans");
  }
}

export function validateDockerObjectRequest(objectType: DockerObjectType, id: string): void {
  if (!isDockerObjectType(objectType) || typeof id !== "string" || !OBJECT_ID_PATTERN.test(id) ||
      hasUnsafeDockerTargetSyntax(id) || id.includes("..") || id.includes("\\") || id.includes("\0") || id.includes("\n")) {
    throw new BrokerError("PRECONDITION_FAILED", "Docker object target is outside the supported range");
  }
}

export function validateDockerLogsRequest(containerId: string, tail: number, sinceSeconds: number): void {
  if (typeof containerId !== "string" || !OBJECT_ID_PATTERN.test(containerId) || hasUnsafeDockerTargetSyntax(containerId) ||
      !Number.isSafeInteger(tail) || tail < 1 || tail > MAX_LOG_LINES ||
      !Number.isSafeInteger(sinceSeconds) || sinceSeconds < 0 || sinceSeconds > 31_536_000) {
    throw new BrokerError("PRECONDITION_FAILED", "Docker log arguments are outside the supported range");
  }
}

function hasUnsafeDockerTargetSyntax(value: string): boolean {
  return value.startsWith("-") || value.startsWith("/") || /^(?:unix|tcp|http|https):\/\//iu.test(value);
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
    const parsed = value ? parseDockerContainerRecord(value) : undefined;
    if (!parsed) {
      warnings.push("Some Docker container records were outside the supported shape and were omitted");
      continue;
    }
    containers.push(parsed);
  }
  if (boundedLines(output, MAX_ITEMS + 1).length > MAX_ITEMS) warnings.push("Docker container results were capped");
  return containers;
}

function parseImageLines(output: string, warnings: string[]): SafeDockerImage[] {
  const images: SafeDockerImage[] = [];
  for (const line of boundedLines(output, MAX_ITEMS)) {
    if (!line.trim()) continue;
    const value = parseJsonObject(line, warnings);
    const parsed = value ? parseDockerImageRecord(value) : undefined;
    if (!parsed) {
      warnings.push("Some Docker image records were outside the supported shape and were omitted");
      continue;
    }
    images.push(parsed);
  }
  if (boundedLines(output, MAX_ITEMS + 1).length > MAX_ITEMS) warnings.push("Docker image results were capped");
  return images;
}

function parseInspection(objectType: DockerObjectType, requestedId: string, output: string, truncated: boolean): SafeDockerInspection {
  let parsed: unknown;
  try { parsed = parseJsonStrict(output); } catch { throw new BrokerError("EXECUTION_FAILED", "Docker inspection returned malformed metadata"); }
  if (!Array.isArray(parsed) || parsed.length !== 1 || !isPlainDataRecord(parsed[0])) {
    throw new BrokerError("EXECUTION_FAILED", "Docker inspection returned an unexpected object shape");
  }
  const value = parsed[0];
  const warnings: string[] = [];
  const reportedId = parseAliasedDockerId(value.ID, value.Id);
  if ((value.ID !== undefined || value.Id !== undefined) && !reportedId) {
    throw new BrokerError("EXECUTION_FAILED", "Docker inspection returned an ambiguous object identity");
  }
  if (!reportedId) {
    throw new BrokerError("EXECUTION_FAILED", "Docker inspection returned no object identity");
  }
  const name = boundedValue(value.Name, 256);
  if (!dockerObjectIdentityMatches(objectType, requestedId, reportedId, name)) {
    throw new BrokerError("CONFLICT", "Docker object identity changed during inspection");
  }
  const id = reportedId;
  const stateValue = isPlainDataRecord(value.State) ? boundedValue(value.State.Status, 128) : "";
  const imageValue = isPlainDataRecord(value.Config) ? boundedValue(value.Config.Image, 256) : "";
  const ports = objectType === "container" ? parsePorts(isPlainDataRecord(value.NetworkSettings) ? value.NetworkSettings.Ports : undefined, warnings) : [];
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

const DOCKER_HEX_ID_PATTERN = /^(?:sha256:)?[0-9a-f]{6,64}$/iu;

/**
 * Bind a Docker inspect response to the target selected by the caller.
 *
 * Docker accepts mutable object names and abbreviated hexadecimal IDs. Names
 * are therefore accepted only when the response reads back the exact name;
 * ID targets require an exact ID or a bounded hexadecimal prefix match. A
 * name that looks like an ID is treated as an ID target so a same-name object
 * replacement cannot be silently accepted.
 */
export function dockerObjectIdentityMatches(
  objectType: DockerObjectType,
  requestedId: string,
  reportedId: string | undefined,
  reportedName: string
): boolean {
  if (!isDockerObjectType(objectType) || requestedId.length === 0) return false;
  if (!reportedId) return false;
  const requestedName = normalizeDockerName(requestedId);
  const responseName = normalizeDockerName(reportedName);
  const requestedLooksLikeId = DOCKER_HEX_ID_PATTERN.test(requestedId);
  if (reportedId && dockerIdsEquivalent(requestedId, reportedId)) return true;
  if (requestedLooksLikeId) return false;
  return responseName.length > 0 && responseName === requestedName;
}

function dockerIdsEquivalent(requestedId: string, reportedId: string): boolean {
  if (requestedId === reportedId) return true;
  const requestedHex = dockerHexId(requestedId);
  const reportedHex = dockerHexId(reportedId);
  if (!requestedHex || !reportedHex) return false;
  return reportedHex.length >= requestedHex.length && reportedHex.startsWith(requestedHex);
}

function dockerHexId(value: string): string | undefined {
  if (!DOCKER_HEX_ID_PATTERN.test(value)) return undefined;
  return value.startsWith("sha256:") ? value.slice("sha256:".length).toLowerCase() : value.toLowerCase();
}

function normalizeDockerName(value: string): string {
  return value.startsWith("/") ? value.slice(1) : value;
}

function parseLogs(containerId: string, tail: number, result: ProcessExecutionResult): SafeDockerLogs {
  const entries: SafeDockerLogEntry[] = [];
  const warnings: string[] = [];
  const allLines = result.stdout.split("\n");
  const lineCountCapped = allLines.length > MAX_LOG_LINES;
  const rawLines = lineCountCapped ? allLines.slice(-MAX_LOG_LINES) : allLines;
  if (lineCountCapped) warnings.push("Docker log lines were capped by a fixed adapter budget");
  for (const originalLine of rawLines) {
    const lineCapped = originalLine.length > MAX_LOG_LINE_BYTES;
    const rawLine = lineCapped ? originalLine.slice(0, MAX_LOG_LINE_BYTES) : originalLine;
    if (lineCapped) warnings.push("Docker log line length was capped by a fixed adapter budget");
    if (rawLine.length === 0) continue;
    const match = /^(\S+)\s(.*)$/u.exec(rawLine);
    const timestamp = match ? parseDockerTimestamp(match[1]!) : null;
    const rawMessage = match ? match[2]! : rawLine;
    const redacted = redactLogText(rawMessage);
    entries.push({ timestamp, line: redacted.text.slice(0, MAX_LOG_LINE_BYTES) });
    if (redacted.redacted) warnings.push("Sensitive Docker log content was redacted");
  }
  const lineLimited = entries.length > tail;
  if (lineLimited) entries.splice(0, entries.length - tail);
  if (result.truncated) warnings.push("Docker log output was truncated by a fixed adapter budget");
  return {
    containerId,
    entries,
    truncated: result.truncated || lineLimited || lineCountCapped,
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
  if (!isPlainDataRecord(value)) return [];
  const ports: SafeDockerPort[] = [];
  for (const [key, bindings] of Object.entries(value)) {
    const match = /^(\d+)\/(tcp|udp)$/u.exec(key);
    if (!match) continue;
    const containerPort = Number(match[1]);
    if (!Number.isSafeInteger(containerPort) || containerPort < 1 || containerPort > 65_535) continue;
    const items = isDenseArray(bindings, MAX_PORTS) ? bindings : [];
    if (items.length === 0) {
      ports.push({ protocol: match[2] as "tcp" | "udp", containerPort, hostPort: null });
      continue;
    }
    for (const item of items.slice(0, MAX_PORTS - ports.length)) {
      const hostPort = isPlainDataRecord(item) && typeof item.HostPort === "string" ? Number(item.HostPort) : null;
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
  if (!isDenseArray(value, MAX_MOUNTS)) return [];
  const mounts: SafeDockerMount[] = [];
  for (const item of value.slice(0, MAX_MOUNTS)) {
    if (!isPlainDataRecord(item) || typeof item.Destination !== "string") continue;
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
    if (isPlainDataRecord(parsed)) return parsed;
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

export function parseDockerContainerRecord(value: unknown): SafeDockerContainer | undefined {
  if (!isPlainDataRecord(value) || !hasOnlyKnownFields(value, CONTAINER_RECORD_FIELDS)) return undefined;
  const id = parseAliasedDockerId(value.ID, value.Id);
  if (!id) return undefined;
  const state = parseContainerState(value.State);
  const name = boundedValue(value.Names, 256);
  return { id, state, ...(name ? { name } : {}) };
}

export function parseDockerImageRecord(value: unknown): SafeDockerImage | undefined {
  if (!isPlainDataRecord(value) || !hasOnlyKnownFields(value, IMAGE_RECORD_FIELDS)) return undefined;
  const id = parseAliasedDockerId(value.ID, value.Id);
  if (!id) return undefined;
  const name = boundedValue(value.Repository ?? value.Name, 256);
  const tag = boundedValue(value.Tag, 256);
  return { id, ...(name ? { name } : {}), ...(tag ? { tag } : {}) };
}

function parseAliasedDockerId(primary: unknown, alias: unknown): string | undefined {
  const primaryId = safeDockerId(primary);
  const aliasId = safeDockerId(alias);
  if (primary !== undefined && primaryId === undefined) return undefined;
  if (alias !== undefined && aliasId === undefined) return undefined;
  if (primaryId && aliasId && primaryId !== aliasId) return undefined;
  return primaryId ?? aliasId;
}

function hasOnlyKnownFields(value: Record<string, unknown>, allowed: ReadonlySet<string>): boolean {
  return Object.keys(value).every((key) => allowed.has(key));
}

function isDenseArray(value: unknown, maxLength: number): value is readonly unknown[] {
  if (!Array.isArray(value)) return false;
  const checkedLength = Math.min(value.length, maxLength);
  for (let index = 0; index < checkedLength; index += 1) {
    if (!Object.prototype.hasOwnProperty.call(value, index)) return false;
  }
  return true;
}
