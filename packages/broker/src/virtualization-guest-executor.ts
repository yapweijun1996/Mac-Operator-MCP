import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { ProcessSupervisor, type ProcessExecutionResult, type ProcessSupervisorOptions } from "./process-supervisor.js";
import { isPlainDataRecord } from "./plain-record.js";
import { isSafeProcessEnvironmentKey } from "./process-environment.js";
import { parseTaskNetworkDestination } from "./task-profile.js";
import { redactBoundedText } from "./secret-policy.js";
import {
  virtualizationGuestRequestDigest,
  virtualizationGuestStatusRequestDigest,
  type UnsignedVirtualizationGuestRequest,
  type UnsignedVirtualizationGuestResponse,
  type UnsignedVirtualizationGuestStatusRequest,
  type UnsignedVirtualizationGuestStatusResponse,
  type VirtualizationGuestResultClass,
  type VirtualizationGuestTaskState,
  type VirtualizationGuestVerificationStatus
} from "./virtualization-guest-transport.js";
import type { VirtualizationGuestIdentity } from "./virtualization-guest-attestation.js";

const PROFILE_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const MAX_ARGUMENTS = 128;
const MAX_ARGUMENT_BYTES = 64 * 1024;
const MAX_ENVIRONMENT_KEYS = 64;
const MAX_ENVIRONMENT_BYTES = 64 * 1024;
const MAX_FILESYSTEM_ROOTS = 64;
const MAX_NETWORK_DESTINATIONS = 64;
const MAX_TIMEOUT_MS = 15 * 60_000;
const MAX_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_CONCURRENT = 64;
const FORBIDDEN_EXECUTABLES = new Set([
  "/bin/sh", "/bin/bash", "/bin/zsh", "/bin/dash", "/bin/csh", "/bin/tcsh", "/usr/bin/env"
]);
const FORBIDDEN_FILESYSTEM_ROOTS = new Set(["/", "/System", "/Users", "/private", "/var", "/etc"]);
const PROFILE_KEYS = new Set([
  "args", "credentialPolicy", "cwd", "enabled", "environment", "executable", "filesystemRoots",
  "networkAllowlist", "networkPolicy", "outputCapBytes", "processTreePolicy", "profile",
  "sandboxProfile", "schemaVersion", "timeoutMs", "verificationStrategy"
]);

/**
 * Immutable task material packaged inside a reviewed guest image. A request
 * carries only the two digests derived from this object; it never carries any
 * of the executable, cwd, arguments, environment, or filesystem paths.
 */
export interface VirtualizationGuestTaskProfile {
  schemaVersion: "0.1";
  profile: string;
  sandboxProfile: string;
  executable: string;
  args: readonly string[];
  cwd: string;
  environment?: Readonly<Record<string, string>>;
  filesystemRoots: readonly string[];
  networkPolicy: "none" | "allowlist";
  networkAllowlist?: readonly string[];
  credentialPolicy: "none";
  processTreePolicy: "single_process" | "owned_group";
  timeoutMs: number;
  outputCapBytes: number;
  verificationStrategy: "exit_status_and_declared_task_verification";
  enabled: boolean;
}

export interface VirtualizationGuestProfileDigestInput {
  profile: string;
  sandboxProfile: string;
  filesystemRoots: readonly string[];
  networkPolicy: "none" | "allowlist";
  networkAllowlist?: readonly string[];
  credentialPolicy: "none";
  processTreePolicy: "single_process" | "owned_group";
  verificationStrategy: "exit_status_and_declared_task_verification";
}

export interface VirtualizationGuestTaskDigestInput extends VirtualizationGuestProfileDigestInput {
  executable: string;
  args: readonly string[];
  cwd: string;
  environment?: Readonly<Record<string, string>>;
  timeoutMs: number;
  outputCapBytes: number;
}

export interface VirtualizationGuestTaskExecutionInput {
  readonly request: UnsignedVirtualizationGuestRequest;
  readonly profile: VirtualizationGuestTaskProfile;
  readonly timeoutMs: number;
  readonly outputCapBytes: number;
  readonly signal: AbortSignal;
}

export interface VirtualizationGuestExecutionResult {
  state: VirtualizationGuestTaskState;
  resultClass: VirtualizationGuestResultClass;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  truncated: boolean;
  durationMs: number;
  verification: {
    status: VirtualizationGuestVerificationStatus;
    summary?: string;
  };
}

/** A guest-local process boundary; it receives only a validated manifest. */
export interface VirtualizationGuestProcessAdapter {
  readonly available: boolean;
  run(input: VirtualizationGuestTaskExecutionInput): Promise<VirtualizationGuestExecutionResult>;
  close?(): Promise<void> | void;
}

/**
 * Resolves only startup-owned task manifests. It performs a fresh canonical
 * path check at admission so a replaced executable or cwd is not silently
 * accepted after image startup.
 */
export class VirtualizationGuestTaskProfileRegistry {
  private readonly profiles = new Map<string, VirtualizationGuestTaskProfile>();
  private readonly byTaskDigest = new Map<string, VirtualizationGuestTaskProfile>();

  constructor(profiles: readonly VirtualizationGuestTaskProfile[]) {
    if (!Array.isArray(profiles) || profiles.length < 1 || profiles.length > MAX_CONCURRENT) {
      throw new Error("At least one and no more than 64 guest task profiles are required");
    }
    for (const profile of profiles) {
      validateProfileShape(profile);
      if (this.profiles.has(profile.profile)) throw new Error(`Guest task profile is duplicated: ${profile.profile}`);
      const cloned = cloneProfile(profile);
      const taskDigest = virtualizationGuestTaskDigest(cloned);
      if (this.byTaskDigest.has(taskDigest)) throw new Error("Guest task profile task digest is duplicated");
      this.profiles.set(cloned.profile, cloned);
      this.byTaskDigest.set(taskDigest, cloned);
    }
  }

  names(): readonly string[] {
    return [...this.profiles.keys()].sort();
  }

  taskDigest(profile: string): string {
    const found = this.profiles.get(profile);
    if (found === undefined) throw new BrokerError("TARGET_NOT_FOUND", "Named guest task profile was not found");
    return virtualizationGuestTaskDigest(found);
  }

  async resolve(request: UnsignedVirtualizationGuestRequest): Promise<VirtualizationGuestTaskProfile> {
    validateGuestRequestShape(request);
    const profile = this.byTaskDigest.get(request.taskDigest);
    if (profile === undefined) throw new BrokerError("TARGET_NOT_FOUND", "Guest task digest was not registered");
    if (!profile.enabled) throw new BrokerError("POLICY_DENIED", "Guest task profile is disabled");
    const expectedProfileDigest = virtualizationGuestProfileDigest(profile);
    if (request.profileDigest !== expectedProfileDigest || request.sandboxProfile !== profile.sandboxProfile ||
        request.processTreePolicy !== profile.processTreePolicy) {
      throw new BrokerError("POLICY_DENIED", "Guest task profile binding does not match the startup manifest");
    }
    if (request.timeoutMs > profile.timeoutMs || request.outputCapBytes > profile.outputCapBytes) {
      throw new BrokerError("POLICY_DENIED", "Guest task request exceeds the startup profile budget");
    }
    await assertGuestProfileTargets(profile);
    return cloneProfile(profile);
  }
}

/**
 * The guest-side executor binds authenticated requests to one manifest and
 * keeps a bounded terminal ledger for status recovery. It never accepts a
 * caller-selected command or path.
 */
export class VirtualizationGuestProfileExecutor {
  private readonly ledger = new GuestExecutionLedger();
  private readonly activeControllers = new Set<AbortController>();
  private readonly activeExecutions = new Set<Promise<unknown>>();
  private readonly maxConcurrent: number;
  private active = 0;
  private inFlight = 0;
  private closed = false;
  private closePromise: Promise<void> | undefined;

  constructor(
    private readonly registry: VirtualizationGuestTaskProfileRegistry,
    private readonly adapter: VirtualizationGuestProcessAdapter,
    options: { maxConcurrent?: number } = {}
  ) {
    if (adapter === null || typeof adapter !== "object" || typeof adapter.run !== "function" ||
        typeof adapter.available !== "boolean") {
      throw new Error("Guest process adapter is invalid");
    }
    this.maxConcurrent = options.maxConcurrent ?? 4;
    if (!Number.isSafeInteger(this.maxConcurrent) || this.maxConcurrent < 1 || this.maxConcurrent > MAX_CONCURRENT) {
      throw new Error("Guest executor concurrency is invalid");
    }
  }

  async execute(request: UnsignedVirtualizationGuestRequest, signal?: AbortSignal): Promise<UnsignedVirtualizationGuestResponse> {
    if (this.closed || !this.adapter.available) throw new BrokerError("POLICY_DENIED", "Guest task executor is not available");
    if (signal?.aborted) return this.cancelled(request);
    if (this.active + this.inFlight >= this.maxConcurrent) {
      throw new BrokerError("CONFLICT", "Guest task executor capacity is exhausted", true);
    }
    // Reserve the slot synchronously before manifest resolution. The
    // registry performs asynchronous target readback, so checking only
    // `active` would let concurrent admissions oversubscribe the limit.
    this.inFlight += 1;
    let profile: VirtualizationGuestTaskProfile;
    try {
      profile = await this.registry.resolve(request);
    } finally {
      // Release the reservation even when manifest readback or admission
      // fails before an adapter run starts.
      this.inFlight -= 1;
    }
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Guest task executor is not available");
    if (signal?.aborted) return this.cancelled(request);
    const controller = new AbortController();
    const abortFromCaller = (): void => controller.abort();
    signal?.addEventListener("abort", abortFromCaller, { once: true });
    this.activeControllers.add(controller);
    this.active += 1;
    this.ledger.start(request);
    try {
      const execution = this.adapter.run({
        request,
        profile,
        timeoutMs: Math.min(request.timeoutMs, profile.timeoutMs),
        outputCapBytes: Math.min(request.outputCapBytes, profile.outputCapBytes),
        signal: controller.signal
      });
      this.activeExecutions.add(execution);
      let result: VirtualizationGuestExecutionResult;
      try {
        result = await execution;
      } finally {
        this.activeExecutions.delete(execution);
      }
      if (controller.signal.aborted || this.closed) {
        const cancelled = this.executionResult("cancelled", "CANCELLED", null, "Guest task was cancelled before result publication");
        this.ledger.complete(request, cancelled);
        return this.response(request, cancelled);
      }
      const validated = redactGuestExecutionResult(
        validateGuestExecutionResult(result, request.outputCapBytes),
        request.outputCapBytes
      );
      this.ledger.complete(request, validated);
      return this.response(request, validated);
    } catch (error) {
      if (controller.signal.aborted || this.closed) {
        const cancelled = this.executionResult("cancelled", "CANCELLED", null, "Guest task was cancelled before result publication");
        this.ledger.complete(request, cancelled);
        return this.response(request, cancelled);
      }
      const result = error instanceof BrokerError
        ? error
        : new BrokerError("UNKNOWN_OUTCOME", "Guest task execution outcome could not be established", true);
      if (result.errorClass === "POLICY_DENIED" || result.errorClass === "CONFLICT" || result.errorClass === "TARGET_NOT_FOUND") {
        this.ledger.fail(request, result);
        throw result;
      }
      const mapped = this.resultForError(result);
      this.ledger.complete(request, mapped);
      return this.response(request, mapped);
    } finally {
      this.active -= 1;
      this.activeControllers.delete(controller);
      signal?.removeEventListener("abort", abortFromCaller);
    }
  }

  async lookup(request: UnsignedVirtualizationGuestStatusRequest): Promise<UnsignedVirtualizationGuestStatusResponse> {
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Guest task executor is closed");
    const result = this.ledger.lookup(request);
    return {
      schemaVersion: "0.1",
      protocolVersion: "0.1",
      contractVersion: "0.1",
      kind: "virtualization_guest_task_status_result",
      requestId: request.requestId,
      nonce: request.nonce,
      guestIdentity: { ...request.guestIdentity },
      originalRequestId: request.originalRequestId,
      originalNonce: request.originalNonce,
      originalRequestDigest: request.originalRequestDigest,
      statusRequestDigest: virtualizationGuestStatusRequestDigest(request),
      ...result,
      outputPolicy: "broker-redacted-v1"
    };
  }

  async close(): Promise<void> {
    if (this.closePromise !== undefined) return this.closePromise;
    this.closed = true;
    this.closePromise = (async () => {
      for (const controller of this.activeControllers) controller.abort();
      let firstError: unknown;
      try { await this.adapter.close?.(); }
      catch (error) { firstError = error; }
      await Promise.allSettled([...this.activeExecutions]);
      if (firstError !== undefined) {
        // The executor remains fenced, but a host lifecycle retry must be able
        // to repeat a failed adapter cleanup after active work has drained.
        this.closePromise = undefined;
        throw firstError;
      }
    })();
    return this.closePromise;
  }

  private cancelled(request: UnsignedVirtualizationGuestRequest): UnsignedVirtualizationGuestResponse {
    const result = this.executionResult("cancelled", "CANCELLED", null, "Guest task was cancelled before execution");
    return {
      schemaVersion: "0.1",
      protocolVersion: "0.1",
      contractVersion: "0.1",
      kind: "virtualization_guest_task_result",
      requestId: request.requestId,
      nonce: request.nonce,
      guestIdentity: { ...request.guestIdentity },
      requestDigest: virtualizationGuestRequestDigest(request),
      ...result,
      outputPolicy: "broker-redacted-v1"
    };
  }

  private unknownResult(): VirtualizationGuestExecutionResult {
    return this.executionResult("unknown", "UNKNOWN_OUTCOME", null, "guest task outcome could not be established");
  }

  private resultForError(error: BrokerError): VirtualizationGuestExecutionResult {
    switch (error.errorClass) {
      case "CANCELLED": return this.executionResult("cancelled", "CANCELLED", null, "guest task was cancelled");
      case "TIMEOUT": return this.executionResult("timed_out", "TIMEOUT", null, "guest task exceeded its execution budget");
      case "OUTPUT_LIMIT": return this.executionResult("failed", "OUTPUT_LIMIT", null, "guest task exceeded its output budget");
      case "VERIFICATION_FAILED": return this.executionResult("failed", "VERIFICATION_FAILED", null, "guest task verification failed");
      case "EXECUTION_FAILED": return this.executionResult("failed", "EXECUTION_FAILED", null, "guest task execution failed");
      default: return this.unknownResult();
    }
  }

  private response(
    request: UnsignedVirtualizationGuestRequest,
    result: VirtualizationGuestExecutionResult
  ): UnsignedVirtualizationGuestResponse {
    return {
      schemaVersion: "0.1",
      protocolVersion: "0.1",
      contractVersion: "0.1",
      kind: "virtualization_guest_task_result",
      requestId: request.requestId,
      nonce: request.nonce,
      guestIdentity: { ...request.guestIdentity },
      requestDigest: virtualizationGuestRequestDigest(request),
      ...result,
      outputPolicy: "broker-redacted-v1"
    };
  }

  private executionResult(
    state: VirtualizationGuestTaskState,
    resultClass: VirtualizationGuestResultClass,
    exitCode: number | null,
    summary: string
  ): VirtualizationGuestExecutionResult {
    return {
      state,
      resultClass,
      exitCode,
      stdout: "",
      stderr: "",
      truncated: false,
      durationMs: 0,
      verification: { status: state === "completed" ? "verified" : state === "unknown" ? "unknown" : "failed", summary }
    };
  }
}

/**
 * A concrete guest process adapter backed by ProcessSupervisor. The explicit
 * gates are required because ProcessSupervisor supplies process bounds, while
 * guest-private filesystem/network/credential isolation comes from the
 * reviewed Virtualization image and its independent host evidence.
 */
export class VirtualizationGuestProcessExecutor implements VirtualizationGuestProcessAdapter {
  readonly available: boolean;
  private readonly supervisor: Pick<ProcessSupervisor, "run"> & { close?: () => Promise<void> };

  constructor(options: {
    enabled?: boolean;
    hostEvidenceAccepted?: boolean;
    supervisor?: Pick<ProcessSupervisor, "run"> & { close?: () => Promise<void> };
    supervisorOptions?: ProcessSupervisorOptions;
  } = {}) {
    this.supervisor = options.supervisor ?? new ProcessSupervisor(options.supervisorOptions);
    this.available = options.enabled === true && options.hostEvidenceAccepted === true && process.platform === "darwin";
  }

  async run(input: VirtualizationGuestTaskExecutionInput): Promise<VirtualizationGuestExecutionResult> {
    if (!this.available) throw new BrokerError("POLICY_DENIED", "Guest process isolation evidence is not enabled");
    if (input.signal.aborted) {
      return {
        state: "cancelled",
        resultClass: "CANCELLED",
        exitCode: null,
        stdout: "",
        stderr: "",
        truncated: false,
        durationMs: 0,
        verification: { status: "failed", summary: "Guest task was cancelled before process start" }
      };
    }
    const result = await this.supervisor.run({
      executable: input.profile.executable,
      args: [...input.profile.args],
      cwd: input.profile.cwd,
      ...(input.profile.environment === undefined ? {} : { environment: input.profile.environment }),
      timeoutMs: input.timeoutMs,
      outputCapBytes: input.outputCapBytes,
      requireCleanExitProof: true,
      shouldCancel: () => input.signal.aborted
    });
    return mapProcessResult(result);
  }

  close(): Promise<void> {
    return this.supervisor.close?.() ?? Promise.resolve();
  }
}

export function virtualizationGuestProfileDigest(profile: VirtualizationGuestProfileDigestInput): string {
  return sha256(canonicalJson({
    schemaVersion: "0.1",
    profile: profile.profile,
    sandboxProfile: profile.sandboxProfile,
    filesystemRoots: [...profile.filesystemRoots],
    networkPolicy: profile.networkPolicy,
    networkAllowlist: [...(profile.networkAllowlist ?? [])],
    credentialPolicy: profile.credentialPolicy,
    processTreePolicy: profile.processTreePolicy,
    verificationStrategy: profile.verificationStrategy
  }));
}

export function virtualizationGuestTaskDigest(
  profile: VirtualizationGuestTaskDigestInput,
  profileDigest = virtualizationGuestProfileDigest(profile)
): string {
  return sha256(canonicalJson({
    schemaVersion: "0.1",
    profileDigest,
    process: {
      executable: profile.executable,
      args: [...profile.args],
      cwd: profile.cwd,
      environment: { ...(profile.environment ?? {}) },
      timeoutMs: profile.timeoutMs,
      outputCapBytes: profile.outputCapBytes
    }
  }));
}

function validateProfileShape(profile: VirtualizationGuestTaskProfile): void {
  if (!isPlainDataRecord(profile) || !hasAllowedKeys(profile, PROFILE_KEYS) ||
      profile.schemaVersion !== "0.1" || !PROFILE_PATTERN.test(profile.profile) ||
      !PROFILE_PATTERN.test(profile.sandboxProfile) || !isCanonicalAbsolutePath(profile.executable) ||
      FORBIDDEN_EXECUTABLES.has(profile.executable) || !isDenseStringArray(profile.args, MAX_ARGUMENTS) ||
      !isCanonicalAbsolutePath(profile.cwd) || !isDenseStringArray(profile.filesystemRoots, MAX_FILESYSTEM_ROOTS) || profile.filesystemRoots.length < 1 ||
      profile.filesystemRoots.some((root) => !isCanonicalAbsolutePath(root) || FORBIDDEN_FILESYSTEM_ROOTS.has(root)) ||
      profile.credentialPolicy !== "none" || (profile.networkPolicy !== "none" && profile.networkPolicy !== "allowlist") ||
      profile.processTreePolicy !== "single_process" && profile.processTreePolicy !== "owned_group" ||
      !Number.isSafeInteger(profile.timeoutMs) || profile.timeoutMs < 1 || profile.timeoutMs > MAX_TIMEOUT_MS ||
      !Number.isSafeInteger(profile.outputCapBytes) || profile.outputCapBytes < 1 || profile.outputCapBytes > MAX_OUTPUT_BYTES ||
      profile.verificationStrategy !== "exit_status_and_declared_task_verification" || typeof profile.enabled !== "boolean" ||
      (profile.environment !== undefined && !isPlainDataRecord(profile.environment)) ||
      (profile.networkAllowlist !== undefined && !isDenseStringArray(profile.networkAllowlist, MAX_NETWORK_DESTINATIONS))) {
    throw new Error("Guest task profile manifest is malformed");
  }
  validateArguments(profile.args);
  validateEnvironment(profile.environment ?? {});
  const networkAllowlist = profile.networkAllowlist ?? [];
  if (profile.networkPolicy === "none" && networkAllowlist.length !== 0) {
    throw new Error("No-network guest profile cannot declare destinations");
  }
  if (profile.networkPolicy === "allowlist" && (networkAllowlist.length < 1 ||
      networkAllowlist.some((destination) => parseTaskNetworkDestination(destination) === null))) {
    throw new Error("Guest profile network allowlist is malformed");
  }
}

async function assertGuestProfileTargets(profile: VirtualizationGuestTaskProfile): Promise<void> {
  await assertCanonicalExecutable(profile.executable);
  await assertCanonicalDirectory(profile.cwd);
  const roots = await Promise.all(profile.filesystemRoots.map(assertCanonicalDirectory));
  if (!roots.some((root) => isContained(root, profile.cwd))) {
    throw new BrokerError("POLICY_DENIED", "Guest task cwd is outside the startup filesystem roots");
  }
}

async function assertCanonicalExecutable(path: string): Promise<void> {
  try {
    const stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || (stat.mode & 0o111) === 0 || await realpath(path) !== path) {
      throw new BrokerError("POLICY_DENIED", "Guest task executable is not a canonical regular executable");
    }
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Guest task executable was not found");
  }
}

async function assertCanonicalDirectory(path: string): Promise<string> {
  try {
    const stat = await lstat(path);
    if (!stat.isDirectory() || stat.isSymbolicLink() || await realpath(path) !== path) {
      throw new BrokerError("POLICY_DENIED", "Guest task directory is not canonical");
    }
    return path;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Guest task directory was not found");
  }
}

function validateGuestRequestShape(request: UnsignedVirtualizationGuestRequest): void {
  if (!isPlainDataRecord(request) || !hasAllowedKeys(request, [
    "schemaVersion", "protocolVersion", "contractVersion", "kind", "requestId", "nonce", "timestampMs",
    "expiresAtMs", "guestIdentity", "sandboxProfile", "profileDigest", "taskDigest", "processTreePolicy",
    "timeoutMs", "outputCapBytes", "operation"
  ]) ||
      !SHA256_PATTERN.test(request.profileDigest) || !SHA256_PATTERN.test(request.taskDigest) ||
      !PROFILE_PATTERN.test(request.sandboxProfile)) {
    throw new BrokerError("PRECONDITION_FAILED", "Guest task request digest binding is malformed");
  }
}

function hasAllowedKeys(value: Record<string, unknown>, allowed: ReadonlySet<string> | readonly string[]): boolean {
  const allowedSet = allowed instanceof Set ? allowed : new Set(allowed);
  return Object.keys(value).every((key) => allowedSet.has(key));
}

function isDenseStringArray(value: unknown, maxLength: number): value is readonly string[] {
  if (!Array.isArray(value) || value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0 ||
      Object.keys(value).length !== value.length || Object.getOwnPropertyNames(value).length !== value.length + 1) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor) || typeof descriptor.value !== "string") return false;
  }
  return true;
}

function validateArguments(args: readonly string[]): void {
  if (args.length > MAX_ARGUMENTS) throw new Error("Guest task arguments exceed the supported count");
  let bytes = 0;
  for (const argument of args) {
    if (typeof argument !== "string" || argument.length > 4_096 || argument.includes("\0") || argument.includes("\n")) {
      throw new Error("Guest task argument is malformed");
    }
    bytes += Buffer.byteLength(argument, "utf8");
    if (bytes > MAX_ARGUMENT_BYTES) throw new Error("Guest task arguments exceed the supported size");
  }
}

function validateEnvironment(environment: Readonly<Record<string, string>>): void {
  const entries = Object.entries(environment);
  if (entries.length > MAX_ENVIRONMENT_KEYS) throw new Error("Guest task environment is too large");
  let bytes = 0;
  for (const [key, value] of entries) {
    if (!isSafeProcessEnvironmentKey(key) || typeof value !== "string" || value.includes("\0") || value.includes("\n") || value.length > 4_096) {
      throw new Error("Guest task environment contains an unsafe entry");
    }
    bytes += Buffer.byteLength(key, "utf8") + Buffer.byteLength(value, "utf8") + 2;
    if (bytes > MAX_ENVIRONMENT_BYTES) throw new Error("Guest task environment is too large");
  }
}

function cloneProfile(profile: VirtualizationGuestTaskProfile): VirtualizationGuestTaskProfile {
  return {
    ...profile,
    args: [...profile.args],
    ...(profile.environment === undefined ? {} : { environment: { ...profile.environment } }),
    filesystemRoots: [...profile.filesystemRoots],
    ...(profile.networkAllowlist === undefined ? {} : { networkAllowlist: [...profile.networkAllowlist] })
  };
}

function mapProcessResult(result: ProcessExecutionResult): VirtualizationGuestExecutionResult {
  const verificationStatus: VirtualizationGuestVerificationStatus = result.resultClass === "SUCCEEDED"
    ? "verified" : result.resultClass === "UNKNOWN_OUTCOME" ? "unknown" : "failed";
  return {
    state: result.state,
    resultClass: result.resultClass,
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    truncated: result.truncated,
    durationMs: result.durationMs,
    verification: {
      status: verificationStatus,
      summary: result.resultClass === "SUCCEEDED" ? "guest process exited successfully" : "guest process did not satisfy execution verification"
    }
  };
}

/**
 * Guest output crosses an authenticated transport before the host Broker gets
 * a chance to persist it. Apply the same bounded log redaction policy here so
 * a successful response cannot carry a credential-like value in clear text.
 * The adapter's `truncated` bit is preserved: redaction may shorten a stream
 * for transport safety, but it does not change the task's execution result.
 */
function redactGuestExecutionResult(
  value: VirtualizationGuestExecutionResult,
  outputCapBytes: number
): VirtualizationGuestExecutionResult {
  const streamCap = Math.max(1, Math.floor(outputCapBytes / 2));
  const stdout = redactBoundedText(value.stdout, streamCap);
  const stderr = redactBoundedText(value.stderr, streamCap);
  const summary = value.verification.summary === undefined
    ? undefined
    : redactBoundedText(value.verification.summary, 512).text;
  return {
    ...value,
    stdout: stdout.text,
    stderr: stderr.text,
    verification: {
      ...value.verification,
      ...(summary === undefined ? {} : { summary })
    }
  };
}

function validateGuestExecutionResult(value: VirtualizationGuestExecutionResult, outputCapBytes: number): VirtualizationGuestExecutionResult {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      !(["completed", "failed", "cancelled", "timed_out", "unknown"] as readonly string[]).includes(value.state) ||
      !(["SUCCEEDED", "EXECUTION_FAILED", "CANCELLED", "TIMEOUT", "OUTPUT_LIMIT", "VERIFICATION_FAILED", "UNKNOWN_OUTCOME"] as readonly string[]).includes(value.resultClass) ||
      (value.exitCode !== null && (!Number.isSafeInteger(value.exitCode) || value.exitCode < -1 || value.exitCode > 255)) ||
      typeof value.stdout !== "string" || typeof value.stderr !== "string" || typeof value.truncated !== "boolean" ||
      !Number.isSafeInteger(value.durationMs) || value.durationMs < 0 || value.durationMs > MAX_TIMEOUT_MS * 2 ||
      value.verification === null || typeof value.verification !== "object" ||
      !(["verified", "failed", "unknown", "not_run"] as readonly string[]).includes(value.verification.status)) {
    throw new BrokerError("EXECUTION_FAILED", "Guest process adapter returned a malformed result");
  }
  if (Buffer.byteLength(value.stdout, "utf8") + Buffer.byteLength(value.stderr, "utf8") > outputCapBytes ||
      Buffer.byteLength(value.stdout, "utf8") + Buffer.byteLength(value.stderr, "utf8") > MAX_OUTPUT_BYTES ||
      (value.verification.summary !== undefined && (typeof value.verification.summary !== "string" || value.verification.summary.length > 512))) {
    throw new BrokerError("OUTPUT_LIMIT", "Guest process adapter exceeded the output budget");
  }
  if ((value.resultClass === "SUCCEEDED" && (value.state !== "completed" || value.verification.status !== "verified")) ||
      (value.resultClass === "CANCELLED" && value.state !== "cancelled") ||
      (value.resultClass === "TIMEOUT" && value.state !== "timed_out") ||
      (value.resultClass === "UNKNOWN_OUTCOME" && value.state !== "unknown")) {
    throw new BrokerError("VERIFICATION_FAILED", "Guest process adapter result state is inconsistent");
  }
  return value;
}

class GuestExecutionLedger {
  private readonly entries = new Map<string, VirtualizationGuestExecutionResult>();
  private readonly maxEntries = 4096;

  start(request: UnsignedVirtualizationGuestRequest): void {
    const key = this.key(request.requestId, request.nonce, virtualizationGuestRequestDigest(request));
    if (this.entries.size >= this.maxEntries && !this.entries.has(key)) {
      const first = this.entries.keys().next().value;
      if (typeof first === "string") this.entries.delete(first);
    }
    this.entries.set(key, {
      state: "unknown",
      resultClass: "UNKNOWN_OUTCOME",
      exitCode: null,
      stdout: "",
      stderr: "",
      truncated: false,
      durationMs: 0,
      verification: { status: "unknown", summary: "guest task is still executing or its outcome is not yet known" }
    });
  }

  complete(request: UnsignedVirtualizationGuestRequest, result: VirtualizationGuestExecutionResult): void {
    this.entries.set(this.key(request.requestId, request.nonce, virtualizationGuestRequestDigest(request)), cloneResult(result));
  }

  fail(request: UnsignedVirtualizationGuestRequest, error: BrokerError): void {
    this.complete(request, {
      state: "failed",
      resultClass: error.errorClass === "CONFLICT" ? "EXECUTION_FAILED" : "VERIFICATION_FAILED",
      exitCode: null,
      stdout: "",
      stderr: "",
      truncated: false,
      durationMs: 0,
      verification: { status: "failed", summary: "guest task admission failed" }
    });
  }

  lookup(request: UnsignedVirtualizationGuestStatusRequest): VirtualizationGuestExecutionResult {
    const result = this.entries.get(this.key(request.originalRequestId, request.originalNonce, request.originalRequestDigest));
    if (result !== undefined && Buffer.byteLength(result.stdout, "utf8") + Buffer.byteLength(result.stderr, "utf8") > request.outputCapBytes) {
      throw new BrokerError("OUTPUT_LIMIT", "Guest task status exceeds the requested output budget");
    }
    return result === undefined ? {
      state: "unknown",
      resultClass: "UNKNOWN_OUTCOME",
      exitCode: null,
      stdout: "",
      stderr: "",
      truncated: false,
      durationMs: 0,
      verification: { status: "unknown", summary: "guest task outcome is not present in the bounded ledger" }
    } : cloneResult(result);
  }

  private key(requestId: string, nonce: string, digest: string): string {
    return `${requestId}\0${nonce}\0${digest}`;
  }
}

function cloneResult(result: VirtualizationGuestExecutionResult): VirtualizationGuestExecutionResult {
  return {
    ...result,
    verification: { ...result.verification }
  };
}

function isCanonicalAbsolutePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096 && isAbsolute(value) &&
    resolve(value) === value && !value.includes("\0") && !value.includes("\n") && !value.includes("\r");
}

function isContained(root: string, target: string): boolean {
  const child = relative(root, target);
  return child === "" || (!child.startsWith(`..${sep}`) && child !== ".." && !isAbsolute(child));
}
