import { lstat, realpath } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import type { ProcessExecutionRequest } from "./process-supervisor.js";

const PROFILE_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const MAX_PROFILE_ARGUMENTS = 64;
const MAX_ARGUMENT_LENGTH = 1_024;
const MAX_ARGUMENT_BYTES = 32 * 1024;
const MAX_ENVIRONMENT_KEYS = 32;
const MAX_ENVIRONMENT_BYTES = 16 * 1024;
const MAX_TIMEOUT_MS = 600_000;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const SAFE_ENVIRONMENT_KEY = /^[A-Z_][A-Z0-9_]{0,63}$/u;
const SECRET_ENVIRONMENT_KEY = /(?:API|AUTH|COOKIE|CREDENTIAL|KEY|PASSWORD|PASSWD|SECRET|TOKEN|AWS|GITHUB|OPENAI|SSH)/iu;

export type TaskNetworkPolicy = "none" | "allowlist";
export type TaskProcessTreePolicy = "single_process" | "owned_group";

export interface TaskProfile {
  schemaVersion: "0.1";
  profile: string;
  executable: string;
  fixedArgs?: readonly string[];
  allowedCwdRoots: readonly string[];
  allowedArgumentPattern?: string;
  maxArguments?: number;
  environment?: Readonly<Record<string, string>>;
  filesystemRoots: readonly string[];
  networkPolicy: TaskNetworkPolicy;
  networkAllowlist?: readonly string[];
  /** Defaults to single_process; owned_group requires separate process-tree evidence. */
  processTreePolicy?: TaskProcessTreePolicy;
  sandboxProfile: string;
  timeoutMs: number;
  outputCapBytes: number;
  verificationStrategy: "exit_status_and_declared_task_verification";
  enabled: boolean;
}

export interface TaskRunRequest {
  profile: string;
  cwd: string;
  args?: readonly string[];
  asynchronous?: boolean;
}

export function validateTaskRunArguments(argumentsValue: Readonly<Record<string, unknown>>): TaskRunRequest {
  const keys = Object.keys(argumentsValue);
  if (keys.some((key) => !["profile", "cwd", "args", "async"].includes(key)) ||
      typeof argumentsValue.profile !== "string" || !PROFILE_ID_PATTERN.test(argumentsValue.profile) ||
      typeof argumentsValue.cwd !== "string" || argumentsValue.cwd.length < 1 || argumentsValue.cwd.length > 4_096 ||
      argumentsValue.cwd.includes("\0") ||
      (argumentsValue.args !== undefined && (!Array.isArray(argumentsValue.args) || argumentsValue.args.some((value) => typeof value !== "string"))) ||
      (argumentsValue.async !== undefined && typeof argumentsValue.async !== "boolean")) {
    throw new BrokerError("PRECONDITION_FAILED", "Task run arguments are malformed");
  }
  const args = argumentsValue.args as readonly string[] | undefined;
  if (args && args.some((argument) => argument.length > MAX_ARGUMENT_LENGTH || argument.includes("\0") || argument.includes("\n"))) {
    throw new BrokerError("PRECONDITION_FAILED", "Task argument is malformed");
  }
  if (argumentsValue.async === true) {
    throw new BrokerError("UNSUPPORTED_CAPABILITY", "Asynchronous task dispatch is not enabled");
  }
  return {
    profile: argumentsValue.profile,
    cwd: argumentsValue.cwd,
    ...(args === undefined ? {} : { args }),
    asynchronous: argumentsValue.async ?? false
  };
}

export interface ResolvedTaskProfile {
  profile: string;
  cwd: string;
  process: ProcessExecutionRequest;
  filesystemRoots: readonly string[];
  networkPolicy: TaskNetworkPolicy;
  networkAllowlist: readonly string[];
  processTreePolicy: TaskProcessTreePolicy;
  sandboxProfile: string;
  verificationStrategy: "exit_status_and_declared_task_verification";
}

/**
 * Resolves a named task to Broker-owned executable, environment, and limits.
 * This class deliberately does not execute a process or select a sandbox.
 */
export class TaskProfileRegistry {
  private readonly profiles = new Map<string, TaskProfile>();
  private readonly argumentPatterns = new Map<string, RegExp>();

  constructor(profiles: readonly TaskProfile[]) {
    for (const profile of profiles) {
      validateProfileDocument(profile);
      if (this.profiles.has(profile.profile)) throw new Error(`Task profile is duplicated: ${profile.profile}`);
      this.profiles.set(profile.profile, cloneProfile(profile));
      this.argumentPatterns.set(profile.profile, new RegExp(profile.allowedArgumentPattern ?? "a^", "u"));
    }
  }

  names(): readonly string[] {
    return [...this.profiles.keys()].sort();
  }

  async resolve(request: TaskRunRequest): Promise<ResolvedTaskProfile> {
    if (request === null || typeof request !== "object" || Array.isArray(request) ||
        Object.keys(request as unknown as Record<string, unknown>).some((key) => !["profile", "cwd", "args", "asynchronous"].includes(key)) ||
        typeof request.profile !== "string" || !PROFILE_ID_PATTERN.test(request.profile)) {
      throw new BrokerError("PRECONDITION_FAILED", "Task profile request is malformed");
    }
    const profile = this.profiles.get(request.profile);
    if (!profile) throw new BrokerError("TARGET_NOT_FOUND", "Named task profile was not found");
    if (!profile.enabled) throw new BrokerError("POLICY_DENIED", "Named task profile is disabled");
    if (!isCanonicalAbsolutePath(request.cwd)) {
      throw new BrokerError("PRECONDITION_FAILED", "Task cwd must be a canonical absolute path");
    }
    const cwd = await validateCanonicalDirectory(request.cwd);
    const allowedRoot = await this.findAllowedCwdRoot(profile.allowedCwdRoots, cwd);
    if (!allowedRoot) throw new BrokerError("POLICY_DENIED", "Task cwd is outside the profile roots");

    const executable = await validateCanonicalExecutable(profile.executable);
    for (const root of profile.filesystemRoots) await validateCanonicalDirectory(root);
    const requestedArgs = request.args ?? [];
    const argumentPattern = this.argumentPatterns.get(profile.profile)!;
    validateArguments(requestedArgs, profile.maxArguments ?? 0, argumentPattern);
    const args = [...(profile.fixedArgs ?? []), ...requestedArgs];
    validateTotalArguments(args);

    const environment = { ...(profile.environment ?? {}) };
    return {
      profile: profile.profile,
      cwd,
      process: { executable, args, cwd, environment, timeoutMs: profile.timeoutMs, outputCapBytes: profile.outputCapBytes },
      filesystemRoots: [...profile.filesystemRoots],
      networkPolicy: profile.networkPolicy,
      networkAllowlist: [...(profile.networkAllowlist ?? [])],
      processTreePolicy: profile.processTreePolicy ?? "single_process",
      sandboxProfile: profile.sandboxProfile,
      verificationStrategy: profile.verificationStrategy
    };
  }

  private async findAllowedCwdRoot(roots: readonly string[], cwd: string): Promise<string | undefined> {
    for (const root of roots) {
      const canonicalRoot = await validateCanonicalDirectory(root);
      if (isContained(canonicalRoot, cwd)) return canonicalRoot;
    }
    return undefined;
  }
}

function validateProfileDocument(profile: TaskProfile): void {
  if (profile === null || typeof profile !== "object" || Array.isArray(profile) ||
      profile.schemaVersion !== "0.1" ||
      typeof profile.profile !== "string" || !PROFILE_ID_PATTERN.test(profile.profile) ||
      typeof profile.executable !== "string" || !isCanonicalAbsolutePath(profile.executable) ||
      !Array.isArray(profile.allowedCwdRoots) || profile.allowedCwdRoots.length === 0 ||
      profile.allowedCwdRoots.some((root) => typeof root !== "string" || !isCanonicalAbsolutePath(root)) ||
      !Array.isArray(profile.filesystemRoots) || profile.filesystemRoots.some((root) => typeof root !== "string" || !isCanonicalAbsolutePath(root)) ||
      profile.filesystemRoots.length === 0 ||
      typeof profile.sandboxProfile !== "string" || !PROFILE_ID_PATTERN.test(profile.sandboxProfile) ||
      !Number.isSafeInteger(profile.timeoutMs) || profile.timeoutMs < 1 || profile.timeoutMs > MAX_TIMEOUT_MS ||
      !Number.isSafeInteger(profile.outputCapBytes) || profile.outputCapBytes < 1 || profile.outputCapBytes > MAX_OUTPUT_BYTES ||
      profile.verificationStrategy !== "exit_status_and_declared_task_verification" ||
      typeof profile.enabled !== "boolean" ||
      (profile.fixedArgs !== undefined && !Array.isArray(profile.fixedArgs)) ||
      (profile.environment !== undefined && !isPlainRecord(profile.environment)) ||
      (profile.networkAllowlist !== undefined && !Array.isArray(profile.networkAllowlist)) ||
      (profile.processTreePolicy !== undefined && profile.processTreePolicy !== "single_process" && profile.processTreePolicy !== "owned_group") ||
      (profile.networkPolicy !== "none" && profile.networkPolicy !== "allowlist")) {
    throw new Error("Task profile document is malformed");
  }
  validateArguments(profile.fixedArgs ?? [], MAX_PROFILE_ARGUMENTS, /[\s\S]*/u, true);
  if (profile.maxArguments !== undefined &&
      (!Number.isSafeInteger(profile.maxArguments) || profile.maxArguments < 0 || profile.maxArguments > MAX_PROFILE_ARGUMENTS)) {
    throw new Error("Task profile argument limit is invalid");
  }
  if (profile.allowedArgumentPattern !== undefined && typeof profile.allowedArgumentPattern !== "string") {
    throw new Error("Task profile argument pattern is invalid");
  }
  if (profile.allowedArgumentPattern !== undefined) {
    if (!profile.allowedArgumentPattern.startsWith("^") || !profile.allowedArgumentPattern.endsWith("$")) {
      throw new Error("Task profile argument pattern must be anchored");
    }
    try { new RegExp(profile.allowedArgumentPattern, "u"); }
    catch { throw new Error("Task profile argument pattern is invalid"); }
  }
  const environment = profile.environment ?? {};
  const environmentEntries = Object.entries(environment);
  if (environmentEntries.length > MAX_ENVIRONMENT_KEYS) throw new Error("Task profile environment is too large");
  let environmentBytes = 0;
  for (const [key, value] of environmentEntries) {
    if (!SAFE_ENVIRONMENT_KEY.test(key) || SECRET_ENVIRONMENT_KEY.test(key) || typeof value !== "string" ||
        value.includes("\0") || value.includes("\n") || value.length > 4_096) {
      throw new Error("Task profile environment contains an unsafe entry");
    }
    environmentBytes += Buffer.byteLength(key, "utf8") + Buffer.byteLength(value, "utf8") + 2;
    if (environmentBytes > MAX_ENVIRONMENT_BYTES) throw new Error("Task profile environment is too large");
  }
  const networkAllowlist = profile.networkAllowlist ?? [];
  if (profile.networkPolicy === "none" && networkAllowlist.length !== 0) {
    throw new Error("A no-network task profile cannot declare network destinations");
  }
  if (networkAllowlist.some((destination) => typeof destination !== "string" ||
      destination.length < 1 || destination.length > 256 || destination.includes("\0") || destination.includes("*") || destination.includes("/"))) {
    throw new Error("Task profile network allowlist is malformed");
  }
}

function cloneProfile(profile: TaskProfile): TaskProfile {
  return {
    ...profile,
    ...(profile.fixedArgs ? { fixedArgs: [...profile.fixedArgs] } : {}),
    allowedCwdRoots: [...profile.allowedCwdRoots],
    ...(profile.environment ? { environment: { ...profile.environment } } : {}),
    filesystemRoots: [...profile.filesystemRoots],
    ...(profile.networkAllowlist ? { networkAllowlist: [...profile.networkAllowlist] } : {})
  };
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validateArguments(
  args: readonly string[],
  maxArguments: number,
  pattern: RegExp,
  allowFixedArguments = false
): void {
  if (!Array.isArray(args) || args.length > maxArguments || args.length > MAX_PROFILE_ARGUMENTS) {
    throw new Error(allowFixedArguments ? "Task profile fixed arguments exceed the limit" : "Task arguments exceed the profile limit");
  }
  let bytes = 0;
  for (const argument of args) {
    if (typeof argument !== "string" || argument.length > MAX_ARGUMENT_LENGTH || argument.includes("\0") || argument.includes("\n")) {
      throw new Error(allowFixedArguments ? "Task profile fixed argument is malformed" : "Task argument is malformed");
    }
    pattern.lastIndex = 0;
    if (!pattern.test(argument)) {
      throw new Error(allowFixedArguments ? "Task profile fixed argument is not allowlisted" : "Task argument is not allowlisted by the profile");
    }
    bytes += Buffer.byteLength(argument, "utf8");
    if (bytes > MAX_ARGUMENT_BYTES) throw new Error("Task arguments exceed the byte limit");
  }
}

function validateTotalArguments(args: readonly string[]): void {
  if (args.length > 128 || args.reduce((sum, argument) => sum + Buffer.byteLength(argument, "utf8"), 0) > 64 * 1024) {
    throw new BrokerError("PRECONDITION_FAILED", "Task arguments exceed the supported size");
  }
}

async function validateCanonicalExecutable(path: string): Promise<string> {
  try {
    const stat = await lstat(path);
    if (stat.isSymbolicLink() || !stat.isFile() || (stat.mode & 0o111) === 0) {
      throw new BrokerError("POLICY_DENIED", "Task executable must be a regular non-symlink executable");
    }
    const canonical = await realpath(path);
    if (canonical !== path) throw new BrokerError("POLICY_DENIED", "Task executable must be canonical");
    return canonical;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Task executable was not found");
  }
}

async function validateCanonicalDirectory(path: string): Promise<string> {
  try {
    const stat = await lstat(path);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      throw new BrokerError("POLICY_DENIED", "Task directory must be a regular non-symlink directory");
    }
    const canonical = await realpath(path);
    if (canonical !== path) throw new BrokerError("POLICY_DENIED", "Task directory must be canonical");
    return canonical;
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Task directory was not found");
  }
}

function isCanonicalAbsolutePath(path: string): boolean {
  return typeof path === "string" && path.length > 0 && path.length <= 4_096 &&
    isAbsolute(path) && resolve(path) === path && !path.includes("\0") && !path.includes("\n");
}

function isContained(root: string, target: string): boolean {
  const child = relative(root, target);
  return child === "" || (!child.startsWith(`..${sep}`) && child !== ".." && !isAbsolute(child));
}
