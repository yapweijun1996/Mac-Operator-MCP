import { lstat, readFile, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { captureProcessPathIdentity, type ProcessExecutionRequest } from "./process-supervisor.js";
import { isSafeProcessEnvironmentKey } from "./process-environment.js";
import { isPlainDataRecord } from "./plain-record.js";
import { assertArgumentsDoNotContainSecrets, containsSecretRepresentation } from "./secret-policy.js";

const PROFILE_ID_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const MAX_PROFILE_ARGUMENTS = 64;
const MAX_ARGUMENT_LENGTH = 1_024;
const MAX_ARGUMENT_BYTES = 32 * 1024;
const MAX_ENVIRONMENT_KEYS = 32;
const MAX_ENVIRONMENT_BYTES = 16 * 1024;
const MAX_TIMEOUT_MS = 600_000;
const MAX_OUTPUT_BYTES = 2 * 1024 * 1024;
const MAX_ARGUMENT_PATTERN_LENGTH = 256;
const MAX_PROFILE_PATHS = 32;
const MAX_NETWORK_DESTINATIONS = 32;
const MAX_SCRIPT_BYTES = 16 * 1024 * 1024;
const NETWORK_DESTINATION_PATTERN = /^(tcp|udp):\/\/(localhost|127\.0\.0\.1):(\d{1,5})$/u;

export type TaskNetworkPolicy = "none" | "allowlist";
export type TaskProcessTreePolicy = "single_process" | "owned_group";
/** Explicit task source shape for the future App Sandbox interpreter path. */
export type TaskExecutionKind = "binary" | "posix-sh-script";
/** Task credentials are intentionally unavailable until a separate broker-managed workflow exists. */
export type TaskCredentialPolicy = "none";

export interface TaskNetworkDestination {
  protocol: "tcp" | "udp";
  address: string;
  port: number;
}

export function parseTaskNetworkDestination(value: unknown): TaskNetworkDestination | null {
  if (typeof value !== "string" || value.length > 128) return null;
  const match = NETWORK_DESTINATION_PATTERN.exec(value);
  if (!match) return null;
  const protocol = match[1];
  const address = match[2];
  const portText = match[3];
  if (protocol === undefined || address === undefined || portText === undefined) return null;
  const port = Number(portText);
  if (port < 1 || port > 65_535) return null;
  return { protocol: protocol as "tcp" | "udp", address: "localhost", port };
}

export interface TaskProfile {
  schemaVersion: "0.1";
  profile: string;
  executable: string;
  /** Optional signed content identity for the profile-owned executable. */
  executableContentSha256?: string;
  /** A fixed Broker-owned script may be interpreted only by the fixed /bin/sh path. */
  executionKind?: TaskExecutionKind;
  scriptPath?: string;
  fixedArgs?: readonly string[];
  allowedCwdRoots: readonly string[];
  allowedArgumentPattern?: string;
  maxArguments?: number;
  environment?: Readonly<Record<string, string>>;
  filesystemRoots: readonly string[];
  networkPolicy: TaskNetworkPolicy;
  networkAllowlist?: readonly string[];
  /** Explicitly records that the child receives no Broker/user credentials. */
  credentialPolicy?: TaskCredentialPolicy;
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

export function validateTaskProfileRegistry(value: unknown): asserts value is TaskProfileRegistry {
  if (value === null || typeof value !== "object" || Array.isArray(value) ||
      typeof (value as { resolve?: unknown }).resolve !== "function" ||
      typeof (value as { names?: unknown }).names !== "function") {
    throw new Error("Task profile registry is malformed");
  }
}

export function validateTaskRunArguments(argumentsValue: unknown): TaskRunRequest {
  if (!isPlainDataRecord(argumentsValue) || !hasAllowedKeys(argumentsValue, ["profile", "cwd", "args", "async"])) {
    throw new BrokerError("PRECONDITION_FAILED", "Task run arguments are malformed");
  }
  const keys = Object.keys(argumentsValue);
  if (keys.some((key) => !["profile", "cwd", "args", "async"].includes(key)) ||
      typeof argumentsValue.profile !== "string" || !PROFILE_ID_PATTERN.test(argumentsValue.profile) ||
      typeof argumentsValue.cwd !== "string" || argumentsValue.cwd.length < 1 || argumentsValue.cwd.length > 4_096 ||
      argumentsValue.cwd.includes("\0") ||
      (argumentsValue.args !== undefined && !isStringArray(argumentsValue.args, MAX_PROFILE_ARGUMENTS)) ||
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
    ...(args === undefined ? {} : { args: [...args] }),
    asynchronous: argumentsValue.async ?? false
  };
}

export interface ResolvedTaskProfile {
  profile: string;
  cwd: string;
  executionKind?: TaskExecutionKind;
  scriptPath?: string;
  /** Broker-read UTF-8 snapshot; used only by the deny-fork stdin runner. */
  scriptContent?: string;
  scriptContentSha256?: string;
  process: ProcessExecutionRequest;
  filesystemRoots: readonly string[];
  networkPolicy: TaskNetworkPolicy;
  networkAllowlist: readonly string[];
  credentialPolicy: TaskCredentialPolicy;
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
    const safeRequest = snapshotTaskRunRequest(request);
    const profile = this.profiles.get(safeRequest.profile);
    if (!profile) throw new BrokerError("TARGET_NOT_FOUND", "Named task profile was not found");
    if (!profile.enabled) throw new BrokerError("POLICY_DENIED", "Named task profile is disabled");
    if (!isCanonicalAbsolutePath(safeRequest.cwd)) {
      throw new BrokerError("PRECONDITION_FAILED", "Task cwd must be a canonical absolute path");
    }
    const cwd = await validateCanonicalDirectory(safeRequest.cwd);
    const allowedRoot = await this.findAllowedCwdRoot(profile.allowedCwdRoots, cwd);
    if (!allowedRoot) throw new BrokerError("POLICY_DENIED", "Task cwd is outside the profile roots");

    const executable = await validateCanonicalExecutable(profile.executable);
    const executableIdentity = await captureProcessPathIdentity(executable, "executable");
    const executableContentSha256 = executableIdentity.contentSha256;
    if (executableContentSha256 === undefined ||
        (profile.executableContentSha256 !== undefined && profile.executableContentSha256 !== executableContentSha256)) {
      throw new BrokerError("POLICY_DENIED", "Task executable content identity does not match the profile");
    }
    const filesystemRoots = await Promise.all(profile.filesystemRoots.map((root) => validateCanonicalDirectory(root)));
    const executionKind = profile.executionKind ?? "binary";
    let scriptPath: string | undefined;
    let scriptContent: string | undefined;
    let scriptContentSha256: string | undefined;
    if (executionKind === "posix-sh-script") {
      if (profile.scriptPath === undefined || executable !== "/bin/sh") {
        throw new BrokerError("POLICY_DENIED", "A posix-sh task must bind the fixed /bin/sh interpreter and a script");
      }
      const script = await validateCanonicalScript(profile.scriptPath);
      if (!filesystemRoots.some((root) => isContained(root, script.path))) {
        throw new BrokerError("POLICY_DENIED", "Task script is outside the Broker-owned filesystem roots");
      }
      scriptPath = script.path;
      scriptContent = script.content;
      scriptContentSha256 = script.contentSha256;
    } else if (profile.scriptPath !== undefined) {
      throw new BrokerError("POLICY_DENIED", "A binary task cannot declare a script path");
    }
    const requestedArgs = safeRequest.args ?? [];
    const argumentPattern = this.argumentPatterns.get(profile.profile)!;
    validateArguments(requestedArgs, profile.maxArguments ?? 0, argumentPattern);
    const args = [...(profile.fixedArgs ?? []), ...requestedArgs];
    validateTotalArguments(args);
    assertArgumentsDoNotContainSecrets(args);

    const environment = { ...(profile.environment ?? {}) };
    return freezeResolvedTaskProfile({
      profile: profile.profile,
      cwd,
      process: {
        executable,
        expectedExecutableContentSha256: executableContentSha256,
        args,
        cwd,
        environment,
        timeoutMs: profile.timeoutMs,
        outputCapBytes: profile.outputCapBytes
      },
      ...(executionKind === "posix-sh-script"
        ? { executionKind, scriptPath: scriptPath!, scriptContent: scriptContent!, scriptContentSha256: scriptContentSha256! }
        : {}),
      filesystemRoots,
      networkPolicy: profile.networkPolicy,
      networkAllowlist: [...(profile.networkAllowlist ?? [])],
      credentialPolicy: profile.credentialPolicy ?? "none",
      processTreePolicy: profile.processTreePolicy ?? "single_process",
      sandboxProfile: profile.sandboxProfile,
      verificationStrategy: profile.verificationStrategy
    });
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
  if (!isPlainDataRecord(profile) ||
      !hasAllowedKeys(profile, [
        "schemaVersion", "profile", "executable", "executableContentSha256", "executionKind", "scriptPath", "fixedArgs", "allowedCwdRoots",
        "allowedArgumentPattern", "maxArguments", "environment", "filesystemRoots",
        "networkPolicy", "networkAllowlist", "credentialPolicy", "processTreePolicy",
        "sandboxProfile", "timeoutMs", "outputCapBytes", "verificationStrategy", "enabled"
      ]) ||
      profile.schemaVersion !== "0.1" ||
      typeof profile.profile !== "string" || !PROFILE_ID_PATTERN.test(profile.profile) ||
      typeof profile.executable !== "string" || !isCanonicalAbsolutePath(profile.executable) ||
      (profile.executableContentSha256 !== undefined && !/^[a-f0-9]{64}$/u.test(profile.executableContentSha256)) ||
      (profile.executionKind !== undefined && profile.executionKind !== "binary" && profile.executionKind !== "posix-sh-script") ||
      (profile.scriptPath !== undefined && !isCanonicalAbsolutePath(profile.scriptPath)) ||
      !isStringArray(profile.allowedCwdRoots, MAX_PROFILE_PATHS) || profile.allowedCwdRoots.length === 0 ||
      profile.allowedCwdRoots.some((root) => typeof root !== "string" || !isCanonicalAbsolutePath(root)) ||
      !isStringArray(profile.filesystemRoots, MAX_PROFILE_PATHS) || profile.filesystemRoots.some((root) => typeof root !== "string" || !isCanonicalAbsolutePath(root)) ||
      profile.filesystemRoots.length === 0 ||
      typeof profile.sandboxProfile !== "string" || !PROFILE_ID_PATTERN.test(profile.sandboxProfile) ||
      !Number.isSafeInteger(profile.timeoutMs) || profile.timeoutMs < 1 || profile.timeoutMs > MAX_TIMEOUT_MS ||
      !Number.isSafeInteger(profile.outputCapBytes) || profile.outputCapBytes < 1 || profile.outputCapBytes > MAX_OUTPUT_BYTES ||
      profile.verificationStrategy !== "exit_status_and_declared_task_verification" ||
      typeof profile.enabled !== "boolean" ||
      (profile.fixedArgs !== undefined && !isStringArray(profile.fixedArgs, MAX_PROFILE_ARGUMENTS)) ||
      (profile.environment !== undefined && !isPlainRecord(profile.environment)) ||
      (profile.networkAllowlist !== undefined && !isStringArray(profile.networkAllowlist, MAX_NETWORK_DESTINATIONS)) ||
      (profile.credentialPolicy !== undefined && profile.credentialPolicy !== "none") ||
      (profile.processTreePolicy !== undefined && profile.processTreePolicy !== "single_process" && profile.processTreePolicy !== "owned_group") ||
      (profile.networkPolicy !== "none" && profile.networkPolicy !== "allowlist")) {
    throw new Error("Task profile document is malformed");
  }
  if (!isStringArray(profile.allowedCwdRoots, MAX_PROFILE_PATHS) ||
      !isStringArray(profile.filesystemRoots, MAX_PROFILE_PATHS)) {
    throw new Error("Task profile paths are malformed");
  }
  const executionKind = profile.executionKind ?? "binary";
  if ((executionKind === "posix-sh-script" && (profile.executable !== "/bin/sh" || profile.scriptPath === undefined)) ||
      (executionKind === "binary" && profile.scriptPath !== undefined)) {
    throw new Error("Task profile script binding is malformed");
  }
  validateArguments(profile.fixedArgs ?? [], MAX_PROFILE_ARGUMENTS, /[\s\S]*/u, true);
  assertArgumentsDoNotContainSecrets(profile.fixedArgs ?? []);
  if (profile.maxArguments !== undefined &&
      (!Number.isSafeInteger(profile.maxArguments) || profile.maxArguments < 0 || profile.maxArguments > MAX_PROFILE_ARGUMENTS)) {
    throw new Error("Task profile argument limit is invalid");
  }
  if (profile.allowedArgumentPattern !== undefined && typeof profile.allowedArgumentPattern !== "string") {
    throw new Error("Task profile argument pattern is invalid");
  }
  if (profile.allowedArgumentPattern !== undefined) {
    validateArgumentPattern(profile.allowedArgumentPattern);
  }
  const environment = profile.environment ?? {};
  const environmentEntries = Object.entries(environment);
  if (environmentEntries.length > MAX_ENVIRONMENT_KEYS) throw new Error("Task profile environment is too large");
  let environmentBytes = 0;
  for (const [key, value] of environmentEntries) {
    if (!isSafeProcessEnvironmentKey(key) || typeof value !== "string" ||
        value.includes("\0") || value.includes("\n") || value.length > 4_096 ||
        containsSecretRepresentation(value)) {
      throw new Error("Task profile environment contains an unsafe entry");
    }
    environmentBytes += Buffer.byteLength(key, "utf8") + Buffer.byteLength(value, "utf8") + 2;
    if (environmentBytes > MAX_ENVIRONMENT_BYTES) throw new Error("Task profile environment is too large");
  }
  const networkAllowlist = profile.networkAllowlist ?? [];
  if (profile.networkPolicy === "none" && networkAllowlist.length !== 0) {
    throw new Error("A no-network task profile cannot declare network destinations");
  }
  if (profile.networkPolicy === "allowlist" && networkAllowlist.length === 0) {
    throw new Error("An allowlist task profile must declare destinations");
  }
  if (networkAllowlist.some((destination) => parseTaskNetworkDestination(destination) === null)) {
    throw new Error("Task profile network allowlist is malformed");
  }
}

/**
 * Restrict profile-owned argument matching to a bounded fragment with no
 * grouping, alternation, or backreferences. Arbitrary regular expressions
 * are a Broker denial-of-service surface because JavaScript RegExp has no
 * execution timeout.
 */
function validateArgumentPattern(pattern: string): void {
  if (pattern.length > MAX_ARGUMENT_PATTERN_LENGTH || pattern.includes("\0") || pattern.includes("\n")) {
    throw new Error("Task profile argument pattern is invalid");
  }
  if (!pattern.startsWith("^") || !pattern.endsWith("$")) {
    throw new Error("Task profile argument pattern must be anchored");
  }
  let index = 1;
  let canQuantify = false;
  let quantified = false;
  while (index < pattern.length - 1) {
    const character = pattern[index];
    if (character === undefined) throw new Error("Task profile argument pattern is invalid");
    if (character === "(" || character === ")" || character === "|") {
      throw new Error("Task profile argument pattern uses an unsupported construct");
    }
    if (character === "\\") {
      const escaped = pattern[index + 1];
      if (escaped === undefined || /[0-9]/u.test(escaped)) {
        throw new Error("Task profile argument pattern uses an unsupported construct");
      }
      index += 2;
      canQuantify = true;
      quantified = false;
      continue;
    }
    if (character === "[") {
      let closed = false;
      let classIndex = index + 1;
      for (; classIndex < pattern.length - 1; classIndex += 1) {
        const classCharacter = pattern[classIndex];
        if (classCharacter === undefined) break;
        if (classCharacter === "\\") {
          if (classIndex + 1 >= pattern.length - 1 || /[0-9]/u.test(pattern[classIndex + 1] ?? "")) {
            throw new Error("Task profile argument pattern uses an unsupported construct");
          }
          classIndex += 1;
          continue;
        }
        if (classCharacter === "[") {
          throw new Error("Task profile argument pattern uses an unsupported construct");
        }
        if (classCharacter === "]") {
          closed = true;
          break;
        }
      }
      if (!closed || classIndex === index + 1) throw new Error("Task profile argument pattern is invalid");
      index = classIndex + 1;
      canQuantify = true;
      quantified = false;
      continue;
    }
    if (character === "*" || character === "+" || character === "?") {
      if (!canQuantify || quantified) throw new Error("Task profile argument pattern is invalid");
      index += 1;
      canQuantify = false;
      quantified = true;
      continue;
    }
    if (character === "{") {
      if (!canQuantify || quantified) throw new Error("Task profile argument pattern is invalid");
      const quantifier = /^\{(\d{1,4})(,(\d{1,4})?)?\}/u.exec(pattern.slice(index));
      if (!quantifier) throw new Error("Task profile argument pattern is invalid");
      const minimum = Number(quantifier[1]);
      if (quantifier[2] !== undefined && quantifier[3] === undefined) {
        throw new Error("Task profile argument pattern is invalid");
      }
      const maximum = quantifier[3] === undefined ? minimum : Number(quantifier[3]);
      if (minimum > MAX_ARGUMENT_LENGTH || maximum > MAX_ARGUMENT_LENGTH || minimum > maximum) {
        throw new Error("Task profile argument pattern is invalid");
      }
      index += quantifier[0].length;
      canQuantify = false;
      quantified = true;
      continue;
    }
    if (character === "}" || character === "]" || character === "^") {
      throw new Error("Task profile argument pattern is invalid");
    }
    index += 1;
    canQuantify = true;
    quantified = false;
  }
  try { new RegExp(pattern, "u"); }
  catch { throw new Error("Task profile argument pattern is invalid"); }
}

function cloneProfile(profile: TaskProfile): TaskProfile {
  return {
    ...profile,
    ...(profile.fixedArgs ? { fixedArgs: [...profile.fixedArgs] } : {}),
    ...(profile.executionKind === undefined ? {} : { executionKind: profile.executionKind }),
    ...(profile.scriptPath === undefined ? {} : { scriptPath: profile.scriptPath }),
    allowedCwdRoots: [...profile.allowedCwdRoots],
    ...(profile.environment ? { environment: { ...profile.environment } } : {}),
    filesystemRoots: [...profile.filesystemRoots],
    ...(profile.networkAllowlist ? { networkAllowlist: [...profile.networkAllowlist] } : {})
  };
}

/**
 * The resolved profile is the authorization snapshot handed to an adapter.
 * Freeze the complete data graph so adapters cannot widen targets, budgets, or
 * environment after the Broker has completed admission.
 */
function freezeResolvedTaskProfile(profile: ResolvedTaskProfile): ResolvedTaskProfile {
  const seen = new Set<object>();
  const freeze = (value: unknown): void => {
    if (value === null || typeof value !== "object" || seen.has(value)) return;
    seen.add(value);
    if (Array.isArray(value)) {
      for (const item of value) freeze(item);
    } else {
      for (const child of Object.values(value)) freeze(child);
    }
    Object.freeze(value);
  };
  freeze(profile);
  return profile;
}

function snapshotTaskRunRequest(value: unknown): TaskRunRequest {
  if (!isPlainDataRecord(value) || !hasAllowedKeys(value, ["profile", "cwd", "args", "asynchronous"]) ||
      typeof value.profile !== "string" || !PROFILE_ID_PATTERN.test(value.profile) ||
      typeof value.cwd !== "string" || (value.args !== undefined && !isStringArray(value.args, MAX_PROFILE_ARGUMENTS)) ||
      (value.asynchronous !== undefined && typeof value.asynchronous !== "boolean")) {
    throw new BrokerError("PRECONDITION_FAILED", "Task profile request is malformed");
  }
  const snapshot: TaskRunRequest = { profile: value.profile, cwd: value.cwd };
  if (value.args !== undefined) snapshot.args = [...value.args];
  if (value.asynchronous !== undefined) snapshot.asynchronous = value.asynchronous;
  return snapshot;
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return isPlainDataRecord(value);
}

function hasAllowedKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
  const allowedSet = new Set(allowed);
  return Object.keys(value).every((key) => allowedSet.has(key));
}

function isStringArray(value: unknown, maxLength: number): value is readonly string[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0 ||
      Object.keys(value).length !== value.length || Object.getOwnPropertyNames(value).length !== value.length + 1) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor) || typeof descriptor.value !== "string") return false;
  }
  return true;
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

async function validateCanonicalScript(path: string): Promise<{ path: string; content: string; contentSha256: string }> {
  try {
    const before = await lstat(path);
    if (before.isSymbolicLink() || !before.isFile() || before.size > MAX_SCRIPT_BYTES) {
      throw new BrokerError("POLICY_DENIED", "Task script must be a bounded regular non-symlink file");
    }
    const canonical = await realpath(path);
    if (canonical !== path) throw new BrokerError("POLICY_DENIED", "Task script must be canonical");
    const content = await readFile(canonical);
    const after = await lstat(canonical);
    if (after.dev !== before.dev || after.ino !== before.ino || after.size !== before.size ||
        after.mtimeMs !== before.mtimeMs || after.ctimeMs !== before.ctimeMs) {
      throw new BrokerError("POLICY_DENIED", "Task script changed while being authorized");
    }
    let text: string;
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(content);
    } catch {
      throw new BrokerError("POLICY_DENIED", "Task script must contain valid UTF-8");
    }
    return { path: canonical, content: text, contentSha256: createHash("sha256").update(content).digest("hex") };
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Task script was not found");
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
