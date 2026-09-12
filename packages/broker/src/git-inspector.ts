import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import {
  ProcessSupervisor,
  type ProcessExecutionResult
} from "./process-supervisor.js";
import { redactLogText } from "./secret-policy.js";

const GIT_EXECUTABLE = "/usr/bin/git";
const MAX_PROJECT_ROOT_LENGTH = 4_096;
const MAX_BRANCH_LENGTH = 256;
const MAX_PATH_LENGTH = 4_096;
const MAX_PATHS = 5_000;
const MAX_OUTPUT_BYTES = 262_144;
const MAX_TIMEOUT_MS = 10_000;
const MAX_CONFIG_BYTES = 262_144;
const PROJECT_ROOT_PATTERN = /^\/[^\u0000\n]*$/u;
const SAFE_GIT_ENVIRONMENT = {
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
  GIT_CONFIG_SYSTEM: "/dev/null",
  GIT_TERMINAL_PROMPT: "0",
  GIT_OPTIONAL_LOCKS: "0"
} as const;

export interface SafeGitStatus {
  projectRoot: string;
  branch: string;
  head: string;
  stagedPaths: readonly string[];
  unstagedPaths: readonly string[];
  untrackedPaths: readonly string[];
  conflictedPaths: readonly string[];
  dirty: boolean;
  warnings: readonly string[];
  truncated: boolean;
}

export interface GitExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface GitInspector {
  status(projectRoot: string, includeUntracked: boolean, control: GitExecutionControl): Promise<SafeGitStatus>;
}

export class GitStatusInspector implements GitInspector {
  private readonly supervisor: Pick<ProcessSupervisor, "run">;

  constructor(supervisor: Pick<ProcessSupervisor, "run"> = new ProcessSupervisor({
    maxConcurrent: 2,
    allowedEnvironmentKeys: Object.keys(SAFE_GIT_ENVIRONMENT)
  })) {
    this.supervisor = supervisor;
  }

  async status(projectRoot: string, includeUntracked: boolean, control: GitExecutionControl): Promise<SafeGitStatus> {
    validateGitStatusRequest(projectRoot, includeUntracked);
    const identity = canonicalProjectRoot(projectRoot);
    const args = [
      "--no-pager",
      "--no-optional-locks",
      "--git-dir=.git",
      "--work-tree=.",
      "-c", "core.fsmonitor=false",
      "-c", "core.hooksPath=/dev/null",
      "status",
      "--porcelain=v2",
      "-z",
      "--branch",
      includeUntracked ? "--untracked-files=all" : "--untracked-files=no"
    ];
    const result = await this.supervisor.run({
      executable: GIT_EXECUTABLE,
      args,
      cwd: identity.path,
      environment: SAFE_GIT_ENVIRONMENT,
      timeoutMs: Math.min(control.timeoutMs, MAX_TIMEOUT_MS),
      outputCapBytes: MAX_OUTPUT_BYTES,
      shouldCancel: control.shouldCancel
    });
    assertProjectIdentity(identity.path, identity.identity);
    return parseGitStatusOutput(identity.path, result);
  }
}

export function validateGitStatusRequest(projectRoot: string, includeUntracked = true): void {
  if (typeof projectRoot !== "string" || projectRoot.length < 1 || projectRoot.length > MAX_PROJECT_ROOT_LENGTH ||
      !PROJECT_ROOT_PATTERN.test(projectRoot) || !isAbsolute(projectRoot) || resolve(projectRoot) !== projectRoot ||
      typeof includeUntracked !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "Git status arguments are outside the supported range");
  }
}

export function parseGitStatusOutput(projectRoot: string, result: ProcessExecutionResult): SafeGitStatus {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Git status was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Git status timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Git status exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") {
    if (/not a git repository/u.test(result.stderr)) {
      throw new BrokerError("TARGET_NOT_FOUND", "The project root is not a Git repository");
    }
    throw new BrokerError("EXECUTION_FAILED", "Git status failed");
  }

  const records = result.stdout.split("\0");
  let branch = "";
  let head = "";
  const stagedPaths: string[] = [];
  const unstagedPaths: string[] = [];
  const untrackedPaths: string[] = [];
  const conflictedPaths: string[] = [];
  const warnings: string[] = [];
  let truncated = result.truncated;
  let redacted = false;
  let malformed = false;

  const addWarning = (warning: string): void => {
    if (!warnings.includes(warning) && warnings.length < 32) warnings.push(warning);
  };
  const sanitize = (value: string, maxLength: number): string | null => {
    if (value.length < 1 || value.length > maxLength) return null;
    const safe = redactLogText(value).text.replace(/[\u0001-\u001f\u007f]/gu, "�");
    if (safe !== value) redacted = true;
    return safe.length > maxLength ? safe.slice(0, maxLength) : safe;
  };
  const addPath = (target: string[], path: string): void => {
    const safePath = sanitize(path, MAX_PATH_LENGTH);
    if (safePath === null) {
      malformed = true;
      return;
    }
    if (target.length >= MAX_PATHS) {
      truncated = true;
      return;
    }
    target.push(safePath);
  };

  for (let index = 0; index < records.length; index += 1) {
    const record = records[index]!;
    if (record.length === 0) continue;
    if (record.startsWith("# branch.oid ")) {
      head = record.slice("# branch.oid ".length);
      continue;
    }
    if (record.startsWith("# branch.head ")) {
      const safeBranch = sanitize(record.slice("# branch.head ".length), MAX_BRANCH_LENGTH);
      if (safeBranch === null || safeBranch === "(detached)" || safeBranch === "(unknown)") {
        branch = safeBranch === null ? "" : safeBranch === "(detached)" ? "" : safeBranch;
      } else {
        branch = safeBranch;
      }
      continue;
    }
    if (record.startsWith("# ")) continue;
    if (record.startsWith("? ")) {
      addPath(untrackedPaths, record.slice(2));
      continue;
    }
    if (record.startsWith("! ")) continue;

    const type = record[0];
    if (type !== "1" && type !== "2" && type !== "u") {
      malformed = true;
      continue;
    }
    const fields = record.split(" ");
    const xy = fields[1];
    const pathStart = type === "1" ? 8 : type === "2" ? 9 : 10;
    if (typeof xy !== "string" || !/^[.A-Z?]{2}$/u.test(xy) || fields.length <= pathStart) {
      malformed = true;
      continue;
    }
    const path = fields.slice(pathStart).join(" ");
    const target = xy[0] !== "." ? stagedPaths : unstagedPaths;
    if (xy[0] !== "." && xy[1] !== ".") {
      addPath(stagedPaths, path);
      addPath(unstagedPaths, path);
    } else {
      addPath(target, path);
    }
    if (type === "u" || xy.includes("U")) addPath(conflictedPaths, path);
    if (type === "2") {
      const original = records[index + 1];
      if (original === undefined || original.length === 0) {
        malformed = true;
      } else {
        index += 1;
        if (xy[0] !== ".") addPath(stagedPaths, original);
        if (xy[1] !== ".") addPath(unstagedPaths, original);
      }
    }
  }

  if (!/^[A-Fa-f0-9]{40,128}$/u.test(head) || /^0+$/u.test(head)) {
    throw new BrokerError("TARGET_NOT_FOUND", "The Git repository has no committed HEAD");
  }
  if (malformed) {
    truncated = true;
    addWarning("Some Git status records were malformed and were omitted");
  }
  if (redacted) addWarning("Sensitive Git status text was redacted");
  if (truncated) addWarning("Git status output was limited by fixed adapter budgets");
  return {
    projectRoot,
    branch,
    head,
    stagedPaths,
    unstagedPaths,
    untrackedPaths,
    conflictedPaths,
    dirty: stagedPaths.length > 0 || unstagedPaths.length > 0 || untrackedPaths.length > 0 || conflictedPaths.length > 0,
    warnings,
    truncated
  };
}

function canonicalProjectRoot(projectRoot: string): { path: string; identity: string } {
  let canonical: string;
  try {
    const lexicalStat = lstatSync(projectRoot);
    if (!lexicalStat.isDirectory() || lexicalStat.isSymbolicLink()) {
      throw new BrokerError("POLICY_DENIED", "Git project root must be a non-symlink directory");
    }
    canonical = realpathSync.native(projectRoot);
    if (canonical !== projectRoot || resolve(canonical) !== canonical) {
      throw new BrokerError("POLICY_DENIED", "Git project root must be canonical");
    }
    const stat = statSync(canonical);
    const gitDirectory = join(canonical, ".git");
    const gitStat = lstatSync(gitDirectory);
    if (!gitStat.isDirectory() || gitStat.isSymbolicLink() || realpathSync.native(gitDirectory) !== gitDirectory) {
      throw new BrokerError("POLICY_DENIED", "Git metadata must be a canonical non-symlink directory");
    }
    const configIdentity = validateRepositoryConfig(gitDirectory);
    return { path: canonical, identity: `${stat.dev}:${stat.ino}:${gitStat.dev}:${gitStat.ino}:${configIdentity}` };
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Git project root was not found");
  }
}

function assertProjectIdentity(projectRoot: string, expectedIdentity: string): void {
  try {
    const canonical = realpathSync.native(projectRoot);
    const stat = statSync(canonical);
    const gitDirectory = join(canonical, ".git");
    const gitStat = lstatSync(gitDirectory);
    const configIdentity = validateRepositoryConfig(gitDirectory);
    if (canonical !== projectRoot || !gitStat.isDirectory() || gitStat.isSymbolicLink() ||
        realpathSync.native(gitDirectory) !== gitDirectory ||
        `${stat.dev}:${stat.ino}:${gitStat.dev}:${gitStat.ino}:${configIdentity}` !== expectedIdentity) {
      throw new BrokerError("POLICY_DENIED", "Git project root changed during inspection");
    }
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("POLICY_DENIED", "Git project root changed during inspection");
  }
}

function validateRepositoryConfig(gitDirectory: string): string {
  const configPath = join(gitDirectory, "config");
  let configStat;
  try {
    configStat = lstatSync(configPath);
  } catch {
    throw new BrokerError("POLICY_DENIED", "Git repository configuration is unavailable");
  }
  if (!configStat.isFile() || configStat.isSymbolicLink() || configStat.size > MAX_CONFIG_BYTES) {
    throw new BrokerError("POLICY_DENIED", "Git repository configuration is not a bounded regular file");
  }
  let descriptor: number | undefined;
  let config: string;
  try {
    descriptor = openSync(configPath, constants.O_RDONLY | constants.O_NOFOLLOW);
    const openedStat = fstatSync(descriptor);
    if (openedStat.dev !== configStat.dev || openedStat.ino !== configStat.ino || openedStat.size !== configStat.size) {
      throw new BrokerError("POLICY_DENIED", "Git repository configuration changed while opening");
    }
    config = readFileSync(descriptor, "utf8");
  } catch {
    throw new BrokerError("POLICY_DENIED", "Git repository configuration cannot be read safely");
  } finally {
    if (typeof descriptor === "number") closeSync(descriptor);
  }
  for (const line of config.split(/\r?\n/u)) {
    const section = /^\s*\[\s*([^\]]+)\]/u.exec(line)?.[1]?.trim().toLocaleLowerCase("en-US");
    const key = /^\s*([A-Za-z][A-Za-z0-9.-]*)\s*=/u.exec(line)?.[1]?.toLocaleLowerCase("en-US");
    if (section && /^(?:include|filter(?:\s|$)|fsmonitor|diff(?:\s|$)|merge(?:\s|$)|credential(?:\s|$)|url(?:\s|$)|mergetool(?:\s|$))/u.test(section)) {
      throw new BrokerError("POLICY_DENIED", "Git repository configuration contains an executable integration");
    }
    if (key && /^(?:clean|smudge|process|command|textconv|external|sshcommand|uploadpack|receivepack|worktree|gitdir|hookspath|fsmonitor)$/u.test(key)) {
      throw new BrokerError("POLICY_DENIED", "Git repository configuration contains an executable integration");
    }
  }
  return `${configStat.dev}:${configStat.ino}`;
}
