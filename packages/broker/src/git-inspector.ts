import { createHash } from "node:crypto";
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, join, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import {
  ProcessSupervisor,
  type ProcessExecutionResult
} from "./process-supervisor.js";
import { redactBoundedText, redactLogText } from "./secret-policy.js";

const GIT_EXECUTABLE = "/usr/bin/git";
const MAX_PROJECT_ROOT_LENGTH = 4_096;
const MAX_BRANCH_LENGTH = 256;
const MAX_PATH_LENGTH = 4_096;
const MAX_PATHS = 5_000;
const MAX_OUTPUT_BYTES = 262_144;
const MAX_TIMEOUT_MS = 10_000;
const MAX_CONFIG_BYTES = 262_144;
const MAX_DIFF_BYTES = 1_048_576;
const MAX_DIFF_PROCESS_OUTPUT_BYTES = 1_200_000;
const MAX_DIFF_TIMEOUT_MS = 15_000;
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

export interface SafeGitBranch {
  name: string;
  current: boolean;
  upstream?: string;
  ahead?: number;
  behind?: number;
}

export interface SafeGitBranches {
  projectRoot: string;
  branches: readonly SafeGitBranch[];
  warnings: readonly string[];
  truncated: boolean;
}

export interface GitBranchInspector {
  branches(projectRoot: string, includeRemote: boolean, control: GitExecutionControl): Promise<SafeGitBranches>;
}

export interface SafeGitCommit {
  id: string;
  author?: string;
  timestamp: string;
  subject: string;
}

export interface SafeGitLog {
  projectRoot: string;
  commits: readonly SafeGitCommit[];
  truncated: boolean;
  warnings: readonly string[];
}

export interface GitLogInspector {
  log(projectRoot: string, limit: number, ref: string | undefined, control: GitExecutionControl): Promise<SafeGitLog>;
}

export interface SafeGitDiff {
  projectRoot: string;
  diff: string;
  changedPaths: readonly string[];
  staged: boolean;
  base?: string;
  sha256: string;
  truncated: boolean;
  warnings: readonly string[];
}

export interface GitDiffInspector {
  diff(
    projectRoot: string,
    paths: readonly string[],
    staged: boolean,
    base: string | undefined,
    maxBytes: number,
    control: GitExecutionControl
  ): Promise<SafeGitDiff>;
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

export class GitBranchListInspector implements GitBranchInspector {
  private readonly supervisor: Pick<ProcessSupervisor, "run">;

  constructor(supervisor: Pick<ProcessSupervisor, "run"> = new ProcessSupervisor({
    maxConcurrent: 2,
    allowedEnvironmentKeys: Object.keys(SAFE_GIT_ENVIRONMENT)
  })) {
    this.supervisor = supervisor;
  }

  async branches(projectRoot: string, includeRemote: boolean, control: GitExecutionControl): Promise<SafeGitBranches> {
    validateGitBranchRequest(projectRoot, includeRemote);
    const identity = canonicalProjectRoot(projectRoot);
    const refs = includeRemote ? ["refs/heads", "refs/remotes"] : ["refs/heads"];
    const result = await this.supervisor.run({
      executable: GIT_EXECUTABLE,
      args: [
        "--no-pager",
        "--no-optional-locks",
        "--git-dir=.git",
        "--work-tree=.",
        "-c", "core.fsmonitor=false",
        "-c", "core.hooksPath=/dev/null",
        "for-each-ref",
        "--format=%(refname:short)%00%(HEAD)%00%(upstream:short)%00%(upstream:track)%00",
        "--sort=refname",
        ...refs
      ],
      cwd: identity.path,
      environment: SAFE_GIT_ENVIRONMENT,
      timeoutMs: Math.min(control.timeoutMs, MAX_TIMEOUT_MS),
      outputCapBytes: MAX_OUTPUT_BYTES,
      shouldCancel: control.shouldCancel
    });
    assertProjectIdentity(identity.path, identity.identity);
    return parseGitBranchResult(identity.path, result);
  }
}

export class GitLogInspectorImpl implements GitLogInspector {
  private readonly supervisor: Pick<ProcessSupervisor, "run">;

  constructor(supervisor: Pick<ProcessSupervisor, "run"> = new ProcessSupervisor({
    maxConcurrent: 2,
    allowedEnvironmentKeys: Object.keys(SAFE_GIT_ENVIRONMENT)
  })) {
    this.supervisor = supervisor;
  }

  async log(projectRoot: string, limit: number, ref: string | undefined, control: GitExecutionControl): Promise<SafeGitLog> {
    validateGitLogRequest(projectRoot, limit, ref);
    const identity = canonicalProjectRoot(projectRoot);
    const args = [
      "--no-pager",
      "--no-optional-locks",
      "--git-dir=.git",
      "--work-tree=.",
      "-c", "core.fsmonitor=false",
      "-c", "core.hooksPath=/dev/null",
      "log",
      "--format=%H%x00%an%x00%aI%x00%s%x00",
      `--max-count=${limit}`,
      "--no-decorate",
      "--no-ext-diff",
      "--no-textconv",
      "--no-renames",
      "--end-of-options",
      ref ?? "HEAD"
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
    return parseGitLogResult(identity.path, result);
  }
}

export class GitDiffInspectorImpl implements GitDiffInspector {
  private readonly supervisor: Pick<ProcessSupervisor, "run">;

  constructor(supervisor: Pick<ProcessSupervisor, "run"> = new ProcessSupervisor({
    maxConcurrent: 2,
    allowedEnvironmentKeys: Object.keys(SAFE_GIT_ENVIRONMENT)
  })) {
    this.supervisor = supervisor;
  }

  async diff(
    projectRoot: string,
    paths: readonly string[],
    staged: boolean,
    base: string | undefined,
    maxBytes: number,
    control: GitExecutionControl
  ): Promise<SafeGitDiff> {
    validateGitDiffRequest(projectRoot, paths, staged, base, maxBytes);
    const identity = canonicalProjectRoot(projectRoot);
    const args = [
      "--no-pager",
      "--no-optional-locks",
      "--literal-pathspecs",
      "--git-dir=.git",
      "--work-tree=.",
      "-c", "core.fsmonitor=false",
      "-c", "core.hooksPath=/dev/null",
      "-c", "diff.external=false",
      "diff",
      ...(staged ? ["--cached"] : []),
      "--no-ext-diff",
      "--no-textconv",
      "--no-renames",
      "--no-color",
      "--full-index",
      "--unified=3",
      "--end-of-options",
      ...(base !== undefined ? [base] : []),
      "--",
      ...paths
    ];
    const result = await this.supervisor.run({
      executable: GIT_EXECUTABLE,
      args,
      cwd: identity.path,
      environment: SAFE_GIT_ENVIRONMENT,
      timeoutMs: Math.min(control.timeoutMs, MAX_DIFF_TIMEOUT_MS),
      outputCapBytes: Math.min(MAX_DIFF_PROCESS_OUTPUT_BYTES, maxBytes + 64_000),
      shouldCancel: control.shouldCancel
    });
    assertProjectIdentity(identity.path, identity.identity);
    return parseGitDiffResult(identity.path, paths, staged, base, maxBytes, result);
  }
}

export function validateGitStatusRequest(projectRoot: string, includeUntracked = true): void {
  if (typeof projectRoot !== "string" || projectRoot.length < 1 || projectRoot.length > MAX_PROJECT_ROOT_LENGTH ||
      !PROJECT_ROOT_PATTERN.test(projectRoot) || !isAbsolute(projectRoot) || resolve(projectRoot) !== projectRoot ||
      typeof includeUntracked !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "Git status arguments are outside the supported range");
  }
}

export function validateGitBranchRequest(projectRoot: string, includeRemote = false): void {
  if (typeof includeRemote !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "include_remote must be a boolean");
  }
  validateGitStatusRequest(projectRoot, true);
}

export function validateGitLogRequest(projectRoot: string, limit = 50, ref?: string): void {
  validateGitStatusRequest(projectRoot, true);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 200 || !isSafeGitRevision(ref, 256)) {
    throw new BrokerError("PRECONDITION_FAILED", "Git log arguments are outside the supported range");
  }
}

export function validateGitDiffRequest(
  projectRoot: string,
  paths: readonly string[] = [],
  staged = false,
  base?: string,
  maxBytes = MAX_DIFF_BYTES
): void {
  validateGitStatusRequest(projectRoot, true);
  if (!Array.isArray(paths) || paths.length > MAX_PATHS ||
      paths.some((path) => typeof path !== "string" || !isSafeGitPath(path))) {
    throw new BrokerError("PRECONDITION_FAILED", "Git diff paths are outside the supported range");
  }
  if (typeof staged !== "boolean" || !isSafeGitRevision(base) ||
      !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_DIFF_BYTES) {
    throw new BrokerError("PRECONDITION_FAILED", "Git diff arguments are outside the supported range");
  }
}

function isSafeGitRevision(ref: string | undefined, maxLength = 128): boolean {
  return ref === undefined || (typeof ref === "string" && ref.length <= maxLength &&
    /^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/u.test(ref) && !ref.includes(".."));
}

function isSafeGitPath(path: string): boolean {
  if (path.length < 1 || path.length > MAX_PATH_LENGTH || isAbsolute(path) || path.startsWith(":")) return false;
  if (/[\u0000-\u001f\u007f\\]/u.test(path)) return false;
  const segments = path.split("/");
  return segments.every((segment) => segment.length > 0 && segment !== "." && segment !== "..");
}

function sanitizeGitValue(value: string, maxLength: number, allowEmpty = false): { value: string | null; redacted: boolean } {
  if ((!allowEmpty && value.length < 1) || value.length > maxLength) return { value: null, redacted: false };
  const redactedValue = redactLogText(value);
  const safe = redactedValue.text.replace(/[\u0001-\u001f\u007f]/gu, "�");
  return {
    value: safe.length > maxLength ? safe.slice(0, maxLength) : safe,
    redacted: redactedValue.redacted || safe !== value
  };
}

export function parseGitLogResult(projectRoot: string, result: ProcessExecutionResult): SafeGitLog {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Git log was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Git log timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Git log exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") {
    if (/not a git repository/u.test(result.stderr)) {
      throw new BrokerError("TARGET_NOT_FOUND", "The project root is not a Git repository");
    }
    throw new BrokerError("EXECUTION_FAILED", "Git log failed");
  }
  const commits: SafeGitCommit[] = [];
  const warnings: string[] = [];
  const records = result.stdout.split("\0");
  let malformed = false;
  let redacted = false;
  for (let index = 0; index + 3 < records.length; index += 4) {
    const id = records[index]!;
    const author = sanitizeGitValue(records[index + 1]!, 256, true);
    const timestamp = records[index + 2]!;
    const subject = sanitizeGitValue(records[index + 3]!, 500, true);
    if (!/^[A-Fa-f0-9]{40,64}$/u.test(id) || author.value === null || subject.value === null) {
      malformed = true;
      continue;
    }
    const parsedTimestamp = Date.parse(timestamp);
    if (Number.isNaN(parsedTimestamp)) {
      malformed = true;
      continue;
    }
    redacted ||= author.redacted || subject.redacted;
    commits.push({
      id,
      ...(author.value.length > 0 ? { author: author.value } : {}),
      timestamp: new Date(parsedTimestamp).toISOString(),
      subject: subject.value
    });
  }
  if (records.length % 4 !== 1) malformed = true;
  const addWarning = (warning: string): void => {
    if (!warnings.includes(warning) && warnings.length < 32) warnings.push(warning);
  };
  if (malformed) addWarning("Some Git log records were malformed and were omitted");
  if (redacted) addWarning("Sensitive Git log text was redacted");
  const truncated = result.truncated || malformed;
  if (truncated) addWarning("Git log output was limited by fixed adapter budgets");
  return { projectRoot, commits, truncated, warnings };
}

export function parseGitDiffResult(
  projectRoot: string,
  paths: readonly string[],
  staged: boolean,
  base: string | undefined,
  maxBytes: number,
  result: ProcessExecutionResult
): SafeGitDiff {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Git diff was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Git diff timed out");
  if (result.resultClass !== "SUCCEEDED" && result.resultClass !== "OUTPUT_LIMIT") {
    if (/not a git repository/u.test(result.stderr)) {
      throw new BrokerError("TARGET_NOT_FOUND", "The project root is not a Git repository");
    }
    throw new BrokerError("EXECUTION_FAILED", "Git diff failed");
  }
  const bounded = redactBoundedText(result.stdout, maxBytes);
  const safeText = redactBoundedText(
    bounded.text.replace(/[\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, "�"),
    maxBytes
  );
  const diff = safeText.text;
  const warnings: string[] = [];
  const addWarning = (warning: string): void => {
    if (!warnings.includes(warning) && warnings.length < 32) warnings.push(warning);
  };
  const changedPaths = extractGitDiffPaths(diff, addWarning);
  const truncated = result.truncated || result.resultClass === "OUTPUT_LIMIT" || bounded.truncated || safeText.truncated;
  if (bounded.redacted || safeText.redacted) addWarning("Sensitive Git diff text was redacted");
  if (truncated) addWarning("Git diff output was limited by fixed adapter budgets");
  const digest = createHash("sha256").update(diff, "utf8").digest("hex");
  return {
    projectRoot,
    diff,
    changedPaths,
    staged,
    ...(base !== undefined ? { base } : {}),
    sha256: digest,
    truncated,
    warnings
  };
}

function extractGitDiffPaths(diff: string, addWarning: (warning: string) => void): string[] {
  const paths: string[] = [];
  const seen = new Set<string>();
  let truncated = false;
  const add = (value: string): void => {
    const safe = sanitizeGitValue(value, MAX_PATH_LENGTH);
    if (safe.value === null || !isSafeGitPath(safe.value)) return;
    if (seen.has(safe.value)) return;
    if (paths.length >= MAX_PATHS) {
      truncated = true;
      return;
    }
    seen.add(safe.value);
    paths.push(safe.value);
  };
  for (const line of diff.split("\n")) {
    if (line.startsWith("diff --git ")) {
      const separator = line.lastIndexOf(" b/");
      if (separator > "diff --git a/".length) {
        const left = line.slice("diff --git a/".length, separator);
        const right = line.slice(separator + " b/".length);
        add(left);
        add(right);
      }
    } else if (line.startsWith("--- a/")) {
      add(line.slice("--- a/".length));
    } else if (line.startsWith("+++ b/")) {
      add(line.slice("+++ b/".length));
    }
  }
  if (truncated) addWarning("Changed Git diff paths were limited by fixed adapter budgets");
  return paths;
}

export function parseGitBranchResult(projectRoot: string, result: ProcessExecutionResult): SafeGitBranches {
  if (result.resultClass === "CANCELLED") throw new BrokerError("CANCELLED", "Git branch listing was cancelled");
  if (result.resultClass === "TIMEOUT") throw new BrokerError("TIMEOUT", "Git branch listing timed out");
  if (result.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Git branch listing exceeded its output limit");
  if (result.resultClass !== "SUCCEEDED") {
    if (/not a git repository/u.test(result.stderr)) {
      throw new BrokerError("TARGET_NOT_FOUND", "The project root is not a Git repository");
    }
    throw new BrokerError("EXECUTION_FAILED", "Git branch listing failed");
  }
  const branches: SafeGitBranch[] = [];
  const warnings: string[] = [];
  let malformed = false;
  let truncated = result.truncated;
  let redacted = false;
  const records = result.stdout.split("\0");
  const addWarning = (warning: string): void => {
    if (!warnings.includes(warning) && warnings.length < 32) warnings.push(warning);
  };
  for (let index = 0; index + 3 < records.length; index += 4) {
    const name = sanitizeGitValue(records[index]!, MAX_BRANCH_LENGTH);
    const marker = records[index + 1];
    const upstream = records[index + 2] === ""
      ? { value: "", redacted: false }
      : sanitizeGitValue(records[index + 2]!, MAX_BRANCH_LENGTH);
    const track = records[index + 3]!;
    if (name.value === null || (marker !== "*" && marker !== " ") || upstream.value === null ||
        (track.length > MAX_BRANCH_LENGTH && track.length > 0)) {
      malformed = true;
      continue;
    }
    redacted ||= name.redacted || upstream.redacted;
    if (branches.length >= 500) {
      truncated = true;
      continue;
    }
    const branch: SafeGitBranch = { name: name.value, current: marker === "*" };
    if (upstream.value.length > 0) branch.upstream = upstream.value;
    if (track.length > 0) {
      const ahead = /\[ahead (\d+)(?:, behind (\d+))?\]/u.exec(track);
      const behindOnly = /\[behind (\d+)\]/u.exec(track);
      if (ahead) {
        const aheadValue = Number(ahead[1]);
        const behindValue = ahead[2] === undefined ? undefined : Number(ahead[2]);
        if (!Number.isSafeInteger(aheadValue) || aheadValue > 1_000_000 ||
            (behindValue !== undefined && (!Number.isSafeInteger(behindValue) || behindValue > 1_000_000))) {
          malformed = true;
          continue;
        }
        branch.ahead = aheadValue;
        if (behindValue !== undefined) branch.behind = behindValue;
      } else if (behindOnly) {
        const behindValue = Number(behindOnly[1]);
        if (!Number.isSafeInteger(behindValue) || behindValue > 1_000_000) {
          malformed = true;
          continue;
        }
        branch.behind = behindValue;
      } else {
        malformed = true;
        continue;
      }
    }
    branches.push(branch);
  }
  if (records.length % 4 !== 1) malformed = true;
  if (malformed) {
    truncated = true;
    addWarning("Some Git branch records were malformed and were omitted");
  }
  if (redacted) addWarning("Sensitive Git branch text was redacted");
  if (truncated) addWarning("Git branch output was limited by fixed adapter budgets");
  return { projectRoot, branches, warnings, truncated };
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
