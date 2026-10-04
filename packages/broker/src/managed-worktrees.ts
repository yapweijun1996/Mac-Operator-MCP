import { randomUUID } from "node:crypto";
import { constants, closeSync, existsSync, fstatSync, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, relative, isAbsolute, sep } from "node:path";
import { BrokerError, canonicalJson, parseJsonStrict, sha256 } from "@mac-operator/contracts";
import { canonicalProjectRoot, assertProjectIdentity, GitStatusInspector, SAFE_GIT_ENVIRONMENT, type GitExecutionControl, type GitMetadataResolver } from "./git-inspector.js";
import { loadNativePeerAdapter, parsePeerProcessIdentity } from "./peer-credentials.js";
import { ProcessSupervisor } from "./process-supervisor.js";
import { assertContentPathAllowed } from "./secret-policy.js";
import { isPlainDataRecord } from "./plain-record.js";

export interface ManagedWorktreeRecord {
  projectRoot: string;
  worktree: string;
  branchName: string;
  baseRef: string;
  baseCommit: string;
  taskId: string;
  owner: string;
  fingerprint: string;
  idempotencyKey: string;
  state: "pending" | "active" | "removing" | "removed";
  removalKey: string;
  rootIdentity: string;
  projectIdentity: string;
  gitDirectory: string;
  gitIdentity: string;
}

export interface WorktreeCreateRequest {
  projectRoot: string;
  branchName: string;
  baseRef: string;
  taskId: string;
  idempotencyKey: string;
  owner: string;
}

/** Protected provenance only; execution/job authority stays in BrokerStore. */
/** Outcome of the branch cleanup that follows a successful worktree removal. */
export interface WorktreeRemoval {
  branchName: string;
  branchDeleted: boolean;
  branchNote?: string;
}

const TASK_BRANCH_PATTERN = /^codex\/[A-Za-z0-9][A-Za-z0-9._/-]{0,120}$/u;

export class ManagedWorktrees {
  private readonly stateIdentity: string;
  private readonly treeIdentity: string;
  private readonly lockPath: string;
  private readonly statePath: string;
  private readonly records: ManagedWorktreeRecord[];
  private operation: Promise<unknown> = Promise.resolve();
  private closed = false;
  private lockReleased = false;
  private lockIdentity = "";
  private readonly supervisor: Pick<ProcessSupervisor, "run">;
  readonly resolveGitMetadata: GitMetadataResolver = (worktree) => {
    const record = this.records.find((entry) => entry.worktree === worktree && entry.state === "active");
    if (!record) throw new BrokerError("POLICY_DENIED", "Git worktree has no managed provenance");
    this.verify(record);
    return { gitDirectory: record.gitDirectory, commonDirectory: join(record.projectRoot, ".git"),
      identity: `${record.rootIdentity}:${record.gitIdentity}:${record.projectIdentity}` };
  };

  constructor(readonly stateRoot: string, readonly worktreeRoot: string, supervisor?: Pick<ProcessSupervisor, "run">) {
    this.stateIdentity = protectedDirectory(stateRoot);
    this.treeIdentity = protectedDirectory(worktreeRoot);
    if (stateRoot === worktreeRoot || contained(stateRoot, worktreeRoot) || contained(worktreeRoot, stateRoot)) {
      throw new Error("Worktree storage and protected provenance must be separate roots");
    }
    this.supervisor = supervisor ?? new ProcessSupervisor({ maxConcurrent: 2, requireRootOwnedExecutable: true,
      allowedEnvironmentKeys: Object.keys(SAFE_GIT_ENVIRONMENT) });
    this.lockPath = join(stateRoot, "worktrees.lock");
    this.statePath = join(stateRoot, "worktrees.json");
    let lock: number | undefined;
    try {
      if (existsSync(this.lockPath)) {
        const priorStat = lstatSync(this.lockPath);
        const prior = parseJsonStrict(readBounded(this.lockPath, 4096, true)) as { pid?: number; startTimeMicros?: number };
        if (!Number.isSafeInteger(prior.pid) || !Number.isSafeInteger(prior.startTimeMicros) || prior.pid! < 1 || prior.startTimeMicros! < 1) {
          throw new Error("Managed inventory lock is malformed; operator reconciliation required");
        }
        const native = loadNativePeerAdapter();
        if (native.isProcessIdentityAlive(prior.pid!, prior.startTimeMicros!) !== false) {
          throw new Error("Managed inventory lock is owned by a live or unknown process");
        }
        this.releaseExactLock(priorStat.dev, priorStat.ino);
      }
      const identity = parsePeerProcessIdentity(loadNativePeerAdapter().getProcessIdentity(process.pid));
      lock = openSync(this.lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      writeFileSync(lock, canonicalJson({ ...identity, instance: randomUUID() }));
      fsyncSync(lock);
      const stat = fstatSync(lock);
      this.lockIdentity = `${stat.dev}:${stat.ino}`;
      if (existsSync(this.statePath)) {
        const data = parseJsonStrict(readBounded(this.statePath, 2 * 1024 * 1024, true));
        if (!Array.isArray(data) || data.length > 256) throw new Error("Malformed worktree inventory");
        this.records = data as ManagedWorktreeRecord[];
        for (const record of this.records) validateRecord(record, worktreeRoot);
      } else this.records = [];
    } catch (error) {
      if (lock !== undefined) {
        const stat = fstatSync(lock);
        this.releaseExactLock(stat.dev, stat.ino);
      }
      throw error;
    } finally { if (lock !== undefined) closeSync(lock); }
  }

  async close(): Promise<void> {
    this.closed = true;
    await this.operation.catch(() => undefined);
    if (this.lockReleased) return;
    this.lockReleased = true;
    if (existsSync(this.lockPath)) {
      const stat = lstatSync(this.lockPath);
      if (`${stat.dev}:${stat.ino}` !== this.lockIdentity) throw new Error("Managed inventory lock ownership changed");
      this.releaseExactLock(stat.dev, stat.ino);
    }
  }

  private releaseExactLock(device: number, inode: number): void {
    if (protectedDirectory(this.stateRoot) !== this.stateIdentity) throw new Error("Managed lock parent changed");
    const result = loadNativePeerAdapter().unlinkFileWithinRoot(this.stateRoot, this.lockPath, true, String(device), String(inode));
    if (!isPlainDataRecord(result) || result.removed !== true || result.path !== this.lockPath || result.rootPath !== this.stateRoot) {
      throw new Error("Managed inventory lock release readback failed");
    }
  }

  list(projectRoot: string, owner: string): readonly ManagedWorktreeRecord[] {
    this.checkStorage();
    return this.records.filter((entry) => entry.projectRoot === projectRoot && entry.owner === owner && entry.state === "active")
      .map((entry) => { this.verify(entry); return { ...entry }; });
  }

  require(worktree: string, projectRoot: string, owner: string, taskId?: string): ManagedWorktreeRecord {
    this.checkStorage();
    const record = this.records.find((entry) => entry.worktree === worktree && entry.projectRoot === projectRoot &&
      entry.owner === owner && entry.state === "active" && (taskId === undefined || entry.taskId === taskId));
    if (!record) throw new BrokerError("POLICY_DENIED", "Worktree is not owned by this project, principal and task");
    this.verify(record);
    return { ...record };
  }

  originalProject(worktree: string, owner: string): string | undefined {
    const record = this.records.find((entry) => entry.worktree === worktree && entry.owner === owner && entry.state === "active");
    if (!record) return undefined;
    this.verify(record);
    return record.projectRoot;
  }

  create(input: WorktreeCreateRequest, control: GitExecutionControl, assertAuthority: () => void): Promise<{ record: ManagedWorktreeRecord; reused: boolean }> {
    return this.serialize(async () => {
      this.checkStorage();
      validateCreate(input);
      assertAuthority();
      const primary = canonicalProjectRoot(input.projectRoot);
      if (contained(input.projectRoot, this.worktreeRoot) || contained(this.worktreeRoot, input.projectRoot) ||
          contained(input.projectRoot, this.stateRoot) || contained(this.stateRoot, input.projectRoot)) {
        throw new BrokerError("POLICY_DENIED", "Managed storage must be outside the primary project");
      }
      const fingerprint = sha256(canonicalJson(input));
      const duplicate = this.records.find((entry) => entry.owner === input.owner && entry.idempotencyKey === input.idempotencyKey);
      if (duplicate) {
        if (duplicate.fingerprint !== fingerprint) throw new BrokerError("CONFLICT", "Worktree retry key belongs to a different operation");
        if (duplicate.state !== "active") throw new BrokerError("UNKNOWN_OUTCOME", "Worktree operation requires operator reconciliation");
        this.verify(duplicate);
        return { record: { ...duplicate }, reused: true };
      }
      if (this.records.length >= 256) throw new BrokerError("CONFLICT", "Managed worktree inventory is full");
      const taskDuplicate = this.records.find((entry) => entry.owner === input.owner && entry.projectRoot === input.projectRoot &&
        entry.taskId === input.taskId && entry.state !== "removed");
      if (taskDuplicate) throw new BrokerError("CONFLICT", "Task already has a managed worktree");
      const baseCommit = (await this.git(input.projectRoot, ["rev-parse", "--verify", "--end-of-options", `${input.baseRef}^{commit}`], control)).trim();
      if (!/^[a-f0-9]{40,64}$/u.test(baseCommit)) throw new BrokerError("VERIFICATION_FAILED", "Base reference did not resolve to a commit");
      const before = await this.primarySnapshot(input.projectRoot, control);
      const worktree = join(this.worktreeRoot, `task-${sha256(canonicalJson({ project: input.projectRoot, owner: input.owner, task: input.taskId })).slice(0, 32)}`);
      if (existsSync(worktree)) throw new BrokerError("CONFLICT", "Worktree destination already exists");
      const record: ManagedWorktreeRecord = { ...input, fingerprint, baseCommit, worktree, state: "pending", rootIdentity: "",
        projectIdentity: primary.identity, gitDirectory: "", gitIdentity: "", removalKey: "" };
      this.records.push(record);
      this.persist();
      assertAuthority();
      await this.git(input.projectRoot, ["worktree", "add", "--no-track", "-b", input.branchName, "--", worktree, baseCommit], control);
      assertProjectIdentity(input.projectRoot, primary.identity);
      record.rootIdentity = directoryIdentity(worktree);
      const pointer = readBounded(join(worktree, ".git"), 4096);
      const match = /^gitdir: (\/[^\r\n]+)\n?$/u.exec(pointer);
      if (!match) throw new BrokerError("VERIFICATION_FAILED", "Created worktree metadata is malformed");
      record.gitDirectory = match[1]!;
      const metadataParent = join(input.projectRoot, ".git", "worktrees");
      if (dirname(record.gitDirectory) !== metadataParent || realpathSync.native(record.gitDirectory) !== record.gitDirectory) {
        throw new BrokerError("VERIFICATION_FAILED", "Created Git metadata escaped the primary repository");
      }
      record.gitIdentity = directoryIdentity(record.gitDirectory);
      record.state = "active";
      try {
        this.verify(record);
        assertAuthority();
        if (before !== await this.primarySnapshot(input.projectRoot, control)) {
          throw new BrokerError("UNKNOWN_OUTCOME", "Primary checkout changed during worktree creation");
        }
        this.persist();
        return { record: { ...record }, reused: false };
      } catch (error) {
        record.state = "pending";
        this.persist();
        throw error;
      }
    });
  }

  remove(projectRoot: string, worktree: string, owner: string, taskId: string, control: GitExecutionControl,
    assertAuthority: () => void, hasActiveJob: () => boolean, idempotencyKey = "legacy-remove"): Promise<WorktreeRemoval> {
    return this.serialize(async () => {
      if (this.removalRetry(projectRoot, worktree, owner, taskId, idempotencyKey)) {
        // A retry after a completed removal only re-attempts the branch cleanup that may not have finished.
        const done = this.records.find((entry) => entry.worktree === worktree)!;
        return this.deleteTaskBranch(done, control);
      }
      const record = this.require(worktree, projectRoot, owner, taskId);
      if (worktree === projectRoot || hasActiveJob()) throw new BrokerError("CONFLICT", "Worktree is primary or has an active/unresolved job");
      assertAuthority();
      const status = await new GitStatusInspector(this.supervisor, this.resolveGitMetadata).status(worktree, true, control);
      const ignored = await this.git(worktree, ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"], control);
      if (status.dirty || status.truncated || ignored.length !== 0) {
        throw new BrokerError("POLICY_DENIED", "Worktree removal requires clean status including ignored files");
      }
      const before = await this.primarySnapshot(projectRoot, control);
      this.verify(record);
      assertAuthority();
      if (hasActiveJob()) throw new BrokerError("CONFLICT", "Worktree became active before removal");
      const stored = this.records.find((entry) => entry.worktree === worktree)!;
      stored.state = "removing";
      stored.removalKey = idempotencyKey;
      this.persist();
      await this.git(projectRoot, ["worktree", "remove", "--", worktree], control);
      if (existsSync(worktree) || existsSync(record.gitDirectory) || before !== await this.primarySnapshot(projectRoot, control)) {
        throw new BrokerError("VERIFICATION_FAILED", "Worktree removal readback failed");
      }
      stored.state = "removed";
      this.persist();
      return this.deleteTaskBranch(stored, control);
    });
  }

  /**
   * Deletes the task branch with `git branch -d` so commits that were never merged are never lost. The worktree is
   * already gone and recorded as removed, so a failure here is reported as a kept branch instead of failing the removal.
   */
  private async deleteTaskBranch(record: ManagedWorktreeRecord, control: GitExecutionControl): Promise<WorktreeRemoval> {
    const branchName = record.branchName;
    if (!TASK_BRANCH_PATTERN.test(branchName)) return { branchName, branchDeleted: false, branchNote: "Task branch name is not a managed codex/ branch and was left alone" };
    // for-each-ref exits 0 with empty output for a missing branch, so a real Git failure is not mistaken for absence.
    const exists = async (): Promise<boolean> => (await this.git(record.projectRoot, ["for-each-ref", "--format=%(refname)", `refs/heads/${branchName}`], control)).trim() !== "";
    const kept = (): WorktreeRemoval => ({ branchName, branchDeleted: false, branchNote:
      `Branch ${branchName} was kept because git branch -d refused it (commits not merged into the primary checkout's HEAD, or the delete could not run); merge it or delete it from the owner terminal` });
    try {
      await this.git(record.projectRoot, ["branch", "-d", "--", branchName], control);
    } catch {
      // `-d` refuses a branch with commits not merged into the primary checkout's HEAD, and fails when it is already gone.
      return { ...(await exists().then((present) => !present, () => false) ? { branchName, branchDeleted: true } : kept()) };
    }
    return await exists().then((present) => ({ branchName, branchDeleted: !present }), () => kept());
  }

  removalRetry(projectRoot: string, worktree: string, owner: string, taskId: string, idempotencyKey: string): boolean {
    this.checkStorage();
    const record = this.records.find((entry) => entry.projectRoot === projectRoot && entry.worktree === worktree && entry.owner === owner && entry.taskId === taskId);
    if (!record) return false;
    if (record.state === "removing") throw new BrokerError("UNKNOWN_OUTCOME", "Worktree removal requires operator reconciliation");
    if (record.state !== "removed") return false;
    if (record.removalKey !== idempotencyKey) throw new BrokerError("CONFLICT", "Removed worktree belongs to another retry key");
    if (existsSync(worktree) || existsSync(record.gitDirectory)) throw new BrokerError("CONFLICT", "Removed worktree path was reused");
    return true;
  }

  private verify(record: ManagedWorktreeRecord): void {
    this.checkStorage();
    const expectedHead = `ref: refs/heads/${record.branchName}`;
    if (canonicalProjectRoot(record.projectRoot).identity !== record.projectIdentity) {
      throw new BrokerError("POLICY_DENIED", "Primary project identity changed");
    }
    const primaryMetadata = join(record.projectRoot, ".git");
    if (readBounded(join(primaryMetadata, "HEAD"), 4096).trim() === expectedHead) {
      throw new BrokerError("POLICY_DENIED", "Task branch is checked out in the primary repository");
    }
    const metadataRoot = join(primaryMetadata, "worktrees");
    if (existsSync(metadataRoot)) {
      const entries = readdirSync(metadataRoot);
      if (entries.length > 256) throw new BrokerError("POLICY_DENIED", "Worktree branch ownership is unbounded");
      for (const entry of entries) {
        const metadata = join(metadataRoot, entry);
        if (metadata !== record.gitDirectory && readBounded(join(metadata, "HEAD"), 4096).trim() === expectedHead) {
          throw new BrokerError("POLICY_DENIED", "Task branch is shared with another checkout");
        }
      }
    }
    if (record.state !== "active" || directoryIdentity(record.worktree) !== record.rootIdentity ||
        directoryIdentity(record.gitDirectory) !== record.gitIdentity ||
        canonicalProjectRoot(record.projectRoot).identity !== record.projectIdentity ||
        dirname(record.worktree) !== this.worktreeRoot || dirname(record.gitDirectory) !== join(record.projectRoot, ".git", "worktrees") ||
        readBounded(join(record.worktree, ".git"), 4096).trim() !== `gitdir: ${record.gitDirectory}` ||
        readBounded(join(record.gitDirectory, "gitdir"), 4096).trim() !== join(record.worktree, ".git") ||
        readBounded(join(record.gitDirectory, "commondir"), 4096).trim() !== "../.." ||
        readBounded(join(record.gitDirectory, "HEAD"), 4096).trim() !== `ref: refs/heads/${record.branchName}`) {
      throw new BrokerError("POLICY_DENIED", "Managed worktree identity or metadata changed");
    }
  }

  private async primarySnapshot(projectRoot: string, control: GitExecutionControl): Promise<string> {
    const head = await this.git(projectRoot, ["rev-parse", "--verify", "HEAD"], control);
    const index = join(projectRoot, ".git", "index");
    const indexHash = existsSync(index) ? sha256(readBoundedBytes(index, 4 * 1024 * 1024)) : "absent";
    const status = await this.git(projectRoot, ["status", "--porcelain=v2", "-z", "--untracked-files=all"], control);
    return sha256(head + indexHash + status);
  }

  private async git(cwd: string, args: readonly string[], control: GitExecutionControl): Promise<string> {
    const identity = canonicalProjectRoot(cwd, this.resolveGitMetadata);
    const result = await this.supervisor.run({ executable: "/usr/bin/git", cwd, environment: SAFE_GIT_ENVIRONMENT,
      args: ["--no-pager", "--no-optional-locks", `--git-dir=${identity.gitArgument}`, "--work-tree=.",
        "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "submodule.recurse=false", ...args],
      timeoutMs: Math.min(control.timeoutMs, 30_000), outputCapBytes: 131_072, shouldCancel: control.shouldCancel });
    assertProjectIdentity(cwd, identity.identity, this.resolveGitMetadata);
    if (result.resultClass !== "SUCCEEDED" || result.exitCode !== 0 || result.truncated) {
      throw new BrokerError(result.resultClass === "TIMEOUT" ? "TIMEOUT" : result.resultClass === "CANCELLED" ? "CANCELLED" : "EXECUTION_FAILED", "Fixed worktree Git operation failed");
    }
    return result.stdout;
  }

  private checkStorage(): void {
    if (this.closed || protectedDirectory(this.stateRoot) !== this.stateIdentity || protectedDirectory(this.worktreeRoot) !== this.treeIdentity) {
      throw new BrokerError("POLICY_DENIED", "Managed worktree storage is unavailable or changed");
    }
  }

  private persist(): void {
    this.checkStorage();
    if (existsSync(this.statePath)) readBounded(this.statePath, 2 * 1024 * 1024, true);
    const temporary = join(this.stateRoot, `.worktrees-${randomUUID()}.tmp`);
    const fd = openSync(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { writeFileSync(fd, canonicalJson(this.records)); fsyncSync(fd); }
    finally { closeSync(fd); }
    renameSync(temporary, this.statePath);
    const directory = openSync(this.stateRoot, constants.O_RDONLY | constants.O_NOFOLLOW);
    try { fsyncSync(directory); } finally { closeSync(directory); }
  }

  private serialize<T>(operation: () => Promise<T>): Promise<T> {
    const next = this.operation.catch(() => undefined).then(operation);
    this.operation = next;
    return next;
  }
}

export function validateCreate(input: WorktreeCreateRequest): void {
  canonicalProjectRoot(input.projectRoot);
  assertContentPathAllowed(input.projectRoot);
  for (const value of [input.taskId, input.idempotencyKey, input.owner]) {
    if (typeof value !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value)) {
      throw new BrokerError("PRECONDITION_FAILED", "Worktree identifier is malformed");
    }
  }
  if (typeof input.branchName !== "string" || !TASK_BRANCH_PATTERN.test(input.branchName) ||
      input.branchName.includes("..") || input.branchName.includes("//") || input.branchName.endsWith("/") ||
      input.branchName.split("/").some((part) => part.startsWith(".") || part.endsWith(".") || part.endsWith(".lock"))) {
    throw new BrokerError("PRECONDITION_FAILED", "Task branch must start with codex/ followed by letters, digits, . _ - or / (no empty, dotted or .lock segments, at most 127 characters), for example codex/my-task");
  }
  if (typeof input.baseRef !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/u.test(input.baseRef) ||
      input.baseRef.includes("..") || input.baseRef.includes("//")) {
    throw new BrokerError("PRECONDITION_FAILED", "Worktree base reference is malformed");
  }
}

function validateRecord(value: ManagedWorktreeRecord, root: string): void {
  const keys = ["projectRoot", "worktree", "branchName", "baseRef", "baseCommit", "taskId", "owner", "fingerprint", "idempotencyKey", "state", "rootIdentity", "projectIdentity", "gitDirectory", "gitIdentity", "removalKey"];
  if (!value || typeof value !== "object" || Object.keys(value).sort().join() !== keys.sort().join() ||
      keys.some((key) => typeof (value as unknown as Record<string, unknown>)[key] !== "string") ||
      !["pending", "active", "removing", "removed"].includes(value.state) || dirname(value.worktree) !== root ||
      !/^task-[a-f0-9]{32}$/u.test(value.worktree.slice(root.length + 1)) ||
      !/^[a-f0-9]{64}$/u.test(value.fingerprint) || !/^[a-f0-9]{40,64}$/u.test(value.baseCommit)) {
    throw new Error("Malformed managed worktree provenance");
  }
  validateCreate(value);
}

function directoryIdentity(path: string): string {
  if (!isAbsolute(path) || resolve(path) !== path || realpathSync.native(path) !== path) throw new BrokerError("POLICY_DENIED", "Worktree path must be canonical");
  const stat = lstatSync(path);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new BrokerError("POLICY_DENIED", "Worktree path is not a regular directory");
  return `${stat.dev}:${stat.ino}`;
}

function protectedDirectory(path: string): string {
  const identity = directoryIdentity(path);
  const stat = lstatSync(path);
  if (stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0) throw new Error("Managed storage must be owner-only");
  return identity;
}

function readBounded(path: string, maxBytes: number, protectedFile = false): string {
  return readBoundedBytes(path, maxBytes, protectedFile).toString("utf8");
}

function readBoundedBytes(path: string, maxBytes: number, protectedFile = false): Buffer {
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > maxBytes ||
      (protectedFile && (before.uid !== process.getuid?.() || (before.mode & 0o077) !== 0))) {
    throw new BrokerError("POLICY_DENIED", "Worktree metadata is not a bounded regular file");
  }
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(fd);
    const content = readFileSync(fd);
    const after = fstatSync(fd);
    if (before.dev !== opened.dev || before.ino !== opened.ino || before.size !== opened.size ||
        opened.ctimeMs !== after.ctimeMs || opened.mtimeMs !== after.mtimeMs || opened.size !== after.size || content.length > maxBytes) {
      throw new BrokerError("POLICY_DENIED", "Worktree metadata changed while reading");
    }
    return content;
  } finally { closeSync(fd); }
}

function contained(root: string, path: string): boolean {
  const value = relative(root, path);
  return value === "" || (!value.startsWith(`..${sep}`) && value !== ".." && !isAbsolute(value));
}
