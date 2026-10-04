import { randomUUID } from "node:crypto";
import { constants, closeSync, existsSync, fstatSync, fsyncSync, lstatSync, openSync, readFileSync, realpathSync, readdirSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, relative, isAbsolute, sep } from "node:path";
import { BrokerError, canonicalJson, parseJsonStrict, sha256 } from "@mac-operator/contracts";
import { canonicalProjectRoot, assertProjectIdentity, GitStatusInspector, SAFE_GIT_ENVIRONMENT, type GitExecutionControl, type GitMetadataResolver, type SafeGitStatus } from "./git-inspector.js";
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

  /** Pure in-memory check (no I/O, no verify()) so a denial path can name the caller's own active worktree. */
  ownedWorktreeContaining(path: string, owner: string): boolean {
    const target = resolve(path);
    return this.records.some((entry) => entry.owner === owner && entry.state === "active" && contained(entry.worktree, target));
  }

  /**
   * Records stuck in pending or removing: list() and require() hide them, so callers surface them as warnings.
   * Runs behind any in-flight create or remove, whose own pending or removing record is not stuck.
   */
  unresolved(projectRoot: string, owner: string): Promise<readonly Pick<ManagedWorktreeRecord, "taskId" | "state">[]> {
    return this.serialize(async () => {
      this.checkStorage();
      return this.records.filter((entry) => entry.projectRoot === projectRoot && entry.owner === owner && (entry.state === "pending" || entry.state === "removing"))
        .map((entry) => ({ taskId: entry.taskId, state: entry.state }));
    });
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
        const holder = `task ${duplicate.taskId} (branch ${duplicate.branchName}, state ${duplicate.state})`;
        if (duplicate.fingerprint !== fingerprint) {
          throw new BrokerError("CONFLICT", `Worktree retry key belongs to a different operation: this idempotency_key is held by ${holder}. Use a new idempotency_key or repeat the original request`);
        }
        if (duplicate.state === "removed") {
          throw new BrokerError("CONFLICT", `IDEMPOTENCY_KEY_IN_USE: this idempotency_key created the worktree for task ${duplicate.taskId} (branch ${duplicate.branchName}), ` +
            "which was later removed. Use a new idempotency_key; the task can be created again");
        }
        if (duplicate.state !== "active") {
          throw new BrokerError("UNKNOWN_OUTCOME", `Worktree operation requires operator reconciliation: the worktree for task ${duplicate.taskId} (branch ${duplicate.branchName}) is ${duplicate.state}`);
        }
        this.verify(duplicate);
        return { record: { ...duplicate }, reused: true };
      }
      if (this.records.length >= 256) throw new BrokerError("CONFLICT", "Managed worktree inventory is full");
      const taskDuplicate = this.records.find((entry) => entry.owner === input.owner && entry.projectRoot === input.projectRoot &&
        entry.taskId === input.taskId && entry.state !== "removed");
      if (taskDuplicate) {
        throw new BrokerError("CONFLICT", `Task already has a managed worktree: task ${taskDuplicate.taskId} (branch ${taskDuplicate.branchName}, state ${taskDuplicate.state}). ` +
          (taskDuplicate.state === "active" ? "Use it, remove it, or choose another task_id" : "It needs operator reconciliation; choose another task_id"));
      }
      const baseCommit = (await this.git(input.projectRoot, ["rev-parse", "--verify", "--end-of-options", `${input.baseRef}^{commit}`], control)).trim();
      if (!/^[a-f0-9]{40,64}$/u.test(baseCommit)) throw new BrokerError("VERIFICATION_FAILED", "Base reference did not resolve to a commit");
      const before = await this.primarySnapshot(input.projectRoot, control);
      const worktree = join(this.worktreeRoot, `task-${sha256(canonicalJson({ project: input.projectRoot, owner: input.owner, task: input.taskId })).slice(0, 32)}`);
      if (existsSync(worktree)) throw new BrokerError("CONFLICT", "Worktree destination already exists");
      // Refuse before the pending record exists: a failed `worktree add -b` would leave it behind and burn an inventory slot.
      await this.assertBranchFree(input.projectRoot, input.branchName, control);
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
    assertAuthority: () => void, hasActiveJob: () => boolean, idempotencyKey = "legacy-remove", describeActiveJobs?: () => string): Promise<WorktreeRemoval> {
    return this.serialize(async () => {
      const done = this.completedRemoval(projectRoot, worktree, owner, taskId, idempotencyKey);
      // A retry after a completed removal only re-attempts the branch cleanup that may not have finished.
      if (done) return this.deleteTaskBranch(done, control);
      const record = this.require(worktree, projectRoot, owner, taskId);
      if (worktree === projectRoot) throw new BrokerError("CONFLICT", "Worktree is the primary checkout and cannot be removed");
      if (hasActiveJob()) throw new BrokerError("CONFLICT", describeActiveJobs?.() ?? "Worktree has an active or unresolved job");
      assertAuthority();
      await this.assertCleanForRemoval(worktree, control);
      const before = await this.primarySnapshot(projectRoot, control);
      this.verify(record);
      assertAuthority();
      if (hasActiveJob()) throw new BrokerError("CONFLICT", "Worktree became active before removal");
      // require() returns a copy and a removed record can share this path, so mutate the live record itself.
      const stored = this.recordsAt(projectRoot, worktree, owner, taskId).find((entry) => entry.state === "active")!;
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
   * Removal needs a clean status that includes ignored files. The refusal reports counts only: ignored and untracked
   * names can be secret-shaped, and output beyond the Git cap is the same refusal rather than a generic Git failure.
   */
  private async assertCleanForRemoval(worktree: string, control: GitExecutionControl): Promise<void> {
    let status: SafeGitStatus | undefined;
    let ignored: number | undefined;
    try {
      status = await new GitStatusInspector(this.supervisor, this.resolveGitMetadata).status(worktree, true, control);
      ignored = (await this.git(worktree, ["ls-files", "--others", "--ignored", "--exclude-standard", "-z"], control, true))
        .split("\0").filter((path) => path !== "").length;
    } catch (error) {
      if (!(error instanceof BrokerError && error.errorClass === "OUTPUT_LIMIT")) throw error;
    }
    if (status && !status.dirty && !status.truncated && ignored === 0) return;
    const count = (value: number | undefined): string => value === undefined ? "over the output limit" : String(value);
    throw new BrokerError("POLICY_DENIED", "Worktree removal requires clean status including ignored files. " +
      `Paths found${status?.truncated ? " (at least; the status listing was truncated)" : ""}: staged ${count(status?.stagedPaths.length)}, ` +
      `unstaged ${count(status?.unstagedPaths.length)}, untracked ${count(status?.untrackedPaths.length)}, ignored ${count(ignored)} (names are not shown). ` +
      "Tracked and untracked changes can be committed with mac_git_stage and mac_git_commit (the task branch is then kept); ignored files cannot be removed by any tool");
  }

  /**
   * Deletes the task branch with `git branch -d` so commits that were never merged are never lost. The worktree is
   * already gone and recorded as removed, so a failure here is reported as a kept branch instead of failing the removal.
   */
  /**
   * Exact existence of refs/heads/<name> plus whether a ref nests below it. for-each-ref matches a pattern by prefix at
   * a slash and exits 0 with empty output for nothing, so a real Git failure is never mistaken for absence. The exact
   * ref sorts before its descendants, so two lines are enough to see both.
   */
  private async branchRefs(projectRoot: string, name: string, control: GitExecutionControl): Promise<{ exact: boolean; descendant: boolean }> {
    const lines = (await this.git(projectRoot, ["for-each-ref", "--count=2", "--format=%(refname)", `refs/heads/${name}`], control)).split("\n").filter((line) => line !== "");
    return { exact: lines[0] === `refs/heads/${name}`, descendant: lines.some((line) => line.startsWith(`refs/heads/${name}/`)) };
  }

  /** Refuses an existing branch and either direction of a Git directory/file ref conflict before any pending record exists. */
  private async assertBranchFree(projectRoot: string, name: string, control: GitExecutionControl): Promise<void> {
    const own = await this.branchRefs(projectRoot, name, control);
    if (own.exact) throw new BrokerError("CONFLICT", `Branch ${name} already exists; choose another branch_name`);
    if (own.descendant) {
      throw new BrokerError("CONFLICT", `Branch ${name} cannot be created because branches below ${name}/ already exist; choose another branch_name`);
    }
    const parts = name.split("/");
    for (let end = 1; end < parts.length; end += 1) {
      const ancestor = parts.slice(0, end).join("/");
      if ((await this.branchRefs(projectRoot, ancestor, control)).exact) {
        throw new BrokerError("CONFLICT", `Branch ${name} cannot be created because branch ${ancestor} already exists; choose another branch_name`);
      }
    }
  }

  private async deleteTaskBranch(record: ManagedWorktreeRecord, control: GitExecutionControl): Promise<WorktreeRemoval> {
    const branchName = record.branchName;
    if (!TASK_BRANCH_PATTERN.test(branchName)) return { branchName, branchDeleted: false, branchNote: "Task branch name is not a managed codex/ branch and was left alone" };
    const exists = async (): Promise<boolean> => (await this.branchRefs(record.projectRoot, branchName, control)).exact;
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
    return this.completedRemoval(projectRoot, worktree, owner, taskId, idempotencyKey) !== undefined;
  }

  /** Every record this principal ever kept for the task at this path; a removed task can be created again at the same path. */
  private recordsAt(projectRoot: string, worktree: string, owner: string, taskId: string): ManagedWorktreeRecord[] {
    return this.records.filter((entry) => entry.projectRoot === projectRoot && entry.worktree === worktree && entry.owner === owner && entry.taskId === taskId);
  }

  /**
   * The removed record this retry key completed, or undefined when the key is a fresh removal. Resolution looks at every
   * record at the path so a stale retry of an earlier removal can never act on a worktree that was created after it.
   */
  private completedRemoval(projectRoot: string, worktree: string, owner: string, taskId: string, idempotencyKey: string): ManagedWorktreeRecord | undefined {
    this.checkStorage();
    const records = this.recordsAt(projectRoot, worktree, owner, taskId);
    if (records.some((entry) => entry.state === "removing")) throw new BrokerError("UNKNOWN_OUTCOME", "Worktree removal requires operator reconciliation");
    const removed = records.filter((entry) => entry.state === "removed");
    const done = removed.find((entry) => entry.removalKey === idempotencyKey);
    if (records.some((entry) => entry.state === "active" || entry.state === "pending")) {
      if (done) {
        throw new BrokerError("CONFLICT", `IDEMPOTENCY_KEY_IN_USE: this idempotency_key already removed an earlier worktree for task ${taskId}; ` +
          "the worktree now at this path was created later and was not touched. Use a new idempotency_key to remove it");
      }
      return undefined;
    }
    if (removed.length === 0) return undefined;
    if (!done) throw new BrokerError("CONFLICT", "Removed worktree belongs to another retry key");
    if (existsSync(worktree) || existsSync(done.gitDirectory)) throw new BrokerError("CONFLICT", "Removed worktree path was reused");
    return done;
  }

  private verify(record: ManagedWorktreeRecord): void {
    this.checkStorage();
    const expectedHead = `ref: refs/heads/${record.branchName}`;
    if (!sameProjectIdentity(canonicalProjectRoot(record.projectRoot).identity, record.projectIdentity)) {
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
        !sameProjectIdentity(canonicalProjectRoot(record.projectRoot).identity, record.projectIdentity) ||
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

  private async git(cwd: string, args: readonly string[], control: GitExecutionControl, reportOutputLimit = false): Promise<string> {
    const identity = canonicalProjectRoot(cwd, this.resolveGitMetadata);
    const result = await this.supervisor.run({ executable: "/usr/bin/git", cwd, environment: SAFE_GIT_ENVIRONMENT,
      args: ["--no-pager", "--no-optional-locks", `--git-dir=${identity.gitArgument}`, "--work-tree=.",
        "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "submodule.recurse=false", ...args],
      timeoutMs: Math.min(control.timeoutMs, 30_000), outputCapBytes: 131_072, shouldCancel: control.shouldCancel });
    assertProjectIdentity(cwd, identity.identity, this.resolveGitMetadata);
    if (reportOutputLimit && (result.resultClass === "OUTPUT_LIMIT" || result.truncated)) {
      throw new BrokerError("OUTPUT_LIMIT", "Fixed worktree Git operation exceeded its output limit");
    }
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
    throw new BrokerError("PRECONDITION_FAILED", "Worktree base reference must be a branch, tag or commit name of letters, digits, . _ - and / (no \"..\" or \"//\", no revision expressions such as HEAD~1 or main@{1})");
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

/**
 * Project identities read `dev:ino:gitDev:gitIno:configDev:configIno:configSha256`. Git rewrites .git/config through a
 * lock file and rename (for example `git branch -d` on every worktree removal), which changes the config inode while the
 * bytes stay identical, so only the content digest of the config is compared, never its inode.
 */
function sameProjectIdentity(current: string, stored: string): boolean {
  const stable = (identity: string): string => {
    const parts = identity.split(":");
    return parts.length === 7 ? [...parts.slice(0, 4), parts[6]].join(":") : identity;
  };
  return stable(current) === stable(stored);
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
