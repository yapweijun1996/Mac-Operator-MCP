import { lstatSync, realpathSync } from "node:fs";
import { join, isAbsolute, resolve } from "node:path";
import { BrokerError, type BrokerRequest } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";
import { ManagedWorktrees, validateCreate, type ManagedWorktreeRecord } from "./managed-worktrees.js";
import { canonicalProjectRoot, type GitExecutionControl } from "./git-inspector.js";
import { assertContentDoesNotContainSecrets, assertContentPathAllowed } from "./secret-policy.js";
import { TaskProfileRegistry, freezeResolvedTaskProfile, type ResolvedTaskProfile } from "./task-profile.js";
import { validateTaskIsolationProof, type TaskRunner } from "./task-runner.js";
import { DEVELOPMENT_TOOL_NAMES } from "./development-policy.js";

export interface RegisteredDevelopmentCommand {
  projectRoot: string;
  type: "test" | "build" | "lint" | "typecheck" | "package_script";
  profile: string;
}

export interface AgentReadiness {
  installed: boolean;
  version: string | null;
  authentication: "ready" | "unknown" | "unavailable";
  supportedModels: readonly string[];
  /** Accepted outer-runtime evidence, not a prompt or a Codex CLI flag. */
  enforcedProfiles: readonly ("readonly" | "workspace-write" | "test-only")[];
  hostGitDenied: boolean;
  networkPolicies: readonly ("none" | "allowlist")[];
}

/** Host-owned provisioning seam. No production coding adapter ships in V2 yet. */
export interface CodingAgentProvider {
  readonly readiness: AgentReadiness;
  resolve(input: Readonly<Record<string, unknown>>, worktree: ManagedWorktreeRecord): Promise<ResolvedTaskProfile>;
}

export interface DevelopmentPlan {
  projectRoot: string;
  worktree?: string;
  taskId?: string;
  profile?: string;
  execution: boolean;
}

export interface DevelopmentGatewayOptions {
  worktrees: ManagedWorktrees;
  commands?: readonly RegisteredDevelopmentCommand[];
  codingAgent?: CodingAgentProvider;
  /** Metadata-only installation hint; never execute or read auth/config in preflight. */
  codexExecutable?: string;
}

export class DevelopmentGateway {
  readonly worktrees: ManagedWorktrees;
  private readonly commands: readonly RegisteredDevelopmentCommand[];
  private readonly agent: CodingAgentProvider | undefined;
  private readonly readiness: Readonly<AgentReadiness> | undefined;
  private readonly codexExecutable: string | undefined;

  constructor(options: DevelopmentGatewayOptions) {
    this.worktrees = options.worktrees;
    this.commands = Object.freeze((options.commands ?? []).map((entry) => {
      if (!isPlainDataRecord(entry) || Object.keys(entry).sort().join() !== "profile,projectRoot,type" ||
          !["test", "build", "lint", "typecheck", "package_script"].includes(entry.type) ||
          typeof entry.profile !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(entry.profile)) {
        throw new Error("Development command registration is malformed");
      }
      canonicalProjectRoot(entry.projectRoot);
      return Object.freeze({ ...entry });
    }));
    if (new Set(this.commands.map((entry) => `${entry.projectRoot}:${entry.type}:${entry.profile}`)).size !== this.commands.length) {
      throw new Error("Development command registration is duplicated");
    }
    this.agent = options.codingAgent;
    if (this.agent) {
      const ready = this.agent.readiness;
      if (!isPlainDataRecord(ready) || typeof ready.installed !== "boolean" || typeof ready.hostGitDenied !== "boolean" ||
          (ready.version !== null && (typeof ready.version !== "string" || ready.version.length > 128)) ||
          !["ready", "unknown", "unavailable"].includes(ready.authentication) ||
          !Array.isArray(ready.supportedModels) || ready.supportedModels.length > 32 ||
          ready.supportedModels.some(model => typeof model !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(model)) ||
          !Array.isArray(ready.enforcedProfiles) || ready.enforcedProfiles.length > 3 || ready.enforcedProfiles.some(profile => !["readonly", "workspace-write", "test-only"].includes(profile)) ||
          !Array.isArray(ready.networkPolicies) || ready.networkPolicies.length > 2 || ready.networkPolicies.some(network => !["none", "allowlist"].includes(network))) {
        throw new Error("Coding agent readiness is malformed");
      }
      this.readiness = Object.freeze({ ...ready, supportedModels: Object.freeze([...ready.supportedModels]),
        enforcedProfiles: Object.freeze([...ready.enforcedProfiles]), networkPolicies: Object.freeze([...ready.networkPolicies]) });
    }
    this.codexExecutable = options.codexExecutable;
  }

  codingAgentReady(): boolean {
    const ready = this.readiness;
    return Boolean(ready?.installed && ready.authentication === "ready" && ready.hostGitDenied && ready.enforcedProfiles.length && ready.networkPolicies.length);
  }

  close(): Promise<void> { return this.worktrees.close(); }

  assertProtectedStorage(roots: readonly { path: string }[]): void {
    for (const { path } of roots) {
      const state = this.worktrees.stateRoot;
      const trees = this.worktrees.worktreeRoot;
      if (path === "/" || path === state || state.startsWith(`${path}/`) || path.startsWith(`${state}/`) ||
          path === trees || trees.startsWith(`${path}/`)) {
        throw new BrokerError("POLICY_DENIED", "Gateway provenance and all-task storage cannot be ordinary filesystem roots");
      }
    }
  }

  plan(request: BrokerRequest): DevelopmentPlan {
    const { tool, arguments: args } = request;
    if (!DEVELOPMENT_TOOL_NAMES.includes(tool)) throw new BrokerError("UNSUPPORTED_CAPABILITY", "Unknown development operation");
    const keys: Record<string, readonly string[]> = {
      mac_git_worktree_create: ["project_root", "branch_name", "base_ref", "task_id", "idempotency_key"],
      mac_git_branch_create: ["project_root", "branch_name", "base_ref", "task_id", "idempotency_key"],
      mac_git_worktree_list: ["project_root"],
      mac_git_worktree_remove: ["project_root", "worktree", "task_id", "idempotency_key"],
      mac_codex_preflight: ["project_root", "worktree"],
      mac_codex_run: ["project_root", "worktree", "task", "task_id", "execution_profile", "max_runtime", "idempotency_key", "network_policy", "model", "allowed_paths", "validation_plan"],
      mac_test_run: ["project_root", "worktree", "task_id", "max_runtime", "idempotency_key", "profile"],
      mac_build_run: ["project_root", "worktree", "task_id", "max_runtime", "idempotency_key", "profile"],
      mac_git_push: ["project_root", "worktree", "remote", "branch_name", "approval_id", "idempotency_key"],
      mac_pr_prepare: ["project_root", "worktree", "base_ref"],
      mac_execution_audit: ["project_root", "limit"]
    };
    if (!isPlainDataRecord(args) || Object.keys(args).some((key) => !keys[tool]!.includes(key)) || typeof args.project_root !== "string") {
      throw new BrokerError("PRECONDITION_FAILED", "Development arguments are malformed");
    }
    canonicalProjectRoot(args.project_root);
    assertContentPathAllowed(args.project_root);
    const plan: DevelopmentPlan = { projectRoot: args.project_root, execution: ["mac_codex_run", "mac_test_run", "mac_build_run"].includes(tool) };
    if (args.worktree !== undefined) {
      if (typeof args.worktree !== "string") throw new BrokerError("PRECONDITION_FAILED", "Worktree must be a canonical path");
      if (!(tool === "mac_git_worktree_remove" && typeof args.task_id === "string" && typeof args.idempotency_key === "string" &&
          this.worktrees.removalRetry(plan.projectRoot, args.worktree, request.principal.principalId, args.task_id, args.idempotency_key))) {
        this.worktrees.require(args.worktree, plan.projectRoot, request.principal.principalId, typeof args.task_id === "string" ? args.task_id : undefined);
      }
      plan.worktree = args.worktree;
    }
    if (["mac_git_worktree_create", "mac_git_branch_create"].includes(tool)) {
      validateCreate({ projectRoot: plan.projectRoot, branchName: args.branch_name as string, baseRef: args.base_ref as string,
        taskId: args.task_id as string, idempotencyKey: args.idempotency_key as string, owner: request.principal.principalId });
      plan.taskId = args.task_id as string;
    }
    if (plan.execution || tool === "mac_git_worktree_remove") {
      if (!plan.worktree || typeof args.task_id !== "string" || !identifier(args.task_id) ||
          typeof args.idempotency_key !== "string" || !identifier(args.idempotency_key)) {
        throw new BrokerError("PRECONDITION_FAILED", "Execution/removal requires an owned worktree, task and retry key");
      }
      plan.taskId = args.task_id;
    }
    if (plan.execution) {
      if (!Number.isSafeInteger(args.max_runtime) || (args.max_runtime as number) < 1 || (args.max_runtime as number) > 600_000) {
        throw new BrokerError("PRECONDITION_FAILED", "Execution runtime must be bounded");
      }
      if (tool === "mac_codex_run") this.validateAgent(args, plan.worktree!);
      else {
        const type = tool === "mac_test_run" ? "test" : "build";
        const registered = this.commands.filter((entry) => entry.projectRoot === plan.projectRoot && entry.type === type &&
          (args.profile === undefined || entry.profile === args.profile));
        if (registered.length !== 1) throw new BrokerError("POLICY_DENIED", "No unambiguous approved command profile exists");
        plan.profile = registered[0]!.profile;
      }
    }
    if (tool === "mac_git_push") throw new BrokerError("POLICY_DENIED", "HIGH_RISK_PUSH_UNAVAILABLE: separate supported push authorization is required");
    if (tool === "mac_pr_prepare" && !plan.worktree) throw new BrokerError("PRECONDITION_FAILED", "Review preparation requires a managed worktree");
    if (args.base_ref !== undefined && (typeof args.base_ref !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$/u.test(args.base_ref) || args.base_ref.includes(".."))) {
      throw new BrokerError("PRECONDITION_FAILED", "Review base reference is malformed");
    }
    if (args.limit !== undefined && (!Number.isSafeInteger(args.limit) || (args.limit as number) < 1 || (args.limit as number) > 100)) {
      throw new BrokerError("PRECONDITION_FAILED", "Audit limit must be between 1 and 100");
    }
    return plan;
  }

  async prepareExecution(request: BrokerRequest, plan: DevelopmentPlan, registry: TaskProfileRegistry, runner: TaskRunner): Promise<ResolvedTaskProfile> {
    this.assertRunner(runner);
    const record = this.worktrees.require(plan.worktree!, plan.projectRoot, request.principal.principalId, plan.taskId);
    const resolved = request.tool === "mac_codex_run"
      ? await this.agent!.resolve(request.arguments, record)
      : await registry.resolve({ profile: plan.profile!, cwd: record.worktree, args: [] });
    this.worktrees.require(plan.worktree!, plan.projectRoot, request.principal.principalId, plan.taskId);
    if (["/usr/bin/sudo", "/bin/su", "/usr/bin/su"].includes(resolved.process.executable)) throw new BrokerError("POLICY_DENIED", "PRIVILEGE_ESCALATION_DENIED");
    if (resolved.cwd !== record.worktree || resolved.process.cwd !== record.worktree || resolved.credentialPolicy !== "none" ||
        !resolved.filesystemRoots.some(root => root === record.worktree || record.worktree.startsWith(`${root}/`)) ||
        (request.tool === "mac_codex_run" && (resolved.filesystemRoots.length !== 1 || resolved.filesystemRoots[0] !== record.worktree))) {
      throw new BrokerError("POLICY_DENIED", "Execution profile does not confine authority to the managed worktree");
    }
    if (resolved.networkPolicy !== "none" && resolved.networkAllowlist.length === 0) throw new BrokerError("POLICY_DENIED", "Network allowlist must be explicit");
    if (request.tool === "mac_codex_run" && resolved.networkPolicy !== request.arguments.network_policy) {
      throw new BrokerError("POLICY_DENIED", "Agent network profile differs from the requested policy");
    }
    // Restrict approved generic validation profiles to this exact task checkout.
    return freezeResolvedTaskProfile({ ...structuredClone(resolved), filesystemRoots: [record.worktree],
      process: { ...structuredClone(resolved.process), timeoutMs: Math.min(resolved.process.timeoutMs, request.arguments.max_runtime as number) } });
  }

  assertRunner(runner: TaskRunner): void {
    if (!runner.available || runner.publicEnablement !== "production") {
      throw new BrokerError("POLICY_DENIED", "PRODUCTION_ISOLATION_UNAVAILABLE");
    }
    const proof = validateTaskIsolationProof(runner.isolationProof);
    if (proof.sandboxMechanism !== runner.mechanism || proof.processTree !== "owned") {
      throw new BrokerError("POLICY_DENIED", "OWNED_PROCESS_ISOLATION_REQUIRED");
    }
  }

  preflightData(plan: DevelopmentPlan, dirty: boolean, runner: TaskRunner) {
    let ready = false;
    const reasons: string[] = [];
    try { this.assertRunner(runner); } catch { reasons.push("PRODUCTION_ISOLATION_UNAVAILABLE"); }
    if (!plan.worktree) reasons.push("MANAGED_WORKTREE_REQUIRED");
    if (!this.codingAgentReady()) reasons.push("CODING_AGENT_ADAPTER_UNAVAILABLE");
    if (this.readiness?.authentication !== "ready") reasons.push("CREDENTIAL_FREE_AUTHENTICATION_UNAVAILABLE");
    ready = reasons.length === 0;
    return { project_root: plan.projectRoot, worktree: plan.worktree ?? null,
      installed: this.readiness?.installed ?? this.installed(), version: this.readiness?.version ?? null,
      authentication: this.readiness?.authentication ?? "unknown", supported_models: [...(this.readiness?.supportedModels ?? [])],
      permission: ready ? "allow" : "deny", reason_codes: reasons,
      available_commands: this.commands.filter((entry) => entry.projectRoot === plan.projectRoot).map(({ type, profile }) => ({ type, profile })),
      git_dirty: dirty, environment_ready: ready };
  }

  private installed(): boolean {
    try {
      if (!this.codexExecutable) return false;
      const stat = lstatSync(this.codexExecutable);
      return stat.isFile() && !stat.isSymbolicLink() && realpathSync.native(this.codexExecutable) === this.codexExecutable;
    } catch { return false; }
  }

  private validateAgent(args: Readonly<Record<string, unknown>>, worktree: string): void {
    if (typeof args.task !== "string" || args.task.length < 1 || args.task.length > 16_384 || args.task.includes("\0") ||
        !["readonly", "workspace-write", "test-only"].includes(args.execution_profile as string) ||
        !["none", "allowlist"].includes(args.network_policy as string)) {
      throw new BrokerError("PRECONDITION_FAILED", "Coding task or execution/network profile is malformed");
    }
    assertContentDoesNotContainSecrets(Buffer.from(args.task));
    for (const field of ["allowed_paths", "validation_plan"]) {
      const value = args[field];
      if (value !== undefined && (!Array.isArray(value) || value.length > (field === "allowed_paths" ? 128 : 32) ||
          value.some((entry) => typeof entry !== "string" || entry.length < 1 || entry.length > (field === "allowed_paths" ? 4096 : 1024) || entry.includes("\0")))) {
        throw new BrokerError("PRECONDITION_FAILED", "Agent path/validation list is malformed");
      }
    }
    for (const path of (args.allowed_paths ?? []) as string[]) {
      if (isAbsolute(path) || resolve(worktree, path) !== join(worktree, path) || path.split("/").some((part) => part === ".." || part === ".git")) {
        throw new BrokerError("POLICY_DENIED", "Agent path escapes the worktree");
      }
      assertContentPathAllowed(join(worktree, path));
    }
    if (args.model !== undefined && (typeof args.model !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(args.model))) {
      throw new BrokerError("PRECONDITION_FAILED", "Agent model is malformed");
    }
    const readiness = this.readiness;
    if (!readiness || !readiness.installed || readiness.authentication !== "ready" || !readiness.hostGitDenied ||
        !readiness.enforcedProfiles.includes(args.execution_profile as "readonly" | "workspace-write" | "test-only") ||
        !readiness.networkPolicies.includes(args.network_policy as "none" | "allowlist")) {
      throw new BrokerError("POLICY_DENIED", "CODING_AGENT_ADAPTER_UNAVAILABLE");
    }
    if (args.model !== undefined && !readiness.supportedModels.includes(args.model as string)) {
      throw new BrokerError("POLICY_DENIED", "Agent model is not provisioned");
    }
  }
}

function identifier(value: string): boolean { return /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value); }

export function worktreeResult(record: ManagedWorktreeRecord, reused: boolean) {
  return { project_root: record.projectRoot, worktree: record.worktree, branch_name: record.branchName,
    base_ref: record.baseRef, task_id: record.taskId, reused };
}
