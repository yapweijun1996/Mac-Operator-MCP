import type { ContainerTaskJobMetadata } from "./container-job-metadata.js";
import { DevelopmentGateway, worktreeResult, type DevelopmentPlan } from "./development-gateway.js";
import { DEVELOPMENT_TOOL_NAMES, DEVELOPMENT_EXECUTION_TOOLS } from "./development-policy.js";
import { GuiProcessSupervisor, guiApplicationExecutable, guiLauncherExecutable } from "./gui-process-supervisor.js";
import {
  BrokerError,
  CAPABILITY_FAMILIES,
  canonicalJson,
  CONTRACT_VERSION,
  PROTOCOL_VERSION,
  sha256,
  signBrokerResponse,
  signBrokerRevocationResponse,
  parseJsonStrict,
  verifyRequestAuthentication,
  verifyBrokerRevocationEvent,
  type AuthenticatedBrokerRevocationResponse,
  type AuthenticatedBrokerResponse,
  type BrokerFailure,
  type BrokerRequest,
  type BrokerResult,
  type BrokerRevocationEvent,
  type BrokerRevocationResult,
  type CapabilityFamily
} from "@mac-operator/contracts";
import { randomUUID } from "node:crypto";
import { dirname, isAbsolute, join } from "node:path";
import { isPlainDataRecord } from "./plain-record.js";
import { GUI_SESSION_PREVIEW_TTL_MS, APPROVAL_PREVIEW_TTL_MS, privilegedHelperPayloadTarget, validatePrivilegedHelperPayload, TASK_JOB_TOOLS, type ArchivedJobRecord, type ApprovalConsumptionBinding, type BrokerJob, type BrokerStore, type GuestTaskJobMetadata, type JobLease, type PrivilegedHelperPayload, type WriteJobMetadata } from "./persistence.js";
import { EdgeKeyring, isValidEdgeId, keyIdentity } from "./edge-keyring.js";
import {
  authorizePrincipalProjection,
  authorizeTarget,
  authorizeTool,
  cloneBrokerPolicy,
  guiCapabilityProbeTarget,
  isCapabilityFamilyDisabled,
  runtimeToolStates,
  validateBrokerPolicy,
  type BrokerPolicy,
  type NormalizedTarget,
  type TargetKind,
  type ToolPolicy
} from "./policy.js";
import { isPolicyQueryTargetReference } from "./target-authority.js";
import { DESKTOP_APP_ID, desktopDeniedApplications, desktopDisplayHint } from "./desktop-ui.js";
import { PolicyManager } from "./policy-loader.js";
import { parseBrokerRequest, parseBrokerRevocationEvent } from "./request-validator.js";
import { FilesystemInspector, normalizeProjectTypes, type FilesystemPathPlan, type SafeWritePostcondition, type TemporaryWriteCleanupResult, type UnlinkRecoveryResult } from "./filesystem-inspector.js";
import type { FilesystemPatchResult } from "./filesystem-patch.js";
import { WorkerFilesystemExecutor, type FilesystemExecutor } from "./filesystem-executor.js";
import { inspectSystem } from "./system-inspector.js";
import { inspectNetwork } from "./network-inspector.js";
import { WorkerProcessExecutor, type ProcessExecutor } from "./process-executor.js";
import { ProcessSupervisor, type ProcessOwnershipSnapshot } from "./process-supervisor.js";
import { LaunchdServiceInspector, validateServiceId, type ServiceInspector } from "./service-inspector.js";
import { MacLogInspector, validateLogRequest, type LogInspector } from "./log-inspector.js";
import { GitBranchListInspector, GitDiffInspectorImpl, GitLogInspectorImpl, SAFE_GIT_ENVIRONMENT, GitStatusInspector, GitWriteInspectorImpl, validateGitBranchRequest, validateGitCommitRequest, validateGitDiffRequest, validateGitLogRequest, validateGitStageRequest, validateGitStatusRequest, type GitBranchInspector, type GitDiffInspector, type GitInspector, type GitLogInspector, type GitWriteInspector } from "./git-inspector.js";
import { PackageInspectorImpl, validatePackageInspectRequest, type PackageInspector, type PackageManagerRequest } from "./package-inspector.js";
import { createDockerProcessSupervisor, DOCKER_CODE_SIGNATURE_EXPECTATION, DOCKER_EXECUTABLE_CANDIDATES, DockerInspectorImpl, dockerObjectIdentityMatches, validateDockerLogsRequest, validateDockerObjectRequest, validateDockerStatusRequest, type DockerInspector, type DockerObjectType } from "./docker-inspector.js";
import { assertContentDoesNotContainSecrets, redactBoundedText } from "./secret-policy.js";
import { FailClosedTaskRunner, requireTaskIsolationProof, taskDescriptorDigest, validateTaskExecutionResult, validateTaskIsolationProof, type TaskExecutionResult, type TaskRecoveryRequest, type TaskRunner, type VirtualizationGuestTaskAdmission } from "./task-runner.js";
import { TaskProfileRegistry, validateTaskProfileRegistry, validateTaskRunArguments, type ResolvedTaskProfile } from "./task-profile.js";
import type { RootHelperSnapshotRequestAdmission } from "./root-helper-snapshot.js";
import type { RootHelperSnapshotRequestAuthority } from "./root-helper-snapshot-authority.js";
import { AppInventoryInspectorImpl, validateAppListRequest, type AppInventoryInspector } from "./app-inspector.js";
import { AppControlInspectorImpl, normalizeAppId, validateAppFocusRequest, validateAppOpenRequest, type AppControlInspector } from "./app-control.js";
import { isBoundedBrowserNavigation, MacUiInspectorImpl, UiSnapshotRegistry, VISUAL_ACTION_NAMES, validateSensitiveUiTarget, validateUiActionRequest, validateUiObserveRequest, validateUiTypeRequest, validateUiVisualActionRequest, type UiActionName, type UiCaptureMode, type UiInputKey, type UiInspector, type UiSnapshotRecord, type UiVisualActionOptions } from "./ui-inspector.js";
import { MacGuiHelperReadinessProbe, guiReadinessPermissions, type GuiHelperReadinessProbe } from "./gui-helper-readiness.js";
import { requiresAccessibilityPermission, type GuiPublicEnablement } from "./gui-readiness.js";
import { requiresDeveloperReadiness, type DeveloperPublicEnablement } from "./developer-readiness.js";
import { PrivilegedHelperJobExecutor, type PrivilegedHelperJobExecutionInput, type PrivilegedHelperJobExecutionOutcome } from "./privileged-helper-executor.js";
import { validatePrivilegedHelperExecutionResult, type PrivilegedHelperExecutionResult, type PrivilegedHelperOperation, type PrivilegedHelperResponse } from "./privileged-helper.js";
import { parseUserServiceControlArguments, UserServiceControlBrokerCandidate, type UserServiceControlCandidateExecution } from "./user-service-control-admission.js";
import { UserServiceControlAdapter, validateUserServiceControlResult, type UserServiceControlRequest } from "./user-service-control.js";
import { createServiceControlJobMetadata, UserServiceControlJobExecutor } from "./user-service-control-executor.js";
import { parseOwnerTerminalRequest, type OwnerTerminalExecutor, type OwnerTerminalRequest } from "./owner-terminal.js";
import { dispatchOwnerTerminal } from "./owner-terminal-dispatch.js";
import type { OwnerTerminalSessionManager } from "./owner-terminal-session.js";
import { parseOwnerTerminalSessionRequest, type OwnerTerminalSessionRequest } from "./owner-terminal-session-request.js";
import { dispatchOwnerTerminalSessionIo, startOwnerTerminalSession } from "./owner-terminal-session-dispatch.js";
import { validateSemanticResourceBudget, validateStorageSemanticResourceBudget } from "./resource-budget.js";

export interface GuiSessionOperation {
  requiresExplicitApproval?: boolean;
  requestId: string;
  principalId: string;
  sessionId: string;
  appId: string;
  tool: string;
  contractVersion: string;
  policyVersion: string;
  targetKind: string;
  targetRef: string;
  payloadDigest: string;
  expiresAtMs: number;
}

export interface OwnerTerminalOperation extends Omit<GuiSessionOperation, "appId"> {
  timeoutMs: number;
}

export interface DevelopmentOperation {
  requestId: string;
  principalId: string;
  sessionId: string;
  tool: string;
  contractVersion: string;
  policyVersion: string;
  targetKind: string;
  targetRef: string;
  payloadDigest: string;
  approvalClass: "trusted_write" | "trusted_profile";
  expiresAtMs: number;
  projectRoot: string;
  worktree?: string;
  taskId?: string;
}

export interface BrokerOptions {
  store: BrokerStore;
  policy: BrokerPolicy | PolicyManager;
  edgeAuthenticationKeys: EdgeKeyring;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  /** Maximum number of concurrently executing requests per principal/session. */
  maxActiveRequestsPerSession?: number;
  /** Maximum number of concurrently admitted requests across this Broker store. */
  maxActiveRequestsGlobal?: number;
  /** Maximum number of concurrently admitted requests for each capability family. */
  maxActiveRequestsByFamily?: Partial<Record<CapabilityFamily, number>>;
  now?: () => number;
  filesystemExecutor?: FilesystemExecutor;
  processExecutor?: ProcessExecutor;
  /** Shared Broker-owned OS process authority for default adapters. */
  processSupervisor?: ProcessSupervisor;
  serviceInspector?: ServiceInspector;
  logInspector?: LogInspector;
  gitInspector?: GitInspector;
  gitBranchInspector?: GitBranchInspector;
  gitLogInspector?: GitLogInspector;
  gitDiffInspector?: GitDiffInspector;
  gitWriteInspector?: GitWriteInspector;
  packageInspector?: PackageInspector;
  dockerInspector?: DockerInspector;
  appInspector?: AppInventoryInspector;
  appControlInspector?: AppControlInspector;
  uiInspector?: UiInspector;
  /** Production startup evidence gate for Accessibility-dependent GUI tools. */
  guiPublicEnablement?: GuiPublicEnablement;
  guiHelperReadiness?: GuiHelperReadinessProbe;
  /** Explicit desktop policy requires the matching native ordinary-app capability. */
  ordinaryGuiApplications?: boolean;
  /** Production startup evidence gate for D1 mutation tools. */
  developerPublicEnablement?: DeveloperPublicEnablement;
  uiSnapshotRegistry?: UiSnapshotRegistry;
  /** Owner-consented GUI session issuer; ordinary policy checks still apply. */
  authorizeGuiSession?: (operation: GuiSessionOperation) => Promise<boolean>;
  developmentGateway?: DevelopmentGateway;
  /** Explicit owner delegation restricted to owned development tasks, independent of HIGH_RISK authority. */
  authorizeDevelopment?: (operation: DevelopmentOperation) => Promise<boolean>;
  /** Explicit personal owner authority; omitted and disabled by default. */
  ownerTerminalExecutor?: OwnerTerminalExecutor;
  /** Interactive PTY sessions; share the owner-terminal delegation and scope. */
  ownerTerminalSessions?: OwnerTerminalSessionManager;
  authorizeOwnerTerminal?: (operation: OwnerTerminalOperation) => Promise<boolean>;
  taskProfileRegistry?: TaskProfileRegistry;
  taskRunner?: TaskRunner;
  /** Optional Broker-owned active-request authority for root-helper tasks. */
  rootHelperSnapshotRequestAuthority?: RootHelperSnapshotRequestAuthority;
  /** Optional privileged helper Job boundary; disabled by default. */
  privilegedHelperExecutor?: PrivilegedHelperJobExecutor;
  /** Optional MOP-104 runtime; omitted and disabled by default. */
  userServiceControlCandidate?: {
    adapter: UserServiceControlAdapter;
    executor: UserServiceControlJobExecutor;
    authorizedPrincipalIds: readonly string[];
    enabled?: boolean;
    now?: () => number;
    maxRequestAgeMs?: number;
  };
}

const JOB_LEASE_DURATION_MS = 30_000;
const JOB_LEASE_RENEW_INTERVAL_MS = 5_000;
const MAX_REQUEST_AGE_MS = 600_000;
const MAX_SESSION_LIFETIME_MS = 24 * 60 * 60 * 1_000;
const MAX_CLOCK_SKEW_MS = 60_000;
const DEFAULT_MAX_ACTIVE_REQUESTS_PER_SESSION = 8;
const MAX_ACTIVE_REQUESTS_PER_SESSION = 64;
const DEFAULT_MAX_ACTIVE_REQUESTS_GLOBAL = 64;
const MAX_ACTIVE_REQUESTS_GLOBAL = 256;
const DEFAULT_MAX_ACTIVE_REQUESTS_BY_FAMILY: Readonly<Record<CapabilityFamily, number>> = {
  read: 48,
  write: 16,
  process: 8,
  network: 8,
  gui: 4,
  destructive: 2,
  privileged: 1
};

export class Broker {
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly maxActiveRequestsPerSession: number;
  private readonly maxActiveRequestsGlobal: number;
  private readonly maxActiveRequestsByFamily: Readonly<Record<CapabilityFamily, number>>;
  private readonly now: () => number;
  private readonly filesystemExecutor: FilesystemExecutor;
  private readonly processExecutor: ProcessExecutor;
  private readonly processSupervisor: ProcessSupervisor;
  /** Separate authority so Docker cannot inherit ordinary pathname execution. */
  private readonly dockerProcessSupervisor: ProcessSupervisor | undefined;
  private readonly serviceInspector: ServiceInspector;
  private readonly logInspector: LogInspector;
  private readonly gitInspector: GitInspector;
  private readonly gitBranchInspector: GitBranchInspector;
  private readonly gitLogInspector: GitLogInspector;
  private readonly gitDiffInspector: GitDiffInspector;
  private readonly gitWriteInspector: GitWriteInspector;
  private readonly packageInspector: PackageInspector;
  private readonly dockerInspector: DockerInspector;
  private readonly appInspector: AppInventoryInspector;
  private readonly appControlInspector: AppControlInspector;
  private readonly uiInspector: UiInspector;
  private readonly guiHelperReadiness: GuiHelperReadinessProbe | undefined;
  private readonly uiSnapshotRegistry: UiSnapshotRegistry;
  private readonly taskProfileRegistry: TaskProfileRegistry;
  private readonly taskRunner: TaskRunner;
  private readonly rootHelperSnapshotRequestAuthority: RootHelperSnapshotRequestAuthority | undefined;
  private readonly privilegedHelperExecutor: PrivilegedHelperJobExecutor;
  private readonly userServiceControlCandidate: UserServiceControlBrokerCandidate | undefined;
  private readonly staticPolicy: BrokerPolicy | undefined;
  private readonly jobLeaseOwnerId: string;
  private readonly activeRequestsBySession = new Map<string, number>();
  private readonly activeAsyncTasks = new Map<string, Promise<void>>();
  private closing = false;
  private closePromise: Promise<void> | undefined;

  constructor(private readonly options: BrokerOptions) {
    const initialPolicy = options.policy instanceof PolicyManager ? options.policy.current() : options.policy;
    validateBrokerPolicy(initialPolicy);
    this.staticPolicy = options.policy instanceof PolicyManager ? undefined : cloneBrokerPolicy(initialPolicy);
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? 60_000;
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    this.maxActiveRequestsPerSession = options.maxActiveRequestsPerSession ?? DEFAULT_MAX_ACTIVE_REQUESTS_PER_SESSION;
    this.maxActiveRequestsGlobal = options.maxActiveRequestsGlobal ?? DEFAULT_MAX_ACTIVE_REQUESTS_GLOBAL;
    this.now = options.now ?? Date.now;
    if (!Number.isSafeInteger(this.maxRequestAgeMs) || this.maxRequestAgeMs < 1 || this.maxRequestAgeMs > MAX_REQUEST_AGE_MS ||
        !Number.isSafeInteger(this.allowedClockSkewMs) || this.allowedClockSkewMs < 0 || this.allowedClockSkewMs > MAX_CLOCK_SKEW_MS ||
        !Number.isSafeInteger(this.maxActiveRequestsPerSession) || this.maxActiveRequestsPerSession < 1 ||
        this.maxActiveRequestsPerSession > MAX_ACTIVE_REQUESTS_PER_SESSION ||
        !Number.isSafeInteger(this.maxActiveRequestsGlobal) || this.maxActiveRequestsGlobal < 1 ||
        this.maxActiveRequestsGlobal > MAX_ACTIVE_REQUESTS_GLOBAL) {
      throw new Error("Broker request or session limits are invalid");
    }
    if (options.maxActiveRequestsByFamily !== undefined && !isPlainDataRecord(options.maxActiveRequestsByFamily)) {
      throw new Error("Broker request or session limits are invalid");
    }
    this.maxActiveRequestsByFamily = {
      ...DEFAULT_MAX_ACTIVE_REQUESTS_BY_FAMILY,
      ...(options.maxActiveRequestsByFamily ?? {})
    };
    for (const [family, limit] of Object.entries(this.maxActiveRequestsByFamily)) {
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > MAX_ACTIVE_REQUESTS_GLOBAL ||
          !(CAPABILITY_FAMILIES as readonly string[]).includes(family)) {
        throw new Error("Broker request or session limits are invalid");
      }
    }
    if (options.maxActiveRequestsByFamily !== undefined) {
      for (const family of Object.keys(options.maxActiveRequestsByFamily)) {
        if (!Object.prototype.hasOwnProperty.call(DEFAULT_MAX_ACTIVE_REQUESTS_BY_FAMILY, family)) {
          throw new Error("Broker request or session limits are invalid");
        }
      }
    }
    this.filesystemExecutor = options.filesystemExecutor ?? new WorkerFilesystemExecutor();
    this.processExecutor = options.processExecutor ?? new WorkerProcessExecutor();
    this.processSupervisor = options.processSupervisor ?? new ProcessSupervisor({
      maxConcurrent: 16,
      requireRootOwnedExecutable: true,
      allowedEnvironmentKeys: [
        "DOCKER_CONFIG", "DOCKER_HOST", "HOME", ...Object.keys(SAFE_GIT_ENVIRONMENT)
      ],
      trustedUserOwnedExecutablePaths: [...DOCKER_EXECUTABLE_CANDIDATES, guiLauncherExecutable]
    });
    this.serviceInspector = options.serviceInspector ?? new LaunchdServiceInspector(this.processSupervisor);
    this.logInspector = options.logInspector ?? new MacLogInspector(this.processSupervisor);
    this.gitInspector = options.gitInspector ?? new GitStatusInspector(this.processSupervisor, options.developmentGateway?.worktrees.resolveGitMetadata);
    this.gitBranchInspector = options.gitBranchInspector ?? new GitBranchListInspector(this.processSupervisor, options.developmentGateway?.worktrees.resolveGitMetadata);
    this.gitLogInspector = options.gitLogInspector ?? new GitLogInspectorImpl(this.processSupervisor, options.developmentGateway?.worktrees.resolveGitMetadata);
    this.gitDiffInspector = options.gitDiffInspector ?? new GitDiffInspectorImpl(this.processSupervisor, options.developmentGateway?.worktrees.resolveGitMetadata);
    this.gitWriteInspector = options.gitWriteInspector ?? new GitWriteInspectorImpl(this.processSupervisor, options.developmentGateway?.worktrees.resolveGitMetadata);
    this.packageInspector = options.packageInspector ?? new PackageInspectorImpl();
    if (options.dockerInspector !== undefined) {
      this.dockerProcessSupervisor = undefined;
      this.dockerInspector = options.dockerInspector;
    } else {
      this.dockerProcessSupervisor = createDockerProcessSupervisor();
      this.dockerInspector = new DockerInspectorImpl({
        supervisor: this.dockerProcessSupervisor,
        requireCodeSignature: true,
        codeSignatureExpectation: DOCKER_CODE_SIGNATURE_EXPECTATION
      });
    }
    const guiSupervisor = new GuiProcessSupervisor(this.processSupervisor);
    this.guiHelperReadiness = options.guiHelperReadiness ?? (options.uiInspector === undefined && options.appControlInspector === undefined ? new MacGuiHelperReadinessProbe(undefined, timeoutMs => guiSupervisor.run({
      executable: guiApplicationExecutable, args: ["permission"], cwd: "/", timeoutMs, outputCapBytes: 4096
    }), { requireOrdinaryApplications: options.ordinaryGuiApplications === true,
      productionCapabilities: timeoutMs => guiSupervisor.run({
        executable: guiApplicationExecutable, args: ["capabilities"], cwd: "/", timeoutMs, outputCapBytes: 4096
      }) }) : undefined);
    this.appInspector = options.appInspector ?? new AppInventoryInspectorImpl(this.processSupervisor);
    this.appControlInspector = options.appControlInspector ?? new AppControlInspectorImpl(this.appInspector, guiSupervisor);
    this.uiInspector = options.uiInspector ?? new MacUiInspectorImpl(guiSupervisor);
    this.uiSnapshotRegistry = options.uiSnapshotRegistry ?? new UiSnapshotRegistry();
    this.taskProfileRegistry = options.taskProfileRegistry ?? new TaskProfileRegistry([]);
    validateTaskProfileRegistry(this.taskProfileRegistry);
    const configuredTaskRunner = options.taskRunner ?? new FailClosedTaskRunner();
    this.taskRunner = configuredTaskRunner.mechanism === null || (configuredTaskRunner.mechanism === "virtualization" || configuredTaskRunner.mechanism === "docker-container")
      ? configuredTaskRunner
      : new PersistentlyQuarantinedTaskRunner(
        configuredTaskRunner,
        () => options.store.hasUnresolvedHostTaskExecution()
      );
    if (options.rootHelperSnapshotRequestAuthority !== undefined &&
        (typeof options.rootHelperSnapshotRequestAuthority.admit !== "function" ||
         typeof options.rootHelperSnapshotRequestAuthority.assertAuthorized !== "function" ||
         typeof options.rootHelperSnapshotRequestAuthority.release !== "function" ||
         typeof options.rootHelperSnapshotRequestAuthority.revoke !== "function")) {
      throw new Error("Root-helper snapshot request authority is malformed");
    }
    this.rootHelperSnapshotRequestAuthority = options.rootHelperSnapshotRequestAuthority;
    this.privilegedHelperExecutor = options.privilegedHelperExecutor ?? new PrivilegedHelperJobExecutor({ store: options.store });
    this.userServiceControlCandidate = options.userServiceControlCandidate === undefined
      ? undefined
      : new UserServiceControlBrokerCandidate({
        store: options.store,
        adapter: options.userServiceControlCandidate.adapter,
        executor: options.userServiceControlCandidate.executor,
        authorizedPrincipalIds: options.userServiceControlCandidate.authorizedPrincipalIds,
        ...(options.userServiceControlCandidate.enabled === undefined ? {} : { enabled: options.userServiceControlCandidate.enabled }),
        ...(options.userServiceControlCandidate.now === undefined ? {} : { now: options.userServiceControlCandidate.now }),
        ...(options.userServiceControlCandidate.maxRequestAgeMs === undefined ? {} : { maxRequestAgeMs: options.userServiceControlCandidate.maxRequestAgeMs })
      });
    this.jobLeaseOwnerId = `broker:${randomUUID()}`;
  }

  private currentPolicy(): BrokerPolicy {
    return this.options.policy instanceof PolicyManager ? this.options.policy.current() : this.staticPolicy!;
  }

  /**
   * Returns the policy-enabled capabilities whose concrete runtime boundary
   * is also available. Service metadata must not advertise a capability that
   * the Broker will reject at execution planning time.
   */
  enabledRuntimeCapabilityNames(): readonly string[] {
    const policy = this.currentPolicy();
    return runtimeToolStates(policy)
      .filter((state) => state.enabled && this.runtimeCapabilityDisabledReason(state.tool) === undefined)
      .map((state) => state.tool);
  }

  async guiHelperStatus() {
    return this.guiHelperReadiness?.probe();
  }

  private runtimeCapabilityDisabledReason(toolName: string): string | undefined {
    if (toolName === "mac_terminal_exec" && (!this.options.ownerTerminalExecutor?.available || !this.options.authorizeOwnerTerminal)) return "runtime_unavailable";
    if (toolName === "mac_terminal_session" && (!this.options.ownerTerminalSessions?.available || !this.options.authorizeOwnerTerminal)) return "runtime_unavailable";
    if (TASK_JOB_TOOLS.has(toolName) && !this.taskRunner.available) return "runtime_unavailable";
    if (DEVELOPMENT_TOOL_NAMES.includes(toolName)) {
      const gateway = this.options.developmentGateway;
      if (!gateway || toolName === "mac_git_push" || toolName === "mac_codex_run" && !gateway.codingAgentReady()) return "runtime_unavailable";
      try {
        gateway.assertProtectedStorage(this.currentPolicy().filesystemRoots);
        if (DEVELOPMENT_EXECUTION_TOOLS.includes(toolName)) gateway.assertRunner(this.taskRunner);
      } catch { return "runtime_unavailable"; }
    }
    if (requiresAccessibilityPermission(toolName) && this.options.guiPublicEnablement !== undefined &&
        this.options.guiPublicEnablement !== "production") return "runtime_unavailable";
    if (requiresDeveloperReadiness(toolName) && this.options.developerPublicEnablement !== undefined &&
        this.options.developerPublicEnablement !== "production") return "runtime_unavailable";
    if (toolName === "mac_service_control" && (this.userServiceControlCandidate === undefined || !this.userServiceControlCandidate.available)) {
      return "runtime_unavailable";
    }
    if (toolName === "mac_priv_service_control" && !this.privilegedHelperExecutor.supportsOperation("service_control")) return "runtime_unavailable";
    if (toolName === "mac_priv_package_install" && !this.privilegedHelperExecutor.supportsOperation("package_install")) return "runtime_unavailable";
    if (toolName === "mac_priv_power" && !this.privilegedHelperExecutor.supportsOperation("power")) return "runtime_unavailable";
    return undefined;
  }

  /**
   * Close Broker-owned execution resources after transport shutdown. Active
   * worker-backed mutations fail through their existing UNKNOWN Job path and
   * task-runner processes are terminated and drained; callers must await this
   * boundary before closing the BrokerStore.
   */
  close(): Promise<void> {
    if (this.closePromise !== undefined) return this.closePromise;
    this.closing = true;
    const resources = [this.filesystemExecutor, this.processExecutor, this.processSupervisor, this.dockerProcessSupervisor, this.taskRunner, this.options.ownerTerminalExecutor, this.options.ownerTerminalSessions];
    this.closePromise = (async () => {
      let firstError: unknown;
      for (const resource of resources) {
        if (resource === undefined) continue;
        if (typeof resource.close !== "function") continue;
        try { await resource.close.call(resource); }
        catch (error) { firstError ??= error; }
      }
      // Background Jobs retain BrokerStore authority until their terminal
      // persistence and audit settle. Never close the store around a child.
      await Promise.allSettled([...this.activeAsyncTasks.values()]);
      await this.options.developmentGateway?.close();
      if (firstError !== undefined) {
        // Keep the Broker fenced against new work, but permit an explicit
        // shutdown retry after a resource reports a recoverable close failure.
        this.closePromise = undefined;
        throw firstError;
      }
    })();
    return this.closePromise;
  }

  /**
   * Internal-only MOP-104 candidate path. No MCP, HTTPS Edge, or IPC handler
   * calls this method; public capability discovery remains unchanged. The
   * candidate is explicitly disabled unless its adapter, executor, principal
   * allowlist, and host evidence are supplied by a local owner process.
   */
  async executeUserServiceControlCandidate(rawRequest: unknown): Promise<UserServiceControlCandidateExecution> {
    const candidate = this.userServiceControlCandidate;
    if (candidate === undefined) {
      throw new BrokerError("UNSUPPORTED_CAPABILITY", "User service-control candidate is not configured");
    }
    const request = parseBrokerRequest(rawRequest);
    const startedAt = this.now();
    const policy = this.currentPolicy();
    this.authenticate(request, startedAt, policy);
    this.checkRevocation(request);
    if (request.policyVersion !== policy.version) {
      throw new BrokerError("POLICY_DENIED", "Request policy version is not active");
    }
    authorizePrincipalProjection(
      policy,
      request.principal.principalId,
      request.principal.issuer,
      request.principal.scopes
    );
    this.reserveSessionRequest(request.principal.principalId, request.principal.sessionId);
    const assertAuthority = (): void => {
      if (this.closing) throw new BrokerError("CANCELLED", "Broker is shutting down");
      if (this.now() >= request.principal.expiresAtMs) throw new BrokerError("CANCELLED", "Active work session expired");
      this.checkRevocation(request);
      const currentPolicy = this.currentPolicy();
      if (currentPolicy.version !== request.policyVersion || currentPolicy.killSwitches.global || currentPolicy.killSwitches.mutations ||
          this.options.store.isSwitchDisabled("global") || this.options.store.isSwitchDisabled("mutations")) {
        throw new BrokerError("REVOKED", "User service-control candidate authority is no longer active");
      }
      authorizePrincipalProjection(
        currentPolicy,
        request.principal.principalId,
        request.principal.issuer,
        request.principal.scopes
      );
    };
    try {
      const admission = await candidate.admit(request, { assertRequestAuthority: assertAuthority }, {
        maxActiveRequestsGlobal: this.maxActiveRequestsGlobal,
        maxActiveRequestsPerSession: this.maxActiveRequestsPerSession,
        maxActiveRequestsByFamily: this.maxActiveRequestsByFamily
      });
      return await candidate.execute(admission, { assertRequestAuthority: assertAuthority });
    } finally {
      this.releaseSessionRequest(request.principal.principalId, request.principal.sessionId);
    }
  }

  /**
   * Host-startup recovery hook for user-service Jobs left unresolved by a
   * prior Broker instance. Recovery performs readback only: it never replays
   * a service mutation or promotes an UNKNOWN Job to success.
   */
  async reconcileRestartedUserServiceJobs(limit = 100): Promise<{
    inspected: number;
    readback: number;
    identityMismatch: number;
    unavailable: number;
    unknown: number;
  }> {
    const candidate = this.userServiceControlCandidate;
    if (candidate === undefined) {
      return { inspected: 0, readback: 0, identityMismatch: 0, unavailable: 0, unknown: 0 };
    }
    return candidate.executor.reconcileRestartedJobs(limit);
  }

  /**
   * Reconcile exact temporary artifacts left by writes interrupted at a
   * Broker restart. This is deliberately an explicit host-startup hook, not
   * an MCP tool: the caller must establish that the prior Broker instance no
   * longer owns active workers before invoking it.
   */
  reconcileRestartedWriteArtifacts(limit = 100): {
    inspected: number;
    removed: number;
    absent: number;
    skipped: number;
  } {
    const policy = this.currentPolicy();
    const jobs = this.options.store.restartUnknownWriteJobs(limit);
    if (jobs.length === 0) return { inspected: 0, removed: 0, absent: 0, skipped: 0 };
    if (policy.killSwitches.global || policy.killSwitches.mutations) {
      return { inspected: jobs.length, removed: 0, absent: 0, skipped: jobs.length };
    }
    const inspector = new FilesystemInspector(policy.filesystemRoots);
    let removed = 0;
    let absent = 0;
    let skipped = 0;
    for (const job of jobs) {
      const metadata = job.writeMetadata;
      const auditRequestId = `job-temp-cleanup-${job.jobId}-${job.revision}`;
      if (metadata?.temporaryName === undefined) {
        skipped += 1;
        continue;
      }
      if (metadata.rootPath === undefined || metadata.rootDevice === undefined || metadata.rootInode === undefined) {
        // Legacy write rows do not contain the policy-root identity required
        // to prove that restart cleanup still addresses the original root.
        skipped += 1;
        continue;
      }
      const temporaryName = metadata.temporaryName;
      const targetRef = `path:${metadata.path}`;
      const priorCompletion = this.options.store.auditEventResult(auditRequestId, "completion");
      if (priorCompletion !== undefined) {
        if (priorCompletion === "TEMPORARY_REMOVED" || priorCompletion === "TEMPORARY_ABSENT" || priorCompletion === "TEMPORARY_RECOVERED") absent += 1;
        else if (priorCompletion === "TEMPORARY_CLEANUP_SKIPPED") {
          // A failed inspection may be transient (for example, a temporary
          // root identity race). Retry the exact recorded artifact later;
          // cleanupWriteTemporary still applies its own identity and symlink
          // checks before unlinking anything.
        } else {
          skipped += 1;
          continue;
        }
      }
      if (!this.options.store.auditEventExists(auditRequestId, "intent")) {
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_write_temporary_cleanup",
          eventType: "intent",
          decision: "allow",
          resultClass: "INTENT_RECORDED",
          targetRef,
          policyVersion: job.policyVersion,
          evidence: { jobId: job.jobId, jobRevision: job.revision, rootId: metadata.rootId, temporaryName: metadata.temporaryName },
          timestampMs: this.now()
        });
      }
      let activeJob = job;
      let activeMetadata = metadata;
      let plan: FilesystemPathPlan | undefined;
      let result: TemporaryWriteCleanupResult;
      const recordRecoveryCompletion = (recovery: UnlinkRecoveryResult): boolean => {
        if (recovery.status !== "recovered") return false;
        removed += 1;
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_write_temporary_cleanup",
          eventType: "completion",
          decision: "allow",
          resultClass: "TEMPORARY_RECOVERED",
          targetRef,
          policyVersion: job.policyVersion,
          evidence: {
            jobId: activeJob.jobId,
            jobRevision: activeJob.revision,
            rootId: activeMetadata.rootId,
            temporaryName,
            temporaryDevice: activeMetadata.temporaryDevice,
            temporaryInode: activeMetadata.temporaryInode,
            temporaryRecoveryRecordedAtMs: activeMetadata.temporaryRecoveryRecordedAtMs,
            path: recovery.path,
            quarantinePath: recovery.quarantinePath,
            recoveryStatus: recovery.status
          },
          timestampMs: this.now()
        });
        return true;
      };
      try {
        plan = inspector.planPath(activeMetadata.path, "write");
        if (plan.rootId !== activeMetadata.rootId) throw new BrokerError("POLICY_DENIED", "Write temporary root identity no longer matches");
        if (plan.rootIdentity.rootPath !== activeMetadata.rootPath ||
            plan.rootIdentity.device !== activeMetadata.rootDevice ||
            plan.rootIdentity.inode !== activeMetadata.rootInode) {
          throw new BrokerError("POLICY_DENIED", "Write temporary policy root identity no longer matches");
        }
        const hasRecordedIdentity = activeMetadata.temporaryDevice !== undefined && activeMetadata.temporaryInode !== undefined;
        if (hasRecordedIdentity) {
          const temporaryPlan = inspector.planPath(join(dirname(activeMetadata.path), temporaryName), "write");
          if (temporaryPlan.rootId !== activeMetadata.rootId) throw new BrokerError("POLICY_DENIED", "Write temporary recovery root identity no longer matches");
          if (temporaryPlan.rootIdentity.rootPath !== activeMetadata.rootPath ||
              temporaryPlan.rootIdentity.device !== activeMetadata.rootDevice ||
              temporaryPlan.rootIdentity.inode !== activeMetadata.rootInode) {
            throw new BrokerError("POLICY_DENIED", "Write temporary policy root identity no longer matches");
          }
          const recovery = inspector.recoverUnlinkOrphan(temporaryPlan, {
            present: true,
            device: activeMetadata.temporaryDevice!,
            inode: activeMetadata.temporaryInode!
          });
          if (recovery.status === "recovered") {
            recordRecoveryCompletion(recovery);
            continue;
          }
          if (recovery.status === "not_stale" || recovery.status === "ambiguous") {
            throw new BrokerError("CONFLICT", "Filesystem temporary recovery artifact is recent or ambiguous");
          }
        }
        result = inspector.cleanupWriteTemporary(plan, temporaryName, (artifact) => {
          const hasRecordedIdentity = activeMetadata.temporaryDevice !== undefined && activeMetadata.temporaryInode !== undefined;
          if (hasRecordedIdentity) {
            if (activeMetadata.temporaryDevice !== artifact.device || activeMetadata.temporaryInode !== artifact.inode) {
              throw new BrokerError("CONFLICT", "Filesystem temporary artifact identity no longer matches the recovery journal");
            }
            return;
          }
          activeJob = this.options.store.recordWriteUnlinkRecovery(
            activeJob.jobId,
            activeJob.ownerPrincipalId,
            activeJob.revision,
            { device: artifact.device, inode: artifact.inode },
            this.now()
          );
          activeMetadata = activeJob.writeMetadata ?? activeMetadata;
        });
      } catch (error) {
        if (plan !== undefined && activeMetadata.temporaryDevice !== undefined && activeMetadata.temporaryInode !== undefined) {
          try {
            const temporaryPlan = inspector.planPath(join(dirname(activeMetadata.path), temporaryName), "write");
            if (temporaryPlan.rootId !== activeMetadata.rootId) throw new BrokerError("POLICY_DENIED", "Write temporary recovery root identity no longer matches");
            if (temporaryPlan.rootIdentity.rootPath !== activeMetadata.rootPath ||
                temporaryPlan.rootIdentity.device !== activeMetadata.rootDevice ||
                temporaryPlan.rootIdentity.inode !== activeMetadata.rootInode) {
              throw new BrokerError("POLICY_DENIED", "Write temporary policy root identity no longer matches");
            }
            const recovery = inspector.recoverUnlinkOrphan(temporaryPlan, {
              present: true,
              device: activeMetadata.temporaryDevice,
              inode: activeMetadata.temporaryInode
            });
            if (recordRecoveryCompletion(recovery)) continue;
          } catch {
            // Preserve the original cleanup failure below. A recovery scan
            // that cannot prove a unique stale artifact must fail closed.
          }
        }
        skipped += 1;
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_write_temporary_cleanup",
          eventType: "completion",
          decision: "allow",
          resultClass: "TEMPORARY_CLEANUP_SKIPPED",
          targetRef,
          policyVersion: job.policyVersion,
          evidence: {
            jobId: job.jobId,
            jobRevision: activeJob.revision,
            errorClass: error instanceof BrokerError ? error.errorClass : "EXECUTION_FAILED"
          },
          timestampMs: this.now()
        });
        continue;
      }
      if (result.status === "removed") removed += 1;
      else absent += 1;
      this.options.store.appendAudit({
        requestId: auditRequestId,
        principalId: job.ownerPrincipalId,
        tool: "internal_write_temporary_cleanup",
        eventType: "completion",
        decision: "allow",
        resultClass: result.status === "removed" ? "TEMPORARY_REMOVED" : "TEMPORARY_ABSENT",
        targetRef,
        policyVersion: job.policyVersion,
        evidence: {
          jobId: activeJob.jobId,
          jobRevision: activeJob.revision,
          rootId: activeMetadata.rootId,
          temporaryName,
          ...(activeMetadata.temporaryDevice !== undefined ? { temporaryDevice: activeMetadata.temporaryDevice } : {}),
          ...(activeMetadata.temporaryInode !== undefined ? { temporaryInode: activeMetadata.temporaryInode } : {}),
          ...(activeMetadata.temporaryRecoveryRecordedAtMs !== undefined ? { temporaryRecoveryRecordedAtMs: activeMetadata.temporaryRecoveryRecordedAtMs } : {}),
          path: result.path,
          ...(result.device !== null ? { device: result.device, inode: result.inode } : {})
        },
        timestampMs: this.now()
      });
    }
    return { inspected: jobs.length, removed, absent, skipped };
  }

  /**
   * Host-startup hook for task processes left by a prior Broker instance.
   * Every candidate is already UNKNOWN; recovery may only terminate an exact
   * persisted PID/start-time identity and never promotes the Job to success.
   */
  async reconcileRestartedTaskProcesses(limit = 100): Promise<{
    inspected: number;
    drained: number;
    absent: number;
    identityMismatch: number;
    unknown: number;
  }> {
    const jobs = this.options.store.unresolvedTaskProcessJobs(limit);
    if (jobs.length === 0) return { inspected: 0, drained: 0, absent: 0, identityMismatch: 0, unknown: 0 };
    let drained = 0;
    let absent = 0;
    let identityMismatch = 0;
    let unknown = 0;
    for (const job of jobs) {
      const metadata = job.processMetadata;
      const auditRequestId = `job-process-recovery-${job.jobId}-${job.revision}`;
      if (metadata === undefined) {
        unknown += 1;
        continue;
      }
      const targetRef = `job:${job.jobId}`;
      const priorCompletion = this.options.store.auditEventResult(auditRequestId, "completion");
      if (priorCompletion !== undefined) {
        if (priorCompletion === "PROCESS_DRAINED") drained += 1;
        else if (priorCompletion === "PROCESS_ABSENT") absent += 1;
        else if (priorCompletion === "PROCESS_IDENTITY_MISMATCH") identityMismatch += 1;
        // A recovery observer failure is not terminal. Retry on a later
        // startup using the same persisted PID/start-time identity; never
        // promote the Job and never issue a fresh task execution request.
        if (priorCompletion === "PROCESS_RECOVERY_UNKNOWN") {
          // Continue below and record the fresh observation only.
        } else {
          if (priorCompletion !== "PROCESS_DRAINED" && priorCompletion !== "PROCESS_ABSENT" &&
              priorCompletion !== "PROCESS_IDENTITY_MISMATCH") unknown += 1;
          continue;
        }
      }
      if (!this.options.store.auditEventExists(auditRequestId, "intent")) {
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_task_process_recovery",
          eventType: "intent",
          decision: "allow",
          resultClass: "INTENT_RECORDED",
          targetRef,
          policyVersion: job.policyVersion,
          evidence: { jobId: job.jobId, jobRevision: job.revision, pid: metadata.pid, processGroupId: metadata.processGroupId },
          timestampMs: this.now()
        });
      }
      let outcome: "PROCESS_DRAINED" | "PROCESS_ABSENT" | "PROCESS_IDENTITY_MISMATCH" | "PROCESS_RECOVERY_UNKNOWN";
      try {
        const result = await this.processSupervisor.recoverOwnedProcess({
          identity: {
            pid: metadata.pid,
            processGroupId: metadata.processGroupId,
            startTimeMicros: metadata.startTimeMicros
          },
          ...(metadata.ownershipProof === undefined ? {} : { ownershipProof: metadata.ownershipProof }),
          descendants: metadata.descendants.map((descendant) => ({
            pid: descendant.pid,
            startTimeMicros: descendant.startTimeMicros
          }))
        }, 5_000);
        outcome = result.outcome === "drained" ? "PROCESS_DRAINED" :
          result.outcome === "absent" ? "PROCESS_ABSENT" :
            result.outcome === "identity_mismatch" ? "PROCESS_IDENTITY_MISMATCH" : "PROCESS_RECOVERY_UNKNOWN";
      } catch {
        outcome = "PROCESS_RECOVERY_UNKNOWN";
      }
      if (outcome === "PROCESS_DRAINED") drained += 1;
      else if (outcome === "PROCESS_ABSENT") absent += 1;
      else if (outcome === "PROCESS_IDENTITY_MISMATCH") identityMismatch += 1;
      else unknown += 1;
      this.options.store.appendAudit({
        requestId: auditRequestId,
        principalId: job.ownerPrincipalId,
        tool: "internal_task_process_recovery",
        eventType: "completion",
        decision: "allow",
        resultClass: outcome,
        targetRef,
        policyVersion: job.policyVersion,
        evidence: { jobId: job.jobId, jobRevision: job.revision, pid: metadata.pid, processGroupId: metadata.processGroupId },
        timestampMs: this.now()
      });
    }
    return { inspected: jobs.length, drained, absent, identityMismatch, unknown };
  }

  /**
   * Host-startup hook for Virtualization guest tasks whose request was
   * admitted before the prior Broker instance stopped. Recovery never replays
   * execution: it asks the authenticated guest for the original task status,
   * and only a signed, verified terminal readback may close the Job.
   */
  async reconcileRestartedContainerTasks(limit = 1000): Promise<{ inspected: number; cleaned: number; unresolved: number }> {
    const jobs = this.options.store.listUnresolvedTaskContainers(limit);
    let cleaned = 0;
    for (const job of jobs) {
      if (job.state !== "unknown" || job.containerMetadata === undefined ||
          this.taskRunner.mechanism !== "docker-container" || !this.taskRunner.recoverContainerTask) continue;
      try {
        if (!await this.taskRunner.recoverContainerTask(job.containerMetadata)) continue;
        this.options.store.reconcileUnknownContainerTask(job.jobId, job.ownerPrincipalId, job.revision,
          job.containerMetadata, { state: job.cancelRequested ? "cancelled" : "failed",
            finishedAtMs: this.now(), containerCleanupVerified: true });
        cleaned += 1;
      } catch { /* Keep exact durable identity unresolved when cleanup cannot be proven. */ }
    }
    return { inspected: jobs.length, cleaned, unresolved: jobs.length - cleaned };
  }

  async reconcileRestartedGuestTasks(limit = 100): Promise<{
    inspected: number;
    recovered: number;
    unavailable: number;
    unknown: number;
    skipped: number;
  }> {
    const jobs = this.options.store.restartUnknownGuestJobs(limit);
    if (jobs.length === 0) return { inspected: 0, recovered: 0, unavailable: 0, unknown: 0, skipped: 0 };
    const policy = this.currentPolicy();
    let recovered = 0;
    let unavailable = 0;
    let unknown = 0;
    let skipped = 0;
    for (const job of jobs) {
      const metadata = job.guestMetadata;
      const auditRequestId = `job-guest-recovery-${job.jobId}-${job.revision}`;
      if (metadata === undefined) {
        unknown += 1;
        continue;
      }
      const priorCompletion = this.options.store.auditEventResult(auditRequestId, "completion");
      if (priorCompletion !== undefined) {
        if (priorCompletion === "GUEST_RECOVERED") recovered += 1;
        else if (priorCompletion !== "GUEST_RECOVERY_UNAVAILABLE" && priorCompletion !== "GUEST_RECOVERY_UNKNOWN") skipped += 1;
        if (priorCompletion === "GUEST_RECOVERED" ||
            (priorCompletion !== "GUEST_RECOVERY_UNAVAILABLE" && priorCompletion !== "GUEST_RECOVERY_UNKNOWN")) continue;
      }
      if (!this.options.store.auditEventExists(auditRequestId, "intent")) {
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_virtualization_guest_recovery",
          eventType: "intent",
          decision: "allow",
          resultClass: "INTENT_RECORDED",
          targetRef: `job:${job.jobId}`,
          policyVersion: job.policyVersion,
          evidence: {
            jobId: job.jobId,
            jobRevision: job.revision,
            requestId: metadata.requestId,
            requestDigest: metadata.requestDigest,
            guestImageSha256: metadata.guestIdentity.imageSha256,
            guestRuntimeVersion: metadata.guestIdentity.runtimeVersion
          },
          timestampMs: this.now()
        });
      }
      const tool = policy.tools.get(job.tool);
      if (policy.killSwitches.global || policy.killSwitches.process || tool?.implemented !== true || tool.enabled !== true ||
          job.policyVersion !== policy.version || this.options.store.isRevoked("principal", job.ownerPrincipalId) ||
          this.options.store.isRevoked("session", job.ownerSessionId) ||
          (job.ownerEdgeId !== null && this.options.store.isRevoked("edge", job.ownerEdgeId)) ||
          (job.ownerEdgeKeyId !== null && this.options.store.isRevoked("edge_key", job.ownerEdgeKeyId)) ||
          (job.guestResultJournal === undefined && (this.taskRunner.mechanism !== "virtualization" ||
            typeof this.taskRunner.recoverUnknownTask !== "function"))) {
        unavailable += 1;
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_virtualization_guest_recovery",
          eventType: "completion",
          decision: "allow",
          resultClass: "GUEST_RECOVERY_UNAVAILABLE",
          targetRef: `job:${job.jobId}`,
          policyVersion: job.policyVersion,
          evidence: { jobId: job.jobId, jobRevision: job.revision },
          timestampMs: this.now()
        });
        continue;
      }
      const authorizeStatusLookup = (input: Parameters<NonNullable<TaskRecoveryRequest["authorizeStatusLookup"]>>[0]): void => {
        const currentPolicy = this.currentPolicy();
        const currentTool = currentPolicy.tools.get(job.tool);
        if (input.originalRequestId !== metadata.requestId || input.originalNonce !== metadata.nonce ||
            input.originalRequestDigest !== metadata.requestDigest || input.timeoutMs !== metadata.timeoutMs ||
            input.outputCapBytes !== metadata.outputCapBytes ||
            input.guestIdentity.imageSha256 !== metadata.guestIdentity.imageSha256 ||
            input.guestIdentity.runtimeVersion !== metadata.guestIdentity.runtimeVersion) {
          throw new BrokerError("POLICY_DENIED", "Guest status lookup is not bound to the persisted Job");
        }
        if (currentPolicy.killSwitches.global || currentPolicy.killSwitches.process || currentTool?.implemented !== true ||
            currentTool.enabled !== true || job.policyVersion !== currentPolicy.version ||
            this.options.store.isRevoked("principal", job.ownerPrincipalId) || this.options.store.isRevoked("session", job.ownerSessionId) ||
            (job.ownerEdgeId !== null && this.options.store.isRevoked("edge", job.ownerEdgeId)) ||
            (job.ownerEdgeKeyId !== null && this.options.store.isRevoked("edge_key", job.ownerEdgeKeyId))) {
          throw new BrokerError("REVOKED", "Guest status lookup authority is revoked");
        }
      };
      let result: TaskExecutionResult;
      try {
        authorizeStatusLookup({
          guestIdentity: metadata.guestIdentity,
          originalRequestId: metadata.requestId,
          originalNonce: metadata.nonce,
          originalRequestDigest: metadata.requestDigest,
          timeoutMs: metadata.timeoutMs,
          outputCapBytes: metadata.outputCapBytes
        });
        if (job.guestResultJournal !== undefined) {
          result = job.guestResultJournal.result;
        } else if (typeof this.taskRunner.recoverUnknownTask === "function") {
          result = await this.taskRunner.recoverUnknownTask({
            metadata,
            authorizeStatusLookup,
            shouldCancel: () => {
              if (this.closing) return true;
              try {
                authorizeStatusLookup({
                  guestIdentity: metadata.guestIdentity,
                  originalRequestId: metadata.requestId,
                  originalNonce: metadata.nonce,
                  originalRequestDigest: metadata.requestDigest,
                  timeoutMs: metadata.timeoutMs,
                  outputCapBytes: metadata.outputCapBytes
                });
                return false;
              } catch {
                return true;
              }
            }
          });
        } else {
          throw new BrokerError("POLICY_DENIED", "Guest result recovery is unavailable");
        }
      } catch (error) {
        if (error instanceof BrokerError && error.errorClass === "POLICY_DENIED") unavailable += 1;
        else unknown += 1;
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_virtualization_guest_recovery",
          eventType: "completion",
          decision: "allow",
          resultClass: error instanceof BrokerError && error.errorClass === "POLICY_DENIED" ? "GUEST_RECOVERY_UNAVAILABLE" : "GUEST_RECOVERY_UNKNOWN",
          targetRef: `job:${job.jobId}`,
          policyVersion: job.policyVersion,
          evidence: { jobId: job.jobId, jobRevision: job.revision, errorClass: error instanceof BrokerError ? error.errorClass : "UNKNOWN" },
          timestampMs: this.now()
        });
        continue;
      }
      if (result.state === "unknown" || result.verification.status !== "verified" || result.truncated ||
          result.durationMs > metadata.timeoutMs ||
          Buffer.byteLength(result.stdout, "utf8") + Buffer.byteLength(result.stderr, "utf8") > metadata.outputCapBytes) {
        unknown += 1;
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_virtualization_guest_recovery",
          eventType: "completion",
          decision: "allow",
          resultClass: "GUEST_RECOVERY_UNKNOWN",
          targetRef: `job:${job.jobId}`,
          policyVersion: job.policyVersion,
          evidence: { jobId: job.jobId, jobRevision: job.revision, state: result.state, resultClass: result.resultClass, verification: result.verification.status },
          timestampMs: this.now()
        });
        continue;
      }
      const terminalState = result.state === "completed" ? "completed" : result.state === "cancelled" ? "cancelled" : "failed";
      const resultClass = result.resultClass === "SUCCEEDED" ? "success" : terminalState === "cancelled" ? "denied" : result.resultClass === "TIMEOUT" || result.resultClass === "OUTPUT_LIMIT" ? "failed" : "failed";
      try {
        authorizeStatusLookup({
          guestIdentity: metadata.guestIdentity,
          originalRequestId: metadata.requestId,
          originalNonce: metadata.nonce,
          originalRequestDigest: metadata.requestDigest,
          timeoutMs: metadata.timeoutMs,
          outputCapBytes: metadata.outputCapBytes
        });
        this.options.store.reconcileUnknownGuestTask(job.jobId, job.ownerPrincipalId, job.revision, {
          state: terminalState,
          resultClass,
          finishedAtMs: this.now(),
          exitCode: result.exitCode,
          stdout: redactBoundedText(result.stdout, Math.max(1, Math.floor((tool?.outputCapBytes ?? 4_096) / 2))).text,
          stderr: redactBoundedText(result.stderr, Math.max(1, Math.floor((tool?.outputCapBytes ?? 4_096) / 2))).text,
          verificationStatus: "verified"
        });
        recovered += 1;
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_virtualization_guest_recovery",
          eventType: "completion",
          decision: "allow",
          resultClass: "GUEST_RECOVERED",
          targetRef: `job:${job.jobId}`,
          policyVersion: job.policyVersion,
          evidence: { jobId: job.jobId, jobRevision: job.revision, state: terminalState, resultClass },
          timestampMs: this.now()
        });
      } catch (error) {
        unknown += 1;
        this.options.store.appendAudit({
          requestId: auditRequestId,
          principalId: job.ownerPrincipalId,
          tool: "internal_virtualization_guest_recovery",
          eventType: "completion",
          decision: "allow",
          resultClass: "GUEST_RECOVERY_UNKNOWN",
          targetRef: `job:${job.jobId}`,
          policyVersion: job.policyVersion,
          evidence: { jobId: job.jobId, jobRevision: job.revision, errorClass: error instanceof BrokerError ? error.errorClass : "UNKNOWN" },
          timestampMs: this.now()
        });
      }
    }
    return { inspected: jobs.length, recovered, unavailable, unknown, skipped };
  }

  /**
   * Host lifecycle hook used when the authenticated Edge process identity is
   * lost. This is not exposed through MCP; it records a durable revocation so
   * queued work is cancelled and active workers fail their next authority
   * check instead of publishing a late success.
   */
  revokeEdge(edgeId: string, reason = "Edge peer process identity was lost", nowMs = this.now()): void {
    if (!isValidEdgeId(edgeId)) {
      throw new Error("Edge identity is invalid");
    }
    this.options.store.revoke("edge", edgeId, reason, nowMs);
  }

  /**
   * Host-only privileged Job seam. MCP dispatch does not call this method
   * while privileged tools remain disabled; future L5 handlers must use this
   * seam so active Broker authority is checked on both sides of helper IPC.
   */
  executePrivilegedHelperJob(
    input: Omit<PrivilegedHelperJobExecutionInput, "assertAuthority"> & {
      request: BrokerRequest;
      target: NormalizedTarget;
      additionalTargets?: readonly NormalizedTarget[];
    }
  ): Promise<PrivilegedHelperJobExecutionOutcome> {
    if (this.closing) return Promise.reject(new BrokerError("CANCELLED", "Broker is shutting down"));
    if (input.request.principal.principalId !== input.principalId || input.request.principal.sessionId !== input.sessionId ||
        input.request.requestId !== input.requestId) {
      return Promise.reject(new BrokerError("AUTH_INVALID", "Privileged helper Job request identity is not bound"));
    }
    const assertAuthority = () => this.ensureActiveAuthority(
      input.request,
      input.target,
      input.additionalTargets ?? []
    );
    // The Broker owns the first authority decision; the executor repeats it
    // immediately before command issuance and after helper readback.
    assertAuthority();
    return this.privilegedHelperExecutor.execute({ ...input, assertAuthority });
  }

  async handle(rawRequest: unknown): Promise<BrokerResult> {
    const startedAt = this.now();
    const policy = this.currentPolicy();
    let request: BrokerRequest | undefined;
    let admitted = false;
    let authorized = false;
    let uiApprovalConsumed = false;
    let plannedAuditTarget: string | undefined;
    let sessionReserved = false;
    try {
      if (this.closing) throw new BrokerError("CANCELLED", "Broker is shutting down");
      request = parseBrokerRequest(rawRequest);
      this.authenticate(request, startedAt, policy);
      this.reserveSessionRequest(request.principal.principalId, request.principal.sessionId);
      sessionReserved = true;
      const requestedToolPolicy = policy.tools.get(request.tool);
      this.options.store.admitRequest({
        requestId: request.requestId,
        edgeId: request.principal.edgeId,
        edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
        nonce: request.nonce,
        nonceExpiresAtMs: startedAt + this.maxRequestAgeMs + this.allowedClockSkewMs,
        principalId: request.principal.principalId,
        sessionId: request.principal.sessionId,
        tool: request.tool,
        policyVersion: request.policyVersion,
        payloadDigest: sha256(canonicalJson(request)),
        mutation: requestedToolPolicy?.mutation ?? false,
        ...(requestedToolPolicy === undefined ? {} : { capabilityFamilies: requestedToolPolicy.capabilityFamilies }),
        receivedAtMs: startedAt
      }, {
        maxActiveRequestsGlobal: this.maxActiveRequestsGlobal,
        maxActiveRequestsPerSession: this.maxActiveRequestsPerSession,
        maxActiveRequestsByFamily: this.maxActiveRequestsByFamily
      });
      admitted = true;
      if (request.policyVersion !== policy.version) {
        throw new BrokerError("POLICY_DENIED", "Request policy version is not active");
      }
      this.checkRevocation(request);
      authorizePrincipalProjection(
        policy,
        request.principal.principalId,
        request.principal.issuer,
        request.principal.scopes
      );
      const toolPolicy = authorizeTool(
        this.options.store,
        policy,
        request.tool,
        request.contractVersion,
        request.principal.scopes
      );
      const execution = this.planExecution(request, policy, toolPolicy);
      const target = execution.target;
      if (target.kind === "project" && this.options.developmentGateway && typeof request.arguments.project_root === "string" &&
          request.arguments.project_root !== target.reference) {
        const record = this.options.developmentGateway.worktrees.require(request.arguments.project_root, target.reference, request.principal.principalId);
        execution.auditContext = { project: target.reference, worktree: record.worktree, taskId: record.taskId };
        if (["mac_git_stage", "mac_git_commit"].includes(request.tool) && this.options.store.hasActiveWorktreeJobs(record.worktree, "job:git-preview")) {
          throw new BrokerError("CONFLICT", "Git mutation must wait for the worktree job to settle");
        }
      }
      if (request.tool === "mac_ui_action" || request.tool === "mac_ui_type") {
        const elementRef = request.tool === "mac_ui_action" ? execution.uiAction?.elementRef : execution.uiType?.elementRef;
        if (!elementRef) throw new BrokerError("EXECUTION_FAILED", "UI execution plan is unavailable");
        const snapshot = this.uiSnapshotRegistry.resolve(
          elementRef,
          request.principal.principalId,
          request.principal.sessionId,
          this.now(),
          uiApprovalBinding(request)
        );
        authorizeTarget(policy, request.principal.principalId, toolPolicy.requiredScopes, {
          kind: "app_window",
          reference: `window:${snapshot.appId}`
        });
        validateSensitiveUiTarget(snapshot.appId, snapshot.windowTitle);
        if (request.tool === "mac_ui_action") execution.uiAction!.snapshot = snapshot;
        else execution.uiType!.snapshot = snapshot;
      } else {
        authorizeTarget(policy, request.principal.principalId, toolPolicy.requiredScopes, target);
      }
      for (const additionalTarget of execution.additionalTargets ?? []) {
        authorizeTarget(policy, request.principal.principalId, toolPolicy.requiredScopes, additionalTarget);
      }
      if (requiresAccessibilityPermission(request.tool) && this.guiHelperReadiness) {
        const gui = await this.guiHelperStatus();
        if (!gui?.installed || !gui.identity_valid) {
          throw new BrokerError("PRECONDITION_FAILED", "GUI_HELPER_UNAVAILABLE: Mac Operator GUI helper is missing or failed identity validation");
        }
        if (gui.accessibility === null) {
          throw new BrokerError("PRECONDITION_FAILED", `${gui.reason ?? "GUI_HELPER_PERMISSION_PROBE_FAILED"}: Production GUI permission readback is unavailable`);
        }
        if (!gui.accessibility) throw new BrokerError("POLICY_DENIED", "ACCESSIBILITY_PERMISSION_REQUIRED: Accessibility permission is not granted to the production GUI application");
        if (this.options.ordinaryGuiApplications && (gui.ordinary_apps !== true || gui.desktop_surfaces !== true)) {
          throw new BrokerError("PRECONDITION_FAILED", `${gui.reason ?? "GUI_HELPER_UPGRADE_REQUIRED"}: Production GUI computer-use capability is unavailable`);
        }
        if (execution.uiObserve && execution.uiObserve.captureMode !== "none" && gui.screen_recording !== true) {
          throw new BrokerError("POLICY_DENIED", "SCREEN_RECORDING_PERMISSION_REQUIRED: Screen Recording permission is not granted to the production GUI application");
        }
        this.checkRevocation(request);
      }
      if (execution.development?.execution) {
        const resolved = await this.options.developmentGateway!.prepareExecution(request, execution.development, this.taskProfileRegistry, this.taskRunner);
        this.checkRevocation(request);
        execution.taskRun = { profile: resolved.profile, cwd: resolved.cwd, args: [], asynchronous: true,
          idempotencyKey: request.arguments.idempotency_key as string, taskId: execution.development.taskId!,
          maxRuntimeMs: request.arguments.max_runtime as number, resolvedProfile: resolved };
      }
      if (request.tool === "mac_task_run" && this.taskRunner.mechanism === "docker-container") {
        const run = execution.taskRun!;
        const project = this.options.developmentGateway?.worktrees.originalProject(run.cwd, request.principal.principalId);
        if (!project || !run.taskId) throw new BrokerError("POLICY_DENIED", "Container task requires an owned development worktree");
        this.options.developmentGateway!.worktrees.require(run.cwd, project, request.principal.principalId, run.taskId);
        authorizeTarget(policy, request.principal.principalId, ["mac.project.read", "mac.project.write"], { kind: "project", reference: project });
        const taskScopes = request.principal.scopes;
        if (!taskScopes.includes("mac.project.read") || !taskScopes.includes("mac.project.write")) {
          throw new BrokerError("POLICY_DENIED", "Container task requires explicit project scopes");
        }
        run.resolvedProfile = await this.taskProfileRegistry.resolve({ profile: run.profile, cwd: run.cwd, args: run.args,
          taskId: run.taskId, ...(run.maxRuntimeMs === undefined ? {} : { maxRuntimeMs: run.maxRuntimeMs }) });
        run.asynchronous = true;
        execution.auditContext = { project, worktree: run.cwd, taskId: run.taskId };
      }
      // Preserve the Broker-normalized target for any later failure. Raw tool
      // arguments are never copied into audit records.
      plannedAuditTarget = execution.auditTarget ?? `${target.kind}:${target.reference}`;
      if (request.tool === "mac_write_file_atomic") {
        const existingWriteJob = this.options.store.ownedJobByIdempotencyKey(
          execution.write!.idempotencyKey,
          request.principal.principalId
        );
        if (existingWriteJob) execution.writeJob = existingWriteJob;
        if (execution.writeJob && (
          execution.writeJob.tool !== request.tool ||
          execution.writeJob.payloadDigest !== sha256(canonicalJson(request.arguments)) ||
          execution.writeJob.targetRef !== `${target.kind}:${target.reference}` ||
          execution.writeJob.policyVersion !== request.policyVersion
        )) {
          throw new BrokerError("CONFLICT", "Idempotency key was already used for a different write operation");
        }
      }
      if (execution.ownerTerminal) {
        const existing = this.options.store.ownedJobByIdempotencyKey(execution.ownerTerminal.idempotencyKey, request.principal.principalId);
        if (existing && (existing.tool !== request.tool || existing.payloadDigest !== sha256(canonicalJson(request.arguments)) ||
            existing.targetRef !== plannedAuditTarget || existing.policyVersion !== request.policyVersion)) {
          throw new BrokerError("CONFLICT", "Idempotency key was already used for a different terminal command");
        }
        if (existing) execution.taskJob = existing;
      }
      if (execution.ownerTerminalSession?.action === "start") {
        const existing = this.options.store.ownedJobByIdempotencyKey(execution.ownerTerminalSession.idempotencyKey, request.principal.principalId);
        if (existing && (existing.tool !== request.tool || existing.payloadDigest !== sha256(canonicalJson(request.arguments)) ||
            existing.targetRef !== plannedAuditTarget || existing.policyVersion !== request.policyVersion)) {
          throw new BrokerError("CONFLICT", "Idempotency key was already used for a different terminal session");
        }
        if (existing) execution.taskJob = existing;
      }
      this.options.store.recordRequestDecision({
        requestId: request.requestId,
        principalId: request.principal.principalId,
        tool: request.tool,
        eventType: "decision",
        decision: "allow",
        resultClass: "AUTHORIZED",
        targetRef: execution.auditTarget ?? `${target.kind}:${target.reference}`,
        policyVersion: policy.version,
        evidence: { scopes: [...toolPolicy.requiredScopes], ...execution.auditContext,
          ...(execution.development === undefined ? {} : { project: execution.development.projectRoot,
            ...(execution.development.worktree === undefined ? {} : { worktree: execution.development.worktree }),
            ...(execution.development.taskId === undefined ? {} : { taskId: execution.development.taskId }) }) },
        timestampMs: startedAt
      });
      authorized = true;
      if (toolPolicy.mutation && ["mac_app_open", "mac_app_focus", "mac_ui_action", "mac_ui_type"].includes(request.tool) && this.options.authorizeGuiSession) {
        const snapshot = execution.uiAction?.snapshot ?? execution.uiType?.snapshot;
        const appId = snapshot?.appId ?? execution.appFocus?.appId ?? execution.appOpen?.appId;
        const input = execution.uiType;
        const submits = input && (input.submit || input.keys.includes("ENTER") || /[\r\n]/u.test(input.text));
        const navigation = input?.snapshot && isBoundedBrowserNavigation({ ...input, snapshot: input.snapshot });
        const sensitiveAction = execution.uiAction && (execution.uiAction.options?.key === "ENTER" ||
          /\b(?:buy|purchase|pay|checkout|send|publish|delete|remove|erase|security|privacy)\b/iu.test(snapshot?.label ?? ""));
        if (appId && await this.options.authorizeGuiSession({
          requestId: request.requestId, principalId: request.principal.principalId, sessionId: request.principal.sessionId,
          appId, tool: request.tool, contractVersion: request.contractVersion, policyVersion: request.policyVersion,
          targetKind: target.kind, targetRef: plannedAuditTarget, payloadDigest: sha256(canonicalJson(request.arguments)),
          requiresExplicitApproval: Boolean(submits && !navigation || sensitiveAction),
          expiresAtMs: request.principal.expiresAtMs
        })) {
          if (snapshot?.screenshotFingerprint) {
            this.uiSnapshotRegistry.retainForApproval(snapshot.elementRef, request.principal.principalId,
              request.principal.sessionId, this.now(), this.now() + APPROVAL_PREVIEW_TTL_MS, uiApprovalBinding(request));
            const retained = this.uiSnapshotRegistry.resolve(snapshot.elementRef, request.principal.principalId,
              request.principal.sessionId, this.now(), uiApprovalBinding(request));
            if (execution.uiAction) execution.uiAction.snapshot = retained;
            if (execution.uiType) execution.uiType.snapshot = retained;
          }
          this.checkRevocation(request);
        }
      }
      if (execution.ownerTerminal || execution.ownerTerminalSession) {
        const delegated = await this.options.authorizeOwnerTerminal!({
          requestId: request.requestId, principalId: request.principal.principalId, sessionId: request.principal.sessionId,
          tool: request.tool, contractVersion: request.contractVersion, policyVersion: request.policyVersion,
          targetKind: target.kind, targetRef: plannedAuditTarget, payloadDigest: sha256(canonicalJson(request.arguments)),
          expiresAtMs: request.principal.expiresAtMs, timeoutMs: execution.ownerTerminal?.timeoutMs ??
            // A session's start approval must stay active for the whole session (see assertRequestApprovalActive).
            (execution.ownerTerminalSession?.action === "start" ? execution.ownerTerminalSession.lifetimeMs : 30_000)
        });
        if (!delegated) throw new BrokerError("POLICY_DENIED", "Owner terminal delegation is unavailable");
        this.checkRevocation(request);
      }
      let developmentDelegated = false;
      const delegatedProject = execution.development?.projectRoot ?? execution.auditContext?.project;
      if (toolPolicy.mutation && this.options.authorizeDevelopment && typeof delegatedProject === "string" &&
          !execution.ownerTerminal && !execution.ownerTerminalSession && ["trusted_write", "trusted_profile"].includes(toolPolicy.approvalPolicy)) {
        developmentDelegated = await this.options.authorizeDevelopment({
          requestId: request.requestId, principalId: request.principal.principalId, sessionId: request.principal.sessionId,
          tool: request.tool, contractVersion: request.contractVersion, policyVersion: request.policyVersion,
          targetKind: target.kind, targetRef: plannedAuditTarget, payloadDigest: sha256(canonicalJson(request.arguments)),
          approvalClass: toolPolicy.approvalPolicy as "trusted_write" | "trusted_profile", expiresAtMs: request.principal.expiresAtMs,
          projectRoot: delegatedProject,
          ...(execution.development?.worktree === undefined && execution.auditContext?.worktree === undefined ? {} :
            { worktree: (execution.development?.worktree ?? execution.auditContext?.worktree) as string }),
          ...(execution.development?.taskId === undefined && execution.auditContext?.taskId === undefined ? {} :
            { taskId: (execution.development?.taskId ?? execution.auditContext?.taskId) as string })
        });
        this.checkRevocation(request);
      }
      if (toolPolicy.mutation) {
        if (execution.ownerTerminal || execution.ownerTerminalSession) {
          const terminalKey = execution.ownerTerminal?.idempotencyKey ??
            (execution.ownerTerminalSession?.action === "start" ? execution.ownerTerminalSession.idempotencyKey : undefined);
          const admissionAt = this.now();
          const approval: ApprovalConsumptionBinding = {
            contractVersion: request.contractVersion, targetKind: target.kind, targetRef: plannedAuditTarget,
            payloadDigest: sha256(canonicalJson(request.arguments)), approvalClass: "trusted_profile", unattended: true
          };
          const intent = { requestId: request.requestId, principalId: request.principal.principalId, tool: request.tool,
            eventType: "intent" as const, decision: "allow" as const, resultClass: "INTENT_RECORDED",
            targetRef: plannedAuditTarget, policyVersion: policy.version,
            evidence: { argumentDigest: approval.payloadDigest }, timestampMs: admissionAt };
          if (execution.taskJob) {
            this.options.store.recordRequestIntent(intent, approval);
            this.options.store.linkRequestJob(request.requestId, execution.taskJob.jobId, admissionAt);
          } else if (terminalKey === undefined) {
            // write, read and stop act on an existing session and create no Job.
            this.options.store.recordRequestIntent(intent, approval);
          } else {
            const admitted = this.options.store.admitApprovedJobAfterDecision({ intent, approval, job: {
              jobId: `job:${execution.ownerTerminal ? "terminal" : "tsession"}-${sha256(canonicalJson({ principalId: request.principal.principalId, key: terminalKey })).slice(0, 48)}`,
              edgeId: request.principal.edgeId, edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
              ownerPrincipalId: request.principal.principalId, ownerSessionId: request.principal.sessionId,
              tool: request.tool, targetRef: plannedAuditTarget, policyVersion: request.policyVersion,
              payloadDigest: approval.payloadDigest, idempotencyKey: terminalKey, createdAtMs: admissionAt
            } });
            execution.taskJob = admitted.job;
            execution.taskJobNew = true;
          }
        } else if (execution.taskRun !== undefined) {
          const admissionAt = this.now();
          const jobInput = {
            jobId: `job:task-${sha256(canonicalJson(execution.taskRun.idempotencyKey === undefined ? { principalId: request.principal.principalId, requestId: request.requestId } : { principalId: request.principal.principalId, idempotencyKey: execution.taskRun.idempotencyKey })).slice(0, 48)}`,
            edgeId: request.principal.edgeId,
            edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
            ownerPrincipalId: request.principal.principalId,
            ownerSessionId: request.principal.sessionId,
            tool: request.tool,
            targetRef: `${target.kind}:${target.reference}`,
            policyVersion: request.policyVersion,
            payloadDigest: sha256(canonicalJson(request.arguments)),
            idempotencyKey: execution.taskRun.idempotencyKey === undefined
              ? `task:${request.requestId}`
              : `task-key:${sha256(execution.taskRun.idempotencyKey)}`,
            createdAtMs: admissionAt
          } as const;
          const approvalBinding: ApprovalConsumptionBinding = {
            contractVersion: request.contractVersion,
            targetKind: target.kind,
            targetRef: execution.auditTarget ?? `${target.kind}:${target.reference}`,
            payloadDigest: sha256(canonicalJson(request.arguments)),
            approvalClass: requireMutationApprovalClass(toolPolicy.approvalPolicy),
            unattended: developmentDelegated
          };
          let admitted: ReturnType<BrokerStore["admitApprovedJobAfterDecision"]>;
          if (execution.development) this.options.developmentGateway!.worktrees.require(execution.taskRun.cwd,
            execution.development.projectRoot, request.principal.principalId, execution.taskRun.taskId);
          if ((execution.development || execution.taskRun.resolvedProfile?.containerExecution) && this.options.store.hasActiveWorktreeJobs(execution.taskRun.cwd, jobInput.jobId)) {
            throw new BrokerError("CONFLICT", "An active or unresolved job already owns this worktree");
          }
          try {
            admitted = this.options.store.admitApprovedJobAfterDecision({
              intent: {
                requestId: request.requestId,
                principalId: request.principal.principalId,
                tool: request.tool,
                eventType: "intent",
                decision: "allow",
                resultClass: "INTENT_RECORDED",
                targetRef: approvalBinding.targetRef,
                policyVersion: policy.version,
                evidence: {
                  argumentDigest: sha256(canonicalJson(request.arguments)),
                  ...(execution.taskRun.taskId === undefined ? {} : { taskId: execution.taskRun.taskId }),
                  scopes: [...toolPolicy.requiredScopes],
                  project: execution.development?.projectRoot ?? execution.auditContext?.project ?? execution.taskRun.cwd,
                  worktree: execution.taskRun.cwd,
                  jobId: jobInput.jobId
                },
                timestampMs: admissionAt
              },
              approval: approvalBinding,
              job: jobInput
            });
          } catch (error) {
            this.persistApprovalPreviewOnMissing(request, approvalBinding, admissionAt, error);
            throw error;
          }
          execution.taskJob = admitted.job;
          execution.taskJobNew = !admitted.reused;
          if (admitted.reused) return this.taskJobReceipt(request, execution, startedAt, true);
        } else {
          const mutationPayloadDigest = execution.privileged === undefined
            ? sha256(canonicalJson(request.arguments))
            : sha256(canonicalJson(execution.privileged.payload));
          const intentAt = this.now();
          const approvalBinding: ApprovalConsumptionBinding = {
            contractVersion: request.contractVersion,
            targetKind: target.kind,
            targetRef: execution.auditTarget ?? `${target.kind}:${target.reference}`,
            payloadDigest: mutationPayloadDigest,
            approvalClass: requireMutationApprovalClass(toolPolicy.approvalPolicy),
            unattended: developmentDelegated
          };
          try {
            this.options.store.recordRequestIntent({
              requestId: request.requestId,
              principalId: request.principal.principalId,
              tool: request.tool,
              eventType: "intent",
              decision: "allow",
              resultClass: "INTENT_RECORDED",
              targetRef: approvalBinding.targetRef,
              policyVersion: policy.version,
              evidence: {
                argumentDigest: sha256(canonicalJson(request.arguments)),
                ...execution.auditContext,
                scopes: [...toolPolicy.requiredScopes],
                ...(execution.development === undefined ? {} : { project: execution.development.projectRoot,
                  ...(execution.development.worktree === undefined ? {} : { worktree: execution.development.worktree }),
                  ...(execution.development.taskId === undefined ? {} : { taskId: execution.development.taskId }) }),
                ...(execution.privileged === undefined ? {} : { privilegedPayloadDigest: mutationPayloadDigest }),
                ...(request.tool === "mac_write_file_atomic" ? { idempotencyKey: execution.write!.idempotencyKey } : {})
              },
              timestampMs: intentAt
            }, approvalBinding);
            uiApprovalConsumed = request.tool === "mac_ui_action" || request.tool === "mac_ui_type";
            const uiSnapshot = execution.uiAction?.snapshot ?? execution.uiType?.snapshot;
            if (uiApprovalConsumed && uiSnapshot?.screenshotFingerprint && !uiSnapshot.revalidationRequired) {
              throw new BrokerError("TARGET_NOT_FOUND", "Approved UI evidence is unavailable; observe and request a new approval");
            }
          } catch (error) {
            this.persistApprovalPreviewOnMissing(request, approvalBinding, intentAt, error);
            throw error;
          }
          if (request.tool === "mac_service_control") {
            const candidate = this.userServiceControlCandidate;
            if (!candidate || !execution.serviceControl) {
              throw new BrokerError("UNSUPPORTED_CAPABILITY", "User service-control runtime is unavailable");
            }
            execution.serviceControl.precondition = await candidate.readPrecondition(
              execution.serviceControl.request,
              this.executionControl(request, execution.target, toolPolicy.timeoutMs),
              request.principal.principalId
            );
          }
          if (request.tool === "mac_priv_service_control" || request.tool === "mac_priv_package_install" || request.tool === "mac_priv_power") {
            if (!execution.privileged) throw new BrokerError("EXECUTION_FAILED", "Privileged helper payload is unavailable");
            const payloadDigest = sha256(canonicalJson(execution.privileged.payload));
            const jobInput = {
              jobId: `job:priv-${sha256(canonicalJson({ principalId: request.principal.principalId, requestId: request.requestId })).slice(0, 48)}`,
              edgeId: request.principal.edgeId,
              edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
              ownerPrincipalId: request.principal.principalId,
              ownerSessionId: request.principal.sessionId,
              tool: request.tool,
              targetRef: `${execution.target.kind}:${execution.target.reference}`,
              policyVersion: request.policyVersion,
              payloadDigest,
              idempotencyKey: `privileged:${sha256(canonicalJson({ tool: request.tool, requestId: request.requestId })).slice(0, 48)}`,
              createdAtMs: this.now(),
              privilegedPayload: execution.privileged.payload
            } as const;
            const created = this.options.store.createJob(jobInput);
            execution.privilegedJob = created.job;
            execution.privilegedJobNew = !created.reused;
            this.options.store.linkRequestJob(request.requestId, created.job.jobId, this.now());
          }
          if (request.tool === "mac_write_file_atomic") {
            const jobInput = {
              jobId: `job:write-${sha256(canonicalJson({ principalId: request.principal.principalId, idempotencyKey: execution.write!.idempotencyKey })).slice(0, 48)}`,
              edgeId: request.principal.edgeId,
              edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
              ownerPrincipalId: request.principal.principalId,
              ownerSessionId: request.principal.sessionId,
              tool: request.tool,
              targetRef: `${target.kind}:${target.reference}`,
              policyVersion: request.policyVersion,
              payloadDigest: sha256(canonicalJson(request.arguments)),
              idempotencyKey: execution.write!.idempotencyKey,
              createdAtMs: this.now(),
              writeMetadata: writeJobMetadata(execution.filesystem!.plan, execution.write!)
            } as const;
            const created = this.options.store.createJob(jobInput);
            execution.writeJob = created.job;
            execution.writeJobNew = !created.reused;
            this.options.store.linkRequestJob(request.requestId, created.job.jobId, this.now());
          }
          if (request.tool === "mac_service_control") {
            const serviceControl = execution.serviceControl;
            if (!serviceControl || !serviceControl.precondition) {
              throw new BrokerError("EXECUTION_FAILED", "User service-control precondition is unavailable");
            }
            const precondition = serviceControl.precondition;
            const jobInput = {
              jobId: `job:service-${sha256(canonicalJson({ principalId: request.principal.principalId, idempotencyKey: serviceControl.idempotencyKey })).slice(0, 48)}`,
              edgeId: request.principal.edgeId,
              edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
              ownerPrincipalId: request.principal.principalId,
              ownerSessionId: request.principal.sessionId,
              tool: request.tool,
              targetRef: `${target.kind}:${target.reference}`,
              policyVersion: request.policyVersion,
              payloadDigest: sha256(canonicalJson(request.arguments)),
              idempotencyKey: `service-control:${serviceControl.idempotencyKey}`,
              createdAtMs: this.now(),
              serviceMetadata: createServiceControlJobMetadata(serviceControl.request, precondition)
            } as const;
            const created = this.options.store.createJob(jobInput);
            execution.serviceControlJob = created.job;
            execution.serviceControlJobNew = !created.reused;
            this.options.store.linkRequestJob(request.requestId, created.job.jobId, this.now());
          }
          if (request.tool === "mac_apply_patch") {
            if (!execution.patch || !execution.filesystem) throw new BrokerError("EXECUTION_FAILED", "Filesystem patch execution plan is unavailable");
            const jobInput = {
              jobId: `job:patch-${sha256(canonicalJson({ principalId: request.principal.principalId, requestId: request.requestId })).slice(0, 48)}`,
              edgeId: request.principal.edgeId,
              edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
              ownerPrincipalId: request.principal.principalId,
              ownerSessionId: request.principal.sessionId,
              tool: request.tool,
              targetRef: `${target.kind}:${target.reference}`,
              policyVersion: request.policyVersion,
              payloadDigest: sha256(canonicalJson(request.arguments)),
              idempotencyKey: `patch:${request.requestId}`,
              createdAtMs: this.now()
            } as const;
            const created = this.options.store.createJob(jobInput);
            execution.patchJob = created.job;
            execution.patchJobNew = !created.reused;
            this.options.store.linkRequestJob(request.requestId, created.job.jobId, this.now());
          }
          if (request.tool === "mac_git_stage" || request.tool === "mac_git_commit") {
            const jobInput = {
              jobId: `job:git-${sha256(canonicalJson({ principalId: request.principal.principalId, requestId: request.requestId })).slice(0, 48)}`,
              edgeId: request.principal.edgeId,
              edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
              ownerPrincipalId: request.principal.principalId,
              ownerSessionId: request.principal.sessionId,
              tool: request.tool,
              targetRef: execution.auditTarget ?? `${target.kind}:${target.reference}`,
              policyVersion: request.policyVersion,
              payloadDigest: sha256(canonicalJson(request.arguments)),
              idempotencyKey: `git:${request.tool}:${request.requestId}`,
              createdAtMs: this.now()
            } as const;
            const created = this.options.store.createJob(jobInput);
            if (request.tool === "mac_git_stage") execution.gitStageJob = created.job;
            else execution.gitCommitJob = created.job;
            execution.gitWriteJobNew = !created.reused;
            this.options.store.linkRequestJob(request.requestId, created.job.jobId, this.now());
          }
          if (request.tool === "mac_app_open") {
            const jobInput = {
              jobId: `job:app-open-${sha256(canonicalJson({ principalId: request.principal.principalId, requestId: request.requestId })).slice(0, 48)}`,
              edgeId: request.principal.edgeId,
              edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
              ownerPrincipalId: request.principal.principalId,
              ownerSessionId: request.principal.sessionId,
              tool: request.tool,
              targetRef: `${target.kind}:${target.reference}`,
              policyVersion: request.policyVersion,
              payloadDigest: sha256(canonicalJson(request.arguments)),
              idempotencyKey: `app-open:${request.requestId}`,
              createdAtMs: this.now()
            } as const;
            const created = this.options.store.createJob(jobInput);
            execution.appOpenJob = created.job;
            execution.appOpenJobNew = !created.reused;
            this.options.store.linkRequestJob(request.requestId, created.job.jobId, this.now());
          }
          if (request.tool === "mac_app_focus") {
            const jobInput = {
              jobId: `job:app-focus-${sha256(canonicalJson({ principalId: request.principal.principalId, requestId: request.requestId })).slice(0, 48)}`,
              edgeId: request.principal.edgeId,
              edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
              ownerPrincipalId: request.principal.principalId,
              ownerSessionId: request.principal.sessionId,
              tool: request.tool,
              targetRef: `${target.kind}:${target.reference}`,
              policyVersion: request.policyVersion,
              payloadDigest: sha256(canonicalJson(request.arguments)),
              idempotencyKey: `app-focus:${request.requestId}`,
              createdAtMs: this.now()
            } as const;
            const created = this.options.store.createJob(jobInput);
            execution.appFocusJob = created.job;
            execution.appFocusJobNew = !created.reused;
            this.options.store.linkRequestJob(request.requestId, created.job.jobId, this.now());
          }
          if (request.tool === "mac_ui_action") {
            const jobInput = {
              jobId: `job:ui-action-${sha256(canonicalJson({ principalId: request.principal.principalId, requestId: request.requestId })).slice(0, 48)}`,
              edgeId: request.principal.edgeId,
              edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
              ownerPrincipalId: request.principal.principalId,
              ownerSessionId: request.principal.sessionId,
              tool: request.tool,
              targetRef: `${target.kind}:${target.reference}`,
              policyVersion: request.policyVersion,
              payloadDigest: sha256(canonicalJson(request.arguments)),
              idempotencyKey: `ui-action:${request.requestId}`,
              createdAtMs: this.now()
            } as const;
            const created = this.options.store.createJob(jobInput);
            execution.uiActionJob = created.job;
            execution.uiActionJobNew = !created.reused;
            this.options.store.linkRequestJob(request.requestId, created.job.jobId, this.now());
          }
          if (request.tool === "mac_ui_type") {
            const jobInput = {
              jobId: `job:ui-type-${sha256(canonicalJson({ principalId: request.principal.principalId, requestId: request.requestId })).slice(0, 48)}`,
              edgeId: request.principal.edgeId,
              edgeKeyId: keyIdentity(request.principal.edgeId, request.authenticationKeyId),
              ownerPrincipalId: request.principal.principalId,
              ownerSessionId: request.principal.sessionId,
              tool: request.tool,
              targetRef: `${target.kind}:${target.reference}`,
              policyVersion: request.policyVersion,
              payloadDigest: sha256(canonicalJson(request.arguments)),
              idempotencyKey: `ui-type:${request.requestId}`,
              createdAtMs: this.now()
            } as const;
            const created = this.options.store.createJob(jobInput);
            execution.uiTypeJob = created.job;
            execution.uiTypeJobNew = !created.reused;
            this.options.store.linkRequestJob(request.requestId, created.job.jobId, this.now());
          }
        }
      }
      this.options.store.markRequestRunning(request.requestId, this.now());
      const pendingJob = execution.patchJob && execution.patchJobNew
        ? { kind: "patch" as const, job: execution.patchJob }
        : execution.writeJob && execution.writeJobNew
          ? { kind: "write" as const, job: execution.writeJob }
          : execution.taskJob && execution.taskJobNew
          ? { kind: "task" as const, job: execution.taskJob }
          : execution.gitStageJob && execution.gitWriteJobNew
            ? { kind: "git_stage" as const, job: execution.gitStageJob }
            : execution.gitCommitJob && execution.gitWriteJobNew
              ? { kind: "git_commit" as const, job: execution.gitCommitJob }
              : execution.appOpenJob && execution.appOpenJobNew
                ? { kind: "app_open" as const, job: execution.appOpenJob }
                : execution.appFocusJob && execution.appFocusJobNew
                  ? { kind: "app_focus" as const, job: execution.appFocusJob }
                  : execution.uiActionJob && execution.uiActionJobNew
                    ? { kind: "ui_action" as const, job: execution.uiActionJob }
                      : execution.uiTypeJob && execution.uiTypeJobNew
                        ? { kind: "ui_type" as const, job: execution.uiTypeJob }
                        : execution.serviceControlJob && execution.serviceControlJobNew
                          ? { kind: "service_control" as const, job: execution.serviceControlJob }
                        : execution.privilegedJob && execution.privilegedJobNew
                          ? { kind: "privileged" as const, job: execution.privilegedJob }
          : undefined;
      if (pendingJob && pendingJob.job.state === "queued") {
        const leaseStartedAtMs = this.now();
        const lease = this.newJobLease(leaseStartedAtMs);
        let started: BrokerJob;
        try {
          this.ensureActiveAuthority(request, execution.target, execution.additionalTargets ?? []);
          started = this.options.store.startJob(
            pendingJob.job.jobId,
            request.principal.principalId,
            pendingJob.job.revision,
            leaseStartedAtMs,
            lease
          );
        } catch (error) {
          try {
            this.options.store.requestJobCancellation(
              pendingJob.job.jobId,
              request.principal.principalId,
              "AUTHORITY_REVOKED_BEFORE_START",
              this.now()
            );
          } catch {
            // Preserve the authority failure; a concurrently cancelled Job is
            // already fail-closed, and an unresolved queued Job is never
            // dispatched without a later authority recheck.
          }
          throw error;
        }
        execution.jobLease = lease;
        if (pendingJob.kind === "write") execution.writeJob = started;
        else if (pendingJob.kind === "patch") execution.patchJob = started;
        else if (pendingJob.kind === "task") execution.taskJob = started;
        else if (pendingJob.kind === "git_stage") execution.gitStageJob = started;
        else if (pendingJob.kind === "git_commit") execution.gitCommitJob = started;
        else if (pendingJob.kind === "app_open") execution.appOpenJob = started;
        else if (pendingJob.kind === "app_focus") execution.appFocusJob = started;
        else if (pendingJob.kind === "ui_action") execution.uiActionJob = started;
        else if (pendingJob.kind === "ui_type") execution.uiTypeJob = started;
        else if (pendingJob.kind === "service_control") execution.serviceControlJob = started;
        else execution.privilegedJob = started;
      }
      if (execution.taskRun?.asynchronous === true) {
        // No await separates authority confirmation, continuation tracking,
        // and admission readback. Shutdown therefore sees every admitted Job.
        this.ensureActiveAuthority(request, execution.target, execution.additionalTargets ?? []);
        const receipt = this.taskJobReceipt(request, execution, startedAt, false);
        const continuation = Promise.resolve().then(async () => {
          try {
            const dispatched = await this.dispatchTask(request!, execution, toolPolicy.timeoutMs, toolPolicy.outputCapBytes);
            this.ensureActiveAuthority(request!, execution.target, execution.additionalTargets ?? []);
            this.options.store.completeRequest({
              requestId: request!.requestId,
              principalId: request!.principal.principalId,
              tool: request!.tool,
              eventType: "completion",
              decision: "allow",
              resultClass: "SUCCEEDED",
              targetRef: execution.auditTarget ?? `${execution.target.kind}:${execution.target.reference}`,
              policyVersion: policy.version,
              evidence: {
                outputClass: "bounded_structured",
                scopes: [...toolPolicy.requiredScopes],
                ...dispatched.auditEvidence,
                ...(execution.development ? { project: execution.development.projectRoot, worktree: execution.development.worktree!, scope: [...toolPolicy.requiredScopes] } : {}),
                ...(execution.taskRun?.taskId === undefined ? {} : { taskId: execution.taskRun.taskId }),
                durationMs: Math.max(0, this.now() - startedAt)
              },
              timestampMs: this.now()
            });
          } catch (error) {
            const brokerError = error instanceof BrokerError ? error : new BrokerError("UNKNOWN_OUTCOME", "Managed task completion could not be persisted", true);
            this.auditFailure(request!, brokerError, this.now(), true, plannedAuditTarget);
          }
        }).finally(() => { this.activeAsyncTasks.delete(execution.taskJob!.jobId); });
        this.activeAsyncTasks.set(execution.taskJob!.jobId, continuation);
        return receipt;
      }
      if (execution.ownerTerminalSession?.action === "start") {
        const sessionJob = execution.taskJob;
        if (!sessionJob || !this.options.ownerTerminalSessions) throw new BrokerError("POLICY_DENIED", "Owner terminal session runtime is unavailable");
        const started = await startOwnerTerminalSession({ store: this.options.store, manager: this.options.ownerTerminalSessions,
          request, session: execution.ownerTerminalSession, job: sessionJob, ...(execution.jobLease ? { lease: execution.jobLease } : {}),
          control: this.executionControl(request, execution.target, toolPolicy.timeoutMs, sessionJob.jobId, [], execution.jobLease),
          assertAuthority: () => this.ensureActiveAuthority(request!, execution.target), now: this.now });
        // The request stays open (and its approval active) until the session ends; the
        // caller receives its session id now and settles the audit from the continuation.
        const continuation = started.finished.then(() => {
          this.options.store.completeRequest({
            requestId: request!.requestId, principalId: request!.principal.principalId, tool: request!.tool,
            eventType: "completion", decision: "allow", resultClass: "SUCCEEDED", targetRef: started.result.auditTarget,
            policyVersion: policy.version,
            evidence: { outputClass: "bounded_structured", scopes: [...toolPolicy.requiredScopes], ...started.result.auditEvidence,
              durationMs: Math.max(0, this.now() - startedAt) },
            timestampMs: this.now()
          });
        }).catch((error: unknown) => {
          const brokerError = error instanceof BrokerError ? error : new BrokerError("UNKNOWN_OUTCOME", "Terminal session completion could not be persisted", true);
          this.auditFailure(request!, brokerError, this.now(), true, plannedAuditTarget);
        }).finally(() => { this.activeAsyncTasks.delete(sessionJob.jobId); });
        this.activeAsyncTasks.set(sessionJob.jobId, continuation);
        this.ensureActiveAuthority(request, execution.target);
        return { ok: true, request_id: request.requestId, tool: request.tool, result_class: "SUCCEEDED", data: started.result.data,
          warnings: started.result.warnings, truncated: false, verification: started.result.verification,
          duration_ms: Math.max(0, this.now() - startedAt) };
      }
      const dispatched = await this.dispatch(request, policy, execution, toolPolicy);
      // Re-check every normalized target immediately before publishing a
      // success. Multi-root inspections keep additional targets in the
      // execution plan; a policy change on any one of them must fail closed.
      this.ensureActiveAuthority(request, execution.target, execution.additionalTargets ?? []);
      const result: BrokerResult = {
        ok: true,
        request_id: request.requestId,
        tool: request.tool,
        result_class: "SUCCEEDED",
        data: dispatched.data,
        warnings: dispatched.warnings ? [...dispatched.warnings] : [],
        truncated: dispatched.truncated ?? false,
        verification: dispatched.verification,
        duration_ms: Math.max(0, this.now() - startedAt)
      };
      if (Buffer.byteLength(JSON.stringify(result), "utf8") > toolPolicy.outputCapBytes) {
        throw new BrokerError("OUTPUT_LIMIT", "Tool result exceeded its output limit");
      }
      this.options.store.completeRequest({
        requestId: request.requestId,
        principalId: request.principal.principalId,
        tool: request.tool,
        eventType: "completion",
        decision: "allow",
        resultClass: "SUCCEEDED",
        targetRef: dispatched.auditTarget ?? `${target.kind}:${target.reference}`,
        policyVersion: policy.version,
        evidence: { outputClass: "bounded_structured", scopes: [...toolPolicy.requiredScopes], durationMs: Math.max(0, this.now() - startedAt), ...execution.auditContext, ...dispatched.auditEvidence,
          ...(execution.development ? { project: execution.development.projectRoot, worktree: execution.development.worktree ?? null, taskId: execution.development.taskId ?? null, scope: [...toolPolicy.requiredScopes], durationMs: Math.max(0, this.now() - startedAt) } : {}) },
        timestampMs: this.now()
      });
      return result;
    } catch (error) {
      const brokerError = error instanceof BrokerError
        ? error
        : new BrokerError("EXECUTION_FAILED", "Broker request failed");
      if (request && admitted) {
        this.auditFailure(request, brokerError, this.now(), authorized, plannedAuditTarget);
      }
      return this.failure(request, brokerError, startedAt);
    } finally {
      if (uiApprovalConsumed && request !== undefined) {
        this.uiSnapshotRegistry.releaseApproval(request.principal.principalId, request.principal.sessionId, uiApprovalBinding(request));
      }
      if (sessionReserved && request !== undefined) {
        this.releaseSessionRequest(request.principal.principalId, request.principal.sessionId);
      }
    }
  }

  /**
   * Accept a signed Edge OAuth-authority event on the existing peer-authenticated
   * IPC channel. This path has no MCP tool shape and can only revoke the
   * session named by the already trusted Edge event.
   */
  async handleRevocationForIpc(rawEvent: unknown): Promise<AuthenticatedBrokerRevocationResponse | BrokerRevocationResult> {
    const startedAt = this.now();
    let event: BrokerRevocationEvent | undefined;
    let key: Buffer | undefined;
    try {
      event = parseBrokerRevocationEvent(rawEvent);
      const policy = this.currentPolicy();
      const identity = keyIdentity(event.edgeId, event.authenticationKeyId);
      const trustedKey = policy.trustedEdgeKeys.get(identity);
      if (!policy.trustedEdgeIds.has(event.edgeId) || trustedKey === undefined) {
        throw new BrokerError("AUTH_INVALID", "Revocation event authentication failed");
      }
      const nowMs = this.now();
      if (nowMs < trustedKey.notBeforeMs || nowMs >= trustedKey.expiresAtMs) {
        throw new BrokerError("AUTH_EXPIRED", "Edge authentication key is not currently valid");
      }
      if (event.timestampMs > nowMs + this.allowedClockSkewMs || nowMs - event.timestampMs > this.maxRequestAgeMs) {
        throw new BrokerError("AUTH_EXPIRED", "Revocation event timestamp is outside the accepted window");
      }
      if (this.options.store.isRevoked("edge", event.edgeId) || this.options.store.isRevoked("edge_key", identity)) {
        throw new BrokerError("REVOKED", "Revocation event authority has been revoked");
      }
      key = this.options.edgeAuthenticationKeys.keyByIdentity(event.edgeId, event.authenticationKeyId);
      if (key === undefined || !verifyBrokerRevocationEvent(event, key)) {
        throw new BrokerError("AUTH_INVALID", "Revocation event authentication failed");
      }
      this.options.store.admitEdgeRevocationEvent({
        requestId: event.requestId,
        nonce: event.nonce,
        edgeId: event.edgeId,
        acceptedAtMs: nowMs,
        expiresAtMs: Math.min(nowMs + this.maxRequestAgeMs, trustedKey.expiresAtMs)
      });
      if (!this.options.store.isRevoked("session", event.sessionId)) {
        this.options.store.revoke("session", event.sessionId, "OAUTH_AUTHORITY_REVOKED", nowMs, event.requestId);
      }
      const response: BrokerRevocationResult = {
        ok: true,
        request_id: event.requestId,
        event_type: event.eventType,
        revoked: true,
        duration_ms: Math.max(0, this.now() - startedAt)
      };
      return signBrokerRevocationResponse(event, response, key);
    } catch (error) {
      const brokerError = error instanceof BrokerError
        ? error
        : new BrokerError("AUDIT_UNAVAILABLE", "Revocation event could not be persisted");
      const response: BrokerRevocationResult = {
        ok: false,
        request_id: event?.requestId ?? "invalid-request",
        event_type: "oauth_authority_revoked",
        result_class: brokerError.errorClass,
        error: { message: brokerError.message, retryable: brokerError.retryable },
        duration_ms: Math.max(0, this.now() - startedAt)
      };
      if (event !== undefined && key !== undefined && verifyBrokerRevocationEvent(event, key)) {
        return signBrokerRevocationResponse(event, response, key);
      }
      return response;
    } finally {
      key?.fill(0);
    }
  }

  async handleForIpc(rawRequest: unknown): Promise<AuthenticatedBrokerResponse | AuthenticatedBrokerRevocationResponse | BrokerResult | BrokerRevocationResult> {
    if (isPlainDataRecord(rawRequest) && rawRequest.eventType === "oauth_authority_revoked") {
      return this.handleRevocationForIpc(rawRequest);
    }
    // Parse once before dispatch and carry that immutable snapshot through the
    // async handler. Re-reading caller-owned input after execution would let a
    // same-process caller swap the signed target while the response envelope
    // is being selected.
    let parsedRequest: BrokerRequest | undefined;
    try {
      parsedRequest = parseBrokerRequest(rawRequest);
    } catch {
      // Let handle() produce the normal bounded failure for malformed input.
    }
    const response = await this.handle(parsedRequest ?? rawRequest);
    try {
      const request = parsedRequest;
      if (request === undefined) return response;
      const key = this.options.edgeAuthenticationKeys.keyByIdentity(
        request.principal.edgeId,
        request.authenticationKeyId
      );
      if (key) {
        try {
          if (verifyRequestAuthentication(request, key)) {
            return signBrokerResponse(request, response, key);
          }
        } finally {
          key.fill(0);
        }
      }
    } catch {
      // Invalid requests receive only an untrusted bounded error response.
    }
    return response;
  }

  private reserveSessionRequest(principalId: string, sessionId: string): void {
    const key = `${principalId}\u0000${sessionId}`;
    const active = this.activeRequestsBySession.get(key) ?? 0;
    if (active >= this.maxActiveRequestsPerSession) {
      throw new BrokerError("CONFLICT", "Session request capacity is exhausted", true);
    }
    this.activeRequestsBySession.set(key, active + 1);
  }

  private releaseSessionRequest(principalId: string, sessionId: string): void {
    const key = `${principalId}\u0000${sessionId}`;
    const active = this.activeRequestsBySession.get(key) ?? 0;
    if (active <= 1) this.activeRequestsBySession.delete(key);
    else this.activeRequestsBySession.set(key, active - 1);
  }

  private authenticate(request: BrokerRequest, nowMs: number, policy: BrokerPolicy): void {
    const edgeKeyIdentity = keyIdentity(request.principal.edgeId, request.authenticationKeyId);
    const trustedKey = policy.trustedEdgeKeys.get(edgeKeyIdentity);
    if (
      !policy.trustedEdgeIds.has(request.principal.edgeId) ||
      !trustedKey
    ) {
      throw new BrokerError("AUTH_INVALID", "Request authentication failed");
    }
    if (nowMs < trustedKey.notBeforeMs || nowMs >= trustedKey.expiresAtMs) {
      throw new BrokerError("AUTH_EXPIRED", "Signed policy does not currently authorize the Edge key");
    }
    const key = this.options.edgeAuthenticationKeys.keyFor(request, nowMs);
    try {
      if (!verifyRequestAuthentication(request, key)) throw new BrokerError("AUTH_INVALID", "Request authentication failed");
    } finally {
      key.fill(0);
    }
    if (request.policyAudience !== policy.audience || request.principal.audience !== policy.audience) {
      throw new BrokerError("AUTH_INVALID", "Request audience is invalid");
    }
    if (request.timestampMs > nowMs + this.allowedClockSkewMs || nowMs - request.timestampMs > this.maxRequestAgeMs) {
      throw new BrokerError("AUTH_EXPIRED", "Request timestamp is outside the accepted window");
    }
    if (
      request.principal.issuedAtMs > nowMs + this.allowedClockSkewMs ||
      request.principal.expiresAtMs <= nowMs ||
      request.principal.expiresAtMs <= request.principal.issuedAtMs ||
      request.principal.expiresAtMs - request.principal.issuedAtMs > MAX_SESSION_LIFETIME_MS ||
      request.timestampMs < request.principal.issuedAtMs - this.allowedClockSkewMs ||
      request.timestampMs >= request.principal.expiresAtMs
    ) {
      throw new BrokerError("AUTH_EXPIRED", "Principal session is not currently valid");
    }
  }

  private checkRevocation(request: BrokerRequest): void {
    const { principal } = request;
    if (
      this.options.store.isRevoked("edge", principal.edgeId) ||
      this.options.store.isRevoked("edge_key", keyIdentity(principal.edgeId, request.authenticationKeyId)) ||
      this.options.store.isRevoked("principal", principal.principalId) ||
      this.options.store.isRevoked("session", principal.sessionId)
    ) {
      throw new BrokerError("REVOKED", "Request authority has been revoked");
    }
  }

  private async dispatch(
    request: BrokerRequest,
    policy: BrokerPolicy,
    execution: ExecutionPlan,
    toolPolicy: ToolPolicy
  ): Promise<DispatchResult> {
    if (execution.development && !execution.development.execution) return this.dispatchDevelopment(request, execution, toolPolicy);
    switch (request.tool) {
      case "mac_health": {
        assertExactArguments(request.arguments, ["include_components"]);
        if (request.arguments.include_components !== undefined && typeof request.arguments.include_components !== "boolean") {
          throw new BrokerError("PRECONDITION_FAILED", "include_components must be a boolean");
        }
        const components = request.arguments.include_components === false
          ? []
          : [{ name: "broker", status: "healthy", version: "0.1.0" }];
        return {
          data: { overall: "healthy", components },
          verification: { required: false, status: "not_required", strategy: "component_health_result_validation" }
        };
      }
      case "mac_capabilities": {
        assertExactArguments(request.arguments, []);
        const gui = runtimeToolStates(policy).some(state => state.enabled && requiresAccessibilityPermission(state.tool))
          ? await this.guiHelperStatus() : undefined;
        const states = runtimeToolStates(policy).map((state) => {
          if (state.enabled && requiresAccessibilityPermission(state.tool) && gui && (!gui.installed || !gui.identity_valid || gui.accessibility !== true ||
              this.options.ordinaryGuiApplications === true && (gui.ordinary_apps !== true || gui.desktop_surfaces !== true))) {
            return { ...state, enabled: false, disabledReason: gui.reason ?? "GUI_HELPER_PERMISSION_PROBE_FAILED" };
          }
          if (!state.enabled) return state;
          const candidate = policy.tools.get(state.tool);
          if (!candidate) return { ...state, enabled: false, disabledReason: "not_implemented" };
          if (candidate.requiredScopes.some((scope) => !request.principal.scopes.includes(scope))) {
            return { ...state, enabled: false, disabledReason: "scope_not_granted" };
          }
          if (isCapabilityFamilyDisabled(this.options.store, policy, candidate.capabilityFamilies)) {
            return { ...state, enabled: false, disabledReason: "disabled_by_kill_switch" };
          }
          try {
            this.authorizeCapabilityTarget(policy, request.principal.principalId, candidate);
            const runtimeDisabledReason = this.runtimeCapabilityDisabledReason(state.tool);
            if (runtimeDisabledReason !== undefined) {
              return { ...state, enabled: false, disabledReason: runtimeDisabledReason };
            }
            return state;
          } catch {
            return { ...state, enabled: false, disabledReason: "target_denied" };
          }
        });
        return {
          data: {
            capabilities: states.map((state) => {
              const tool = policy.tools.get(state.tool);
              return {
                name: state.tool,
                planned: state.planned,
                implemented: state.implemented,
                enabled: state.enabled,
                scopes: tool ? [...tool.requiredScopes] : [],
                contract_version: tool?.contractVersion ?? null,
                reason: state.enabled ? "enabled" : (state.disabledReason ?? "disabled")
              };
            }),
            permissions: gui ? guiReadinessPermissions(gui) : [],
            protocol_version: PROTOCOL_VERSION,
            contract_version: CONTRACT_VERSION,
            version: "0.1.0"
          },
          verification: { required: false, status: "not_required", strategy: "capability_state_result_validation" }
        };
      }
      case "mac_app_open": {
        if (!execution.appOpen || !execution.appOpenJob) {
          throw new BrokerError("EXECUTION_FAILED", "App open job execution plan is unavailable");
        }
        return this.dispatchAppOpen(request, execution, toolPolicy.timeoutMs);
      }
      case "mac_app_focus": {
        if (!execution.appFocus || !execution.appFocusJob) {
          throw new BrokerError("EXECUTION_FAILED", "App focus job execution plan is unavailable");
        }
        return this.dispatchAppFocus(request, execution, toolPolicy.timeoutMs);
      }
      case "mac_ui_action": {
        if (!execution.uiAction || !execution.uiAction.snapshot || !execution.uiActionJob) {
          throw new BrokerError("EXECUTION_FAILED", "UI action job execution plan is unavailable");
        }
        return this.dispatchUiAction(request, execution, toolPolicy.timeoutMs);
      }
      case "mac_ui_type": {
        if (!execution.uiType || !execution.uiType.snapshot || !execution.uiTypeJob) {
          throw new BrokerError("EXECUTION_FAILED", "UI type job execution plan is unavailable");
        }
        return this.dispatchUiType(request, execution, toolPolicy.timeoutMs);
      }
      case "mac_app_list": {
        if (!execution.appList) throw new BrokerError("EXECUTION_FAILED", "App inventory execution plan is unavailable");
        const inventory = await this.appInspector.list(
          execution.appList.runningOnly,
          execution.appList.includeInstalled,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        this.ensureActiveAuthority(request, execution.target);
        const data = {
          apps: inventory.apps.map((app) => ({
            app_id: app.appId,
            bundle_id: app.bundleId,
            name: app.name,
            running: app.running,
            ...(app.version !== undefined ? { version: app.version } : {})
          }))
        };
        return {
          data,
          verification: {
            required: false,
            status: "verified",
            strategy: "app_inventory_result_validation",
            evidence: {
              summary: "App metadata was collected through a fixed Broker-owned JXA inventory adapter and validated without returning bundle paths or process arguments",
              readback_hash: sha256(canonicalJson(data)),
              observed_at: new Date(this.now()).toISOString()
            }
          },
          warnings: [...inventory.warnings],
          truncated: inventory.truncated,
          auditTarget: "app_set:all",
          auditEvidence: {
            appCount: inventory.apps.length,
            runningOnly: execution.appList.runningOnly,
            includeInstalled: execution.appList.includeInstalled,
            warningCount: inventory.warnings.length,
            truncated: inventory.truncated
          }
        };
      }
      case "mac_ui_observe": {
        if (!execution.uiObserve) throw new BrokerError("EXECUTION_FAILED", "Accessibility observation execution plan is unavailable");
        const observed = await this.uiInspector.observe(
          execution.uiObserve.appId,
          execution.uiObserve.windowHint,
          execution.uiObserve.maxNodes,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs),
          execution.uiObserve.captureMode
        );
        this.ensureActiveAuthority(request, execution.target);
        this.uiSnapshotRegistry.recordObservation(
          observed,
          request.principal.principalId,
          request.principal.sessionId,
          this.now()
        );
        const data = {
          app_id: observed.appId,
          window_id: observed.windowId,
          ...(observed.windowTitle !== undefined ? { window_title: observed.windowTitle } : {}),
          focused: observed.focused,
          ...(observed.visualRef === undefined ? {} : { visual_ref: observed.visualRef }),
          nodes: observed.nodes.map((node) => ({
            element_ref: node.elementRef,
            role: node.role,
            ...(node.label !== undefined ? { label: node.label } : {}),
            enabled: node.enabled,
            focused: node.focused,
            secure: node.secure
          })),
          truncated: observed.truncated,
          ...(observed.screenshot === undefined ? {} : { screenshot: {
            mode: observed.screenshot.mode,
            mime_type: observed.screenshot.mimeType,
            image_base64: observed.screenshot.base64,
            screen_width: observed.screenshot.screenWidth,
            screen_height: observed.screenshot.screenHeight,
            window_x: observed.screenshot.windowX,
            window_y: observed.screenshot.windowY,
            window_width: observed.screenshot.windowWidth,
            window_height: observed.screenshot.windowHeight,
            capture_width: observed.screenshot.captureWidth,
            capture_height: observed.screenshot.captureHeight,
            image_width: observed.screenshot.imageWidth,
            image_height: observed.screenshot.imageHeight
          } })
        };
        return {
          data,
          verification: { required: false, status: "not_required", strategy: "accessibility_snapshot_validation" },
          warnings: [...observed.warnings],
          truncated: observed.truncated,
          auditTarget: `app_window:${observed.windowId}`,
          auditEvidence: {
            appId: observed.appId,
            windowId: observed.windowId,
            focused: observed.focused,
            nodeCount: observed.nodes.length,
            warningCount: observed.warnings.length,
            truncated: observed.truncated
          }
        };
      }
      case "mac_system_summary": {
        assertExactArguments(request.arguments, ["include_load"]);
        const includeLoad = request.arguments.include_load ?? false;
        if (typeof includeLoad !== "boolean") throw new BrokerError("PRECONDITION_FAILED", "include_load must be a boolean");
        const summary = inspectSystem(includeLoad);
        return {
          data: {
            os_version: summary.osVersion,
            architecture: summary.architecture,
            cpu_count: summary.cpuCount,
            memory_bytes: summary.memoryBytes,
            uptime_seconds: summary.uptimeSeconds,
            ...(summary.load ? { load: summary.load } : {})
          },
          verification: { required: false, status: "verified", strategy: "bounded_system_result_validation" }
        };
      }
      case "mac_network_status": {
        assertExactArguments(request.arguments, ["include_listeners"]);
        const includeListeners = request.arguments.include_listeners ?? false;
        if (typeof includeListeners !== "boolean") throw new BrokerError("PRECONDITION_FAILED", "include_listeners must be a boolean");
        const status = inspectNetwork(includeListeners);
        return {
          data: {
            interfaces: status.interfaces.map((networkInterface) => ({
              name: networkInterface.name,
              state: networkInterface.state,
              addresses: [...networkInterface.addresses]
            })),
            listeners: status.listeners.map((listener) => ({
              protocol: listener.protocol,
              address: listener.address,
              port: listener.port
            })),
            connectivity: status.connectivity
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_network_result_validation",
            evidence: { summary: "Network state was collected from local interface metadata without active probes or packet capture" }
          },
          warnings: [...status.warnings],
          truncated: status.truncated,
          auditTarget: "host:broker",
          auditEvidence: {
            interfaceCount: status.interfaces.length,
            listenerCount: status.listeners.length,
            connectivity: status.connectivity,
            truncated: status.truncated
          }
        };
      }
      case "mac_service_status": {
        if (!execution.serviceId) throw new BrokerError("EXECUTION_FAILED", "Service execution plan is unavailable");
        const status = await this.serviceInspector.inspect(
          execution.serviceId,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        return {
          data: {
            service: {
              service_id: status.serviceId,
              loaded: status.loaded,
              running: status.running,
              state: status.state,
              last_exit_code: status.lastExitCode,
              pid: status.pid
            }
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "service_state_result_validation",
            evidence: { summary: "Launchd state was collected through a fixed system adapter with bounded output and no mutation" }
          },
          warnings: [...status.warnings],
          truncated: status.truncated,
          auditTarget: `service:${status.serviceId}`,
          auditEvidence: { loaded: status.loaded, running: status.running, state: status.state, pid: status.pid }
        };
      }
      case "mac_log_tail": {
        if (!execution.logTail) throw new BrokerError("EXECUTION_FAILED", "Log execution plan is unavailable");
        const tail = await this.logInspector.tail(
          execution.logTail.source,
          execution.logTail.lines,
          execution.logTail.sinceSeconds,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        return {
          data: {
            source: tail.source,
            entries: tail.entries.map((entry) => ({
              timestamp: entry.timestamp,
              ...(entry.level ? { level: entry.level } : {}),
              message: entry.message
            })),
            truncated: tail.truncated
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "sanitized_log_result_validation",
            evidence: { summary: "Log records were collected from a fixed allowlisted source, parsed as bounded compact records, and secret-redacted before return" }
          },
          warnings: [...tail.warnings],
          truncated: tail.truncated,
          auditTarget: `log_source:${tail.source}`,
          auditEvidence: { entryCount: tail.entries.length, truncated: tail.truncated, warningCount: tail.warnings.length }
        };
      }
      case "mac_git_status": {
        if (!execution.gitStatus) throw new BrokerError("EXECUTION_FAILED", "Git status execution plan is unavailable");
        const status = await this.gitInspector.status(
          execution.gitStatus.projectRoot,
          execution.gitStatus.includeUntracked,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        return {
          data: {
            project_root: status.projectRoot,
            branch: status.branch,
            head: status.head,
            staged_paths: [...status.stagedPaths],
            unstaged_paths: [...status.unstagedPaths],
            untracked_paths: [...status.untrackedPaths],
            conflicted_paths: [...status.conflictedPaths],
            dirty: status.dirty
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_result_validation",
            evidence: { summary: "Git status was collected through a fixed read-only adapter with empty environment and target identity readback" }
          },
          warnings: [...status.warnings],
          truncated: status.truncated,
          auditTarget: `project:${status.projectRoot}`,
          auditEvidence: { branch: status.branch, dirty: status.dirty, stagedCount: status.stagedPaths.length, unstagedCount: status.unstagedPaths.length, untrackedCount: status.untrackedPaths.length, conflictedCount: status.conflictedPaths.length, truncated: status.truncated }
        };
      }
      case "mac_git_branch_list": {
        if (!execution.gitBranches) throw new BrokerError("EXECUTION_FAILED", "Git branch execution plan is unavailable");
        const branches = await this.gitBranchInspector.branches(
          execution.gitBranches.projectRoot,
          execution.gitBranches.includeRemote,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        return {
          data: {
            project_root: branches.projectRoot,
            branches: branches.branches.map((branch) => ({
              name: branch.name,
              current: branch.current,
              ...(branch.upstream !== undefined ? { upstream: branch.upstream } : {}),
              ...(branch.ahead !== undefined ? { ahead: branch.ahead } : {}),
              ...(branch.behind !== undefined ? { behind: branch.behind } : {})
            }))
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_result_validation",
            evidence: { summary: "Git branch metadata was collected through a fixed read-only adapter with repository identity readback" }
          },
          warnings: [...branches.warnings],
          truncated: branches.truncated,
          auditTarget: `project:${branches.projectRoot}`,
          auditEvidence: { branchCount: branches.branches.length, truncated: branches.truncated, warningCount: branches.warnings.length }
        };
      }
      case "mac_git_log": {
        if (!execution.gitLog) throw new BrokerError("EXECUTION_FAILED", "Git log execution plan is unavailable");
        const log = await this.gitLogInspector.log(
          execution.gitLog.projectRoot,
          execution.gitLog.limit,
          execution.gitLog.ref,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        return {
          data: {
            project_root: log.projectRoot,
            commits: log.commits.map((commit) => ({
              id: commit.id,
              ...(commit.author !== undefined ? { author: commit.author } : {}),
              timestamp: commit.timestamp,
              subject: commit.subject
            })),
            truncated: log.truncated
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_result_validation",
            evidence: { summary: "Git history metadata was collected through a fixed read-only adapter with redacted author and subject fields" }
          },
          warnings: [...log.warnings],
          truncated: log.truncated,
          auditTarget: `project:${log.projectRoot}`,
          auditEvidence: { commitCount: log.commits.length, truncated: log.truncated, warningCount: log.warnings.length }
        };
      }
      case "mac_git_diff": {
        if (!execution.gitDiff) throw new BrokerError("EXECUTION_FAILED", "Git diff execution plan is unavailable");
        const diff = await this.gitDiffInspector.diff(
          execution.gitDiff.projectRoot,
          execution.gitDiff.paths,
          execution.gitDiff.staged,
          execution.gitDiff.base,
          execution.gitDiff.maxBytes,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        return {
          data: {
            project_root: diff.projectRoot,
            diff: diff.diff,
            changed_paths: [...diff.changedPaths],
            ...(diff.base !== undefined ? { base: diff.base } : {}),
            staged: diff.staged,
            sha256: diff.sha256,
            truncated: diff.truncated
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "sanitized_diff_result_validation",
            evidence: {
              summary: "Git diff was collected through a fixed read-only adapter, bounded, secret-redacted, and hashed after sanitization",
              readback_hash: diff.sha256,
              observed_at: new Date(this.now()).toISOString()
            }
          },
          warnings: [...diff.warnings],
          truncated: diff.truncated,
          auditTarget: `project:${diff.projectRoot}`,
          auditEvidence: {
            changedPathCount: diff.changedPaths.length,
            byteLength: Buffer.byteLength(diff.diff, "utf8"),
            staged: diff.staged,
            ...(diff.base !== undefined ? { base: diff.base } : {}),
            sha256: diff.sha256,
            truncated: diff.truncated,
            warningCount: diff.warnings.length
          }
        };
      }
      case "mac_git_stage": {
        return this.dispatchGitStage(request, execution, toolPolicy.timeoutMs);
      }
      case "mac_git_commit": {
        return this.dispatchGitCommit(request, execution, toolPolicy.timeoutMs);
      }
      case "mac_package_inspect": {
        if (!execution.packageInspect) throw new BrokerError("EXECUTION_FAILED", "Package inspection execution plan is unavailable");
        const inspection = await this.packageInspector.inspect(
          execution.packageInspect.projectRoot,
          execution.packageInspect.manager,
          execution.packageInspect.checkOutdated,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        const data = {
          project_root: inspection.projectRoot,
          manager: inspection.manager,
          dependencies: inspection.dependencies.map((dependency) => ({
            name: dependency.name,
            version: dependency.version,
            ...(dependency.source !== undefined ? { source: dependency.source } : {})
          })),
          lockfile: {
            present: inspection.lockfile.present,
            ...(inspection.lockfile.path !== undefined ? { path: inspection.lockfile.path } : {})
          },
          outdated: inspection.outdated.map((dependency) => ({
            name: dependency.name,
            current: dependency.current,
            latest: dependency.latest
          })),
          truncated: inspection.truncated
        };
        return {
          data,
          verification: {
            required: false,
            status: "verified",
            strategy: "package_metadata_result_validation",
            evidence: {
              summary: "Package manifests and lockfile identity were read through bounded descriptor checks without executing package-manager scripts",
              readback_hash: sha256(canonicalJson(data)),
              observed_at: new Date(this.now()).toISOString()
            }
          },
          warnings: [...inspection.warnings],
          truncated: inspection.truncated,
          auditTarget: `project:${inspection.projectRoot}`,
          auditEvidence: {
            manager: inspection.manager,
            dependencyCount: inspection.dependencies.length,
            lockfilePresent: inspection.lockfile.present,
            outdatedCount: inspection.outdated.length,
            truncated: inspection.truncated,
            warningCount: inspection.warnings.length
          }
        };
      }
      case "mac_docker_status": {
        if (!execution.dockerStatus) throw new BrokerError("EXECUTION_FAILED", "Docker status execution plan is unavailable");
        const status = await this.dockerInspector.status(
          execution.dockerStatus.includeImages,
          execution.dockerStatus.includeStorage,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        const data = {
          daemon: {
            available: status.daemon.available,
            ...(status.daemon.version !== undefined ? { version: status.daemon.version } : {}),
            ...(status.daemon.context !== undefined ? { context: status.daemon.context } : {})
          },
          containers: status.containers.map((container) => ({
            id: container.id,
            ...(container.name !== undefined ? { name: container.name } : {}),
            state: container.state
          })),
          images: status.images.map((image) => ({
            id: image.id,
            ...(image.name !== undefined ? { name: image.name } : {}),
            ...(image.tag !== undefined ? { tag: image.tag } : {})
          })),
          ...(status.storage ? {
            storage: {
              used_bytes: status.storage.usedBytes,
              available_bytes: status.storage.availableBytes
            }
          } : {})
        };
        return {
          data,
          verification: {
            required: false,
            status: "verified",
            strategy: "sanitized_docker_result_validation",
            evidence: {
              summary: "Docker state was collected through a fixed local-only adapter, bounded parsing, and secret-safe field selection",
              readback_hash: sha256(canonicalJson(data)),
              observed_at: new Date(this.now()).toISOString()
            }
          },
          warnings: [...status.warnings],
          truncated: status.truncated,
          auditTarget: "docker_runtime:local",
          auditEvidence: {
            daemonAvailable: status.daemon.available,
            containerCount: status.containers.length,
            imageCount: status.images.length,
            truncated: status.truncated,
            warningCount: status.warnings.length
          }
        };
      }
      case "mac_docker_inspect": {
        if (!execution.dockerInspect) throw new BrokerError("EXECUTION_FAILED", "Docker inspect execution plan is unavailable");
        const inspection = await this.dockerInspector.inspect(
          execution.dockerInspect.objectType,
          execution.dockerInspect.id,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        if (inspection.objectType !== execution.dockerInspect.objectType ||
            !dockerObjectIdentityMatches(
              execution.dockerInspect.objectType,
              execution.dockerInspect.id,
              inspection.id,
              inspection.name
            )) {
          throw new BrokerError("CONFLICT", "Docker object identity changed during inspection");
        }
        const data = {
          object_type: inspection.objectType,
          id: inspection.id,
          name: inspection.name,
          state: inspection.state,
          image: inspection.image,
          ports: inspection.ports.map((port) => ({
            protocol: port.protocol,
            container_port: port.containerPort,
            host_port: port.hostPort
          })),
          mounts: inspection.mounts.map((mount) => ({
            ...(mount.source !== undefined ? { source: mount.source } : {}),
            target: mount.target,
            read_only: mount.readOnly
          }))
        };
        return {
          data,
          verification: {
            required: false,
            status: "verified",
            strategy: "sanitized_docker_result_validation",
            evidence: {
              summary: "Docker object metadata was selected from a fixed inspect response with environment omission and mount redaction",
              readback_hash: sha256(canonicalJson(data)),
              observed_at: new Date(this.now()).toISOString()
            }
          },
          warnings: [...inspection.warnings],
          truncated: inspection.truncated,
          auditTarget: `docker_object:${inspection.id}`,
          auditEvidence: {
            objectType: inspection.objectType,
            portCount: inspection.ports.length,
            mountCount: inspection.mounts.length,
            truncated: inspection.truncated,
            warningCount: inspection.warnings.length
          }
        };
      }
      case "mac_docker_logs": {
        if (!execution.dockerLogs) throw new BrokerError("EXECUTION_FAILED", "Docker logs execution plan is unavailable");
        const logs = await this.dockerInspector.logs(
          execution.dockerLogs.containerId,
          execution.dockerLogs.tail,
          execution.dockerLogs.sinceSeconds,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        const data = {
          container_id: logs.containerId,
          entries: logs.entries.map((entry) => ({ timestamp: entry.timestamp, line: entry.line })),
          truncated: logs.truncated
        };
        return {
          data,
          verification: {
            required: false,
            status: "verified",
            strategy: "sanitized_docker_result_validation",
            evidence: {
              summary: "Docker logs were collected for one authorized container with fixed tail/time bounds and mandatory secret redaction",
              readback_hash: sha256(canonicalJson(data)),
              observed_at: new Date(this.now()).toISOString()
            }
          },
          warnings: [...logs.warnings],
          truncated: logs.truncated,
          auditTarget: `docker_object:${logs.containerId}`,
          auditEvidence: {
            entryCount: logs.entries.length,
            truncated: logs.truncated,
            warningCount: logs.warnings.length
          }
        };
      }
      case "mac_process_list": {
        assertExactArguments(request.arguments, ["limit", "sort"]);
        validateProcessArguments(request.arguments);
        const inventory = await this.processExecutor.list(
          (request.arguments.limit ?? 100) as number,
          (request.arguments.sort ?? "pid") as "cpu" | "memory" | "pid" | "name",
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        return {
          data: {
            processes: inventory.processes.map((process) => ({
              pid: process.pid,
              name: process.name,
              executable: process.executable,
              cpu_percent: process.cpuPercent,
              memory_bytes: process.memoryBytes,
              owner: process.owner
            }))
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_process_result_validation",
            evidence: { summary: "Process inventory was collected through bounded native metadata and redacted owner identity" }
          },
          truncated: inventory.truncated,
          auditTarget: "process:all",
          auditEvidence: { processCount: inventory.processes.length, truncated: inventory.truncated }
        };
      }
      case "mac_process_inspect": {
        assertExactArguments(request.arguments, ["pid"]);
        const pid = request.arguments.pid;
        if (!Number.isSafeInteger(pid) || (pid as number) < 1 || (pid as number) > 99_999_999) {
          throw new BrokerError("PRECONDITION_FAILED", "pid must be an integer between 1 and 99999999");
        }
        const process = await this.processExecutor.inspect(
          pid as number,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        if (process.pid !== pid) {
          // The requested PID is the target identity. A worker or native
          // adapter returning a different process must never be serialized as
          // a successful read, even though the policy target is the bounded
          // process domain (`process:all`).
          throw new BrokerError("CONFLICT", "Process identity changed during inspection");
        }
        return {
          data: {
            process: {
              pid: process.pid,
              name: process.name,
              executable: process.executable,
              state: process.state,
              cpu_percent: process.cpuPercent,
              memory_bytes: process.memoryBytes,
              parent_pid: process.parentPid,
              child_pids: [...process.childPids],
              owner: process.owner
            }
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_process_result_validation",
            evidence: { summary: "Process metadata was collected through bounded native inspection with redacted owner identity" }
          },
          auditTarget: `process:${process.pid}`,
          auditEvidence: { pid: process.pid, childCount: process.childPids.length }
        };
      }
      case "mac_policy_explain": {
        assertExactArguments(request.arguments, ["proposed_tool", "target", "argument_digest", "proposed_arguments"]);
        const candidate = request.arguments.proposed_tool;
        if (typeof candidate !== "string" || !/^[A-Za-z0-9._:@/+-]{1,128}$/u.test(candidate)) {
          throw new BrokerError("PRECONDITION_FAILED", "proposed_tool is malformed");
        }
        const argumentDigest = request.arguments.argument_digest;
        if (argumentDigest !== undefined && (typeof argumentDigest !== "string" || !/^[A-Fa-f0-9]{64}$/u.test(argumentDigest))) {
          throw new BrokerError("PRECONDITION_FAILED", "argument_digest is malformed");
        }
        const target = normalizePolicyQueryTarget(request.arguments.target);
        try {
          const tool = authorizeTool(this.options.store, policy, candidate, request.contractVersion, request.principal.scopes);
          let authorizationTarget = target;
          let reportedTarget = target;
          if (request.arguments.proposed_arguments !== undefined) {
            if (!isPlainDataRecord(request.arguments.proposed_arguments) || Buffer.byteLength(canonicalJson(request.arguments.proposed_arguments)) > 32_768) {
              throw new BrokerError("PRECONDITION_FAILED", "Proposed arguments are malformed or oversized");
            }
            const proposed = { ...request, tool: candidate, arguments: request.arguments.proposed_arguments };
            const planned = this.planExecution(proposed, policy, tool);
            if (planned.target.kind !== target.kind || planned.target.reference !== target.reference) {
              throw new BrokerError("PRECONDITION_FAILED", "Proposed arguments and target differ");
            }
            authorizationTarget = planned.target;
            reportedTarget = planned.target;
          }

          if (tool.targetType === "path" || tool.targetType === "filesystem_roots") {
            if (target.kind !== "path") throw new BrokerError("PRECONDITION_FAILED", "Filesystem policy query requires a path target");
            const capability = candidate === "mac_read_file" || candidate === "mac_list_directory" || candidate === "mac_directory_tree" ? "content_read" : candidate === "mac_write_file_atomic" ? "write" : "metadata";
            const plan = new FilesystemInspector(policy.filesystemRoots).planPath(target.reference, capability);
            authorizationTarget = { kind: "path", reference: plan.rootId };
            reportedTarget = { kind: "path", reference: plan.requestedPath };
          } else if (tool.targetType === "job") {
            if (target.kind !== "job") throw new BrokerError("PRECONDITION_FAILED", "Job policy query requires a job target");
            if (!this.options.store.ownedJob(target.reference, request.principal.principalId)) {
              throw new BrokerError("TARGET_NOT_FOUND", "Broker-owned job was not found");
            }
            authorizationTarget = { kind: "job", reference: "owned" };
          } else if (tool.targetType === "project") {
            if (target.kind !== "project") throw new BrokerError("PRECONDITION_FAILED", "Project policy query requires a project target");
            validateGitStatusRequest(target.reference, true);
          }
          authorizeTarget(policy, request.principal.principalId, tool.requiredScopes, authorizationTarget);
          if (DEVELOPMENT_TOOL_NAMES.includes(candidate) && this.runtimeCapabilityDisabledReason(candidate) !== undefined) {
            throw new BrokerError("POLICY_DENIED", "DEVELOPMENT_RUNTIME_UNAVAILABLE");
          }
          return {
            data: {
              decision: "allow", normalized_target: reportedTarget, required_scopes: [...tool.requiredScopes],
              missing_scopes: [], reason_codes: ["AUTHORIZED"], policy_version: policy.version
            },
            verification: { required: false, status: "not_required", strategy: "policy_decision_result_validation" }
          };
        } catch (error) {
          if (!(error instanceof BrokerError)) throw error;
          const tool = policy.tools.get(candidate);
          const requiredScopes = tool ? [...tool.requiredScopes] : [];
          return {
            data: {
              decision: "deny", normalized_target: target, required_scopes: requiredScopes,
              missing_scopes: requiredScopes.filter((scope) => !request.principal.scopes.includes(scope)),
              reason_codes: DEVELOPMENT_TOOL_NAMES.includes(candidate) ? [error.errorClass,
                ...(error.message.includes("protected secret zone") ? ["SECRET_PATH_ACCESS"] :
                  error.message.includes("escapes the worktree") ? ["WORKTREE_ESCAPE_DENIED"] :
                  /^[A-Z_]+(?::|$)/u.test(error.message) ? [error.message.split(":")[0]!] : [])] : [error.errorClass], policy_version: policy.version
            },
            verification: { required: false, status: "not_required", strategy: "policy_decision_result_validation" }
          };
        }
      }
      case "mac_stat_path": {
        if (!execution.filesystem) throw new BrokerError("EXECUTION_FAILED", "Filesystem execution plan is unavailable");
        const workerResult = await this.filesystemExecutor.stat(
          execution.filesystem.plan,
          (request.arguments.follow_symlink ?? true) as boolean,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        if (workerResult.operation !== "stat") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        const metadata = workerResult.metadata;
        return {
          data: {
            path: metadata.path,
            type: metadata.type,
            size_bytes: metadata.sizeBytes,
            modified_at: metadata.modifiedAt,
            mode: metadata.mode,
            symlink: {
              is_symlink: metadata.isSymlink,
              ...(metadata.isSymlink ? { target_type: null } : {})
            }
          },
          verification: { required: false, status: "not_required", strategy: "canonical_metadata_result_validation" },
          auditTarget: `path:${metadata.path}`,
          auditEvidence: { rootId: metadata.rootId, device: metadata.device, inode: metadata.inode }
        };
      }
      case "mac_read_file": {
        if (!execution.filesystem) throw new BrokerError("EXECUTION_FAILED", "Filesystem execution plan is unavailable");
        const encoding = (request.arguments.encoding ?? "utf8") as "utf8" | "base64" | "metadata";
        const offset = (request.arguments.offset ?? 0) as number;
        const requestedMaxBytes = (request.arguments.max_bytes ?? 65_536) as number;
        const maxBytes = encoding === "metadata" ? 0 : encoding === "base64" ? Math.min(requestedMaxBytes, 786_432) : requestedMaxBytes;
        const workerResult = await this.filesystemExecutor.read(
          execution.filesystem.plan,
          offset,
          maxBytes,
          encoding,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        if (workerResult.operation !== "read") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return {
          data: {
            path: workerResult.path,
            encoding: workerResult.encoding,
            ...(workerResult.content !== undefined ? { content: workerResult.content } : {}),
            size_bytes: workerResult.sizeBytes,
            sha256: workerResult.sha256,
            truncated: workerResult.truncated
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_content_result_validation",
            evidence: { summary: "Returned bytes hashed after descriptor identity readback", readback_hash: workerResult.sha256 }
          },
          truncated: workerResult.truncated,
          auditTarget: `path:${workerResult.path}`,
          auditEvidence: {
            rootId: workerResult.rootId,
            device: workerResult.device,
            inode: workerResult.inode,
            bytesReturned: workerResult.bytesReturned
          }
        };
      }
      case "mac_hash_file": {
        if (!execution.filesystem || !execution.hashAlgorithm || !this.filesystemExecutor.hash) {
          throw new BrokerError("EXECUTION_FAILED", "Filesystem hash execution plan is unavailable");
        }
        const workerResult = await this.filesystemExecutor.hash(
          execution.filesystem.plan,
          execution.hashAlgorithm,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        if (workerResult.operation !== "hash") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return {
          data: {
            path: workerResult.path,
            algorithm: workerResult.algorithm,
            digest: workerResult.digest,
            size_bytes: workerResult.sizeBytes
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "digest_result_validation",
            evidence: { summary: "File digest was computed after descriptor identity readback" }
          },
          auditTarget: `path:${workerResult.path}`,
          auditEvidence: {
            rootId: workerResult.rootId,
            device: workerResult.device,
            inode: workerResult.inode,
            algorithm: workerResult.algorithm,
            sizeBytes: workerResult.sizeBytes
          }
        };
      }
      case "mac_list_directory": {
        if (!execution.filesystem || !execution.list || !this.filesystemExecutor.list) {
          throw new BrokerError("EXECUTION_FAILED", "Filesystem directory-list execution plan is unavailable");
        }
        const workerResult = await this.filesystemExecutor.list(
          execution.filesystem.plan,
          execution.list.cursor,
          execution.list.limit,
          execution.list.includeHidden,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        if (workerResult.operation !== "list") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return {
          data: {
            path: workerResult.path,
            entries: workerResult.entries.map((entry) => ({
              name: entry.name,
              type: entry.type,
              size_bytes: entry.sizeBytes,
              modified_at: entry.modifiedAt,
              hidden: entry.hidden
            })),
            next_cursor: workerResult.nextCursor === null ? null : encodeDirectoryCursor(workerResult.nextCursor)
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_result_validation",
            evidence: { summary: "Directory entries were enumerated from a descriptor with identity readback" }
          },
          auditTarget: `path:${workerResult.path}`,
          auditEvidence: { rootId: workerResult.rootId, entryCount: workerResult.entries.length, hasNextCursor: workerResult.nextCursor !== null }
        };
      }
      case "mac_directory_tree": {
        if (!execution.filesystem || !execution.tree || !this.filesystemExecutor.tree) {
          throw new BrokerError("EXECUTION_FAILED", "Filesystem directory-tree execution plan is unavailable");
        }
        const workerResult = await this.filesystemExecutor.tree(
          execution.filesystem.plan,
          execution.tree.depth,
          execution.tree.maxEntries,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        if (workerResult.operation !== "tree") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return {
          data: {
            root: workerResult.root,
            entries: workerResult.entries.map((entry) => ({
              path: entry.path,
              type: entry.type,
              depth: entry.depth,
              size_bytes: entry.sizeBytes
            })),
            truncated: workerResult.truncated
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_tree_result_validation",
            evidence: { summary: "Directory tree entries were enumerated from descriptor-backed directories with protected-entry and volume filtering" }
          },
          truncated: workerResult.truncated,
          auditTarget: `path:${workerResult.root}`,
          auditEvidence: { rootId: workerResult.rootId, entryCount: workerResult.entries.length, truncated: workerResult.truncated }
        };
      }
      case "mac_find_files": {
        if (!execution.find || !this.filesystemExecutor.find) {
          throw new BrokerError("EXECUTION_FAILED", "Filesystem search execution plan is unavailable");
        }
        const workerResult = await this.filesystemExecutor.find(
          execution.find.plans,
          execution.find.query,
          execution.find.maxResults,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs, undefined, execution.additionalTargets)
        );
        if (workerResult.operation !== "find") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return {
          data: {
            roots: workerResult.roots,
            query: workerResult.query,
            matches: workerResult.matches.map((match) => ({
              path: match.path,
              type: match.type,
              size_bytes: match.sizeBytes,
              modified_at: match.modifiedAt
            })),
            truncated: workerResult.truncated
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_result_validation",
            evidence: { summary: "Matching paths were enumerated through descriptor-backed, secret-filtered directory traversal" }
          },
          truncated: workerResult.truncated,
          ...(execution.auditTarget ? { auditTarget: execution.auditTarget } : {}),
          auditEvidence: {
            rootCount: workerResult.roots.length,
            matchCount: workerResult.matches.length,
            truncated: workerResult.truncated
          }
        };
      }
      case "mac_recent_files": {
        if (!execution.recent || !this.filesystemExecutor.recent) {
          throw new BrokerError("EXECUTION_FAILED", "Recent-file execution plan is unavailable");
        }
        const workerResult = await this.filesystemExecutor.recent(
          execution.recent.plans,
          execution.recent.sinceSeconds,
          execution.recent.limit,
          execution.recent.nowMs,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs, undefined, execution.additionalTargets)
        );
        if (workerResult.operation !== "recent") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return {
          data: {
            files: workerResult.files.map((file) => ({
              path: file.path,
              modified_at: file.modifiedAt,
              size_bytes: file.sizeBytes,
              type: file.type
            })),
            truncated: workerResult.truncated
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_result_validation",
            evidence: { summary: "Recent paths were collected from descriptor-backed metadata without reading file contents" }
          },
          truncated: workerResult.truncated,
          ...(execution.auditTarget ? { auditTarget: execution.auditTarget } : {}),
          auditEvidence: {
            fileCount: workerResult.files.length,
            truncated: workerResult.truncated,
            sinceSeconds: execution.recent.sinceSeconds
          }
        };
      }
      case "mac_search_text": {
        if (!execution.searchText || !this.filesystemExecutor.searchText) {
          throw new BrokerError("EXECUTION_FAILED", "Filesystem text-search execution plan is unavailable");
        }
        const workerResult = await this.filesystemExecutor.searchText(
          execution.searchText.plans,
          execution.searchText.query,
          execution.searchText.glob,
          execution.searchText.maxResults,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs, undefined, execution.additionalTargets)
        );
        if (workerResult.operation !== "search_text") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return {
          data: {
            query: workerResult.query,
            matches: workerResult.matches.map((match) => ({
              path: match.path,
              line: match.line,
              start_column: match.startColumn,
              end_column: match.endColumn,
              snippet: match.snippet
            })),
            truncated: workerResult.truncated
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_result_validation",
            evidence: { summary: "Text matches were collected from content-authorized descriptor-backed files with secret filtering and fixed byte budgets" }
          },
          truncated: workerResult.truncated,
          ...(execution.auditTarget ? { auditTarget: execution.auditTarget } : {}),
          auditEvidence: {
            matchCount: workerResult.matches.length,
            truncated: workerResult.truncated
          }
        };
      }
      case "mac_project_discover": {
        if (!execution.projectDiscover || !this.filesystemExecutor.discoverProjects) {
          throw new BrokerError("EXECUTION_FAILED", "Filesystem project-discovery execution plan is unavailable");
        }
        const workerResult = await this.filesystemExecutor.discoverProjects(
          execution.projectDiscover.plans,
          execution.projectDiscover.types,
          execution.projectDiscover.maxResults,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs, undefined, execution.additionalTargets)
        );
        if (workerResult.operation !== "project_discover") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return {
          data: {
            projects: workerResult.projects.map((project) => ({
              root: project.root,
              type: project.type,
              indicators: [...project.indicators]
            })),
            truncated: workerResult.truncated
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "safe_project_result_validation",
            evidence: { summary: "Project roots were discovered from bounded descriptor-backed metadata with protected-entry filtering and no content reads" }
          },
          truncated: workerResult.truncated,
          ...(execution.auditTarget ? { auditTarget: execution.auditTarget } : {}),
          auditEvidence: {
            projectCount: workerResult.projects.length,
            truncated: workerResult.truncated
          }
        };
      }
      case "mac_project_summary": {
        if (!execution.filesystem || !execution.projectSummary || !this.filesystemExecutor.summarizeProject) {
          throw new BrokerError("EXECUTION_FAILED", "Filesystem project-summary execution plan is unavailable");
        }
        const workerResult = await this.filesystemExecutor.summarizeProject(
          execution.filesystem.plan,
          execution.projectSummary.includeTree,
          execution.projectSummary.treeDepth,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
        );
        if (workerResult.operation !== "project_summary") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return {
          data: {
            project_root: workerResult.projectRoot,
            vcs: workerResult.vcs,
            manifests: [...workerResult.manifests],
            languages: [...workerResult.languages],
            tree_entries: workerResult.treeEntries.map((entry) => ({ path: entry.path, type: entry.type, depth: entry.depth })),
            warnings: [...workerResult.warnings]
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "safe_project_result_validation",
            evidence: { summary: "Project summary was collected from bounded descriptor-backed metadata without source or VCS control-file reads" }
          },
          truncated: workerResult.truncated,
          auditTarget: `path:${workerResult.projectRoot}`,
          auditEvidence: { manifestCount: workerResult.manifests.length, treeEntryCount: workerResult.treeEntries.length, truncated: workerResult.truncated }
        };
      }
      case "mac_storage_analysis": {
        if (!execution.storageAnalysis || !this.filesystemExecutor.analyzeStorage) {
          throw new BrokerError("EXECUTION_FAILED", "Filesystem storage-analysis execution plan is unavailable");
        }
        const workerResult = await this.filesystemExecutor.analyzeStorage(
          execution.storageAnalysis.plans,
          execution.storageAnalysis.topN,
          execution.storageAnalysis.maxDepth,
          this.executionControl(request, execution.target, toolPolicy.timeoutMs, undefined, execution.additionalTargets)
        );
        if (workerResult.operation !== "storage_analysis") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
        return {
          data: {
            volumes: workerResult.volumes.map((volume) => ({
              id: volume.id,
              name: volume.name,
              mount_path: volume.mountPath,
              total_bytes: volume.totalBytes,
              available_bytes: volume.availableBytes,
              used_bytes: volume.usedBytes
            })),
            consumers: workerResult.consumers.map((consumer) => ({
              path: consumer.path,
              size_bytes: consumer.sizeBytes,
              type: consumer.type
            })),
            analyzed_roots: [...workerResult.analyzedRoots]
          },
          verification: {
            required: false,
            status: "verified",
            strategy: "bounded_storage_result_validation",
            evidence: { summary: "Volume capacity and ranked consumers were collected from descriptor-backed metadata with protected-path filtering" }
          },
          truncated: workerResult.truncated,
          warnings: [...workerResult.warnings],
          ...(execution.auditTarget ? { auditTarget: execution.auditTarget } : {}),
          auditEvidence: {
            volumeCount: workerResult.volumes.length,
            consumerCount: workerResult.consumers.length,
            rootCount: workerResult.analyzedRoots.length,
            warningCount: workerResult.warnings.length,
            truncated: workerResult.truncated
          }
        };
      }
      case "mac_write_file_atomic": {
        return this.dispatchWrite(request, execution, toolPolicy.timeoutMs);
      }
      case "mac_apply_patch": {
        return this.dispatchPatch(request, execution, toolPolicy.timeoutMs);
      }
      case "mac_terminal_exec": {
        if (!execution.ownerTerminal || !execution.taskJob || !this.options.ownerTerminalExecutor) throw new BrokerError("POLICY_DENIED", "Owner terminal runtime is unavailable");
        return dispatchOwnerTerminal({ store: this.options.store, executor: this.options.ownerTerminalExecutor,
          request, terminal: execution.ownerTerminal, job: execution.taskJob,
          ...(execution.jobLease ? { lease: execution.jobLease } : {}),
          control: this.executionControl(request, execution.target, toolPolicy.timeoutMs, execution.taskJob.jobId, [], execution.jobLease),
          assertAuthority: () => this.ensureActiveAuthority(request, execution.target), now: this.now });
      }
      case "mac_terminal_session": {
        if (!execution.ownerTerminalSession || execution.ownerTerminalSession.action === "start" || !this.options.ownerTerminalSessions) {
          throw new BrokerError("POLICY_DENIED", "Owner terminal session runtime is unavailable");
        }
        return dispatchOwnerTerminalSessionIo({ store: this.options.store, now: this.now, manager: this.options.ownerTerminalSessions, request,
          session: execution.ownerTerminalSession, assertAuthority: () => this.ensureActiveAuthority(request, execution.target) });
      }
      case "mac_task_run":
      case "mac_test_run":
      case "mac_build_run":
      case "mac_codex_run": {
        return this.dispatchTask(request, execution, toolPolicy.timeoutMs, toolPolicy.outputCapBytes);
      }
      case "mac_service_control": {
        return this.dispatchUserServiceControl(request, execution, toolPolicy.timeoutMs);
      }
      case "mac_priv_service_control":
      case "mac_priv_package_install":
      case "mac_priv_power": {
        return this.dispatchPrivileged(request, execution, toolPolicy.timeoutMs);
      }
      case "mac_job_status": {
        if (execution.archivedJob) {
          return {
            data: archivedJobStatusData(execution.archivedJob),
            verification: { required: false, status: "verified", strategy: "job_result_validation" },
            truncated: true,
            warnings: ["Job history was archived; output is no longer retained in the live Broker ledger"],
            auditTarget: `job:${execution.archivedJob.jobId}`,
            auditEvidence: {
              jobState: execution.archivedJob.state,
              jobRevision: execution.archivedJob.revision,
              archiveSha256: execution.archivedJob.archiveSha256
            }
          };
        }
        if (!execution.job) throw new BrokerError("EXECUTION_FAILED", "Job execution plan is unavailable");
        const tailBytes = (request.arguments.tail_bytes ?? 65_536) as number;
        const output = boundedJobOutput(execution.job, tailBytes);
        const recovery = execution.job.state === "unknown"
          ? execution.job.writeMetadata !== undefined
            ? this.inspectWritePostcondition(execution.job, policy)
            : await this.inspectPrivilegedPostcondition(execution.job, request)
          : undefined;
        return {
          data: jobStatusData(execution.job, output, recovery),
          verification: { required: false, status: "verified", strategy: "job_result_validation" },
          truncated: output.truncated,
          auditTarget: `job:${execution.job.jobId}`,
          auditEvidence: {
            jobState: execution.job.state,
            jobRevision: execution.job.revision,
            ...(recovery ? { writePostcondition: recovery.postcondition, writeRecoveryResolution: recovery.resolution } : {})
          },
          ...(recovery?.postcondition === "matches"
            ? { warnings: ["Mutation postcondition matches, but the job remains UNKNOWN because the actor in the crash window cannot be proven"] }
            : recovery?.postcondition === "mismatch"
              ? { warnings: ["Mutation postcondition does not match; the job remains UNKNOWN and must not be retried automatically"] }
              : recovery?.postcondition === "unavailable"
                ? { warnings: ["Mutation postcondition could not be verified; the job remains UNKNOWN"] }
                : {})
        };
      }
      case "mac_job_cancel": {
        if (execution.archivedJob) throw new BrokerError("CONFLICT", "Archived Job history cannot be cancelled");
        if (!execution.job) throw new BrokerError("EXECUTION_FAILED", "Job execution plan is unavailable");
        const cancellation = this.options.store.requestJobCancellation(
          execution.job.jobId,
          request.principal.principalId,
          (request.arguments.reason ?? "REQUESTED_BY_OWNER") as string,
          this.now()
        );
        return {
          data: {
            job_id: cancellation.job.jobId,
            prior_state: cancellation.priorState,
            new_state: cancellation.job.state,
            cancel_requested: cancellation.job.cancelRequested,
            termination_observed: cancellation.terminationObserved
          },
          verification: {
            required: true,
            status: cancellation.terminationObserved ? "verified" : "accepted",
            strategy: "job_state_termination_verification",
            evidence: { summary: cancellation.terminationObserved ? "Terminal job state read back" : "Cancellation persisted; termination pending" }
          },
          auditTarget: `job:${cancellation.job.jobId}`,
          auditEvidence: {
            priorState: cancellation.priorState,
            newState: cancellation.job.state,
            terminationObserved: cancellation.terminationObserved,
            jobRevision: cancellation.job.revision
          }
        };
      }
      default:
        throw new BrokerError("UNSUPPORTED_CAPABILITY", "Tool handler is unavailable");
    }
  }

  private async dispatchPrivileged(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number
  ): Promise<DispatchResult> {
    if (!execution.privileged || !execution.privilegedJob) {
      throw new BrokerError("EXECUTION_FAILED", "Privileged helper Job execution plan is unavailable");
    }
    const job = execution.privilegedJob;
    if (job.state === "completed") {
      return privilegedDispatchResult(job, parseStoredPrivilegedResponse(job.stdout), execution.privileged.payload, true);
    }
    if (job.state === "queued") {
      throw new BrokerError("CONFLICT", "Privileged helper operation is already queued", true);
    }
    if (job.state === "running" && execution.privilegedJobNew !== true) {
      throw new BrokerError("UNKNOWN_OUTCOME", "Privileged helper operation is unresolved; inspect its Broker job", true);
    }
    if (job.state === "unknown") {
      throw new BrokerError("UNKNOWN_OUTCOME", "Privileged helper operation is unresolved; inspect its Broker job", true);
    }
    if (job.state === "cancelled") {
      throw new BrokerError("CANCELLED", "Privileged helper operation was cancelled before execution");
    }
    if (job.state !== "running" || !execution.jobLease) {
      throw new BrokerError("EXECUTION_FAILED", "Privileged helper Job is not executable");
    }
    const outcome = await this.executePrivilegedHelperJob({
      request,
      requestId: request.requestId,
      principalId: request.principal.principalId,
      sessionId: request.principal.sessionId,
      job,
      lease: execution.jobLease,
      operation: execution.privileged.operation,
      timeoutMs,
      target: execution.target,
      ...(execution.additionalTargets === undefined ? {} : { additionalTargets: execution.additionalTargets })
    });
    execution.privilegedJob = outcome.job;
    return privilegedDispatchResult(outcome.job, outcome.response, execution.privileged.payload, false);
  }

  private async dispatchUserServiceControl(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number
  ): Promise<DispatchResult> {
    const candidate = this.userServiceControlCandidate;
    if (!candidate || !execution.serviceControl || !execution.serviceControlJob) {
      throw new BrokerError("EXECUTION_FAILED", "User service-control Job execution plan is unavailable");
    }
    const job = execution.serviceControlJob;
    if (job.state === "completed") {
      return userServiceControlDispatchResult(job, parseStoredUserServiceControlResult(job.stdout), true);
    }
    if (job.state === "queued") {
      throw new BrokerError("CONFLICT", "User service-control operation is already queued", true);
    }
    if (job.state === "running" && execution.serviceControlJobNew !== true) {
      throw new BrokerError("UNKNOWN_OUTCOME", "User service-control operation is unresolved; inspect its Broker job", true);
    }
    if (job.state === "unknown") {
      throw new BrokerError("UNKNOWN_OUTCOME", "User service-control operation is unresolved; inspect its Broker job", true);
    }
    if (job.state === "cancelled") {
      throw new BrokerError("CANCELLED", "User service-control operation was cancelled");
    }
    if (job.state !== "running" || !execution.jobLease) {
      throw new BrokerError("EXECUTION_FAILED", "User service-control Job is not executable");
    }
    const outcome = await candidate.executeJob({
      requestId: request.requestId,
      principalId: request.principal.principalId,
      sessionId: request.principal.sessionId,
      job,
      lease: execution.jobLease,
      timeoutMs,
      assertAuthority: () => this.ensureActiveAuthority(request, execution.target, execution.additionalTargets ?? [])
    }, request.principal.principalId);
    execution.serviceControlJob = outcome.job;
    return userServiceControlDispatchResult(outcome.job, outcome.result, false);
  }

  private async dispatchWrite(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number
  ): Promise<DispatchResult> {
    if (!execution.filesystem || !execution.write || !execution.writeJob || !this.filesystemExecutor.write) {
      throw new BrokerError("EXECUTION_FAILED", "Filesystem write job execution plan is unavailable");
    }
    const job = execution.writeJob;
    if (job.state === "completed") {
      return writeDispatchResult(job, parseStoredWriteResult(job.stdout), true);
    }
    if (job.state === "queued") {
      throw new BrokerError("CONFLICT", "Filesystem write is already queued under this idempotency key", true);
    }
    if (job.state === "running" && execution.writeJobNew !== true) {
      throw new BrokerError("UNKNOWN_OUTCOME", "Filesystem write outcome is unresolved; inspect its Broker job", true);
    }
    if (job.state === "unknown") {
      throw new BrokerError("UNKNOWN_OUTCOME", "Filesystem write outcome is unresolved; inspect its Broker job", true);
    }
    if (job.state === "cancelled") {
      throw new BrokerError("CANCELLED", "Filesystem write was cancelled under this idempotency key");
    }
    if (job.state !== "running") {
      throw new BrokerError("EXECUTION_FAILED", "Filesystem write job already failed under this idempotency key");
    }
    try {
      const workerResult = await this.filesystemExecutor.write(
        execution.filesystem.plan,
        execution.write.content,
        execution.write.expectedSha256,
        execution.write.createOnly,
        this.executionControl(request, execution.target, timeoutMs, job.jobId, [], execution.jobLease),
        execution.write.temporaryName
      );
      if (workerResult.operation !== "write") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
      // Revalidate authority after the adapter returns and before committing a
      // successful Job. A mutation may have completed while a kill switch or
      // revocation changed during the bounded native operation; that outcome
      // must remain UNKNOWN rather than being published as success.
      this.ensureActiveAuthority(request, execution.target);
      const data: WriteResultData = {
        path: workerResult.path,
        bytes_written: workerResult.bytesWritten,
        sha256: workerResult.sha256,
        created: workerResult.created,
        precondition: {
          expected_sha256: workerResult.expectedSha256,
          matched: workerResult.expectedMatched,
          create_only: execution.write.createOnly
        }
      };
      execution.writeJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
        state: "completed",
        resultClass: "success",
        finishedAtMs: this.now(),
        stdout: canonicalJson(data)
      }, execution.jobLease, this.now());
      return writeDispatchResult(execution.writeJob, data, false);
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "Filesystem write job failed");
      try {
        execution.writeJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
          state: "unknown",
          resultClass: "unknown",
          finishedAtMs: this.now()
        }, execution.jobLease, this.now());
      } catch {
        // Preserve the original error; a running job without a terminal readback is unresolved.
      }
      throw brokerError;
    }
  }

  private async dispatchPatch(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number
  ): Promise<DispatchResult> {
    if (!execution.filesystem || !execution.patch || !execution.patchJob || !this.filesystemExecutor.applyPatch) {
      throw new BrokerError("EXECUTION_FAILED", "Filesystem patch job execution plan is unavailable");
    }
    const job = execution.patchJob;
    if (job.state === "completed") {
      return patchDispatchResult(job, parseStoredPatchResult(job.stdout), true);
    }
    if (job.state === "queued") {
      throw new BrokerError("CONFLICT", "Filesystem patch is already queued", true);
    }
    if (job.state === "running" && execution.patchJobNew !== true) {
      throw new BrokerError("UNKNOWN_OUTCOME", "Filesystem patch outcome is unresolved; inspect its Broker job", true);
    }
    if (job.state === "unknown") {
      throw new BrokerError("UNKNOWN_OUTCOME", "Filesystem patch outcome is unresolved; inspect its Broker job", true);
    }
    if (job.state === "cancelled") {
      throw new BrokerError("CANCELLED", "Filesystem patch was cancelled before execution");
    }
    if (job.state !== "running") {
      throw new BrokerError("EXECUTION_FAILED", "Filesystem patch job already failed");
    }
    try {
      const workerResult = await this.filesystemExecutor.applyPatch(
        execution.filesystem.plan,
        execution.patch.patch,
        execution.patch.expectedBaseHash,
        this.executionControl(request, execution.target, timeoutMs, job.jobId, [], execution.jobLease)
      );
      if (workerResult.operation !== "patch") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
      this.ensureActiveAuthority(request, execution.target);
      const data = patchResultData(workerResult);
      execution.patchJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
        state: "completed",
        resultClass: "success",
        finishedAtMs: this.now(),
        stdout: canonicalJson(data)
      }, execution.jobLease, this.now());
      return patchDispatchResult(execution.patchJob, workerResult, false);
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "Filesystem patch job failed");
      try {
        execution.patchJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
          state: "unknown",
          resultClass: "unknown",
          finishedAtMs: this.now()
        }, execution.jobLease, this.now());
      } catch {
        // Preserve the original error; a patch without trusted terminal readback is unresolved.
      }
      throw brokerError;
    }
  }

  private async dispatchAppOpen(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number
  ): Promise<DispatchResult> {
    if (!execution.appOpen || !execution.appOpenJob) {
      throw new BrokerError("EXECUTION_FAILED", "App open job execution plan is unavailable");
    }
    const job = execution.appOpenJob;
    if (job.state === "queued") throw new BrokerError("CONFLICT", "App launch is already queued", true);
    if (job.state === "unknown") throw new BrokerError("UNKNOWN_OUTCOME", "App launch outcome is unresolved; inspect its Broker job", true);
    if (job.state === "cancelled") throw new BrokerError("CANCELLED", "App launch was cancelled before execution");
    if (job.state === "completed") {
      return appOpenDispatchResult(job, parseStoredAppOpenResult(job.stdout), true);
    }
    if (job.state !== "running") throw new BrokerError("EXECUTION_FAILED", "App launch job is not running");
    try {
      const opened = await this.appControlInspector.open(
        execution.appOpen.appId,
        execution.appOpen.documentPath,
        execution.appOpen.url,
        this.executionControl(request, execution.target, timeoutMs, job.jobId, [], execution.jobLease)
      );
      this.ensureActiveAuthority(request, execution.target);
      const data = {
        app_id: opened.appId,
        state: opened.state,
        process_id: opened.processId,
        target: opened.target,
        verified: opened.verified,
        job_id: job.jobId
      };
      execution.appOpenJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
        state: "completed",
        resultClass: "success",
        finishedAtMs: this.now(),
        stdout: canonicalJson(data)
      }, execution.jobLease, this.now());
      return {
        data,
        verification: {
          required: true,
          status: "verified",
          strategy: "launch_state_and_target_reobservation",
          evidence: {
            summary: "The exact bundle identity was opened through fixed /usr/bin/open and its running state was reobserved",
            readback_hash: sha256(canonicalJson(data)),
            observed_at: new Date(this.now()).toISOString()
          }
        },
        warnings: [...opened.warnings],
        truncated: opened.truncated,
        auditTarget: `app:${opened.appId}`,
        auditEvidence: {
          appId: opened.appId,
          state: opened.state,
          verified: opened.verified,
          warningCount: opened.warnings.length
        }
      };
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "App launch failed");
      try {
        execution.appOpenJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
          state: "unknown",
          resultClass: "unknown",
          finishedAtMs: this.now()
        }, execution.jobLease, this.now());
      } catch {
        // Preserve the original error; launch may have occurred without a trusted readback.
      }
      throw brokerError;
    }
  }

  private async dispatchAppFocus(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number
  ): Promise<DispatchResult> {
    if (!execution.appFocus || !execution.appFocusJob) {
      throw new BrokerError("EXECUTION_FAILED", "App focus job execution plan is unavailable");
    }
    const job = execution.appFocusJob;
    if (job.state === "queued") throw new BrokerError("CONFLICT", "App focus is already queued", true);
    if (job.state === "unknown") throw new BrokerError("UNKNOWN_OUTCOME", "App focus outcome is unresolved; inspect its Broker job", true);
    if (job.state === "cancelled") throw new BrokerError("CANCELLED", "App focus was cancelled before execution");
    if (job.state === "completed") {
      return appFocusDispatchResult(job, parseStoredAppFocusResult(job.stdout), true);
    }
    if (job.state !== "running") throw new BrokerError("EXECUTION_FAILED", "App focus job is not running");
    if (!this.appControlInspector.focus) throw new BrokerError("UNSUPPORTED_CAPABILITY", "App focus adapter is not enabled");
    try {
      const focused = await this.appControlInspector.focus(
        execution.appFocus.appId,
        execution.appFocus.windowHint,
        this.executionControl(request, execution.target, timeoutMs, job.jobId, [], execution.jobLease)
      );
      this.ensureActiveAuthority(request, execution.target);
      const data = {
        app_id: focused.appId,
        window_id: focused.windowId,
        ...(focused.windowTitle !== undefined ? { window_title: focused.windowTitle } : {}),
        focused: focused.focused,
        reobserved_at: new Date(this.now()).toISOString(),
        verified: focused.verified,
        job_id: job.jobId
      };
      execution.appFocusJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
        state: "completed",
        resultClass: "success",
        finishedAtMs: this.now(),
        stdout: canonicalJson(data)
      }, execution.jobLease, this.now());
      return {
        data,
        verification: {
          required: true,
          status: "verified",
          strategy: "focused_app_window_reobservation",
          evidence: {
            summary: "The exact app-window identity was focused through fixed Broker-owned Accessibility automation and reobserved as focused",
            readback_hash: sha256(canonicalJson(data)),
            observed_at: data.reobserved_at
          }
        },
        warnings: [...focused.warnings],
        truncated: focused.truncated,
        auditTarget: `app_window:${focused.windowId}`,
        auditEvidence: {
          appId: focused.appId,
          windowId: focused.windowId,
          focused: focused.focused,
          verified: focused.verified,
          warningCount: focused.warnings.length
        }
      };
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "App focus failed");
      try {
        execution.appFocusJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
          state: "unknown",
          resultClass: "unknown",
          finishedAtMs: this.now()
        }, execution.jobLease, this.now());
      } catch {
        // Preserve the original error; focus may have occurred without trusted readback.
      }
      throw brokerError;
    }
  }

  private async visualActionReadback(request: BrokerRequest, execution: ExecutionPlan, timeoutMs: number) {
    if (!execution.uiActionJob || !execution.uiAction?.snapshot) {
      throw new BrokerError("EXECUTION_FAILED", "Visual action readback has no approved target");
    }
    const observed = await this.uiInspector.observe(
      execution.uiAction.snapshot.appId,
      execution.uiAction.snapshot.appId === DESKTOP_APP_ID ? desktopDisplayHint(execution.uiAction.snapshot.nativeWindowIdentity!) : undefined,
      100,
      this.executionControl(request, execution.target, timeoutMs, execution.uiActionJob.jobId, [], execution.jobLease),
      "active_window"
    );
    this.ensureActiveAuthority(request, execution.target);
    if (!observed.focused || observed.screenshot === undefined || observed.visualRef === undefined) {
      throw new BrokerError("VERIFICATION_FAILED", "Visual action did not produce a verified screenshot");
    }
    this.uiSnapshotRegistry.recordObservation(observed, request.principal.principalId, request.principal.sessionId, this.now());
    return {
      visual_ref: observed.visualRef,
      window_title: observed.windowTitle ?? "",
      screenshot: {
        mode: observed.screenshot.mode,
        mime_type: observed.screenshot.mimeType,
        image_base64: observed.screenshot.base64,
        screen_width: observed.screenshot.screenWidth,
        screen_height: observed.screenshot.screenHeight,
        window_x: observed.screenshot.windowX,
        window_y: observed.screenshot.windowY,
        window_width: observed.screenshot.windowWidth,
        window_height: observed.screenshot.windowHeight,
        capture_width: observed.screenshot.captureWidth,
        capture_height: observed.screenshot.captureHeight,
        image_width: observed.screenshot.imageWidth,
        image_height: observed.screenshot.imageHeight
      }
    };
  }

  private async dispatchUiAction(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number
  ): Promise<DispatchResult> {
    if (!execution.uiAction?.snapshot || !execution.uiActionJob) {
      throw new BrokerError("EXECUTION_FAILED", "UI action job execution plan is unavailable");
    }
    const job = execution.uiActionJob;
    if (job.state === "queued") throw new BrokerError("CONFLICT", "UI action is already queued", true);
    if (job.state === "unknown") throw new BrokerError("UNKNOWN_OUTCOME", "UI action outcome is unresolved; inspect its Broker job", true);
    if (job.state === "cancelled") throw new BrokerError("CANCELLED", "UI action was cancelled before execution");
    if (job.state === "completed") return uiActionDispatchResult(job, parseStoredUiActionResult(job.stdout), true);
    if (job.state !== "running") throw new BrokerError("EXECUTION_FAILED", "UI action job is not running");
    if (!this.uiInspector.action) throw new BrokerError("UNSUPPORTED_CAPABILITY", "UI action adapter is not enabled");
    try {
      const acted = await this.uiInspector.action(
        { snapshot: execution.uiAction.snapshot, action: execution.uiAction.action,
          ...(execution.uiAction.options === undefined ? {} : { options: execution.uiAction.options }) },
        this.executionControl(request, execution.target, timeoutMs, job.jobId, [], execution.jobLease)
      );
      this.ensureActiveAuthority(request, execution.target);
      if (acted.elementRef !== execution.uiAction.snapshot.elementRef ||
          acted.appId !== execution.uiAction.snapshot.appId ||
          acted.windowId !== execution.uiAction.snapshot.windowId ||
          acted.action !== execution.uiAction.action || acted.accepted !== true ||
          acted.verified !== true || acted.reobserved.secure !== false) {
        throw new BrokerError("VERIFICATION_FAILED", "UI action readback did not match the approved snapshot");
      }
      const data = {
        element_ref: acted.elementRef,
        action: acted.action,
        accepted: acted.accepted,
        job_id: job.jobId,
        reobserved: {
          role: acted.reobserved.role,
          enabled: acted.reobserved.enabled,
          focused: acted.reobserved.focused,
          ...(acted.reobserved.state !== undefined ? { state: acted.reobserved.state } : {})
        },
        ...(execution.uiAction.snapshot.role === "VisualWindow" ? await this.visualActionReadback(request, execution, timeoutMs) : {})
      };
      const storedData = {
        element_ref: data.element_ref, action: data.action, accepted: data.accepted,
        job_id: data.job_id, reobserved: { ...data.reobserved, secure: false as const }
      };
      execution.uiActionJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
        state: "completed",
        resultClass: "success",
        finishedAtMs: this.now(),
        stdout: canonicalJson(storedData)
      }, execution.jobLease, this.now());
      return {
        data,
        verification: {
          required: true,
          status: "verified",
          strategy: execution.uiAction.snapshot.role === "VisualWindow" ? "visual_action_dispatch" : "accessibility_reobservation",
          evidence: {
            summary: execution.uiAction.snapshot.role === "VisualWindow"
              ? "A bounded event was sent to the observed browser window; inspect a fresh screenshot to verify the page effect"
              : "The approved Accessibility element was re-resolved before and after one fixed action",
            readback_hash: sha256(canonicalJson(storedData)),
            observed_at: new Date(this.now()).toISOString()
          }
        },
        warnings: [...acted.warnings],
        truncated: acted.truncated,
        auditTarget: `ui_element:${acted.elementRef}`,
        auditEvidence: {
          appId: acted.appId,
          windowId: acted.windowId,
          elementRef: acted.elementRef,
          action: acted.action,
          accepted: acted.accepted,
          verified: acted.verified,
          warningCount: acted.warnings.length
        }
      };
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "Accessibility action failed");
      try {
        execution.uiActionJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
          state: "unknown",
          resultClass: "unknown",
          finishedAtMs: this.now()
        }, execution.jobLease, this.now());
      } catch {
        // Preserve the original error; the action may have occurred without trusted readback.
      }
      throw brokerError;
    }
  }

  private async dispatchUiType(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number
  ): Promise<DispatchResult> {
    if (!execution.uiType?.snapshot || !execution.uiTypeJob) {
      throw new BrokerError("EXECUTION_FAILED", "UI type job execution plan is unavailable");
    }
    const job = execution.uiTypeJob;
    if (job.state === "queued") throw new BrokerError("CONFLICT", "UI type is already queued", true);
    if (job.state === "unknown") throw new BrokerError("UNKNOWN_OUTCOME", "UI type outcome is unresolved; inspect its Broker job", true);
    if (job.state === "cancelled") throw new BrokerError("CANCELLED", "UI type was cancelled before execution");
    if (job.state === "completed") return uiTypeDispatchResult(job, parseStoredUiTypeResult(job.stdout), true);
    if (job.state !== "running") throw new BrokerError("EXECUTION_FAILED", "UI type job is not running");
    if (!this.uiInspector.type) throw new BrokerError("UNSUPPORTED_CAPABILITY", "UI type adapter is not enabled");
    try {
      const typed = await this.uiInspector.type(
        { snapshot: execution.uiType.snapshot, text: execution.uiType.text, keys: execution.uiType.keys, submit: execution.uiType.submit },
        this.executionControl(request, execution.target, timeoutMs, job.jobId, [], execution.jobLease)
      );
      this.ensureActiveAuthority(request, execution.target);
      if (typed.elementRef !== execution.uiType.snapshot.elementRef || typed.appId !== execution.uiType.snapshot.appId ||
          typed.windowId !== execution.uiType.snapshot.windowId || typed.charactersAccepted !== execution.uiType.text.length ||
          typed.keysAccepted.length !== execution.uiType.keys.length || typed.keysAccepted.some((key, index) => key !== execution.uiType!.keys[index]) ||
          typed.submitted !== execution.uiType.submit || typed.focusConfirmed !== true || typed.verified !== true || typed.reobserved.secure !== false) {
        throw new BrokerError("VERIFICATION_FAILED", "UI type readback did not match the approved snapshot");
      }
      const data = {
        element_ref: typed.elementRef,
        characters_accepted: typed.charactersAccepted,
        keys_accepted: [...typed.keysAccepted],
        submitted: typed.submitted,
        focus_confirmed: typed.focusConfirmed,
        reobserved: { role: typed.reobserved.role, focused: typed.reobserved.focused, secure: typed.reobserved.secure }
      };
      execution.uiTypeJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
        state: "completed", resultClass: "success", finishedAtMs: this.now(), stdout: canonicalJson(data)
      }, execution.jobLease, this.now());
      return {
        data: { ...data, job_id: job.jobId },
        verification: {
          required: true, status: "verified", strategy: "focused_target_and_input_postcondition",
          evidence: { summary: "Bounded input was delivered through stdin and the approved Accessibility target was reobserved", readback_hash: sha256(canonicalJson(data)), observed_at: new Date(this.now()).toISOString() }
        },
        warnings: [...typed.warnings],
        truncated: typed.truncated,
        auditTarget: `ui_element:${typed.elementRef}`,
        auditEvidence: { jobId: job.jobId, elementRef: typed.elementRef, charactersAccepted: typed.charactersAccepted, keyCount: typed.keysAccepted.length, submitted: typed.submitted, focusConfirmed: typed.focusConfirmed }
      };
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "Accessibility input failed");
      try {
        execution.uiTypeJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, { state: "unknown", resultClass: "unknown", finishedAtMs: this.now() }, execution.jobLease, this.now());
      } catch {
        // Preserve the original error; input may have been delivered without trusted readback.
      }
      throw brokerError;
    }
  }

  private async dispatchGitStage(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number
  ): Promise<DispatchResult> {
    if (!execution.gitStage || !execution.gitStageJob) {
      throw new BrokerError("EXECUTION_FAILED", "Git stage job execution plan is unavailable");
    }
    const job = execution.gitStageJob;
    if (job.state === "queued") throw new BrokerError("CONFLICT", "Git stage is already queued", true);
    if (job.state === "unknown") throw new BrokerError("UNKNOWN_OUTCOME", "Git stage outcome is unresolved; inspect its Broker job", true);
    if (job.state === "cancelled") throw new BrokerError("CANCELLED", "Git stage was cancelled before execution");
    if (job.state !== "running") throw new BrokerError("EXECUTION_FAILED", "Git stage job is not running");
    try {
      const stage = await this.gitWriteInspector.stage(
        execution.gitStage.projectRoot,
        execution.gitStage.paths,
        this.executionControl(request, execution.target, timeoutMs, job.jobId, [], execution.jobLease)
      );
      this.ensureActiveAuthority(request, execution.target);
      const data = {
        project_root: stage.projectRoot,
        staged_paths: [...stage.stagedPaths],
        skipped_paths: [...stage.skippedPaths],
        staged_diff_sha256: stage.stagedDiffSha256,
        index_changed: stage.indexChanged
      };
      execution.gitStageJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
        state: "completed",
        resultClass: "success",
        finishedAtMs: this.now(),
        stdout: canonicalJson(data)
      }, execution.jobLease, this.now());
      return {
        data,
        verification: {
          required: true,
          status: "verified",
          strategy: "staged_diff_hash",
          evidence: {
            summary: "Explicit Git paths were staged and the resulting index snapshot was hashed after repository/path identity readback",
            readback_hash: stage.stagedDiffSha256,
            observed_at: new Date(this.now()).toISOString()
          }
        },
        warnings: [...stage.warnings],
        truncated: stage.truncated,
        auditTarget: `project:${stage.projectRoot}`,
        auditEvidence: {
          stagedPathCount: stage.stagedPaths.length,
          changedPaths: [...stage.stagedPaths],
          skippedPathCount: stage.skippedPaths.length,
          indexChanged: stage.indexChanged,
          stagedDiffSha256: stage.stagedDiffSha256,
          warningCount: stage.warnings.length,
          truncated: stage.truncated
        }
      };
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "Git stage failed");
      try {
        execution.gitStageJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
          state: "unknown",
          resultClass: "unknown",
          finishedAtMs: this.now()
        }, execution.jobLease, this.now());
      } catch {
        // Preserve the original error; the index mutation has no trusted terminal readback.
      }
      throw brokerError;
    }
  }

  private async dispatchGitCommit(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number
  ): Promise<DispatchResult> {
    if (!execution.gitCommit || !execution.gitCommitJob) {
      throw new BrokerError("EXECUTION_FAILED", "Git commit job execution plan is unavailable");
    }
    const job = execution.gitCommitJob;
    if (job.state === "queued") throw new BrokerError("CONFLICT", "Git commit is already queued", true);
    if (job.state === "unknown") throw new BrokerError("UNKNOWN_OUTCOME", "Git commit outcome is unresolved; inspect its Broker job", true);
    if (job.state === "cancelled") throw new BrokerError("CANCELLED", "Git commit was cancelled before execution");
    if (job.state !== "running") throw new BrokerError("EXECUTION_FAILED", "Git commit job is not running");
    try {
      const commit = await this.gitWriteInspector.commit(
        execution.gitCommit.projectRoot,
        execution.gitCommit.message,
        execution.gitCommit.expectedStagedDiffSha256,
        this.executionControl(request, execution.target, timeoutMs, job.jobId, [], execution.jobLease)
      );
      this.ensureActiveAuthority(request, execution.target);
      const data = {
        project_root: commit.projectRoot,
        commit_id: commit.commitId,
        parent_ids: [...commit.parentIds],
        staged_diff_sha256: commit.stagedDiffSha256,
        precondition: {
          expected_sha256: commit.precondition.expectedSha256,
          actual_sha256: commit.precondition.actualSha256,
          matched: commit.precondition.matched
        },
        working_tree_state: commit.workingTreeState
      };
      execution.gitCommitJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
        state: "completed",
        resultClass: "success",
        finishedAtMs: this.now(),
        stdout: canonicalJson(data)
      }, execution.jobLease, this.now());
      return {
        data,
        verification: {
          required: true,
          status: "verified",
          strategy: "commit_id_parent_and_staged_precondition",
          evidence: {
            summary: "Local commit advanced HEAD, matched the staged digest precondition, and read back commit parents and index state",
            readback_hash: commit.stagedDiffSha256,
            observed_at: new Date(this.now()).toISOString()
          }
        },
        warnings: [...commit.warnings],
        truncated: commit.truncated,
        auditTarget: `project:${commit.projectRoot}`,
        auditEvidence: {
          commitId: commit.commitId,
          parentCount: commit.parentIds.length,
          stagedDiffSha256: commit.stagedDiffSha256,
          workingTreeState: commit.workingTreeState,
          warningCount: commit.warnings.length,
          truncated: commit.truncated
        }
      };
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "Git commit failed");
      try {
        execution.gitCommitJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
          state: "unknown",
          resultClass: "unknown",
          finishedAtMs: this.now()
        }, execution.jobLease, this.now());
      } catch {
        // Preserve the original error; the commit may have occurred without a trusted readback.
      }
      throw brokerError;
    }
  }

  private inspectWritePostcondition(job: BrokerJob, policy: BrokerPolicy): WriteRecoveryStatus | undefined {
    const metadata = job.writeMetadata;
    if (job.tool !== "mac_write_file_atomic" || metadata === undefined) return undefined;
    const writeTool = policy.tools.get("mac_write_file_atomic");
    if (!writeTool || writeTool.enabled !== true || policy.killSwitches.global || policy.killSwitches.mutations) {
      return unavailableWriteRecovery(this.now());
    }
    try {
      const inspector = new FilesystemInspector(policy.filesystemRoots);
      const plan = inspector.planPath(metadata.path, "write");
      if (plan.rootId !== metadata.rootId || metadata.rootPath === undefined || metadata.rootDevice === undefined || metadata.rootInode === undefined ||
          plan.rootIdentity.rootPath !== metadata.rootPath || plan.rootIdentity.device !== metadata.rootDevice || plan.rootIdentity.inode !== metadata.rootInode) {
        return unavailableWriteRecovery(this.now());
      }
      const postcondition = inspector.verifyWritePostcondition(plan, metadata.desiredSha256, metadata.bytes);
      return writeRecoveryStatus(postcondition, this.now());
    } catch {
      return unavailableWriteRecovery(this.now());
    }
  }

  /**
   * A privileged helper command cannot be replayed after an unresolved
   * outcome. A separate authenticated helper readback may explain the
   * postcondition, but the Broker Job remains UNKNOWN in every case.
   */
  private async inspectPrivilegedPostcondition(job: BrokerJob, request: BrokerRequest): Promise<WriteRecoveryStatus | undefined> {
    if (job.privilegedPayload === undefined || job.state !== "unknown") return undefined;
    try {
      const readback = await this.privilegedHelperExecutor.readback({
        principalId: request.principal.principalId,
        sessionId: request.principal.sessionId,
        job,
        operation: job.privilegedPayload.operation,
        timeoutMs: 5_000,
        assertAuthority: () => this.checkRevocation(request)
      });
      return {
        postcondition: readback.postcondition,
        resolution: "remains_unknown",
        observed_at: new Date(this.now()).toISOString()
      };
    } catch {
      return unavailableWriteRecovery(this.now());
    }
  }

  private async dispatchDevelopment(request: BrokerRequest, execution: ExecutionPlan, toolPolicy: ToolPolicy): Promise<DispatchResult> {
    const gateway = this.options.developmentGateway!;
    const plan = execution.development!;
    const args = request.arguments;
    const authority = () => this.ensureActiveAuthority(request, execution.target);
    const control = this.executionControl(request, execution.target, toolPolicy.timeoutMs);
    const read = (data: unknown, evidence: Record<string, unknown> = {}): DispatchResult => ({ data,
      verification: { required: true, status: "verified", strategy: "bounded_result_validation" }, auditEvidence: evidence });
    if (request.tool === "mac_git_worktree_create" || request.tool === "mac_git_branch_create") {
      const result = await gateway.worktrees.create({ projectRoot: plan.projectRoot, branchName: args.branch_name as string,
        baseRef: args.base_ref as string, taskId: args.task_id as string, idempotencyKey: args.idempotency_key as string,
        owner: request.principal.principalId }, control, authority);
      return { data: worktreeResult(result.record, result.reused),
        verification: { required: true, status: "verified", strategy: "changed_paths_and_hash_readback" },
        auditEvidence: { project: plan.projectRoot, worktree: result.record.worktree, taskId: result.record.taskId,
          branch: result.record.branchName, reused: result.reused, changedPaths: [result.record.worktree] } };
    }
    if (request.tool === "mac_git_worktree_list") {
      return read({ project_root: plan.projectRoot, worktrees: gateway.worktrees.list(plan.projectRoot, request.principal.principalId)
        .map((record) => ({ worktree: record.worktree, branch_name: record.branchName, base_ref: record.baseRef, task_id: record.taskId })) });
    }
    if (request.tool === "mac_git_worktree_remove") {
      await gateway.worktrees.remove(plan.projectRoot, plan.worktree!, request.principal.principalId, plan.taskId!, control,
        authority, () => this.options.store.hasActiveProjectJobs(plan.projectRoot) || this.options.store.hasActiveProjectJobs(plan.worktree!), args.idempotency_key as string);
      return { data: { project_root: plan.projectRoot, worktree: plan.worktree!, removed: true },
        verification: { required: true, status: "verified", strategy: "changed_paths_and_hash_readback" },
        auditEvidence: { project: plan.projectRoot, worktree: plan.worktree!, taskId: plan.taskId!, changedPaths: [plan.worktree!] } };
    }
    if (request.tool === "mac_codex_preflight") {
      const status = await this.gitInspector.status(plan.worktree ?? plan.projectRoot, true, control);
      const data = gateway.preflightData(plan, status.dirty, this.taskRunner);
      try {
        const agentPolicy = authorizeTool(this.options.store, this.currentPolicy(), "mac_codex_run", request.contractVersion, request.principal.scopes);
        authorizeTarget(this.currentPolicy(), request.principal.principalId, agentPolicy.requiredScopes, execution.target);
      } catch { data.reason_codes.push("AGENT_EXECUTION_AUTHORITY_UNAVAILABLE"); data.permission = "deny"; data.environment_ready = false; }
      return read(data);
    }
    if (request.tool === "mac_execution_audit") {
      const rows = this.options.store.executionAudit(request.principal.principalId, { project: plan.projectRoot, limit: (args.limit ?? 50) as number });
      return read({ project_root: plan.projectRoot, events: rows.map((row) => ({ timestamp: new Date(row.timestamp_ms as number).toISOString(),
        request_id: row.request_id, tool: row.tool, actor: request.principal.principalId, decision: row.decision, result: row.result_class,
        scope: isPlainDataRecord(row.evidence) && Array.isArray(row.evidence.scopes) ? row.evidence.scopes : [],
        target: row.target_ref,
        ...(isPlainDataRecord(row.evidence) ? {
          ...(typeof row.evidence.taskId === "string" ? { task_id: row.evidence.taskId } : {}),
          ...(typeof row.evidence.worktree === "string" ? { worktree: row.evidence.worktree } : {}),
          ...(typeof row.evidence.durationMs === "number" ? { duration_ms: row.evidence.durationMs } : {}),
          ...(Array.isArray(row.evidence.changedPaths) ? { changed_paths: row.evidence.changedPaths.slice(0, 256) } : {}),
          ...(typeof row.evidence.commitId === "string" ? { commit_hash: row.evidence.commitId } : {})
        } : {}) })),
        truncated: rows.length >= ((args.limit ?? 50) as number) });
    }
    if (request.tool === "mac_pr_prepare") {
      const record = gateway.worktrees.require(plan.worktree!, plan.projectRoot, request.principal.principalId);
      const requestedBase = (args.base_ref ?? record.baseCommit) as string;
      const baseMetadata = await this.gitLogInspector.log(plan.worktree!, 1, requestedBase, control);
      const base = baseMetadata.commits[0]?.id;
      if (!base) throw new BrokerError("PRECONDITION_FAILED", "Review base did not resolve to a commit");
      const diff = await this.gitDiffInspector.diff(plan.worktree!, [], false, base, 32_768, control);
      const status = await this.gitInspector.status(plan.worktree!, true, control);
      const log = await this.gitLogInspector.log(plan.worktree!, 50, undefined, control);
      // Bounded ancestry metadata: stop at base when present; never call a publishing CLI.
      const commits = log.commits.filter((commit, index, all) => {
        const baseIndex = all.findIndex((entry) => entry.id === base);
        return baseIndex >= 0 ? index < baseIndex : commit.id !== base;
      }).map(({ id, subject }) => ({ id, subject }));
      const evidence = this.options.store.executionAudit(request.principal.principalId, { project: plan.projectRoot, limit: 100 })
        .filter((row) => ["mac_test_run", "mac_build_run", "mac_task_run"].includes(row.tool as string) &&
          isPlainDataRecord(row.evidence) && row.evidence.worktree === plan.worktree && row.evidence.taskId === record.taskId)
        .map((row) => `${row.tool}: ${row.result_class}`).slice(0, 32);
      const changed = [...new Set([...diff.changedPaths, ...status.untrackedPaths])].slice(0, 256);
      const title = `Development task ${record.taskId}`;
      return read({ project_root: plan.projectRoot, worktree: plan.worktree!, changed_files: changed, commits, title,
        description: `${title}\n\nChanged files: ${changed.length}\nLocal commits: ${commits.length}\nValidation: ${evidence.length ? evidence.join(", ") : "No verified task evidence recorded"}`, test_evidence: evidence });
    }
    throw new BrokerError("UNSUPPORTED_CAPABILITY", "Development operation is unavailable");
  }

  private taskJobReceipt(request: BrokerRequest, execution: ExecutionPlan, startedAt: number, reused: boolean): BrokerResult {
    if (!execution.taskJob || !execution.taskRun) throw new BrokerError("EXECUTION_FAILED", "Task admission readback is unavailable");
    return {
      ok: true,
      request_id: request.requestId,
      tool: request.tool,
      result_class: "SUCCEEDED",
      data: execution.development ? { job_id: execution.taskJob.jobId, state: execution.taskJob.state,
        task_id: execution.taskRun.taskId!, worktree: execution.taskRun.cwd,
        ...(request.tool === "mac_codex_run" ? {} : { profile: execution.taskRun.profile,
          ...(execution.taskRun.resolvedProfile ? { command: [execution.taskRun.resolvedProfile.process.executable,
            ...execution.taskRun.resolvedProfile.process.args].map(argument => redactBoundedText(argument, 4096).text) } : {}) }) } : {
        profile: execution.taskRun.profile,
        cwd: execution.taskRun.cwd,
        state: execution.taskJob.state,
        job_id: execution.taskJob.jobId,
        accepted: true,
        reused,
        ...(execution.taskRun.taskId === undefined ? {} : { task_id: execution.taskRun.taskId })
      },
      warnings: [],
      truncated: false,
      verification: execution.development ? { required: true, status: "accepted", strategy: "exit_status_and_declared_task_verification" } :
        { required: true, status: "accepted", strategy: "exit_status_and_declared_task_verification" },
      duration_ms: Math.max(0, this.now() - startedAt)
    };
  }

  private async dispatchTask(
    request: BrokerRequest,
    execution: ExecutionPlan,
    timeoutMs: number,
    outputCapBytes: number
  ): Promise<DispatchResult> {
    if (!execution.taskRun || !execution.taskJob) {
      throw new BrokerError("EXECUTION_FAILED", "Task job execution plan is unavailable");
    }
    const job = execution.taskJob;
    if (job.state === "unknown") {
      throw new BrokerError("UNKNOWN_OUTCOME", "Task outcome is unresolved; inspect its Broker job", true);
    }
    if (job.state === "cancelled") throw new BrokerError("CANCELLED", "Task was cancelled before execution");
    if (job.state !== "running") throw new BrokerError("EXECUTION_FAILED", "Task job is not running");
    let resolved: ResolvedTaskProfile;
    try {
      resolved = execution.taskRun.resolvedProfile ?? await this.taskProfileRegistry.resolve({
        profile: execution.taskRun.profile,
        cwd: execution.taskRun.cwd,
        args: execution.taskRun.args,
        ...(execution.taskRun.maxRuntimeMs === undefined ? {} : { maxRuntimeMs: execution.taskRun.maxRuntimeMs }),
        ...(execution.taskRun.taskId === undefined ? {} : { taskId: execution.taskRun.taskId })
      });
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("PRECONDITION_FAILED", "Task profile resolution failed");
      try {
        execution.taskJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
          state: "failed",
          resultClass: "failed",
          finishedAtMs: this.now()
        }, execution.jobLease, this.now());
      } catch {
        // Preserve the original profile error when terminal persistence fails.
      }
      throw brokerError;
    }
    let terminalPersisted = false;
    try {
      requireTaskIsolationProof(this.taskRunner.isolationProof, resolved, this.taskRunner.mechanism);
      const descriptorDigest = taskDescriptorDigest(resolved);
      const persistTaskProcessSnapshot = (snapshot: ProcessOwnershipSnapshot, initial: boolean): void => {
        if (!execution.taskJob || !execution.jobLease) {
          throw new BrokerError("EXECUTION_FAILED", "Task process ownership cannot be linked to its Job");
        }
        const recordedAtMs = this.now();
        const metadata = {
          pid: snapshot.identity.pid,
          processGroupId: snapshot.identity.processGroupId,
          startTimeMicros: snapshot.identity.startTimeMicros,
          recordedAtMs,
          taskDescriptorDigest: descriptorDigest,
          ...(snapshot.ownershipProof === undefined ? {} : { ownershipProof: snapshot.ownershipProof }),
          descendants: snapshot.descendants.map((descendant) => ({
            pid: descendant.pid,
            startTimeMicros: descendant.startTimeMicros
          }))
        } as const;
        execution.taskJob = initial
          ? this.options.store.recordJobProcessOwnership(
            execution.taskJob.jobId,
            request.principal.principalId,
            execution.taskJob.revision,
            metadata,
            execution.jobLease,
            recordedAtMs
          )
          : this.options.store.updateJobProcessOwnership(
            execution.taskJob.jobId,
            request.principal.principalId,
            execution.taskJob.revision,
            metadata,
            execution.jobLease,
            recordedAtMs
          );
      };
      const persistGuestRequest = (admission: VirtualizationGuestTaskAdmission): void => {
        if (!execution.taskJob || !execution.jobLease) {
          throw new BrokerError("EXECUTION_FAILED", "Guest request cannot be linked to its Job");
        }
        const recordedAtMs = this.now();
        const metadata: GuestTaskJobMetadata = {
          requestId: admission.requestId,
          nonce: admission.nonce,
          requestDigest: admission.requestDigest,
          guestIdentity: { ...admission.guestIdentity },
          profileDigest: admission.profileDigest,
          taskDigest: admission.taskDigest,
          timeoutMs: admission.timeoutMs,
          outputCapBytes: admission.outputCapBytes,
          recordedAtMs
        };
        execution.taskJob = this.options.store.recordJobGuestRequest(
          execution.taskJob.jobId,
          request.principal.principalId,
          execution.taskJob.revision,
          metadata,
          execution.jobLease,
          recordedAtMs
        );
      };
      const persistContainer = (metadata: Omit<ContainerTaskJobMetadata, "taskDescriptorDigest">): void => {
        if (!execution.taskJob || !execution.jobLease) throw new BrokerError("AUDIT_UNAVAILABLE", "Container ownership requires an active Job lease");
        this.ensureActiveAuthority(request, execution.target);
        execution.taskJob = this.options.store.recordJobContainerOwnership(execution.taskJob.jobId,
          request.principal.principalId, execution.taskJob.revision, { ...metadata, taskDescriptorDigest: descriptorDigest },
          execution.jobLease, this.now());
      };
      const persistWorkspaceImport = (path: string, phase: "intent" | "verified"): void => {
        this.options.store.appendAudit({ requestId: `${request.requestId}:import:${sha256(path).slice(0, 16)}`,
          principalId: request.principal.principalId, tool: request.tool, eventType: phase === "intent" ? "intent" : "completion",
          decision: "allow", resultClass: phase === "intent" ? "SOURCE_WRITE_INTENT" : "SOURCE_WRITE_VERIFIED",
          targetRef: `project:${execution.development?.projectRoot ?? execution.auditContext?.project ?? resolved.cwd}`,
          policyVersion: request.policyVersion, timestampMs: this.now(),
          evidence: { requestId: request.requestId, jobId: job.jobId, taskId: execution.taskRun!.taskId,
            worktree: resolved.cwd, changedPaths: [path], phase } });
      };
      const persistGuestResult = (result: TaskExecutionResult): void => {
        if (!execution.taskJob || !execution.jobLease) {
          throw new BrokerError("EXECUTION_FAILED", "Guest result cannot be linked to its Job");
        }
        this.ensureActiveAuthority(request, execution.target);
        const validated = validateTaskExecutionResult(result);
        const recordedAtMs = this.now();
        execution.taskJob = this.options.store.recordJobGuestResult(
          execution.taskJob.jobId,
          request.principal.principalId,
          execution.taskJob.revision,
          validated,
          execution.jobLease,
          recordedAtMs
        );
      };
      const taskControl = this.executionControl(
        request,
        execution.target,
        execution.taskRun.maxRuntimeMs === undefined ? timeoutMs : Math.min(timeoutMs, resolved.process.timeoutMs),
        job.jobId,
        [],
        execution.jobLease,
        (snapshot) => persistTaskProcessSnapshot(snapshot, true),
        (snapshot) => persistTaskProcessSnapshot(snapshot, false),
        persistGuestRequest,
        this.taskRunner.mechanism === "virtualization" ? persistGuestResult : undefined,
        this.taskRunner.mechanism === "docker-container" ? persistContainer : undefined,
        this.taskRunner.mechanism === "docker-container" ? persistWorkspaceImport : undefined
      );
      const taskResult = validateTaskExecutionResult(await this.taskRunner.run(
        resolved,
        taskControl
      ));
      // Revocation can arrive after the executor has already verified removal.
      // Preserve that cleanup evidence, but never publish execution success.
      let authorityLost = false;
      try { this.ensureActiveAuthority(request, execution.target); }
      catch (error) {
        if (this.taskRunner.mechanism !== "docker-container" || taskResult.containerCleanupVerified !== true) throw error;
        authorityLost = true;
      }
      const rawOutputBytes = Buffer.byteLength(taskResult.stdout, "utf8") + Buffer.byteLength(taskResult.stderr, "utf8");
      const outputBudgetExceeded = taskResult.truncated || rawOutputBytes > resolved.process.outputCapBytes;
      const timeoutBudgetExceeded = taskResult.durationMs > Math.min(timeoutMs, resolved.process.timeoutMs);
      const streamCap = Math.max(1, Math.floor(outputCapBytes / 2));
      const stdout = redactBoundedText(taskResult.stdout, streamCap);
      const stderr = redactBoundedText(taskResult.stderr, streamCap);
      const verificationSummary = taskResult.verification.summary === undefined
        ? undefined
        : redactBoundedText(taskResult.verification.summary, 512).text;
      const durableCancellation = this.options.store.ownedJob(job.jobId, request.principal.principalId)?.cancelRequested === true;
      if (durableCancellation && this.taskRunner.mechanism === "docker-container" && taskResult.containerCleanupVerified !== true) throw new BrokerError("UNKNOWN_OUTCOME", "Cancellation cleanup is unverified", true);
      const finished = !authorityLost && !durableCancellation && !outputBudgetExceeded && !timeoutBudgetExceeded && taskResult.state === "completed" && taskResult.resultClass === "SUCCEEDED" && taskResult.verification.status === "verified";
      const terminalState = authorityLost || durableCancellation ? "cancelled" : finished ? "completed" : timeoutBudgetExceeded || taskResult.state === "timed_out" ? "failed" : taskResult.state === "cancelled" ? "cancelled" : taskResult.state === "unknown" ? "unknown" : "failed";
      const terminalClass = finished ? "success" : terminalState === "cancelled" ? "denied" : terminalState === "unknown" ? "unknown" : timeoutBudgetExceeded || taskResult.state === "timed_out" || outputBudgetExceeded || taskResult.resultClass === "OUTPUT_LIMIT" ? "failed" : taskResult.verification.status === "failed" ? "verification_failed" : "failed";
      if (authorityLost) this.options.store.requestJobCancellation(job.jobId, request.principal.principalId, "Active task authority ended", this.now());
      const currentTaskJob = this.options.store.ownedJob(job.jobId, request.principal.principalId);
      if (currentTaskJob === undefined) throw new BrokerError("AUDIT_UNAVAILABLE", "Task Job disappeared before terminal persistence");
      execution.taskJob = currentTaskJob;
      execution.taskJob = this.options.store.finishJob(job.jobId, request.principal.principalId, currentTaskJob.revision, {
        state: terminalState,
        resultClass: terminalClass,
        finishedAtMs: this.now(),
        exitCode: taskResult.exitCode,
        stdout: stdout.text,
        stderr: stderr.text,
        ...(taskResult.containerCleanupVerified === undefined ? {} : { containerCleanupVerified: taskResult.containerCleanupVerified })
      }, execution.jobLease, this.now());
      terminalPersisted = true;
      if (!finished) {
        if (terminalState === "cancelled") throw new BrokerError("CANCELLED", "Task was cancelled under active authority");
        if (terminalState === "unknown") throw new BrokerError("UNKNOWN_OUTCOME", "Task outcome could not be verified", true);
        if (timeoutBudgetExceeded || taskResult.state === "timed_out") throw new BrokerError("TIMEOUT", "Task exceeded its execution budget");
        if (outputBudgetExceeded || taskResult.resultClass === "OUTPUT_LIMIT") throw new BrokerError("OUTPUT_LIMIT", "Task exceeded its output budget");
        if (taskResult.verification.status !== "verified") throw new BrokerError("VERIFICATION_FAILED", "Task postcondition verification failed");
        throw new BrokerError("EXECUTION_FAILED", "Task execution failed");
      }
      return {
        data: {
          profile: resolved.profile,
          cwd: resolved.cwd,
          state: execution.taskJob.state,
          job_id: execution.taskJob.jobId,
          exit_code: taskResult.exitCode,
          stdout: stdout.text,
          stderr: stderr.text,
          truncated: taskResult.truncated || stdout.truncated || stderr.truncated
        },
        verification: {
          required: true,
          status: "verified",
          strategy: resolved.verificationStrategy,
          evidence: { summary: verificationSummary ?? "Task exit status and declared task verification passed" }
        },
        truncated: taskResult.truncated || stdout.truncated || stderr.truncated,
        auditTarget: `task_profile:${resolved.profile}`,
        auditEvidence: { jobId: execution.taskJob.jobId, state: execution.taskJob.state, verification: taskResult.verification.status,
          ...(taskResult.changedPaths === undefined ? {} : { changedPaths: taskResult.changedPaths }) }
      };
    } catch (error) {
      if (!terminalPersisted) {
        try {
          const currentTaskJob = this.options.store.ownedJob(job.jobId, request.principal.principalId);
          if (currentTaskJob !== undefined) {
            execution.taskJob = currentTaskJob;
            if (currentTaskJob.state === "running") {
              execution.taskJob = this.options.store.finishJob(job.jobId, request.principal.principalId, currentTaskJob.revision, {
                state: "unknown",
                resultClass: "unknown",
                finishedAtMs: this.now()
              }, execution.jobLease, this.now());
            }
          }
        } catch {
          // Preserve the original error; the running task has no trusted terminal readback.
        }
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "Task outcome could not be persisted", true);
    }
  }

  private planExecution(request: BrokerRequest, policy: BrokerPolicy, toolPolicy: ToolPolicy): ExecutionPlan {
    this.options.developmentGateway?.assertProtectedStorage(policy.filesystemRoots);
    if (requiresAccessibilityPermission(request.tool) && this.runtimeCapabilityDisabledReason(request.tool) !== undefined) {
      throw new BrokerError("POLICY_DENIED", "Accessibility-dependent GUI capability is not enabled");
    }
    if (requiresDeveloperReadiness(request.tool) && this.runtimeCapabilityDisabledReason(request.tool) !== undefined) {
      throw new BrokerError("POLICY_DENIED", "Developer mutation capability is not enabled");
    }
    validateSemanticResourceBudget(request.tool, request.arguments);
    if (DEVELOPMENT_TOOL_NAMES.includes(request.tool)) {
      if (!this.options.developmentGateway) throw new BrokerError("POLICY_DENIED", "DEVELOPMENT_GATEWAY_UNCONFIGURED");
      const development = this.options.developmentGateway.plan(request);
      if (development.execution) this.options.developmentGateway.assertRunner(this.taskRunner);
      return { target: { kind: "project", reference: development.projectRoot },
        auditTarget: `project:${development.projectRoot}`, development };
    }
    if (request.tool === "mac_job_status" || request.tool === "mac_job_cancel") {
      assertExactArguments(request.arguments, request.tool === "mac_job_status" ? ["job_id", "tail_bytes"] : ["job_id", "reason"]);
      validateJobArguments(request.tool, request.arguments);
      const jobLookup = this.options.store.ownedJobStatus(request.arguments.job_id as string, request.principal.principalId);
      if (jobLookup.job === undefined && jobLookup.archived === undefined) throw new BrokerError("TARGET_NOT_FOUND", "Broker-owned job was not found");
      return {
        target: { kind: "job", reference: "owned" },
        auditTarget: `job:${jobLookup.job?.jobId ?? jobLookup.archived?.jobId}`,
        ...(jobLookup.job === undefined ? {} : { job: jobLookup.job }),
        ...(jobLookup.archived === undefined ? {} : { archivedJob: jobLookup.archived })
      };
    }
    if (request.tool === "mac_terminal_exec") {
      if (this.runtimeCapabilityDisabledReason(request.tool)) throw new BrokerError("POLICY_DENIED", "Owner terminal runtime is not enabled");
      return { target: { kind: "host", reference: "owner-terminal" }, auditTarget: "host:owner-terminal",
        ownerTerminal: parseOwnerTerminalRequest(request.arguments) };
    }
    if (request.tool === "mac_terminal_session") {
      if (this.runtimeCapabilityDisabledReason(request.tool)) throw new BrokerError("POLICY_DENIED", "Owner terminal sessions are not enabled");
      return { target: { kind: "host", reference: "owner-terminal" }, auditTarget: "host:owner-terminal",
        ownerTerminalSession: parseOwnerTerminalSessionRequest(request.arguments) };
    }
    if (request.tool === "mac_task_run") {
      assertExactArguments(request.arguments, ["profile", "cwd", "args", "async", "idempotency_key", "task_id", "max_runtime"]);
      const parsed = validateTaskRunArguments(request.arguments);
      if (!this.taskRunner.available) {
        throw new BrokerError("POLICY_DENIED", "Task isolation boundary is not enabled");
      }
      const isolationProof = validateTaskIsolationProof(this.taskRunner.isolationProof);
      if (this.taskRunner.mechanism === null || isolationProof.sandboxMechanism !== this.taskRunner.mechanism) {
        throw new BrokerError("POLICY_DENIED", "Task isolation proof does not match the selected runner");
      }
      return {
        target: { kind: "task_profile", reference: parsed.profile },
        auditTarget: `task_profile:${parsed.profile}`,
        taskRun: {
          profile: parsed.profile,
          cwd: parsed.cwd,
          args: [...(parsed.args ?? [])],
          asynchronous: parsed.asynchronous ?? false,
          ...(parsed.idempotencyKey === undefined ? {} : { idempotencyKey: parsed.idempotencyKey }),
          ...(parsed.taskId === undefined ? {} : { taskId: parsed.taskId }),
          ...(parsed.maxRuntimeMs === undefined ? {} : { maxRuntimeMs: parsed.maxRuntimeMs })
        }
      };
    }
    if (request.tool === "mac_service_control") {
      assertExactArguments(request.arguments, ["action", "expected_state", "idempotency_key", "service_id"]);
      const candidate = this.userServiceControlCandidate;
      if (!candidate || !candidate.available || !candidate.isPrincipalAuthorized(request.principal.principalId)) {
        throw new BrokerError("POLICY_DENIED", "User service-control runtime is not enabled for this principal");
      }
      const parsed = parseUserServiceControlArguments(request);
      const serviceRequest: UserServiceControlRequest = {
        serviceId: parsed.serviceId,
        action: parsed.action,
        expectedState: parsed.expectedState
      };
      return {
        target: { kind: "service", reference: parsed.serviceId },
        auditTarget: `service:${parsed.serviceId}`,
        serviceControl: {
          request: serviceRequest,
          idempotencyKey: parsed.idempotencyKey
        }
      };
    }
    if (request.tool === "mac_priv_service_control") {
      assertExactArguments(request.arguments, ["service_id", "action", "expected_state"]);
      const serviceId = request.arguments.service_id;
      const action = request.arguments.action;
      const expectedState = request.arguments.expected_state;
      if (typeof serviceId !== "string" || typeof action !== "string" ||
          (expectedState !== undefined && typeof expectedState !== "string")) {
        throw new BrokerError("PRECONDITION_FAILED", "Privileged service arguments have unsupported types");
      }
      validateServiceId(serviceId);
      if (!["start", "stop", "restart", "enable", "disable"].includes(action)) {
        throw new BrokerError("PRECONDITION_FAILED", "Privileged service action is invalid");
      }
      if (expectedState !== undefined && !["running", "stopped", "enabled", "disabled"].includes(expectedState)) {
        throw new BrokerError("PRECONDITION_FAILED", "Privileged service expected_state is invalid");
      }
      const payload = {
        operation: "service_control" as const,
        service_id: serviceId,
        action: action as "start" | "stop" | "restart" | "enable" | "disable",
        ...(expectedState === undefined ? {} : { expected_state: expectedState as "running" | "stopped" | "enabled" | "disabled" })
      } satisfies PrivilegedHelperPayload;
      validatePrivilegedHelperPayload(payload);
      if (!this.privilegedHelperExecutor.supportsOperation("service_control")) {
        throw new BrokerError("POLICY_DENIED", "Privileged helper operation is not enabled");
      }
      return {
        target: { kind: "service", reference: serviceId },
        auditTarget: `service:${serviceId}`,
        privileged: { operation: payload.operation, payload }
      };
    }
    if (request.tool === "mac_priv_package_install") {
      assertExactArguments(request.arguments, ["package_id", "version", "source_profile"]);
      const packageId = request.arguments.package_id;
      const version = request.arguments.version;
      const sourceProfile = request.arguments.source_profile;
      if (typeof packageId !== "string" ||
          (version !== undefined && typeof version !== "string") ||
          (sourceProfile !== undefined && typeof sourceProfile !== "string")) {
        throw new BrokerError("PRECONDITION_FAILED", "Privileged package arguments have unsupported types");
      }
      if (!/^[A-Za-z0-9._:@/+\-]{1,255}$/u.test(packageId)) {
        throw new BrokerError("PRECONDITION_FAILED", "Privileged package_id is invalid");
      }
      if (version !== undefined && !/^[A-Za-z0-9._:+\-]{1,128}$/u.test(version)) {
        throw new BrokerError("PRECONDITION_FAILED", "Privileged package version is invalid");
      }
      if (sourceProfile !== undefined && !/^[A-Za-z0-9._:-]{1,128}$/u.test(sourceProfile)) {
        throw new BrokerError("PRECONDITION_FAILED", "Privileged package source_profile is invalid");
      }
      const payload = {
        operation: "package_install" as const,
        package_id: packageId,
        ...(version === undefined ? {} : { version }),
        ...(sourceProfile === undefined ? {} : { source_profile: sourceProfile })
      } satisfies PrivilegedHelperPayload;
      validatePrivilegedHelperPayload(payload);
      if (!this.privilegedHelperExecutor.supportsOperation("package_install")) {
        throw new BrokerError("POLICY_DENIED", "Privileged helper operation is not enabled");
      }
      return {
        target: { kind: "package", reference: packageId },
        auditTarget: `package:${packageId}`,
        privileged: { operation: payload.operation, payload }
      };
    }
    if (request.tool === "mac_priv_power") {
      assertExactArguments(request.arguments, ["action", "reason", "not_before"]);
      const action = request.arguments.action;
      const reason = request.arguments.reason;
      const notBefore = request.arguments.not_before;
      if (action !== "reboot" && action !== "shutdown") {
        throw new BrokerError("PRECONDITION_FAILED", "Privileged power action is invalid");
      }
      if (reason !== undefined && (typeof reason !== "string" || reason.length > 200 || reason.includes("\0") || /[\r\n]/u.test(reason))) {
        throw new BrokerError("PRECONDITION_FAILED", "Privileged power reason is invalid");
      }
      if (notBefore !== undefined && (typeof notBefore !== "string" || notBefore.length > 64 || Number.isNaN(Date.parse(notBefore)))) {
        throw new BrokerError("PRECONDITION_FAILED", "Privileged power not_before is invalid");
      }
      const payload = {
        operation: "power" as const,
        action,
        ...(reason === undefined ? {} : { reason }),
        ...(notBefore === undefined ? {} : { not_before: notBefore })
      } satisfies PrivilegedHelperPayload;
      validatePrivilegedHelperPayload(payload);
      if (!this.privilegedHelperExecutor.supportsOperation("power")) {
        throw new BrokerError("POLICY_DENIED", "Privileged helper operation is not enabled");
      }
      return {
        target: { kind: "host", reference: "local" },
        auditTarget: "host:local",
        privileged: { operation: payload.operation, payload }
      };
    }
    if (request.tool === "mac_app_open") {
      assertExactArguments(request.arguments, ["app_id", "document_path", "url"]);
      const appId = normalizeAppId(request.arguments.app_id);
      if (appId === DESKTOP_APP_ID || request.arguments.app_id === "desktop") throw new BrokerError("UNSUPPORTED_CAPABILITY", "Use mac_ui_observe with app_id=desktop for the desktop surface");
      const documentPath = request.arguments.document_path;
      const url = request.arguments.url;
      validateAppOpenRequest(appId, documentPath, url);
      validateSensitiveUiTarget(appId);
      return {
        target: { kind: "app", reference: appId },
        auditTarget: `app:${appId}`,
        appOpen: {
          appId,
          ...(documentPath !== undefined ? { documentPath: documentPath as string } : {}),
          ...(url !== undefined ? { url: url as string } : {})
        }
      };
    }
    if (request.tool === "mac_app_focus") {
      assertExactArguments(request.arguments, ["app_id", "window_hint"]);
      const appId = normalizeAppId(request.arguments.app_id);
      if (appId === DESKTOP_APP_ID || request.arguments.app_id === "desktop") throw new BrokerError("UNSUPPORTED_CAPABILITY", "Focus a concrete application, or observe app_id=desktop");
      const windowHint = request.arguments.window_hint;
      validateAppFocusRequest(appId, windowHint);
      validateSensitiveUiTarget(appId, windowHint as string | undefined);
      return {
        target: { kind: "app_window", reference: `window:${appId}` },
        auditTarget: `app_window:window:${appId}`,
        appFocus: {
          appId,
          ...(windowHint !== undefined ? { windowHint: windowHint as string } : {})
        }
      };
    }
    if (request.tool === "mac_ui_action") {
      assertExactArguments(request.arguments, ["element_ref", "action", "x", "y", "dx", "dy", "key", "wait_ms"]);
      const elementRef = request.arguments.element_ref;
      const action = request.arguments.action;
      const visual = typeof action === "string" && (VISUAL_ACTION_NAMES as readonly string[]).includes(action);
      const options: UiVisualActionOptions = {
        ...(request.arguments.x === undefined ? {} : { x: request.arguments.x as number }),
        ...(request.arguments.y === undefined ? {} : { y: request.arguments.y as number }),
        ...(request.arguments.dx === undefined ? {} : { dx: request.arguments.dx as number }),
        ...(request.arguments.dy === undefined ? {} : { dy: request.arguments.dy as number }),
        ...(request.arguments.key === undefined ? {} : { key: request.arguments.key as string }),
        ...(request.arguments.wait_ms === undefined ? {} : { waitMs: request.arguments.wait_ms as number })
      };
      if (visual) validateUiVisualActionRequest(elementRef, action, options);
      else {
        if (Object.keys(options).length > 0) throw new BrokerError("PRECONDITION_FAILED", "Accessibility actions do not accept visual coordinates");
        validateUiActionRequest(elementRef, action);
      }
      return {
        target: { kind: "ui_element", reference: elementRef as string },
        auditTarget: `ui_element:${elementRef as string}`,
        uiAction: { elementRef: elementRef as string, action: action as UiActionName,
          ...(visual ? { options } : {}) }
      };
    }
    if (request.tool === "mac_ui_type") {
      assertExactArguments(request.arguments, ["element_ref", "text", "keys", "submit"]);
      const elementRef = request.arguments.element_ref ?? this.uiSnapshotRegistry.resolveFocused(
        request.principal.principalId, request.principal.sessionId, this.now(), uiApprovalBinding(request)
      ).elementRef;
      const inputText = request.arguments.text;
      const keys = request.arguments.keys ?? [];
      const submit = request.arguments.submit ?? false;
      validateUiTypeRequest(elementRef, inputText, keys, submit);
      return {
        target: { kind: "ui_element", reference: elementRef as string },
        auditTarget: `ui_element:${elementRef as string}`,
        uiType: { elementRef: elementRef as string, text: inputText as string, keys: [...keys as UiInputKey[]], submit: submit as boolean }
      };
    }
    if (request.tool === "mac_app_list") {
      assertExactArguments(request.arguments, ["running_only", "include_installed"]);
      const runningOnly = request.arguments.running_only ?? false;
      const includeInstalled = request.arguments.include_installed ?? true;
      validateAppListRequest(runningOnly as boolean, includeInstalled as boolean);
      return {
        target: { kind: "app_set", reference: "all" },
        auditTarget: "app_set:all",
        appList: { runningOnly: runningOnly as boolean, includeInstalled: includeInstalled as boolean }
      };
    }
    if (request.tool === "mac_ui_observe") {
      assertExactArguments(request.arguments, ["app_id", "window_hint", "max_nodes", "capture_mode"]);
      const appId = request.arguments.app_id === "desktop" ? DESKTOP_APP_ID : normalizeAppId(request.arguments.app_id);
      const windowHint = request.arguments.window_hint;
      const maxNodes = request.arguments.max_nodes ?? 200;
      const captureMode = request.arguments.capture_mode ?? "active_window";
      validateUiObserveRequest(appId, windowHint, maxNodes as number);
      if (typeof captureMode !== "string" || !["none", "screen", "active_window", "selected_window"].includes(captureMode) ||
          (captureMode === "selected_window" && windowHint === undefined)) {
        throw new BrokerError("PRECONDITION_FAILED", "capture_mode is invalid for this window");
      }
      validateSensitiveUiTarget(appId, windowHint as string | undefined);
      return {
        target: { kind: "app_window", reference: `window:${appId}` },
        auditTarget: `app_window:window:${appId}`,
        uiObserve: {
          appId,
          ...(windowHint !== undefined ? { windowHint: windowHint as string } : {}),
          maxNodes: maxNodes as number,
          captureMode: captureMode as UiCaptureMode
        }
      };
    }
    if (request.tool === "mac_find_files") {
      assertExactArguments(request.arguments, ["roots", "query", "max_results"]);
      validateFindArguments(request.arguments);
      const inspector = new FilesystemInspector(policy.filesystemRoots);
      const roots = request.arguments.roots as string[];
      const plans = roots.map((root) => inspector.planPath(root, "metadata"));
      const targets = plans.map((plan) => ({ kind: "path" as const, reference: plan.rootId }));
      return {
        target: targets[0]!,
        ...(targets.length > 1 ? { additionalTargets: targets.slice(1) } : {}),
        auditTarget: `filesystem_roots:${targets.map((target) => target.reference).join(",")}`,
        find: {
          plans,
          query: request.arguments.query as string,
          maxResults: (request.arguments.max_results ?? 1000) as number
        }
      };
    }
    if (request.tool === "mac_recent_files") {
      assertExactArguments(request.arguments, ["roots", "since_seconds", "limit"]);
      validateRecentArguments(request.arguments);
      const inspector = new FilesystemInspector(policy.filesystemRoots);
      const roots = request.arguments.roots as string[];
      const plans = roots.map((root) => inspector.planPath(root, "metadata"));
      const targets = plans.map((plan) => ({ kind: "path" as const, reference: plan.rootId }));
      return {
        target: targets[0]!,
        ...(targets.length > 1 ? { additionalTargets: targets.slice(1) } : {}),
        auditTarget: `filesystem_roots:${targets.map((target) => target.reference).join(",")}`,
        recent: {
          plans,
          sinceSeconds: request.arguments.since_seconds as number,
          limit: (request.arguments.limit ?? 1000) as number,
          nowMs: this.now()
        }
      };
    }
    if (request.tool === "mac_search_text") {
      assertExactArguments(request.arguments, ["roots", "query", "glob", "max_results"]);
      validateSearchTextArguments(request.arguments);
      const inspector = new FilesystemInspector(policy.filesystemRoots);
      const roots = request.arguments.roots as string[];
      const plans = roots.map((root) => inspector.planPath(root, "content_read"));
      const targets = plans.map((plan) => ({ kind: "path" as const, reference: plan.rootId }));
      return {
        target: targets[0]!,
        ...(targets.length > 1 ? { additionalTargets: targets.slice(1) } : {}),
        auditTarget: `filesystem_roots:${targets.map((target) => target.reference).join(",")}`,
        searchText: {
          plans,
          query: request.arguments.query as string,
          glob: request.arguments.glob as string | undefined,
          maxResults: (request.arguments.max_results ?? 1000) as number
        }
      };
    }
    if (request.tool === "mac_project_discover") {
      assertExactArguments(request.arguments, ["roots", "types", "max_results"]);
      validateProjectDiscoverArguments(request.arguments);
      const inspector = new FilesystemInspector(policy.filesystemRoots);
      const roots = request.arguments.roots as string[];
      const plans = roots.map((root) => inspector.planPath(root, "metadata"));
      const targets = plans.map((plan) => ({ kind: "path" as const, reference: plan.rootId }));
      return {
        target: targets[0]!,
        ...(targets.length > 1 ? { additionalTargets: targets.slice(1) } : {}),
        auditTarget: `filesystem_roots:${targets.map((target) => target.reference).join(",")}`,
        projectDiscover: {
          plans,
          types: normalizeProjectTypes((request.arguments.types ?? []) as string[]),
          maxResults: (request.arguments.max_results ?? 500) as number
        }
      };
    }
    if (request.tool === "mac_project_summary") {
      assertExactArguments(request.arguments, ["project_root", "include_tree", "tree_depth"]);
      validateProjectSummaryArguments(request.arguments);
      const inspector = new FilesystemInspector(policy.filesystemRoots);
      const plan = inspector.planPath(request.arguments.project_root as string, "metadata");
      return {
        target: { kind: "path", reference: plan.rootId },
        filesystem: { inspector, plan },
        projectSummary: {
          includeTree: (request.arguments.include_tree ?? false) as boolean,
          treeDepth: (request.arguments.tree_depth ?? 2) as number
        }
      };
    }
    if (request.tool === "mac_storage_analysis") {
      assertExactArguments(request.arguments, ["roots", "top_n", "max_depth"]);
      validateStorageAnalysisArguments(request.arguments);
      const inspector = new FilesystemInspector(policy.filesystemRoots);
      const requestedRoots = request.arguments.roots as string[] | undefined;
      const roots = requestedRoots && requestedRoots.length > 0
        ? requestedRoots
        : policy.filesystemRoots.filter((root) => root.metadata === true).map((root) => root.path);
      if (roots.length < 1 || roots.length > 32) throw new BrokerError("POLICY_DENIED", "No metadata filesystem roots are authorized for storage analysis");
      validateStorageSemanticResourceBudget(
        roots.length,
        (request.arguments.top_n ?? 20) as number,
        (request.arguments.max_depth ?? 4) as number
      );
      const plans = roots.map((root) => inspector.planPath(root, "metadata"));
      const targets = plans.map((plan) => ({ kind: "path" as const, reference: plan.rootId }));
      return {
        target: targets[0]!,
        ...(targets.length > 1 ? { additionalTargets: targets.slice(1) } : {}),
        auditTarget: `filesystem_roots:${targets.map((target) => target.reference).join(",")}`,
        storageAnalysis: {
          plans,
          topN: (request.arguments.top_n ?? 20) as number,
          maxDepth: (request.arguments.max_depth ?? 4) as number
        }
      };
    }
    if (request.tool === "mac_apply_patch") {
      assertExactArguments(request.arguments, ["project_root", "patch", "expected_base_hash"]);
      const projectRoot = request.arguments.project_root;
      const patchText = request.arguments.patch;
      const expectedBaseHash = request.arguments.expected_base_hash;
      validateApplyPatchArguments(projectRoot, patchText, expectedBaseHash);
      const inspector = new FilesystemInspector(policy.filesystemRoots);
      const plan = inspector.planPath(projectRoot as string, "write");
      return {
        target: { kind: "project", reference: projectRoot as string },
        auditTarget: `project:${projectRoot as string}`,
        filesystem: { inspector, plan },
        patch: {
          projectRoot: projectRoot as string,
          patch: patchText as string,
          ...(expectedBaseHash !== undefined ? { expectedBaseHash: (expectedBaseHash as string).toLowerCase() } : {})
        }
      };
    }
    if (request.tool === "mac_process_inspect") {
      assertExactArguments(request.arguments, ["pid"]);
      const pid = request.arguments.pid;
      if (!Number.isSafeInteger(pid) || (pid as number) < 1 || (pid as number) > 99_999_999) {
        throw new BrokerError("PRECONDITION_FAILED", "pid must be an integer between 1 and 99999999");
      }
      return { target: { kind: "process", reference: "all" } };
    }
    if (request.tool === "mac_service_status") {
      assertExactArguments(request.arguments, ["service_id"]);
      const serviceId = request.arguments.service_id;
      if (typeof serviceId !== "string" || serviceId.length < 1 || serviceId.length > 256) {
        throw new BrokerError("PRECONDITION_FAILED", "service_id must be a bounded string");
      }
      validateServiceId(serviceId);
      return { target: { kind: "service", reference: serviceId }, serviceId };
    }
    if (request.tool === "mac_log_tail") {
      assertExactArguments(request.arguments, ["source", "lines", "since_seconds"]);
      const source = request.arguments.source;
      const lines = (request.arguments.lines ?? 200) as number;
      const sinceSeconds = (request.arguments.since_seconds ?? 60) as number;
      if (typeof source !== "string") throw new BrokerError("PRECONDITION_FAILED", "source must be a string");
      validateLogRequest(source, lines, sinceSeconds);
      return {
        target: { kind: "log_source", reference: source },
        logTail: { source, lines, sinceSeconds }
      };
    }
    if (request.tool === "mac_git_status") {
      assertExactArguments(request.arguments, ["project_root", "include_untracked"]);
      const projectRoot = request.arguments.project_root;
      const includeUntracked = (request.arguments.include_untracked ?? true) as boolean;
      if (typeof projectRoot !== "string") throw new BrokerError("PRECONDITION_FAILED", "project_root must be a string");
      validateGitStatusRequest(projectRoot, includeUntracked);
      const normalizedProjectRoot = projectRoot;
      return {
        target: { kind: "project", reference: this.options.developmentGateway?.worktrees.originalProject(projectRoot, request.principal.principalId) ?? normalizedProjectRoot },
        auditTarget: `project:${normalizedProjectRoot}`,
        gitStatus: { projectRoot: normalizedProjectRoot, includeUntracked }
      };
    }
    if (request.tool === "mac_git_branch_list") {
      assertExactArguments(request.arguments, ["project_root", "include_remote"]);
      const projectRoot = request.arguments.project_root;
      const includeRemote = (request.arguments.include_remote ?? false) as boolean;
      if (typeof projectRoot !== "string") throw new BrokerError("PRECONDITION_FAILED", "project_root must be a string");
      validateGitBranchRequest(projectRoot, includeRemote);
      return {
        target: { kind: "project", reference: this.options.developmentGateway?.worktrees.originalProject(projectRoot, request.principal.principalId) ?? projectRoot },
        auditTarget: `project:${projectRoot}`,
        gitBranches: { projectRoot, includeRemote }
      };
    }
    if (request.tool === "mac_git_log") {
      assertExactArguments(request.arguments, ["project_root", "limit", "ref"]);
      const projectRoot = request.arguments.project_root;
      const limit = (request.arguments.limit ?? 50) as number;
      const ref = request.arguments.ref as string | undefined;
      if (typeof projectRoot !== "string") throw new BrokerError("PRECONDITION_FAILED", "project_root must be a string");
      validateGitLogRequest(projectRoot, limit, ref);
      return {
        target: { kind: "project", reference: this.options.developmentGateway?.worktrees.originalProject(projectRoot, request.principal.principalId) ?? projectRoot },
        auditTarget: `project:${projectRoot}`,
        gitLog: { projectRoot, limit, ...(ref !== undefined ? { ref } : {}) }
      };
    }
    if (request.tool === "mac_git_diff") {
      assertExactArguments(request.arguments, ["project_root", "paths", "staged", "base", "max_bytes"]);
      const projectRoot = request.arguments.project_root;
      const paths = request.arguments.paths === undefined ? [] : request.arguments.paths;
      const staged = (request.arguments.staged ?? false) as boolean;
      const base = request.arguments.base as string | undefined;
      const maxBytes = (request.arguments.max_bytes ?? 1_048_576) as number;
      if (typeof projectRoot !== "string" || !Array.isArray(paths)) {
        throw new BrokerError("PRECONDITION_FAILED", "project_root and paths must have supported types");
      }
      validateGitDiffRequest(projectRoot, paths as readonly string[], staged, base, maxBytes);
      return {
        target: { kind: "project", reference: this.options.developmentGateway?.worktrees.originalProject(projectRoot, request.principal.principalId) ?? projectRoot },
        auditTarget: `project:${projectRoot}`,
        gitDiff: { projectRoot, paths: [...paths] as string[], staged, ...(base !== undefined ? { base } : {}), maxBytes }
      };
    }
    if (request.tool === "mac_git_stage") {
      assertExactArguments(request.arguments, ["project_root", "paths"]);
      const projectRoot = request.arguments.project_root;
      const paths = request.arguments.paths;
      if (typeof projectRoot !== "string" || !Array.isArray(paths)) {
        throw new BrokerError("PRECONDITION_FAILED", "project_root and paths must have supported types");
      }
      validateGitStageRequest(projectRoot, paths as readonly string[]);
      return {
        target: { kind: "project", reference: this.options.developmentGateway?.worktrees.originalProject(projectRoot, request.principal.principalId) ?? projectRoot },
        auditTarget: `project:${projectRoot}`,
        gitStage: { projectRoot, paths: [...paths] as string[] }
      };
    }
    if (request.tool === "mac_git_commit") {
      assertExactArguments(request.arguments, ["project_root", "message", "expected_staged_diff_sha256"]);
      const projectRoot = request.arguments.project_root;
      const message = request.arguments.message;
      const expectedStagedDiffSha256 = request.arguments.expected_staged_diff_sha256 as string | undefined;
      if (typeof projectRoot !== "string" || typeof message !== "string") {
        throw new BrokerError("PRECONDITION_FAILED", "project_root and message must have supported types");
      }
      validateGitCommitRequest(projectRoot, message, expectedStagedDiffSha256);
      return {
        target: { kind: "project", reference: this.options.developmentGateway?.worktrees.originalProject(projectRoot, request.principal.principalId) ?? projectRoot },
        auditTarget: `project:${projectRoot}`,
        gitCommit: { projectRoot, message, ...(expectedStagedDiffSha256 !== undefined ? { expectedStagedDiffSha256 } : {}) }
      };
    }
    if (request.tool === "mac_package_inspect") {
      assertExactArguments(request.arguments, ["project_root", "manager", "check_outdated"]);
      const projectRoot = request.arguments.project_root;
      const manager = (request.arguments.manager ?? "auto") as PackageManagerRequest;
      const checkOutdated = (request.arguments.check_outdated ?? false) as boolean;
      if (typeof projectRoot !== "string") throw new BrokerError("PRECONDITION_FAILED", "project_root must be a string");
      validatePackageInspectRequest(projectRoot, manager, checkOutdated);
      return {
        target: { kind: "project", reference: projectRoot },
        auditTarget: `project:${projectRoot}`,
        packageInspect: { projectRoot, manager, checkOutdated }
      };
    }
    if (request.tool === "mac_docker_status") {
      assertExactArguments(request.arguments, ["include_images", "include_storage"]);
      const includeImages = (request.arguments.include_images ?? false) as boolean;
      const includeStorage = (request.arguments.include_storage ?? false) as boolean;
      validateDockerStatusRequest(includeImages, includeStorage);
      return {
        target: { kind: "docker_runtime", reference: "local" },
        auditTarget: "docker_runtime:local",
        dockerStatus: { includeImages, includeStorage }
      };
    }
    if (request.tool === "mac_docker_inspect") {
      assertExactArguments(request.arguments, ["object_type", "id"]);
      const objectType = request.arguments.object_type as DockerObjectType;
      const id = request.arguments.id;
      if (typeof id !== "string") throw new BrokerError("PRECONDITION_FAILED", "id must be a string");
      validateDockerObjectRequest(objectType, id);
      return {
        target: { kind: "docker_object", reference: id },
        auditTarget: `docker_object:${id}`,
        dockerInspect: { objectType, id }
      };
    }
    if (request.tool === "mac_docker_logs") {
      assertExactArguments(request.arguments, ["container_id", "tail", "since_seconds"]);
      const containerId = request.arguments.container_id;
      const tail = (request.arguments.tail ?? 200) as number;
      const sinceSeconds = (request.arguments.since_seconds ?? 60) as number;
      if (typeof containerId !== "string") throw new BrokerError("PRECONDITION_FAILED", "container_id must be a string");
      validateDockerLogsRequest(containerId, tail, sinceSeconds);
      return {
        target: { kind: "docker_object", reference: containerId },
        auditTarget: `docker_object:${containerId}`,
        dockerLogs: { containerId, tail, sinceSeconds }
      };
    }
    if (request.tool !== "mac_stat_path" && request.tool !== "mac_read_file" && request.tool !== "mac_hash_file" && request.tool !== "mac_list_directory" && request.tool !== "mac_directory_tree" && request.tool !== "mac_write_file_atomic") return { target: executionTarget(toolPolicy) };
    assertExactArguments(request.arguments, request.tool === "mac_stat_path"
      ? ["path", "follow_symlink"]
      : request.tool === "mac_read_file"
        ? ["path", "offset", "max_bytes", "encoding"]
        : request.tool === "mac_hash_file"
          ? ["path", "algorithm"]
          : request.tool === "mac_list_directory"
            ? ["path", "cursor", "limit", "include_hidden"]
            : request.tool === "mac_directory_tree"
              ? ["path", "depth", "max_entries"]
          : ["path", "content", "idempotency_key", "encoding", "expected_sha256", "create_only"]);
    if (typeof request.arguments.path !== "string") {
      throw new BrokerError("PRECONDITION_FAILED", "path must be a string");
    }
    if (request.tool === "mac_stat_path" && request.arguments.follow_symlink !== undefined && typeof request.arguments.follow_symlink !== "boolean") {
      throw new BrokerError("PRECONDITION_FAILED", "follow_symlink must be a boolean");
    }
    if (request.tool === "mac_read_file") validateReadArguments(request.arguments);
    let hashAlgorithm: ExecutionPlan["hashAlgorithm"];
    if (request.tool === "mac_hash_file") {
      validateHashArguments(request.arguments);
      hashAlgorithm = (request.arguments.algorithm ?? "sha256") as "sha256" | "sha512";
    }
    let list: ExecutionPlan["list"];
    if (request.tool === "mac_list_directory") {
      validateListArguments(request.arguments);
      list = {
        cursor: decodeDirectoryCursor(request.arguments.cursor),
        limit: (request.arguments.limit ?? 100) as number,
        includeHidden: (request.arguments.include_hidden ?? false) as boolean
      };
    }
    let tree: ExecutionPlan["tree"];
    if (request.tool === "mac_directory_tree") {
      validateTreeArguments(request.arguments);
      tree = {
        depth: (request.arguments.depth ?? 2) as number,
        maxEntries: (request.arguments.max_entries ?? 500) as number
      };
    }
    let write: ExecutionPlan["write"];
    if (request.tool === "mac_write_file_atomic") {
      validateWriteArguments(request.arguments);
      const content = decodeWriteContent(request.arguments);
      assertContentDoesNotContainSecrets(content);
      write = {
        content,
        expectedSha256: request.arguments.expected_sha256 as string | undefined,
        createOnly: (request.arguments.create_only ?? false) as boolean,
        idempotencyKey: request.arguments.idempotency_key as string,
        temporaryName: `.mac-operator-write-${randomUUID()}`
      };
    }
    const inspector = new FilesystemInspector(policy.filesystemRoots);
    const plan = inspector.planPath(
      request.arguments.path,
      request.tool === "mac_read_file" || request.tool === "mac_list_directory" || request.tool === "mac_directory_tree" ? "content_read" : request.tool === "mac_write_file_atomic" ? "write" : "metadata"
    );
    return {
      target: { kind: "path", reference: plan.rootId },
      filesystem: { inspector, plan },
      ...(hashAlgorithm ? { hashAlgorithm } : {}),
      ...(list ? { list } : {}),
      ...(tree ? { tree } : {}),
      ...(write ? { write } : {})
    };
  }

  private authorizeCapabilityTarget(policy: BrokerPolicy, principalId: string, tool: ToolPolicy): void {
    if (tool.tool === "mac_terminal_exec" || tool.tool === "mac_terminal_session") {
      authorizeTarget(policy, principalId, tool.requiredScopes, { kind: "host", reference: "owner-terminal" });
      return;
    }
    if (tool.targetType === "job") {
      authorizeTarget(policy, principalId, tool.requiredScopes, { kind: "job", reference: "owned" });
      return;
    }
    if (tool.targetType === "filesystem_roots") {
      const requiresContent = tool.tool === "mac_search_text";
      for (const root of policy.filesystemRoots.filter((candidate) => requiresContent ? candidate.contentRead === true : candidate.metadata === true)) {
        try {
          authorizeTarget(policy, principalId, tool.requiredScopes, { kind: "path", reference: root.rootId });
          return;
        } catch {
          // Continue until one independently authorized root is found.
        }
      }
      throw new BrokerError("POLICY_DENIED", "No filesystem root is authorized for this tool");
    }
    if (tool.targetType === "service") {
      for (const rule of policy.targetRules.filter((candidate) =>
        candidate.principalId === principalId && candidate.scope === tool.requiredScopes[0] &&
        candidate.target.kind === "service" && candidate.effect === "allow")) {
        try {
          authorizeTarget(policy, principalId, tool.requiredScopes, rule.target);
          return;
        } catch {
          // Continue until one independently authorized service is found.
        }
      }
      throw new BrokerError("POLICY_DENIED", "No service identifier is authorized for this tool");
    }
    if (tool.targetType === "package") {
      for (const rule of policy.targetRules.filter((candidate) =>
        candidate.principalId === principalId && candidate.scope === tool.requiredScopes[0] &&
        candidate.target.kind === "package" && candidate.effect === "allow")) {
        try {
          authorizeTarget(policy, principalId, tool.requiredScopes, rule.target);
          return;
        } catch {
          // Continue until one independently authorized package identity is found.
        }
      }
      throw new BrokerError("POLICY_DENIED", "No package identity is authorized for this tool");
    }
    if (tool.tool === "mac_priv_power") {
      authorizeTarget(policy, principalId, tool.requiredScopes, { kind: "host", reference: "local" });
      return;
    }
    if (tool.targetType === "log_source") {
      for (const rule of policy.targetRules.filter((candidate) =>
        candidate.principalId === principalId && candidate.scope === tool.requiredScopes[0] &&
        candidate.target.kind === "log_source" && candidate.effect === "allow")) {
        try {
          authorizeTarget(policy, principalId, tool.requiredScopes, rule.target);
          return;
        } catch {
          // Continue until one independently authorized log source is found.
        }
      }
      throw new BrokerError("POLICY_DENIED", "No log source is authorized for this tool");
    }
    if (tool.targetType === "app_set") {
      authorizeTarget(policy, principalId, tool.requiredScopes, { kind: "app_set", reference: "all" });
      return;
    }
    if (tool.targetType === "app") {
      for (const rule of policy.targetRules.filter((candidate) =>
        candidate.principalId === principalId && candidate.scope === tool.requiredScopes[0] &&
        candidate.target.kind === "app" && candidate.effect === "allow")) {
        try {
          authorizeTarget(policy, principalId, tool.requiredScopes, guiCapabilityProbeTarget(policy, rule.target));
          return;
        } catch {
          // Continue until one independently authorized app identity is found.
        }
      }
      throw new BrokerError("POLICY_DENIED", "No app identity is authorized for this tool");
    }
    if (tool.targetType === "app_window" || tool.targetType === "ui_element") {
      for (const rule of policy.targetRules.filter((candidate) =>
        candidate.principalId === principalId && candidate.scope === tool.requiredScopes[0] &&
        candidate.target.kind === "app_window" && candidate.effect === "allow")) {
        try {
          authorizeTarget(policy, principalId, tool.requiredScopes, guiCapabilityProbeTarget(policy, rule.target));
          return;
        } catch {
          // Continue until one independently authorized app-window identity is found.
        }
      }
      throw new BrokerError("POLICY_DENIED", "No app-window identity is authorized for this tool");
    }
    if (tool.targetType === "project") {
      for (const rule of policy.targetRules.filter((candidate) =>
        candidate.principalId === principalId && candidate.scope === tool.requiredScopes[0] &&
        candidate.target.kind === "project" && candidate.effect === "allow")) {
        try {
          authorizeTarget(policy, principalId, tool.requiredScopes, rule.target);
          return;
        } catch {
          // Continue until one independently authorized project is found.
        }
      }
      throw new BrokerError("POLICY_DENIED", "No project root is authorized for this tool");
    }
    if (tool.targetType === "docker_runtime") {
      authorizeTarget(policy, principalId, tool.requiredScopes, { kind: "docker_runtime", reference: "local" });
      return;
    }
    if (tool.targetType === "docker_object") {
      for (const rule of policy.targetRules.filter((candidate) =>
        candidate.principalId === principalId && candidate.scope === tool.requiredScopes[0] &&
        candidate.target.kind === "docker_object" && candidate.effect === "allow")) {
        try {
          authorizeTarget(policy, principalId, tool.requiredScopes, rule.target);
          return;
        } catch {
          // Continue until one independently authorized Docker object is found.
        }
      }
      throw new BrokerError("POLICY_DENIED", "No Docker object is authorized for this tool");
    }
    if (tool.targetType === "task_profile") {
      for (const rule of policy.targetRules.filter((candidate) =>
        candidate.principalId === principalId && candidate.scope === tool.requiredScopes[0] &&
        candidate.target.kind === "task_profile" && candidate.effect === "allow")) {
        try {
          authorizeTarget(policy, principalId, tool.requiredScopes, rule.target);
          return;
        } catch {
          // Continue until one independently authorized task profile is found.
        }
      }
      throw new BrokerError("POLICY_DENIED", "No task profile is authorized for this tool");
    }
    if (tool.targetType !== "path") {
      authorizeTarget(policy, principalId, tool.requiredScopes, executionTarget(tool));
      return;
    }
    for (const root of policy.filesystemRoots.filter((candidate) =>
      tool.tool === "mac_read_file" || tool.tool === "mac_list_directory" || tool.tool === "mac_directory_tree" ? candidate.contentRead === true : tool.tool === "mac_write_file_atomic" ? candidate.write === true : candidate.metadata)) {
      try {
        authorizeTarget(policy, principalId, tool.requiredScopes, { kind: "path", reference: root.rootId });
        return;
      } catch {
        // Continue until one independently authorized root is found.
      }
    }
    throw new BrokerError("POLICY_DENIED", "No filesystem root is authorized for this tool");
  }

  private newJobLease(acquiredAtMs: number): JobLease {
    if (!Number.isSafeInteger(acquiredAtMs) || acquiredAtMs < 0 || acquiredAtMs > Number.MAX_SAFE_INTEGER - JOB_LEASE_DURATION_MS) {
      throw new BrokerError("PRECONDITION_FAILED", "Job lease timestamp is malformed");
    }
    return {
      ownerId: this.jobLeaseOwnerId,
      token: `lease:${randomUUID()}`,
      expiresAtMs: acquiredAtMs + JOB_LEASE_DURATION_MS
    };
  }

  private executionControl(
    request: BrokerRequest,
    target: NormalizedTarget,
    timeoutMs: number,
    jobId?: string,
    additionalTargets: readonly NormalizedTarget[] = [],
    jobLease?: JobLease,
    onProcessStarted?: (snapshot: ProcessOwnershipSnapshot) => void,
    onProcessOwnershipChanged?: (snapshot: ProcessOwnershipSnapshot) => void,
    onGuestRequestAdmitted?: (admission: VirtualizationGuestTaskAdmission) => void,
    onGuestResultVerified?: (result: TaskExecutionResult) => void,
    onContainerCreated?: (metadata: Omit<ContainerTaskJobMetadata, "taskDescriptorDigest">) => void,
    onWorkspaceImport?: (path: string, phase: "intent" | "verified") => void
  ) {
    let lastLeaseHeartbeatMs = Number.NEGATIVE_INFINITY;
    const desktopSurface = target.reference === `window:${DESKTOP_APP_ID}` ||
      target.kind === "ui_element" && this.uiSnapshotRegistry.resolve(target.reference, request.principal.principalId,
        request.principal.sessionId, this.now(), uiApprovalBinding(request)).appId === DESKTOP_APP_ID;
    const rootHelperRequestAuthority = this.rootHelperSnapshotRequestAuthority === undefined
      ? undefined
      : {
        admit: (requestDigest: string, expiresAtMs: number): void => {
          // The exact signed helper envelope is admitted only after the
          // Broker rechecks the current MCP request, target, policy, and
          // revocation state at the final task execution boundary.
          this.ensureActiveAuthority(request, target, additionalTargets);
          this.rootHelperSnapshotRequestAuthority!.admit(requestDigest, expiresAtMs);
        },
        release: (requestDigest: string): void => {
          this.rootHelperSnapshotRequestAuthority!.release(requestDigest);
        }
      } satisfies RootHelperSnapshotRequestAdmission;
    return {
      timeoutMs,
      ...(desktopSurface ? {
        desktopDeniedApps: desktopDeniedApplications(this.currentPolicy(), request.principal.principalId,
          this.currentPolicy().tools.get(request.tool)!.requiredScopes)
      } : {}),
      beforeMutation: () => {
        this.ensureActiveAuthority(request, target, additionalTargets);
      },
      shouldCancel: () => {
        try {
          this.ensureActiveAuthority(request, target, additionalTargets);
          if (jobId && jobLease) {
            const nowMs = this.now();
            if (nowMs - lastLeaseHeartbeatMs >= JOB_LEASE_RENEW_INTERVAL_MS) {
              this.options.store.renewJobLease(jobId, request.principal.principalId, jobLease, nowMs, JOB_LEASE_DURATION_MS);
              lastLeaseHeartbeatMs = nowMs;
            }
          }
          if (jobId && this.options.store.ownedJob(jobId, request.principal.principalId)?.cancelRequested) return true;
          return false;
        } catch {
          return true;
        }
      },
      ...(onProcessStarted === undefined ? {} : { onProcessStarted }),
      ...(onProcessOwnershipChanged === undefined ? {} : { onProcessOwnershipChanged }),
      ...(onGuestRequestAdmitted === undefined ? {} : { onGuestRequestAdmitted }),
      ...(onGuestResultVerified === undefined ? {} : { onGuestResultVerified }),
      ...(onContainerCreated === undefined ? {} : { onContainerCreated }),
      ...(onWorkspaceImport === undefined ? {} : { onWorkspaceImport }),
      ...(rootHelperRequestAuthority === undefined ? {} : { rootHelperSnapshotRequestAuthority: rootHelperRequestAuthority })
    };
  }

  private ensureActiveAuthority(
    request: BrokerRequest,
    target: NormalizedTarget,
    additionalTargets: readonly NormalizedTarget[] = []
  ): void {
    if (this.closing) throw new BrokerError("CANCELLED", "Broker is shutting down");
    if (this.now() >= request.principal.expiresAtMs) {
      throw new BrokerError("CANCELLED", "Active work session expired");
    }
    try {
      this.checkRevocation(request);
      const currentPolicy = this.currentPolicy();
      if (currentPolicy.version !== request.policyVersion) throw new Error("Policy changed");
      authorizePrincipalProjection(
        currentPolicy,
        request.principal.principalId,
        request.principal.issuer,
        request.principal.scopes
      );
      const tool = authorizeTool(
        this.options.store,
        currentPolicy,
        request.tool,
        request.contractVersion,
        request.principal.scopes
      );
      if (tool.mutation) {
        this.options.store.assertRequestApprovalActive(request.requestId, request.principal.principalId, this.now());
      }
      if (request.tool === "mac_ui_action" || request.tool === "mac_ui_type") {
        const execution = this.planExecution(request, currentPolicy, tool);
        const elementRef = request.tool === "mac_ui_action" ? execution.uiAction?.elementRef : execution.uiType?.elementRef;
        if (!elementRef) throw new Error("UI execution plan unavailable");
        const snapshot = this.uiSnapshotRegistry.resolve(
          elementRef,
          request.principal.principalId,
          request.principal.sessionId,
          this.now(),
          uiApprovalBinding(request)
        );
        authorizeTarget(currentPolicy, request.principal.principalId, tool.requiredScopes, {
          kind: "app_window",
          reference: `window:${snapshot.appId}`
        });
      } else {
        for (const activeTarget of [target, ...additionalTargets]) {
          authorizeTarget(currentPolicy, request.principal.principalId, tool.requiredScopes, activeTarget);
        }
      }
    } catch {
      throw new BrokerError("CANCELLED", "Active work authority was revoked");
    }
  }

  private auditFailure(
    request: BrokerRequest,
    error: BrokerError,
    timestampMs: number,
    authorized: boolean,
    targetRef?: string
  ): void {
    try {
      this.options.store.failRequest({
        requestId: request.requestId,
        principalId: request.principal.principalId,
        tool: request.tool,
        eventType: authorized ? "completion" : "decision",
        decision: authorized ? "allow" : "deny",
        resultClass: error.errorClass,
        targetRef: targetRef ?? "unresolved",
        policyVersion: request.policyVersion,
        evidence: { scopes: [...(this.currentPolicy().tools.get(request.tool)?.requiredScopes ?? [])] },
        timestampMs
      });
    } catch {
      // The original denial remains authoritative. Audit outage is observable separately.
    }
  }

  private persistApprovalPreviewOnMissing(
    request: BrokerRequest,
    binding: ApprovalConsumptionBinding,
    createdAtMs: number,
    error: unknown
  ): void {
    if (!(error instanceof BrokerError) || error.errorClass !== "POLICY_DENIED" ||
        error.message !== "No valid approval matches this mutation") return;
    const previewTtl = request.tool === "mac_app_focus" ? GUI_SESSION_PREVIEW_TTL_MS : APPROVAL_PREVIEW_TTL_MS;
    this.options.store.createApprovalPreview(
      request.requestId,
      binding,
      createdAtMs,
      createdAtMs + previewTtl
    );
    if ((request.tool === "mac_ui_action" || request.tool === "mac_ui_type") && binding.targetRef.startsWith("ui_element:")) {
      this.uiSnapshotRegistry.retainForApproval(
        binding.targetRef.slice("ui_element:".length), request.principal.principalId,
        request.principal.sessionId, createdAtMs, createdAtMs + APPROVAL_PREVIEW_TTL_MS, uiApprovalBinding(request)
      );
    }
  }

  private failure(request: BrokerRequest | undefined, error: BrokerError, startedAt: number): BrokerFailure {
    return {
      ok: false,
      request_id: request?.requestId ?? "invalid-request",
      tool: request?.tool ?? "unknown",
      result_class: error.errorClass,
      error: { message: error.message, retryable: error.retryable },
      duration_ms: Math.max(0, this.now() - startedAt)
    };
  }
}

interface ExecutionPlan {
  auditContext?: { project: string; worktree: string; taskId: string };
  development?: DevelopmentPlan;
  target: NormalizedTarget;
  additionalTargets?: readonly NormalizedTarget[];
  auditTarget?: string;
  filesystem?: { inspector: FilesystemInspector; plan: FilesystemPathPlan };
  hashAlgorithm?: "sha256" | "sha512";
  list?: {
    cursor: string | undefined;
    limit: number;
    includeHidden: boolean;
  };
  tree?: {
    depth: number;
    maxEntries: number;
  };
  find?: {
    plans: readonly FilesystemPathPlan[];
    query: string;
    maxResults: number;
  };
  recent?: {
    plans: readonly FilesystemPathPlan[];
    sinceSeconds: number;
    limit: number;
    nowMs: number;
  };
  searchText?: {
    plans: readonly FilesystemPathPlan[];
    query: string;
    glob: string | undefined;
    maxResults: number;
  };
  projectDiscover?: {
    plans: readonly FilesystemPathPlan[];
    types: readonly string[];
    maxResults: number;
  };
  projectSummary?: {
    includeTree: boolean;
    treeDepth: number;
  };
  storageAnalysis?: {
    plans: readonly FilesystemPathPlan[];
    topN: number;
    maxDepth: number;
  };
  serviceId?: string;
  logTail?: {
    source: string;
    lines: number;
    sinceSeconds: number;
  };
  gitStatus?: {
    projectRoot: string;
    includeUntracked: boolean;
  };
  gitBranches?: {
    projectRoot: string;
    includeRemote: boolean;
  };
  gitLog?: {
    projectRoot: string;
    limit: number;
    ref?: string;
  };
  gitDiff?: {
    projectRoot: string;
    paths: readonly string[];
    staged: boolean;
    base?: string;
    maxBytes: number;
  };
  gitStage?: {
    projectRoot: string;
    paths: readonly string[];
  };
  gitCommit?: {
    projectRoot: string;
    message: string;
    expectedStagedDiffSha256?: string;
  };
  packageInspect?: {
    projectRoot: string;
    manager: PackageManagerRequest;
    checkOutdated: boolean;
  };
  dockerStatus?: {
    includeImages: boolean;
    includeStorage: boolean;
  };
  dockerInspect?: {
    objectType: DockerObjectType;
    id: string;
  };
  dockerLogs?: {
    containerId: string;
    tail: number;
    sinceSeconds: number;
  };
  appList?: {
    runningOnly: boolean;
    includeInstalled: boolean;
  };
  uiObserve?: {
    appId: string;
    windowHint?: string;
    maxNodes: number;
    captureMode: UiCaptureMode;
  };
  appOpen?: {
    appId: string;
    documentPath?: string;
    url?: string;
  };
  appFocus?: {
    appId: string;
    windowHint?: string;
  };
  uiAction?: {
    elementRef: string;
    action: UiActionName;
    snapshot?: UiSnapshotRecord;
    options?: UiVisualActionOptions;
  };
  uiType?: {
    elementRef: string;
    text: string;
    keys: readonly UiInputKey[];
    submit: boolean;
    snapshot?: UiSnapshotRecord;
  };
  taskRun?: {
    profile: string;
    cwd: string;
    args: readonly string[];
    asynchronous?: boolean;
    idempotencyKey?: string;
    taskId?: string;
    maxRuntimeMs?: number;
    resolvedProfile?: ResolvedTaskProfile;
  };
  serviceControl?: {
    request: UserServiceControlRequest;
    idempotencyKey: string;
    precondition?: import("./user-service-control.js").UserServiceControlPrecondition;
  };
  privileged?: {
    operation: PrivilegedHelperOperation;
    payload: PrivilegedHelperPayload;
  };
  job?: BrokerJob;
  archivedJob?: ArchivedJobRecord;
  write?: {
    content: Buffer;
    expectedSha256: string | undefined;
    createOnly: boolean;
    idempotencyKey: string;
    temporaryName: string;
  };
  patch?: {
    projectRoot: string;
    patch: string;
    expectedBaseHash?: string;
  };
  writeJob?: BrokerJob;
  writeJobNew?: boolean;
  patchJob?: BrokerJob;
  patchJobNew?: boolean;
  ownerTerminal?: OwnerTerminalRequest;
  ownerTerminalSession?: OwnerTerminalSessionRequest;
  taskJob?: BrokerJob;
  taskJobNew?: boolean;
  gitStageJob?: BrokerJob;
  gitCommitJob?: BrokerJob;
  gitWriteJobNew?: boolean;
  appOpenJob?: BrokerJob;
  appOpenJobNew?: boolean;
  appFocusJob?: BrokerJob;
  appFocusJobNew?: boolean;
  uiActionJob?: BrokerJob;
  uiActionJobNew?: boolean;
  uiTypeJob?: BrokerJob;
  uiTypeJobNew?: boolean;
  serviceControlJob?: BrokerJob;
  serviceControlJobNew?: boolean;
  privilegedJob?: BrokerJob;
  privilegedJobNew?: boolean;
  jobLease?: JobLease;
}

interface DispatchResult {
  data: unknown;
  verification: Record<string, unknown>;
  auditTarget?: string;
  auditEvidence?: Record<string, unknown>;
  truncated?: boolean;
  warnings?: readonly string[];
}

interface WriteResultData {
  path: string;
  bytes_written: number;
  sha256: string;
  created: boolean;
  precondition: {
    expected_sha256: string | null;
    matched: boolean;
    create_only: boolean;
  };
}

interface PatchResultData {
  project_root: string;
  result: "applied" | "no_change";
  changed_paths: readonly string[];
  precondition: {
    checked: boolean;
    expected_sha256: string | null;
    actual_sha256: string;
    matched: boolean;
  };
  files: readonly {
    path: string;
    sha256: string;
    size_bytes: number;
  }[];
}

interface WriteRecoveryStatus {
  postcondition: SafeWritePostcondition["status"];
  resolution: "remains_unknown";
  observed_at: string;
}

function parseStoredPrivilegedResponse(value: string): PrivilegedHelperResponse {
  if (value.length < 1 || value.length > 262_144) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored privileged helper result is unavailable", true);
  }
  let parsed: unknown;
  try {
    parsed = parseJsonStrict(value);
  } catch {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored privileged helper result is malformed", true);
  }
  if (!isPlainDataRecord(parsed) || parsed.ok !== true || !isPlainDataRecord(parsed.result)) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored privileged helper result is malformed", true);
  }
  const result = validatePrivilegedHelperExecutionResult(parsed.result as unknown as PrivilegedHelperExecutionResult);
  return { ok: true, commandId: "stored", requestId: "stored", result, responseProof: "" };
}

function parseStoredUserServiceControlResult(value: string) {
  if (value.length < 1 || value.length > 262_144) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored user service-control result is unavailable", true);
  }
  let parsed: unknown;
  try {
    parsed = parseJsonStrict(value);
  } catch {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored user service-control result is malformed", true);
  }
  try {
    validateUserServiceControlResult(parsed);
  } catch {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored user service-control result is malformed", true);
  }
  return parsed;
}

function userServiceControlDispatchResult(
  job: BrokerJob,
  result: ReturnType<typeof parseStoredUserServiceControlResult>,
  reused: boolean
): DispatchResult {
  if (result.resultClass !== "SUCCEEDED" || result.state !== "completed" || result.verification.status !== "verified") {
    if (result.resultClass === "VERIFICATION_FAILED") {
      throw new BrokerError("VERIFICATION_FAILED", "User service-control postcondition verification failed");
    }
    throw new BrokerError("UNKNOWN_OUTCOME", "User service-control operation outcome is unresolved", true);
  }
  const data = {
    job_id: job.jobId,
    service_id: result.serviceId,
    action: result.action,
    pre_state: result.preState,
    post_state: result.postState,
    source_revision: result.sourceRevision,
    idempotent: result.idempotent,
    rollback_status: result.rollback.status
  };
  return {
    data,
    verification: {
      required: true,
      status: "verified",
      strategy: "service_state_readback",
      evidence: {
        summary: reused ? "Reused a completed user service-control Job readback" : result.verification.summary
      }
    },
    auditTarget: `service:${result.serviceId}`,
    auditEvidence: {
      jobId: job.jobId,
      jobRevision: job.revision,
      reused,
      action: result.action,
      preState: result.preState,
      postState: result.postState,
      sourceRevision: result.sourceRevision,
      rollbackStatus: result.rollback.status,
      verification: result.verification.status
    }
  };
}

function privilegedDispatchResult(
  job: BrokerJob,
  response: PrivilegedHelperResponse,
  payload: PrivilegedHelperPayload,
  reused: boolean
): DispatchResult {
  if (!response.ok) {
    throw new BrokerError(response.resultClass, "Privileged helper rejected the operation", response.error.retryable);
  }
  const result = validatePrivilegedHelperExecutionResult(response.result, {
    operation: payload.operation,
    targetRef: privilegedHelperPayloadTarget(payload)
  });
  if (result.resultClass !== "SUCCEEDED" || result.state !== "completed" || result.verification.status !== "verified") {
    throw privilegedResultError(result);
  }
  const data = privilegedToolResultData(payload, result);
  return {
    data: { ...data, job_id: job.jobId },
    verification: {
      required: true,
      status: "verified",
      strategy: payload.operation === "service_control"
        ? "service_state_readback"
        : payload.operation === "package_install"
          ? "installed_version_verification"
          : "handoff_acceptance_and_scheduled_state",
      evidence: {
        ...(result.verification.summary === undefined ? {} : { summary: result.verification.summary }),
        ...(result.verification.readbackHash === undefined ? {} : { readback_hash: result.verification.readbackHash }),
        observed_at: new Date(Date.now()).toISOString()
      }
    },
    warnings: [...result.warnings],
    truncated: result.truncated,
    auditTarget: privilegedHelperPayloadTarget(payload),
    auditEvidence: {
      jobId: job.jobId,
      operation: payload.operation,
      reused,
      helperResultClass: result.resultClass,
      helperState: result.state,
      verification: result.verification.status
    }
  };
}

function privilegedResultError(result: PrivilegedHelperExecutionResult): BrokerError {
  if (result.resultClass === "CANCELLED" || result.state === "cancelled") {
    return new BrokerError("CANCELLED", "Privileged helper operation was cancelled");
  }
  if (result.resultClass === "TIMEOUT") return new BrokerError("TIMEOUT", "Privileged helper operation timed out");
  if (result.resultClass === "VERIFICATION_FAILED" || result.verification.status === "failed") {
    return new BrokerError("VERIFICATION_FAILED", "Privileged helper postcondition verification failed");
  }
  if (result.resultClass === "UNKNOWN_OUTCOME" || result.state === "unknown" || result.state === "accepted") {
    return new BrokerError("UNKNOWN_OUTCOME", "Privileged helper operation outcome is unresolved", true);
  }
  return new BrokerError("EXECUTION_FAILED", "Privileged helper operation failed");
}

function privilegedToolResultData(
  payload: PrivilegedHelperPayload,
  result: PrivilegedHelperExecutionResult
): Record<string, unknown> {
  const evidence = result.evidence;
  const boundedString = (name: string, maxLength = 512): string => {
    const value = evidence[name];
    if (typeof value !== "string" || value.length < 1 || value.length > maxLength) {
      throw new BrokerError("VERIFICATION_FAILED", `Privileged helper evidence is missing ${name}`);
    }
    return value;
  };
  if (payload.operation === "service_control") {
    return {
      service_id: payload.service_id,
      action: payload.action,
      pre_state: boundedString("pre_state", 128),
      post_state: boundedString("post_state", 128),
      verification_status: "verified"
    };
  }
  if (payload.operation === "package_install") {
    const installedVersion = boundedString("installed_version", 128);
    const artifactId = boundedString("artifact_id", 256);
    if (!/^[A-Za-z0-9._:@/+-]+$/u.test(artifactId)) {
      throw new BrokerError("VERIFICATION_FAILED", "Privileged helper artifact identity is malformed");
    }
    const alreadyInstalled = evidence.already_installed;
    const matchedVersion = evidence.matched_version;
    if (typeof alreadyInstalled !== "boolean" || typeof matchedVersion !== "boolean") {
      throw new BrokerError("VERIFICATION_FAILED", "Privileged helper package precondition evidence is malformed");
    }
    const state = evidence.state;
    if (state !== "installed" && state !== "already_installed") {
      throw new BrokerError("VERIFICATION_FAILED", "Privileged helper package state is malformed");
    }
    return {
      package_id: payload.package_id,
      requested_version: payload.version ?? null,
      installed_version: installedVersion,
      artifact_id: artifactId,
      precondition: { already_installed: alreadyInstalled, matched_version: matchedVersion },
      state
    };
  }
  const state = evidence.state;
  if (state !== "accepted" && state !== "scheduled" && state !== "executed") {
    throw new BrokerError("VERIFICATION_FAILED", "Privileged helper power state is malformed");
  }
  const scheduledFor = evidence.scheduled_for;
  if (scheduledFor !== null && (typeof scheduledFor !== "string" || scheduledFor.length < 1 || scheduledFor.length > 64 || Number.isNaN(Date.parse(scheduledFor)))) {
    throw new BrokerError("VERIFICATION_FAILED", "Privileged helper power schedule is malformed");
  }
  const handoffId = boundedString("handoff_id", 256);
  if (!/^[A-Za-z0-9._:/-]+$/u.test(handoffId) || evidence.connection_loss_expected !== true) {
    throw new BrokerError("VERIFICATION_FAILED", "Privileged helper power handoff evidence is malformed");
  }
  return {
    action: payload.action,
    state,
    scheduled_for: scheduledFor ?? null,
    handoff_id: handoffId,
    connection_loss_expected: true
  };
}

function writeJobMetadata(plan: FilesystemPathPlan, write: NonNullable<ExecutionPlan["write"]>): WriteJobMetadata {
  return {
    rootId: plan.rootId,
    rootPath: plan.rootIdentity.rootPath,
    rootDevice: plan.rootIdentity.device,
    rootInode: plan.rootIdentity.inode,
    path: plan.requestedPath,
    bytes: write.content.length,
    desiredSha256: sha256(write.content),
    expectedSha256: write.expectedSha256?.toLowerCase() ?? null,
    createOnly: write.createOnly,
    temporaryName: write.temporaryName
  };
}

function writeRecoveryStatus(postcondition: SafeWritePostcondition, nowMs: number): WriteRecoveryStatus {
  return {
    postcondition: postcondition.status,
    resolution: "remains_unknown",
    observed_at: new Date(nowMs).toISOString()
  };
}

function unavailableWriteRecovery(nowMs: number): WriteRecoveryStatus {
  return {
    postcondition: "unavailable",
    resolution: "remains_unknown",
    observed_at: new Date(nowMs).toISOString()
  };
}

function writeDispatchResult(job: BrokerJob, data: WriteResultData, reused: boolean): DispatchResult {
  return {
    data: { ...data, job_id: job.jobId },
    verification: {
      required: true,
      status: "verified",
      strategy: "readback_hash",
      evidence: { summary: reused ? "Reused a completed idempotent write job readback" : "Atomic write content was hashed after descriptor readback", readback_hash: data.sha256 }
    },
    auditTarget: `path:${data.path}`,
    auditEvidence: {
      jobId: job.jobId,
      jobRevision: job.revision,
      reused,
      bytesWritten: data.bytes_written,
      expectedMatched: data.precondition.matched,
      created: data.created
    }
  };
}

interface AppOpenResultData {
  app_id: string;
  state: "launched" | "already_running";
  process_id: null;
  target: { kind: "app"; reference: string };
  verified: true;
  job_id: string;
}

interface AppFocusResultData {
  app_id: string;
  window_id: string;
  window_title?: string;
  focused: true;
  reobserved_at: string;
  verified: true;
  job_id: string;
}

function appFocusDispatchResult(job: BrokerJob, data: AppFocusResultData, reused: boolean): DispatchResult {
  return {
    data: { ...data, job_id: job.jobId },
    verification: {
      required: true,
      status: "verified",
      strategy: "focused_app_window_reobservation",
      evidence: {
        summary: reused ? "Reused a completed app focus Job readback" : "App window focus was reobserved for the exact target identity",
        readback_hash: sha256(canonicalJson(data)),
        observed_at: data.reobserved_at
      }
    },
    auditTarget: `app_window:${data.window_id}`,
    auditEvidence: { jobId: job.jobId, jobRevision: job.revision, reused, appId: data.app_id, windowId: data.window_id, focused: data.focused, verified: data.verified }
  };
}

interface UiActionResultData {
  element_ref: string;
  action: UiActionName;
  accepted: true;
  job_id: string;
  reobserved: {
    role: string;
    enabled: boolean;
    focused: boolean;
    secure: false;
    state?: string;
  };
}

interface UiTypeResultData {
  element_ref: string;
  characters_accepted: number;
  keys_accepted: readonly UiInputKey[];
  submitted: boolean;
  focus_confirmed: true;
  reobserved: { role: string; focused: true; secure: false };
}

function uiTypeDispatchResult(job: BrokerJob, data: UiTypeResultData, reused: boolean): DispatchResult {
  if (data.element_ref.length === 0 || data.focus_confirmed !== true || data.reobserved.secure !== false) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI type result is inconsistent");
  }
  return {
    data: { ...data, job_id: job.jobId },
    verification: {
      required: true,
      status: "verified",
      strategy: "focused_target_and_input_postcondition",
      evidence: {
        summary: reused ? "Reused a completed UI type Job readback" : "Bounded input was delivered through stdin and the approved target was reobserved",
        readback_hash: sha256(canonicalJson(data)),
        observed_at: new Date().toISOString()
      }
    },
    auditTarget: `ui_element:${data.element_ref}`,
    auditEvidence: { jobId: job.jobId, jobRevision: job.revision, reused, elementRef: data.element_ref, charactersAccepted: data.characters_accepted, keyCount: data.keys_accepted.length, submitted: data.submitted }
  };
}

function uiActionDispatchResult(job: BrokerJob, data: UiActionResultData, reused: boolean): DispatchResult {
  if (data.job_id !== job.jobId) throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI action Job identity is inconsistent");
  const { secure: _secure, ...reobserved } = data.reobserved;
  return {
    data: { ...data, reobserved },
    verification: {
      required: true,
      status: "verified",
      strategy: data.reobserved.role === "VisualWindow" ? "visual_action_dispatch" : "accessibility_reobservation",
      evidence: {
        summary: reused ? "Reused a completed UI action Job readback" : data.reobserved.role === "VisualWindow"
          ? "A bounded event was sent to the observed browser window; inspect a fresh screenshot to verify the page effect"
          : "The approved Accessibility element was re-resolved before and after one fixed action",
        readback_hash: sha256(canonicalJson(data)),
        observed_at: new Date().toISOString()
      }
    },
    auditTarget: `ui_element:${data.element_ref}`,
    auditEvidence: { jobId: job.jobId, jobRevision: job.revision, reused, elementRef: data.element_ref, action: data.action, accepted: data.accepted }
  };
}

function appOpenDispatchResult(job: BrokerJob, data: AppOpenResultData, reused: boolean): DispatchResult {
  return {
    data: { ...data, job_id: job.jobId },
    verification: {
      required: true,
      status: "verified",
      strategy: "launch_state_and_target_reobservation",
      evidence: {
        summary: reused ? "Reused a completed app launch Job readback" : "App launch state was reobserved for the exact bundle identity",
        readback_hash: sha256(canonicalJson(data))
      }
    },
    auditTarget: `app:${data.app_id}`,
    auditEvidence: { jobId: job.jobId, jobRevision: job.revision, reused, state: data.state, verified: data.verified }
  };
}

export function parseStoredAppOpenResult(value: string): AppOpenResultData {
  let parsed: unknown;
  try { parsed = parseJsonStrict(value); } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored app launch result is malformed"); }
  if (!isPlainDataRecord(parsed) || !hasExactStoredFields(parsed, ["app_id", "state", "process_id", "target", "verified", "job_id"])) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored app launch result is malformed");
  }
  const record = parsed as Record<string, unknown>;
  const target = record.target;
  if (typeof record.app_id !== "string" || !/^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u.test(record.app_id) ||
      (record.state !== "launched" && record.state !== "already_running") || record.process_id !== null || record.verified !== true ||
      typeof record.job_id !== "string" || !/^job:app-open-[a-f0-9]{48}$/u.test(record.job_id) ||
      !isPlainDataRecord(target) || !hasExactStoredFields(target, ["kind", "reference"])) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored app launch result is malformed");
  }
  const targetRecord = target as Record<string, unknown>;
  if (targetRecord.kind !== "app" || targetRecord.reference !== record.app_id) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored app launch target is malformed");
  }
  return {
    app_id: record.app_id,
    state: record.state,
    process_id: null,
    target: { kind: "app", reference: record.app_id },
    verified: true,
    job_id: record.job_id
  };
}

export function parseStoredAppFocusResult(value: string): AppFocusResultData {
  let parsed: unknown;
  try { parsed = parseJsonStrict(value); } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored app focus result is malformed"); }
  if (!isPlainDataRecord(parsed) || !hasExactStoredFields(parsed, ["app_id", "window_id", "focused", "reobserved_at", "verified", "job_id"], ["window_title"])) throw new BrokerError("UNKNOWN_OUTCOME", "Stored app focus result is malformed");
  const record = parsed as Record<string, unknown>;
  if (typeof record.app_id !== "string" || !/^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u.test(record.app_id) ||
      typeof record.window_id !== "string" || !/^window:[a-f0-9]{48}$/u.test(record.window_id) ||
      (record.window_title !== undefined && (typeof record.window_title !== "string" || record.window_title.length > 512)) ||
      record.focused !== true || typeof record.reobserved_at !== "string" || record.reobserved_at.length > 64 ||
      record.verified !== true || typeof record.job_id !== "string" || !/^job:app-focus-[a-f0-9]{48}$/u.test(record.job_id)) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored app focus result is malformed");
  }
  return {
    app_id: record.app_id,
    window_id: record.window_id,
    ...(record.window_title !== undefined ? { window_title: record.window_title } : {}),
    focused: true,
    reobserved_at: record.reobserved_at,
    verified: true,
    job_id: record.job_id
  };
}

export function parseStoredUiActionResult(value: string): UiActionResultData {
  let parsed: unknown;
  try { parsed = parseJsonStrict(value); } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI action result is malformed"); }
  if (!isPlainDataRecord(parsed) || !hasExactStoredFields(parsed, ["element_ref", "action", "accepted", "job_id", "reobserved"])) throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI action result is malformed");
  const record = parsed as Record<string, unknown>;
  const reobserved = record.reobserved;
  if (typeof record.element_ref !== "string" || !/^element:[a-f0-9]{48}$/u.test(record.element_ref) ||
      typeof record.action !== "string" || !["press", "select", "increment", "decrement", "show_menu", "focus", ...VISUAL_ACTION_NAMES].includes(record.action) ||
      record.accepted !== true || typeof record.job_id !== "string" || !/^job:ui-action-[a-f0-9]{48}$/u.test(record.job_id) ||
      !isPlainDataRecord(reobserved) || !hasExactStoredFields(reobserved, ["role", "enabled", "focused", "secure"], ["state"])) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI action result is malformed");
  }
  const state = reobserved as Record<string, unknown>;
  if (typeof state.role !== "string" || state.role.length < 1 || state.role.length > 128 ||
      typeof state.enabled !== "boolean" || typeof state.focused !== "boolean" || state.secure !== false ||
      (state.state !== undefined && (typeof state.state !== "string" || state.state.length > 512))) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI action result is malformed");
  }
  return {
    element_ref: record.element_ref,
    action: record.action as UiActionName,
    accepted: true,
    job_id: record.job_id,
    reobserved: {
      role: state.role,
      enabled: state.enabled,
      focused: state.focused,
      secure: false,
      ...(state.state !== undefined ? { state: state.state } : {})
    }
  };
}

export function parseStoredUiTypeResult(value: string): UiTypeResultData {
  let parsed: unknown;
  try { parsed = parseJsonStrict(value); } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI type result is malformed"); }
  if (!isPlainDataRecord(parsed) || !hasExactStoredFields(parsed, ["element_ref", "characters_accepted", "keys_accepted", "submitted", "focus_confirmed", "reobserved"])) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI type result is malformed");
  }
  const record = parsed as Record<string, unknown>;
  const keys = record.keys_accepted;
  const reobserved = record.reobserved;
  const validKeys = ["ENTER", "TAB", "ESCAPE", "ARROW_UP", "ARROW_DOWN", "ARROW_LEFT", "ARROW_RIGHT", "HOME", "END"];
  if (typeof record.element_ref !== "string" || !/^element:[a-f0-9]{48}$/u.test(record.element_ref) ||
      !Number.isSafeInteger(record.characters_accepted) || (record.characters_accepted as number) < 0 || (record.characters_accepted as number) > 10_000 ||
      !Array.isArray(keys) || keys.length > 32 || keys.some((key) => !validKeys.includes(key as string)) ||
      typeof record.submitted !== "boolean" || record.focus_confirmed !== true || !isPlainDataRecord(reobserved) ||
      !hasExactStoredFields(reobserved, ["role", "focused", "secure"])) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI type result is malformed");
  }
  const state = reobserved as Record<string, unknown>;
  if (typeof state.role !== "string" || state.role.length < 1 || state.role.length > 128 || state.focused !== true || state.secure !== false) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI type result is malformed");
  }
  return {
    element_ref: record.element_ref,
    characters_accepted: record.characters_accepted as number,
    keys_accepted: keys as UiInputKey[],
    submitted: record.submitted,
    focus_confirmed: true,
    reobserved: { role: state.role, focused: true, secure: false }
  };
}

export function parseStoredWriteResult(value: string): WriteResultData {
  let parsed: unknown;
  try { parsed = parseJsonStrict(value); } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem write result is malformed"); }
  if (!isPlainDataRecord(parsed) || !hasExactStoredFields(parsed, ["path", "bytes_written", "sha256", "created", "precondition"])) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem write result is malformed");
  }
  const record = parsed as Record<string, unknown>;
  const precondition = record.precondition;
  if (typeof record.path !== "string" || !isAbsolute(record.path) || record.path.length > 4096 ||
      !Number.isSafeInteger(record.bytes_written) || (record.bytes_written as number) < 0 || (record.bytes_written as number) > 1_048_576 ||
      typeof record.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(record.sha256) || typeof record.created !== "boolean" ||
      !isPlainDataRecord(precondition) || !hasExactStoredFields(precondition, ["expected_sha256", "matched", "create_only"])) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem write result is malformed");
  }
  const condition = precondition as Record<string, unknown>;
  if ((condition.expected_sha256 !== null && (typeof condition.expected_sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(condition.expected_sha256))) ||
      typeof condition.matched !== "boolean" || typeof condition.create_only !== "boolean") {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem write precondition is malformed");
  }
  return {
    path: record.path,
    bytes_written: record.bytes_written as number,
    sha256: record.sha256,
    created: record.created,
    precondition: {
      expected_sha256: condition.expected_sha256 as string | null,
      matched: condition.matched,
      create_only: condition.create_only
    }
  };
}

function patchResultData(result: FilesystemPatchResult): PatchResultData {
  return {
    project_root: result.projectRoot,
    result: result.result,
    changed_paths: [...result.changedPaths],
    precondition: {
      checked: result.precondition.checked,
      expected_sha256: result.precondition.expectedSha256,
      actual_sha256: result.precondition.actualSha256,
      matched: result.precondition.matched
    },
    files: result.files.map((file) => ({ path: file.path, sha256: file.sha256, size_bytes: file.sizeBytes }))
  };
}

export function parseStoredPatchResult(value: string): PatchResultData {
  let parsed: unknown;
  try { parsed = parseJsonStrict(value); } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem patch result is malformed"); }
  if (!isPlainDataRecord(parsed) || !hasExactStoredFields(parsed, ["project_root", "result", "changed_paths", "precondition", "files"])) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem patch result is malformed");
  }
  const record = parsed as Record<string, unknown>;
  const precondition = record.precondition;
  const files = record.files;
  const changedPaths = record.changed_paths;
  if (typeof record.project_root !== "string" || !isAbsolute(record.project_root) || record.project_root.length > 4096 || record.project_root.includes("\0") ||
      (record.result !== "applied" && record.result !== "no_change") || !Array.isArray(changedPaths) || changedPaths.length > 64 ||
      changedPaths.some((path) => !isSafePatchRelativePath(path)) ||
      !isPlainDataRecord(precondition) || !hasExactStoredFields(precondition, ["checked", "expected_sha256", "actual_sha256", "matched"]) ||
      typeof (precondition as Record<string, unknown>).checked !== "boolean" || typeof (precondition as Record<string, unknown>).matched !== "boolean" ||
      typeof (precondition as Record<string, unknown>).actual_sha256 !== "string" || !/^[a-f0-9]{64}$/u.test((precondition as Record<string, unknown>).actual_sha256 as string) ||
      ((precondition as Record<string, unknown>).expected_sha256 !== null && (typeof (precondition as Record<string, unknown>).expected_sha256 !== "string" || !/^[a-f0-9]{64}$/u.test((precondition as Record<string, unknown>).expected_sha256 as string))) ||
      !Array.isArray(files) || files.length > 64) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem patch result is malformed");
  }
  const condition = precondition as Record<string, unknown>;
  const parsedFiles = files.map((file) => {
    if (!isPlainDataRecord(file) || !hasExactStoredFields(file, ["path", "sha256", "size_bytes"])) throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem patch file is malformed");
    const item = file as Record<string, unknown>;
    if (typeof item.path !== "string" || !isAbsolute(item.path) || item.path.length > 4096 || item.path.includes("\0") ||
        typeof item.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(item.sha256) || !Number.isSafeInteger(item.size_bytes) || (item.size_bytes as number) < 0 || (item.size_bytes as number) > 1_048_576) {
      throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem patch file is malformed");
    }
    return { path: item.path, sha256: item.sha256, size_bytes: item.size_bytes as number };
  });
  return {
    project_root: record.project_root,
    result: record.result,
    changed_paths: changedPaths as string[],
    precondition: {
      checked: condition.checked as boolean,
      expected_sha256: condition.expected_sha256 as string | null,
      actual_sha256: condition.actual_sha256 as string,
      matched: condition.matched as boolean
    },
    files: parsedFiles
  };
}

function hasExactStoredFields(
  value: Record<string, unknown>,
  required: readonly string[],
  optional: readonly string[] = []
): boolean {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) && keys.every((key) => allowed.has(key));
}

function patchDispatchResult(job: BrokerJob, result: FilesystemPatchResult | PatchResultData, reused: boolean): DispatchResult {
  const data = "project_root" in result ? result : patchResultData(result);
  return {
    data: { ...data, job_id: job.jobId },
    verification: {
      required: true,
      status: "verified",
      strategy: "changed_paths_and_hash_readback",
      evidence: {
        summary: reused ? "Reused completed Broker patch Job after validating its stored result" : "Patch output was read back from descriptor-bound writes and hashed",
        readback_hash: sha256(canonicalJson(data.files)),
        observed_at: new Date(Date.now()).toISOString()
      }
    },
    auditTarget: `project:${data.project_root}`,
    auditEvidence: {
      jobId: job.jobId,
      result: data.result,
      changedPathCount: data.changed_paths.length,
      fileCount: data.files.length,
      preconditionChecked: data.precondition.checked
    }
  };
}

function isSafePatchRelativePath(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 4096 && !value.includes("\0") &&
    !value.startsWith("/") && !value.includes("\\") &&
    !value.split("/").some((part) => part === "" || part === "." || part === "..");
}

function executionTarget(toolPolicy: ToolPolicy): NormalizedTarget {
  switch (toolPolicy.targetType) {
    case "broker":
    case "policy_query":
      return { kind: "host", reference: "broker" };
    case "path":
      throw new BrokerError("PRECONDITION_FAILED", "Filesystem target requires descriptor-backed planning");
    case "filesystem_roots":
      throw new BrokerError("PRECONDITION_FAILED", "Filesystem roots require descriptor-backed planning");
    case "project":
      throw new BrokerError("PRECONDITION_FAILED", "Project target requires Git-specific planning");
    case "process":
      return { kind: "process", reference: "all" };
    case "service":
      throw new BrokerError("PRECONDITION_FAILED", "Service target requires service-specific planning");
    case "package":
      throw new BrokerError("PRECONDITION_FAILED", "Package target requires package-specific planning");
    case "log_source":
      throw new BrokerError("PRECONDITION_FAILED", "Log target requires log-source-specific planning");
    case "app_set":
      return { kind: "app_set", reference: "all" };
    case "app":
      throw new BrokerError("PRECONDITION_FAILED", "App target requires app-specific planning");
    case "app_window":
      throw new BrokerError("PRECONDITION_FAILED", "App window target requires app-specific planning");
    case "ui_element":
      throw new BrokerError("PRECONDITION_FAILED", "UI element target requires app-specific planning");
    case "docker_runtime":
      throw new BrokerError("PRECONDITION_FAILED", "Docker runtime target requires Docker-specific planning");
    case "docker_object":
      throw new BrokerError("PRECONDITION_FAILED", "Docker object target requires Docker-specific planning");
    case "job":
      throw new BrokerError("PRECONDITION_FAILED", "Job target requires Broker-owned job planning");
    case "task_profile":
      throw new BrokerError("PRECONDITION_FAILED", "Task profile target requires task-specific planning");
  }
}

function assertExactArguments(argumentsValue: Readonly<Record<string, unknown>>, allowed: readonly string[]): void {
  const allowedSet = new Set(allowed);
  if (Object.keys(argumentsValue).some((key) => !allowedSet.has(key))) {
    throw new BrokerError("PRECONDITION_FAILED", "Tool arguments contain an unknown field");
  }
}

function requireMutationApprovalClass(
  approvalPolicy: ToolPolicy["approvalPolicy"]
): "trusted_write" | "trusted_gui" | "trusted_profile" | "explicit_privileged_policy" {
  if (approvalPolicy === "trusted_read") {
    throw new BrokerError("POLICY_DENIED", "Mutation tool does not declare a mutation approval policy");
  }
  return approvalPolicy;
}

function validateReadArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const offset = argumentsValue.offset;
  if (offset !== undefined && (!Number.isSafeInteger(offset) || (offset as number) < 0 || (offset as number) > 1_000_000_000)) {
    throw new BrokerError("PRECONDITION_FAILED", "offset must be a bounded non-negative integer");
  }
  const maxBytes = argumentsValue.max_bytes;
  if (maxBytes !== undefined && (!Number.isSafeInteger(maxBytes) || (maxBytes as number) < 1 || (maxBytes as number) > 1_048_576)) {
    throw new BrokerError("PRECONDITION_FAILED", "max_bytes must be an integer between 1 and 1048576");
  }
  const encoding = argumentsValue.encoding;
  if (encoding !== undefined && encoding !== "utf8" && encoding !== "base64" && encoding !== "metadata") {
    throw new BrokerError("PRECONDITION_FAILED", "encoding must be utf8, base64, or metadata");
  }
}

function validateHashArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const algorithm = argumentsValue.algorithm;
  if (algorithm !== undefined && algorithm !== "sha256" && algorithm !== "sha512") {
    throw new BrokerError("PRECONDITION_FAILED", "algorithm must be sha256 or sha512");
  }
}

function validateListArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const cursor = argumentsValue.cursor;
  if (cursor !== undefined && (typeof cursor !== "string" || cursor.length === 0 || cursor.length > 512 || !/^[A-Za-z0-9_-]+$/u.test(cursor))) {
    throw new BrokerError("PRECONDITION_FAILED", "cursor must be a bounded opaque identifier");
  }
  const limit = argumentsValue.limit;
  if (limit !== undefined && (!Number.isSafeInteger(limit) || (limit as number) < 1 || (limit as number) > 500)) {
    throw new BrokerError("PRECONDITION_FAILED", "limit must be an integer between 1 and 500");
  }
  const includeHidden = argumentsValue.include_hidden;
  if (includeHidden !== undefined && typeof includeHidden !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "include_hidden must be a boolean");
  }
}

function validateTreeArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const depth = argumentsValue.depth;
  if (depth !== undefined && (!Number.isSafeInteger(depth) || (depth as number) < 0 || (depth as number) > 8)) {
    throw new BrokerError("PRECONDITION_FAILED", "depth must be an integer between 0 and 8");
  }
  const maxEntries = argumentsValue.max_entries;
  if (maxEntries !== undefined && (!Number.isSafeInteger(maxEntries) || (maxEntries as number) < 1 || (maxEntries as number) > 5000)) {
    throw new BrokerError("PRECONDITION_FAILED", "max_entries must be an integer between 1 and 5000");
  }
}

function validateFindArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const roots = argumentsValue.roots;
  if (!Array.isArray(roots) || roots.length < 1 || roots.length > 32 || roots.some((root) =>
    typeof root !== "string" || !isAbsolute(root) || root.length > 4096 || root.includes("\0"))) {
    throw new BrokerError("PRECONDITION_FAILED", "roots must contain 1 to 32 bounded absolute paths");
  }
  const query = argumentsValue.query;
  if (typeof query !== "string" || query.length < 1 || query.length > 256 || query.includes("\0")) {
    throw new BrokerError("PRECONDITION_FAILED", "query must be a bounded string");
  }
  const maxResults = argumentsValue.max_results;
  if (maxResults !== undefined && (!Number.isSafeInteger(maxResults) || (maxResults as number) < 1 || (maxResults as number) > 1000)) {
    throw new BrokerError("PRECONDITION_FAILED", "max_results must be an integer between 1 and 1000");
  }
}

function validateRecentArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const roots = argumentsValue.roots;
  if (!Array.isArray(roots) || roots.length < 1 || roots.length > 32 || roots.some((root) =>
    typeof root !== "string" || !isAbsolute(root) || root.length > 4096 || root.includes("\0"))) {
    throw new BrokerError("PRECONDITION_FAILED", "roots must contain 1 to 32 bounded absolute paths");
  }
  const sinceSeconds = argumentsValue.since_seconds;
  if (!Number.isSafeInteger(sinceSeconds) || (sinceSeconds as number) < 1 || (sinceSeconds as number) > 31_536_000) {
    throw new BrokerError("PRECONDITION_FAILED", "since_seconds must be an integer between 1 and 31536000");
  }
  const limit = argumentsValue.limit;
  if (limit !== undefined && (!Number.isSafeInteger(limit) || (limit as number) < 1 || (limit as number) > 1000)) {
    throw new BrokerError("PRECONDITION_FAILED", "limit must be an integer between 1 and 1000");
  }
}

function validateSearchTextArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const roots = argumentsValue.roots;
  if (!Array.isArray(roots) || roots.length < 1 || roots.length > 32 || roots.some((root) =>
    typeof root !== "string" || !isAbsolute(root) || root.length > 4096 || root.includes("\0"))) {
    throw new BrokerError("PRECONDITION_FAILED", "roots must contain 1 to 32 bounded absolute paths");
  }
  const query = argumentsValue.query;
  if (typeof query !== "string" || query.length < 1 || query.length > 512 || query.includes("\0")) {
    throw new BrokerError("PRECONDITION_FAILED", "query must be a bounded string");
  }
  const glob = argumentsValue.glob;
  if (glob !== undefined && (typeof glob !== "string" || glob.length < 1 || glob.length > 256 || glob.includes("\0"))) {
    throw new BrokerError("PRECONDITION_FAILED", "glob must be a bounded string");
  }
  const maxResults = argumentsValue.max_results;
  if (maxResults !== undefined && (!Number.isSafeInteger(maxResults) || (maxResults as number) < 1 || (maxResults as number) > 1000)) {
    throw new BrokerError("PRECONDITION_FAILED", "max_results must be an integer between 1 and 1000");
  }
}

function validateProjectDiscoverArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const roots = argumentsValue.roots;
  if (!Array.isArray(roots) || roots.length < 1 || roots.length > 32 || roots.some((root) =>
    typeof root !== "string" || !isAbsolute(root) || root.length > 4096 || root.includes("\0"))) {
    throw new BrokerError("PRECONDITION_FAILED", "roots must contain 1 to 32 bounded absolute paths");
  }
  const types = argumentsValue.types;
  if (types !== undefined && (!Array.isArray(types) || types.length > 32 || types.some((type) =>
    typeof type !== "string" || type.length < 1 || type.length > 64 || type.includes("\0")))) {
    throw new BrokerError("PRECONDITION_FAILED", "types must contain at most 32 bounded strings");
  }
  normalizeProjectTypes((types ?? []) as string[]);
  const maxResults = argumentsValue.max_results;
  if (maxResults !== undefined && (!Number.isSafeInteger(maxResults) || (maxResults as number) < 1 || (maxResults as number) > 500)) {
    throw new BrokerError("PRECONDITION_FAILED", "max_results must be an integer between 1 and 500");
  }
}

function validateProjectSummaryArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const projectRoot = argumentsValue.project_root;
  if (typeof projectRoot !== "string" || !isAbsolute(projectRoot) || projectRoot.length > 4096 || projectRoot.includes("\0")) {
    throw new BrokerError("PRECONDITION_FAILED", "project_root must be a bounded absolute path");
  }
  const includeTree = argumentsValue.include_tree;
  if (includeTree !== undefined && typeof includeTree !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "include_tree must be a boolean");
  }
  const treeDepth = argumentsValue.tree_depth;
  if (treeDepth !== undefined && (!Number.isSafeInteger(treeDepth) || (treeDepth as number) < 0 || (treeDepth as number) > 4)) {
    throw new BrokerError("PRECONDITION_FAILED", "tree_depth must be an integer between 0 and 4");
  }
}

function validateStorageAnalysisArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const roots = argumentsValue.roots;
  if (roots !== undefined && (!Array.isArray(roots) || roots.length > 32 || roots.some((root) =>
    typeof root !== "string" || !isAbsolute(root) || root.length > 4096 || root.includes("\0")))) {
    throw new BrokerError("PRECONDITION_FAILED", "roots must contain at most 32 bounded absolute paths");
  }
  const topN = argumentsValue.top_n;
  if (topN !== undefined && (!Number.isSafeInteger(topN) || (topN as number) < 1 || (topN as number) > 100)) {
    throw new BrokerError("PRECONDITION_FAILED", "top_n must be an integer between 1 and 100");
  }
  const maxDepth = argumentsValue.max_depth;
  if (maxDepth !== undefined && (!Number.isSafeInteger(maxDepth) || (maxDepth as number) < 0 || (maxDepth as number) > 8)) {
    throw new BrokerError("PRECONDITION_FAILED", "max_depth must be an integer between 0 and 8");
  }
}

function validateProcessArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  const limit = argumentsValue.limit;
  if (limit !== undefined && (!Number.isSafeInteger(limit) || (limit as number) < 1 || (limit as number) > 500)) {
    throw new BrokerError("PRECONDITION_FAILED", "limit must be an integer between 1 and 500");
  }
  const sort = argumentsValue.sort;
  if (sort !== undefined && sort !== "cpu" && sort !== "memory" && sort !== "pid" && sort !== "name") {
    throw new BrokerError("PRECONDITION_FAILED", "sort is unsupported");
  }
}

function decodeDirectoryCursor(value: unknown): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== "string") throw new BrokerError("PRECONDITION_FAILED", "cursor must be a string");
  let decoded: string;
  try {
    const bytes = Buffer.from(value, "base64url");
    if (bytes.length === 0 || bytes.toString("base64url") !== value) throw new Error("non-canonical cursor");
    decoded = bytes.toString("utf8");
  } catch {
    throw new BrokerError("PRECONDITION_FAILED", "cursor is malformed");
  }
  if (decoded.length === 0 || decoded.includes("\0") || decoded.includes("/")) {
    throw new BrokerError("PRECONDITION_FAILED", "cursor is malformed");
  }
  return decoded;
}

function encodeDirectoryCursor(value: string): string {
  return Buffer.from(value, "utf8").toString("base64url");
}

function validateApplyPatchArguments(projectRoot: unknown, patchText: unknown, expectedBaseHash: unknown): void {
  if (typeof projectRoot !== "string" || projectRoot.length < 1 || projectRoot.length > 4096 || projectRoot.includes("\0") || projectRoot.includes("\n") || projectRoot.includes("\r")) {
    throw new BrokerError("PRECONDITION_FAILED", "project_root must be a bounded absolute path");
  }
  if (!isAbsolute(projectRoot)) throw new BrokerError("PRECONDITION_FAILED", "project_root must be an absolute path");
  if (typeof patchText !== "string" || patchText.length < 1 || Buffer.byteLength(patchText, "utf8") > 524_288 || patchText.includes("\0") || patchText.includes("\r")) {
    throw new BrokerError("PRECONDITION_FAILED", "patch must be a bounded textual patch");
  }
  if (expectedBaseHash !== undefined && (typeof expectedBaseHash !== "string" || !/^[A-Fa-f0-9]{64}$/u.test(expectedBaseHash))) {
    throw new BrokerError("PRECONDITION_FAILED", "expected_base_hash must be a SHA-256 digest");
  }
}

function validateWriteArguments(argumentsValue: Readonly<Record<string, unknown>>): void {
  if (typeof argumentsValue.path !== "string" || argumentsValue.path.length === 0 || argumentsValue.path.length > 4096 || argumentsValue.path.includes("\0")) {
    throw new BrokerError("PRECONDITION_FAILED", "path must be a bounded string");
  }
  if (typeof argumentsValue.content !== "string" || argumentsValue.content.length > 1_048_576) {
    throw new BrokerError("PRECONDITION_FAILED", "content must be a bounded string");
  }
  if (typeof argumentsValue.idempotency_key !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(argumentsValue.idempotency_key)) {
    throw new BrokerError("PRECONDITION_FAILED", "idempotency_key must be a bounded stable identifier");
  }
  const encoding = argumentsValue.encoding;
  if (encoding !== undefined && encoding !== "utf8" && encoding !== "base64") {
    throw new BrokerError("PRECONDITION_FAILED", "encoding must be utf8 or base64");
  }
  const expectedSha256 = argumentsValue.expected_sha256;
  if (expectedSha256 !== undefined && (typeof expectedSha256 !== "string" || !/^[A-Fa-f0-9]{64}$/u.test(expectedSha256))) {
    throw new BrokerError("PRECONDITION_FAILED", "expected_sha256 must be a SHA-256 digest");
  }
  if (argumentsValue.create_only !== undefined && typeof argumentsValue.create_only !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "create_only must be a boolean");
  }
}

function decodeWriteContent(argumentsValue: Readonly<Record<string, unknown>>): Buffer {
  validateWriteArguments(argumentsValue);
  const content = argumentsValue.content as string;
  if ((argumentsValue.encoding ?? "utf8") === "utf8") {
    const bytes = Buffer.from(content, "utf8");
    if (bytes.length > 1_048_576) throw new BrokerError("OUTPUT_LIMIT", "Filesystem write content exceeds the contract limit");
    return bytes;
  }
  if (content.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(content)) {
    throw new BrokerError("PRECONDITION_FAILED", "base64 content is malformed");
  }
  const bytes = Buffer.from(content, "base64");
  if (bytes.length > 1_048_576 || bytes.toString("base64") !== content) {
    throw new BrokerError("PRECONDITION_FAILED", "base64 content is malformed");
  }
  return bytes;
}

function validateJobArguments(tool: string, argumentsValue: Readonly<Record<string, unknown>>): void {
  if (typeof argumentsValue.job_id !== "string" || !/^[A-Za-z0-9._:/-]{1,256}$/u.test(argumentsValue.job_id)) {
    throw new BrokerError("PRECONDITION_FAILED", "job_id is malformed");
  }
  if (tool === "mac_job_status") {
    const tailBytes = argumentsValue.tail_bytes;
    if (tailBytes !== undefined && (!Number.isSafeInteger(tailBytes) || (tailBytes as number) < 0 || (tailBytes as number) > 524_288)) {
      throw new BrokerError("PRECONDITION_FAILED", "tail_bytes must be an integer between 0 and 524288");
    }
  } else {
    const reason = argumentsValue.reason;
    if (reason !== undefined && (typeof reason !== "string" || reason.length > 200 || reason.includes("\0"))) {
      throw new BrokerError("PRECONDITION_FAILED", "cancellation reason is malformed");
    }
  }
}

function boundedJobOutput(job: BrokerJob, tailBytes: number): { stdout: string; stderr: string; truncated: boolean } {
  const stdoutBytes = Buffer.from(job.stdout, "utf8");
  const stderrBytes = Buffer.from(job.stderr, "utf8");
  const stderrBudget = Math.min(stderrBytes.length, Math.floor(tailBytes / 2));
  const stdoutBudget = Math.min(stdoutBytes.length, tailBytes - stderrBudget);
  const remaining = tailBytes - stderrBudget - stdoutBudget;
  const finalStderrBudget = Math.min(stderrBytes.length, stderrBudget + remaining);
  const stdout = stdoutBytes.subarray(stdoutBytes.length - stdoutBudget).toString("utf8");
  const stderr = stderrBytes.subarray(stderrBytes.length - finalStderrBudget).toString("utf8");
  return {
    stdout,
    stderr,
    truncated: job.truncated || stdoutBudget < stdoutBytes.length || finalStderrBudget < stderrBytes.length
  };
}

function jobStatusData(
  job: BrokerJob,
  output: { stdout: string; stderr: string; truncated: boolean },
  recovery?: WriteRecoveryStatus
) {
  return {
    job_id: job.jobId,
    state: job.state,
    created_at: new Date(job.createdAtMs).toISOString(),
    started_at: job.startedAtMs === null ? null : new Date(job.startedAtMs).toISOString(),
    finished_at: job.finishedAtMs === null ? null : new Date(job.finishedAtMs).toISOString(),
    exit_code: job.exitCode,
    ...(job.startedAtMs !== null && job.finishedAtMs !== null ? { execution_duration_ms: Math.max(0, job.finishedAtMs - job.startedAtMs) } : {}),
    result_class: job.resultClass,
    stdout: output.stdout,
    stderr: output.stderr,
    truncated: output.truncated,
    ...(recovery ? { recovery } : {})
  };
}

function archivedJobStatusData(job: ArchivedJobRecord) {
  return {
    job_id: job.jobId,
    state: job.state,
    created_at: new Date(job.createdAtMs).toISOString(),
    started_at: job.startedAtMs === null ? null : new Date(job.startedAtMs).toISOString(),
    finished_at: new Date(job.finishedAtMs).toISOString(),
    exit_code: job.exitCode,
    ...(job.startedAtMs !== null && job.finishedAtMs !== null ? { execution_duration_ms: Math.max(0, job.finishedAtMs - job.startedAtMs) } : {}),
    result_class: job.resultClass,
    stdout: "",
    stderr: "",
    truncated: true
  };
}

const POLICY_QUERY_TARGET_KINDS = new Set<TargetKind>([
  "host", "path", "project", "process", "job", "task_profile", "app_set", "app", "app_window", "ui_element",
  "service", "log_source", "docker_runtime", "docker_object", "package", "power"
]);

/**
 * Normalize the caller-provided policy-query target before any policy lookup.
 * Each target kind has a canonical reference grammar so a compromised Edge
 * cannot turn a generic string into an unintended app, UI, service, or runtime
 * identity. Filesystem paths remain lexical here and are descriptor-checked by
 * the filesystem planner before authorization is reported as allowed.
 */
export function normalizePolicyQueryTarget(value: unknown): NormalizedTarget {
  if (value === undefined) return { kind: "host", reference: "broker" };
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("PRECONDITION_FAILED", "target must be an object");
  }
  const target = value as Record<string, unknown>;
  assertExactArguments(target, ["kind", "reference"]);
  if (typeof target.kind !== "string" || !POLICY_QUERY_TARGET_KINDS.has(target.kind as TargetKind) ||
      typeof target.reference !== "string" || !isPolicyQueryTargetReference(target.kind as TargetKind, target.reference)) {
    throw new BrokerError("PRECONDITION_FAILED", "target kind and reference are malformed for policy lookup");
  }
  return { kind: target.kind as TargetKind, reference: target.reference };
}

class PersistentlyQuarantinedTaskRunner implements TaskRunner {
  private poisoned = false;
  private closed = false;
  private closePromise: Promise<void> | undefined;

  constructor(
    private readonly inner: TaskRunner,
    private readonly hasUnresolvedHostTask: () => boolean
  ) {}

  get available(): boolean {
    if (this.closed || this.poisoned) return false;
    try {
      if (!this.inner.available) return false;
      if (this.hasUnresolvedHostTask()) {
        this.quarantine();
        return false;
      }
      return true;
    } catch {
      this.quarantine();
      return false;
    }
  }

  get publicEnablement(): TaskRunner["publicEnablement"] {
    return this.available ? this.inner.publicEnablement : "unavailable";
  }

  get mechanism(): TaskRunner["mechanism"] {
    return this.inner.mechanism;
  }

  get isolationProof(): TaskRunner["isolationProof"] {
    return this.inner.isolationProof;
  }

  async run(
    profile: Parameters<TaskRunner["run"]>[0],
    control: Parameters<TaskRunner["run"]>[1]
  ): ReturnType<TaskRunner["run"]> {
    if (!this.available) {
      throw new BrokerError("POLICY_DENIED", "Host task execution is quarantined after an unresolved process outcome");
    }
    try {
      const result = await this.inner.run(profile, control);
      if (result.state === "unknown" || result.resultClass === "UNKNOWN_OUTCOME") this.quarantine();
      return result;
    } catch (error) {
      if (error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME") this.quarantine();
      throw error;
    }
  }

  async close(): Promise<void> {
    this.closed = true;
    await this.closeInner();
  }

  private quarantine(): void {
    if (this.poisoned) return;
    this.poisoned = true;
    void this.closeInner().catch(() => undefined);
  }

  private closeInner(): Promise<void> {
    if (this.closePromise === undefined) {
      this.closePromise = Promise.resolve()
        .then(async () => { await this.inner.close?.(); })
        .catch((error: unknown) => {
          this.closePromise = undefined;
          throw error;
        });
    }
    return this.closePromise;
  }
}

function uiApprovalBinding(request: BrokerRequest): string {
  return sha256(canonicalJson({ tool: request.tool, arguments: request.arguments }));
}
