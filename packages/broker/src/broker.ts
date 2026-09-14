import {
  BrokerError,
  canonicalJson,
  CONTRACT_VERSION,
  PROTOCOL_VERSION,
  sha256,
  signBrokerResponse,
  verifyRequestAuthentication,
  type AuthenticatedBrokerResponse,
  type BrokerFailure,
  type BrokerRequest,
  type BrokerResult
} from "@mac-operator/contracts";
import { randomUUID } from "node:crypto";
import { isAbsolute } from "node:path";
import type { BrokerJob, BrokerStore, GuestTaskJobMetadata, JobLease, WriteJobMetadata } from "./persistence.js";
import { EdgeKeyring, keyIdentity } from "./edge-keyring.js";
import {
  authorizePrincipalProjection,
  authorizeTarget,
  authorizeTool,
  isCapabilityFamilyDisabled,
  runtimeToolStates,
  type BrokerPolicy,
  type NormalizedTarget,
  type TargetKind,
  type ToolPolicy
} from "./policy.js";
import { PolicyManager } from "./policy-loader.js";
import { parseBrokerRequest } from "./request-validator.js";
import { FilesystemInspector, normalizeProjectTypes, type FilesystemPathPlan, type SafeWritePostcondition, type TemporaryWriteCleanupResult } from "./filesystem-inspector.js";
import type { FilesystemPatchResult } from "./filesystem-patch.js";
import { WorkerFilesystemExecutor, type FilesystemExecutor } from "./filesystem-executor.js";
import { inspectSystem } from "./system-inspector.js";
import { inspectNetwork } from "./network-inspector.js";
import { WorkerProcessExecutor, type ProcessExecutor } from "./process-executor.js";
import { ProcessSupervisor, type ProcessOwnershipSnapshot } from "./process-supervisor.js";
import { LaunchdServiceInspector, validateServiceId, type ServiceInspector } from "./service-inspector.js";
import { MacLogInspector, validateLogRequest, type LogInspector } from "./log-inspector.js";
import { GitBranchListInspector, GitDiffInspectorImpl, GitLogInspectorImpl, GitStatusInspector, GitWriteInspectorImpl, validateGitBranchRequest, validateGitCommitRequest, validateGitDiffRequest, validateGitLogRequest, validateGitStageRequest, validateGitStatusRequest, type GitBranchInspector, type GitDiffInspector, type GitInspector, type GitLogInspector, type GitWriteInspector } from "./git-inspector.js";
import { PackageInspectorImpl, validatePackageInspectRequest, type PackageInspector, type PackageManagerRequest } from "./package-inspector.js";
import { DockerInspectorImpl, validateDockerLogsRequest, validateDockerObjectRequest, validateDockerStatusRequest, type DockerInspector, type DockerObjectType } from "./docker-inspector.js";
import { assertContentDoesNotContainSecrets, redactBoundedText } from "./secret-policy.js";
import { FailClosedTaskRunner, requireTaskIsolationProof, validateTaskExecutionResult, validateTaskIsolationProof, type TaskRecoveryRequest, type TaskRunner, type VirtualizationGuestTaskAdmission } from "./task-runner.js";
import { TaskProfileRegistry, validateTaskRunArguments, type ResolvedTaskProfile } from "./task-profile.js";
import { AppInventoryInspectorImpl, validateAppListRequest, type AppInventoryInspector } from "./app-inspector.js";
import { AppControlInspectorImpl, validateAppFocusRequest, validateAppOpenRequest, type AppControlInspector } from "./app-control.js";
import { MacUiInspectorImpl, UiSnapshotRegistry, validateSensitiveUiTarget, validateUiActionRequest, validateUiObserveRequest, type UiActionName, type UiInspector, type UiSnapshotRecord } from "./ui-inspector.js";
import { PrivilegedHelperJobExecutor, type PrivilegedHelperJobExecutionInput, type PrivilegedHelperJobExecutionOutcome } from "./privileged-helper-executor.js";

export interface BrokerOptions {
  store: BrokerStore;
  policy: BrokerPolicy | PolicyManager;
  edgeAuthenticationKeys: EdgeKeyring;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
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
  uiSnapshotRegistry?: UiSnapshotRegistry;
  taskProfileRegistry?: TaskProfileRegistry;
  taskRunner?: TaskRunner;
  /** Optional privileged helper Job boundary; disabled by default. */
  privilegedHelperExecutor?: PrivilegedHelperJobExecutor;
}

const JOB_LEASE_DURATION_MS = 30_000;
const JOB_LEASE_RENEW_INTERVAL_MS = 5_000;

export class Broker {
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;
  private readonly filesystemExecutor: FilesystemExecutor;
  private readonly processExecutor: ProcessExecutor;
  private readonly processSupervisor: ProcessSupervisor;
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
  private readonly uiSnapshotRegistry: UiSnapshotRegistry;
  private readonly taskProfileRegistry: TaskProfileRegistry;
  private readonly taskRunner: TaskRunner;
  private readonly privilegedHelperExecutor: PrivilegedHelperJobExecutor;
  private readonly jobLeaseOwnerId: string;
  private closing = false;
  private closePromise: Promise<void> | undefined;

  constructor(private readonly options: BrokerOptions) {
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? 60_000;
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    this.now = options.now ?? Date.now;
    this.filesystemExecutor = options.filesystemExecutor ?? new WorkerFilesystemExecutor();
    this.processExecutor = options.processExecutor ?? new WorkerProcessExecutor();
    this.processSupervisor = options.processSupervisor ?? new ProcessSupervisor({
      maxConcurrent: 16,
      allowedEnvironmentKeys: [
        "DOCKER_CONFIG", "DOCKER_HOST", "GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM", "GIT_NO_REPLACE_OBJECTS", "GIT_TERMINAL_PROMPT", "GIT_OPTIONAL_LOCKS", "HOME"
      ]
    });
    this.serviceInspector = options.serviceInspector ?? new LaunchdServiceInspector(this.processSupervisor);
    this.logInspector = options.logInspector ?? new MacLogInspector(this.processSupervisor);
    this.gitInspector = options.gitInspector ?? new GitStatusInspector(this.processSupervisor);
    this.gitBranchInspector = options.gitBranchInspector ?? new GitBranchListInspector(this.processSupervisor);
    this.gitLogInspector = options.gitLogInspector ?? new GitLogInspectorImpl(this.processSupervisor);
    this.gitDiffInspector = options.gitDiffInspector ?? new GitDiffInspectorImpl(this.processSupervisor);
    this.gitWriteInspector = options.gitWriteInspector ?? new GitWriteInspectorImpl(this.processSupervisor);
    this.packageInspector = options.packageInspector ?? new PackageInspectorImpl();
    this.dockerInspector = options.dockerInspector ?? new DockerInspectorImpl({ supervisor: this.processSupervisor });
    this.appInspector = options.appInspector ?? new AppInventoryInspectorImpl(this.processSupervisor);
    this.appControlInspector = options.appControlInspector ?? new AppControlInspectorImpl(this.appInspector, this.processSupervisor);
    this.uiInspector = options.uiInspector ?? new MacUiInspectorImpl(this.processSupervisor);
    this.uiSnapshotRegistry = options.uiSnapshotRegistry ?? new UiSnapshotRegistry();
    this.taskProfileRegistry = options.taskProfileRegistry ?? new TaskProfileRegistry([]);
    this.taskRunner = options.taskRunner ?? new FailClosedTaskRunner();
    this.privilegedHelperExecutor = options.privilegedHelperExecutor ?? new PrivilegedHelperJobExecutor({ store: options.store });
    this.jobLeaseOwnerId = `broker:${randomUUID()}`;
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
    const resources = [this.filesystemExecutor, this.processExecutor, this.processSupervisor, this.taskRunner];
    this.closePromise = (async () => {
      let firstError: unknown;
      for (const resource of resources) {
        if (typeof resource.close !== "function") continue;
        try { await resource.close.call(resource); }
        catch (error) { firstError ??= error; }
      }
      if (firstError !== undefined) throw firstError;
    })();
    return this.closePromise;
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
    const policy = this.options.policy instanceof PolicyManager ? this.options.policy.current() : this.options.policy;
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
      const targetRef = `path:${metadata.path}`;
      const priorCompletion = this.options.store.auditEventResult(auditRequestId, "completion");
      if (priorCompletion !== undefined) {
        if (priorCompletion === "TEMPORARY_REMOVED" || priorCompletion === "TEMPORARY_ABSENT") absent += 1;
        else skipped += 1;
        continue;
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
      let result: TemporaryWriteCleanupResult;
      try {
        const plan = inspector.planPath(metadata.path, "write");
        if (plan.rootId !== metadata.rootId) throw new BrokerError("POLICY_DENIED", "Write temporary root identity no longer matches");
        result = inspector.cleanupWriteTemporary(plan, metadata.temporaryName);
      } catch (error) {
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
            jobRevision: job.revision,
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
          jobId: job.jobId,
          jobRevision: job.revision,
          rootId: metadata.rootId,
          temporaryName: metadata.temporaryName,
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
    const jobs = this.options.store.restartUnknownProcessJobs(limit);
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
        else unknown += 1;
        continue;
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
  async reconcileRestartedGuestTasks(limit = 100): Promise<{
    inspected: number;
    recovered: number;
    unavailable: number;
    unknown: number;
    skipped: number;
  }> {
    const jobs = this.options.store.restartUnknownGuestJobs(limit);
    if (jobs.length === 0) return { inspected: 0, recovered: 0, unavailable: 0, unknown: 0, skipped: 0 };
    const policy = this.options.policy instanceof PolicyManager ? this.options.policy.current() : this.options.policy;
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
      const tool = policy.tools.get("mac_task_run");
      if (policy.killSwitches.global || policy.killSwitches.process || tool?.implemented !== true || tool.enabled !== true ||
          job.policyVersion !== policy.version || this.options.store.isRevoked("principal", job.ownerPrincipalId) ||
          this.options.store.isRevoked("session", job.ownerSessionId) || this.taskRunner.mechanism !== "virtualization" ||
          typeof this.taskRunner.recoverUnknownTask !== "function") {
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
        const currentPolicy = this.options.policy instanceof PolicyManager ? this.options.policy.current() : this.options.policy;
        const currentTool = currentPolicy.tools.get("mac_task_run");
        if (input.originalRequestId !== metadata.requestId || input.originalNonce !== metadata.nonce ||
            input.originalRequestDigest !== metadata.requestDigest || input.timeoutMs !== metadata.timeoutMs ||
            input.outputCapBytes !== metadata.outputCapBytes ||
            input.guestIdentity.imageSha256 !== metadata.guestIdentity.imageSha256 ||
            input.guestIdentity.runtimeVersion !== metadata.guestIdentity.runtimeVersion) {
          throw new BrokerError("POLICY_DENIED", "Guest status lookup is not bound to the persisted Job");
        }
        if (currentPolicy.killSwitches.global || currentPolicy.killSwitches.process || currentTool?.implemented !== true ||
            currentTool.enabled !== true || job.policyVersion !== currentPolicy.version ||
            this.options.store.isRevoked("principal", job.ownerPrincipalId) || this.options.store.isRevoked("session", job.ownerSessionId)) {
          throw new BrokerError("REVOKED", "Guest status lookup authority is revoked");
        }
      };
      let result;
      try {
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
      if (result.state === "unknown" || result.verification.status !== "verified") {
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
    if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(edgeId)) {
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
    const policy = this.options.policy instanceof PolicyManager ? this.options.policy.current() : this.options.policy;
    let request: BrokerRequest | undefined;
    let admitted = false;
    let authorized = false;
    try {
      if (this.closing) throw new BrokerError("CANCELLED", "Broker is shutting down");
      request = parseBrokerRequest(rawRequest);
      this.authenticate(request, startedAt, policy);
      this.options.store.admitRequest({
        requestId: request.requestId,
        edgeId: request.principal.edgeId,
        nonce: request.nonce,
        nonceExpiresAtMs: startedAt + this.maxRequestAgeMs + this.allowedClockSkewMs,
        principalId: request.principal.principalId,
        sessionId: request.principal.sessionId,
        tool: request.tool,
        policyVersion: request.policyVersion,
        payloadDigest: sha256(canonicalJson(request)),
        mutation: policy.tools.get(request.tool)?.mutation ?? false,
        receivedAtMs: startedAt
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
      if (request.tool === "mac_ui_action") {
        if (!execution.uiAction) throw new BrokerError("EXECUTION_FAILED", "UI action execution plan is unavailable");
        const snapshot = this.uiSnapshotRegistry.resolve(
          execution.uiAction.elementRef,
          request.principal.principalId,
          request.principal.sessionId,
          this.now()
        );
        authorizeTarget(policy, request.principal.principalId, toolPolicy.requiredScopes, {
          kind: "app_window",
          reference: `window:${snapshot.appId}`
        });
        validateSensitiveUiTarget(snapshot.appId, snapshot.windowTitle);
        execution.uiAction.snapshot = snapshot;
      } else {
        authorizeTarget(policy, request.principal.principalId, toolPolicy.requiredScopes, target);
      }
      for (const additionalTarget of execution.additionalTargets ?? []) {
        authorizeTarget(policy, request.principal.principalId, toolPolicy.requiredScopes, additionalTarget);
      }
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
      this.options.store.recordRequestDecision({
        requestId: request.requestId,
        principalId: request.principal.principalId,
        tool: request.tool,
        eventType: "decision",
        decision: "allow",
        resultClass: "AUTHORIZED",
        targetRef: execution.auditTarget ?? `${target.kind}:${target.reference}`,
        policyVersion: policy.version,
        evidence: {},
        timestampMs: startedAt
      });
      authorized = true;
      if (toolPolicy.mutation) {
        if (request.tool === "mac_task_run") {
          const admissionAt = this.now();
          const jobInput = {
            jobId: `job:task-${sha256(canonicalJson({ principalId: request.principal.principalId, requestId: request.requestId })).slice(0, 48)}`,
            ownerPrincipalId: request.principal.principalId,
            ownerSessionId: request.principal.sessionId,
            tool: request.tool,
            targetRef: `${target.kind}:${target.reference}`,
            policyVersion: request.policyVersion,
            payloadDigest: sha256(canonicalJson(request.arguments)),
            idempotencyKey: `task:${request.requestId}`,
            createdAtMs: admissionAt
          } as const;
          const admitted = this.options.store.admitApprovedJobAfterDecision({
            intent: {
              requestId: request.requestId,
              principalId: request.principal.principalId,
              tool: request.tool,
              eventType: "intent",
              decision: "allow",
              resultClass: "INTENT_RECORDED",
              targetRef: execution.auditTarget ?? `${target.kind}:${target.reference}`,
              policyVersion: policy.version,
              evidence: { argumentDigest: sha256(canonicalJson(request.arguments)) },
              timestampMs: admissionAt
            },
            approval: {
              contractVersion: request.contractVersion,
              targetKind: target.kind,
              targetRef: execution.auditTarget ?? `${target.kind}:${target.reference}`,
              payloadDigest: sha256(canonicalJson(request.arguments)),
              approvalClass: requireMutationApprovalClass(toolPolicy.approvalPolicy),
              unattended: false
            },
            job: jobInput
          });
          execution.taskJob = admitted.job;
          execution.taskJobNew = true;
        } else {
          this.options.store.recordRequestIntent({
            requestId: request.requestId,
            principalId: request.principal.principalId,
            tool: request.tool,
            eventType: "intent",
            decision: "allow",
            resultClass: "INTENT_RECORDED",
            targetRef: execution.auditTarget ?? `${target.kind}:${target.reference}`,
            policyVersion: policy.version,
            evidence: {
              argumentDigest: sha256(canonicalJson(request.arguments)),
              ...(request.tool === "mac_write_file_atomic" ? { idempotencyKey: execution.write!.idempotencyKey } : {})
            },
            timestampMs: this.now()
          }, {
            contractVersion: request.contractVersion,
            targetKind: target.kind,
            targetRef: execution.auditTarget ?? `${target.kind}:${target.reference}`,
            payloadDigest: sha256(canonicalJson(request.arguments)),
            approvalClass: requireMutationApprovalClass(toolPolicy.approvalPolicy),
            unattended: false
          });
          if (request.tool === "mac_write_file_atomic") {
            const jobInput = {
              jobId: `job:write-${sha256(canonicalJson({ principalId: request.principal.principalId, idempotencyKey: execution.write!.idempotencyKey })).slice(0, 48)}`,
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
          if (request.tool === "mac_apply_patch") {
            if (!execution.patch || !execution.filesystem) throw new BrokerError("EXECUTION_FAILED", "Filesystem patch execution plan is unavailable");
            const jobInput = {
              jobId: `job:patch-${sha256(canonicalJson({ principalId: request.principal.principalId, requestId: request.requestId })).slice(0, 48)}`,
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
              ownerPrincipalId: request.principal.principalId,
              ownerSessionId: request.principal.sessionId,
              tool: request.tool,
              targetRef: `${target.kind}:${target.reference}`,
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
        else execution.uiActionJob = started;
      }
      const dispatched = await this.dispatch(request, policy, execution, toolPolicy);
      this.ensureActiveAuthority(request, execution.target);
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
        evidence: { outputClass: "bounded_structured", ...dispatched.auditEvidence },
        timestampMs: this.now()
      });
      return result;
    } catch (error) {
      const brokerError = error instanceof BrokerError
        ? error
        : new BrokerError("EXECUTION_FAILED", "Broker request failed");
      if (request && admitted) {
        this.auditFailure(request, brokerError, this.now(), authorized);
      }
      return this.failure(request, brokerError, startedAt);
    }
  }

  async handleForIpc(rawRequest: unknown): Promise<AuthenticatedBrokerResponse | BrokerResult> {
    const response = await this.handle(rawRequest);
    try {
      const request = parseBrokerRequest(rawRequest);
      const key = this.options.edgeAuthenticationKeys.keyByIdentity(
        request.principal.edgeId,
        request.authenticationKeyId
      );
      if (key && verifyRequestAuthentication(request, key)) {
        return signBrokerResponse(request, response, key);
      }
    } catch {
      // Invalid requests receive only an untrusted bounded error response.
    }
    return response;
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
    if (!verifyRequestAuthentication(request, key)) throw new BrokerError("AUTH_INVALID", "Request authentication failed");
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
        const states = runtimeToolStates(policy).map((state) => {
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
                enabled: state.enabled,
                scopes: tool ? [...tool.requiredScopes] : [],
                contract_version: tool?.contractVersion ?? null,
                reason: state.enabled ? "enabled" : (state.disabledReason ?? "disabled")
              };
            }),
            permissions: [],
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
          this.executionControl(request, execution.target, toolPolicy.timeoutMs)
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
          nodes: observed.nodes.map((node) => ({
            element_ref: node.elementRef,
            role: node.role,
            ...(node.label !== undefined ? { label: node.label } : {}),
            enabled: node.enabled,
            focused: node.focused,
            secure: node.secure
          })),
          truncated: observed.truncated
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
              summary: "Docker state was collected through fixed local-only CLI arguments, bounded parsing, and secret-safe field selection",
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
        assertExactArguments(request.arguments, ["proposed_tool", "target", "argument_digest"]);
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
              reason_codes: [error.errorClass], policy_version: policy.version
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
      case "mac_task_run": {
        return this.dispatchTask(request, execution, toolPolicy.timeoutMs, toolPolicy.outputCapBytes);
      }
      case "mac_job_status": {
        if (!execution.job) throw new BrokerError("EXECUTION_FAILED", "Job execution plan is unavailable");
        const tailBytes = (request.arguments.tail_bytes ?? 65_536) as number;
        const output = boundedJobOutput(execution.job, tailBytes);
        const recovery = execution.job.state === "unknown"
          ? this.inspectWritePostcondition(execution.job, policy)
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
            ? { warnings: ["Write postcondition matches, but the job remains UNKNOWN because the actor in the crash window cannot be proven"] }
            : recovery?.postcondition === "mismatch"
              ? { warnings: ["Write postcondition does not match; the job remains UNKNOWN and must not be retried automatically"] }
              : recovery?.postcondition === "unavailable"
                ? { warnings: ["Write postcondition could not be verified; the job remains UNKNOWN"] }
                : {})
        };
      }
      case "mac_job_cancel": {
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
        { snapshot: execution.uiAction.snapshot, action: execution.uiAction.action },
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
        }
      };
      execution.uiActionJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
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
          strategy: "accessibility_reobservation",
          evidence: {
            summary: "The approved Accessibility element was re-resolved before and after one fixed action",
            readback_hash: sha256(canonicalJson(data)),
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
      if (plan.rootId !== metadata.rootId) return unavailableWriteRecovery(this.now());
      const postcondition = inspector.verifyWritePostcondition(plan, metadata.desiredSha256, metadata.bytes);
      return writeRecoveryStatus(postcondition, this.now());
    } catch {
      return unavailableWriteRecovery(this.now());
    }
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
      resolved = await this.taskProfileRegistry.resolve({
        profile: execution.taskRun.profile,
        cwd: execution.taskRun.cwd,
        args: execution.taskRun.args
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
      const taskControl = this.executionControl(
        request,
        execution.target,
        timeoutMs,
        job.jobId,
        [],
        execution.jobLease,
        (snapshot) => persistTaskProcessSnapshot(snapshot, true),
        (snapshot) => persistTaskProcessSnapshot(snapshot, false),
        persistGuestRequest
      );
      const taskResult = validateTaskExecutionResult(await this.taskRunner.run(
        resolved,
        taskControl
      ));
      // A runner may return after cancellation or revocation without observing
      // the control callback. Never publish a success after the Broker lost
      // authority; the outcome is unresolved and must remain inspectable.
      this.ensureActiveAuthority(request, execution.target);
      const rawOutputBytes = Buffer.byteLength(taskResult.stdout, "utf8") + Buffer.byteLength(taskResult.stderr, "utf8");
      const outputBudgetExceeded = taskResult.truncated || rawOutputBytes > resolved.process.outputCapBytes;
      const timeoutBudgetExceeded = taskResult.durationMs > Math.min(timeoutMs, resolved.process.timeoutMs);
      const streamCap = Math.max(1, Math.floor(outputCapBytes / 2));
      const stdout = redactBoundedText(taskResult.stdout, streamCap);
      const stderr = redactBoundedText(taskResult.stderr, streamCap);
      const verificationSummary = taskResult.verification.summary === undefined
        ? undefined
        : redactBoundedText(taskResult.verification.summary, 512).text;
      const finished = !outputBudgetExceeded && !timeoutBudgetExceeded && taskResult.state === "completed" && taskResult.resultClass === "SUCCEEDED" && taskResult.verification.status === "verified";
      const terminalState = finished ? "completed" : timeoutBudgetExceeded || taskResult.state === "timed_out" ? "failed" : taskResult.state === "cancelled" ? "cancelled" : taskResult.state === "unknown" ? "unknown" : "failed";
      const terminalClass = finished ? "success" : terminalState === "cancelled" ? "denied" : terminalState === "unknown" ? "unknown" : timeoutBudgetExceeded || taskResult.state === "timed_out" || outputBudgetExceeded || taskResult.resultClass === "OUTPUT_LIMIT" ? "failed" : taskResult.verification.status === "failed" ? "verification_failed" : "failed";
      execution.taskJob = this.options.store.finishJob(job.jobId, request.principal.principalId, execution.taskJob.revision, {
        state: terminalState,
        resultClass: terminalClass,
        finishedAtMs: this.now(),
        exitCode: taskResult.exitCode,
        stdout: stdout.text,
        stderr: stderr.text
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
        auditEvidence: { jobId: execution.taskJob.jobId, state: execution.taskJob.state, verification: taskResult.verification.status }
      };
    } catch (error) {
      if (!terminalPersisted) {
        try {
          execution.taskJob = this.options.store.finishJob(job.jobId, request.principal.principalId, execution.taskJob?.revision ?? job.revision, {
            state: "unknown",
            resultClass: "unknown",
            finishedAtMs: this.now()
          }, execution.jobLease, this.now());
        } catch {
          // Preserve the original error; the running task has no trusted terminal readback.
        }
      }
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("UNKNOWN_OUTCOME", "Task outcome could not be persisted", true);
    }
  }

  private planExecution(request: BrokerRequest, policy: BrokerPolicy, toolPolicy: ToolPolicy): ExecutionPlan {
    if (request.tool === "mac_job_status" || request.tool === "mac_job_cancel") {
      assertExactArguments(request.arguments, request.tool === "mac_job_status" ? ["job_id", "tail_bytes"] : ["job_id", "reason"]);
      validateJobArguments(request.tool, request.arguments);
      const job = this.options.store.ownedJob(request.arguments.job_id as string, request.principal.principalId);
      if (!job) throw new BrokerError("TARGET_NOT_FOUND", "Broker-owned job was not found");
      return { target: { kind: "job", reference: "owned" }, auditTarget: `job:${job.jobId}`, job };
    }
    if (request.tool === "mac_task_run") {
      assertExactArguments(request.arguments, ["profile", "cwd", "args", "async"]);
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
          args: [...(parsed.args ?? [])]
        }
      };
    }
    if (request.tool === "mac_app_open") {
      assertExactArguments(request.arguments, ["app_id", "document_path", "url"]);
      const appId = request.arguments.app_id;
      const documentPath = request.arguments.document_path;
      const url = request.arguments.url;
      validateAppOpenRequest(appId, documentPath, url);
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
      const appId = request.arguments.app_id;
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
      assertExactArguments(request.arguments, ["element_ref", "action"]);
      const elementRef = request.arguments.element_ref;
      const action = request.arguments.action;
      validateUiActionRequest(elementRef, action);
      return {
        target: { kind: "ui_element", reference: elementRef as string },
        auditTarget: `ui_element:${elementRef as string}`,
        uiAction: { elementRef: elementRef as string, action }
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
      assertExactArguments(request.arguments, ["app_id", "window_hint", "max_nodes"]);
      const appId = request.arguments.app_id;
      const windowHint = request.arguments.window_hint;
      const maxNodes = request.arguments.max_nodes ?? 200;
      validateUiObserveRequest(appId, windowHint, maxNodes as number);
      validateSensitiveUiTarget(appId, windowHint as string | undefined);
      return {
        target: { kind: "app_window", reference: `window:${appId}` },
        auditTarget: `app_window:window:${appId}`,
        uiObserve: {
          appId,
          ...(windowHint !== undefined ? { windowHint: windowHint as string } : {}),
          maxNodes: maxNodes as number
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
        target: { kind: "project", reference: normalizedProjectRoot },
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
        target: { kind: "project", reference: projectRoot },
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
        target: { kind: "project", reference: projectRoot },
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
        target: { kind: "project", reference: projectRoot },
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
        target: { kind: "project", reference: projectRoot },
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
        target: { kind: "project", reference: projectRoot },
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
          authorizeTarget(policy, principalId, tool.requiredScopes, rule.target);
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
          authorizeTarget(policy, principalId, tool.requiredScopes, rule.target);
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
    onGuestRequestAdmitted?: (admission: VirtualizationGuestTaskAdmission) => void
  ) {
    let lastLeaseHeartbeatMs = Number.NEGATIVE_INFINITY;
    return {
      timeoutMs,
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
      ...(onGuestRequestAdmitted === undefined ? {} : { onGuestRequestAdmitted })
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
      const currentPolicy = this.options.policy instanceof PolicyManager ? this.options.policy.current() : this.options.policy;
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
      if (request.tool === "mac_ui_action") {
        const execution = this.planExecution(request, currentPolicy, tool);
        if (!execution.uiAction) throw new Error("UI action plan unavailable");
        const snapshot = this.uiSnapshotRegistry.resolve(
          execution.uiAction.elementRef,
          request.principal.principalId,
          request.principal.sessionId,
          this.now()
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
    authorized: boolean
  ): void {
    try {
      this.options.store.failRequest({
        requestId: request.requestId,
        principalId: request.principal.principalId,
        tool: request.tool,
        eventType: authorized ? "completion" : "decision",
        decision: authorized ? "allow" : "deny",
        resultClass: error.errorClass,
        targetRef: "unresolved",
        policyVersion: request.policyVersion,
        evidence: {},
        timestampMs
      });
    } catch {
      // The original denial remains authoritative. Audit outage is observable separately.
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
  };
  taskRun?: {
    profile: string;
    cwd: string;
    args: readonly string[];
  };
  job?: BrokerJob;
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

function writeJobMetadata(plan: FilesystemPathPlan, write: NonNullable<ExecutionPlan["write"]>): WriteJobMetadata {
  return {
    rootId: plan.rootId,
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

function uiActionDispatchResult(job: BrokerJob, data: UiActionResultData, reused: boolean): DispatchResult {
  if (data.job_id !== job.jobId) throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI action Job identity is inconsistent");
  return {
    data: { ...data },
    verification: {
      required: true,
      status: "verified",
      strategy: "accessibility_reobservation",
      evidence: {
        summary: reused ? "Reused a completed UI action Job readback" : "The approved Accessibility element was re-resolved before and after one fixed action",
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

function parseStoredAppOpenResult(value: string): AppOpenResultData {
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored app launch result is malformed"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored app launch result is malformed");
  }
  const record = parsed as Record<string, unknown>;
  const target = record.target;
  if (typeof record.app_id !== "string" || !/^bundle:[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$/u.test(record.app_id) ||
      (record.state !== "launched" && record.state !== "already_running") || record.process_id !== null || record.verified !== true ||
      typeof record.job_id !== "string" || !/^job:app-open-[a-f0-9]{48}$/u.test(record.job_id) ||
      target === null || typeof target !== "object" || Array.isArray(target)) {
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

function parseStoredAppFocusResult(value: string): AppFocusResultData {
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored app focus result is malformed"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new BrokerError("UNKNOWN_OUTCOME", "Stored app focus result is malformed");
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

function parseStoredUiActionResult(value: string): UiActionResultData {
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI action result is malformed"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) throw new BrokerError("UNKNOWN_OUTCOME", "Stored UI action result is malformed");
  const record = parsed as Record<string, unknown>;
  const reobserved = record.reobserved;
  if (typeof record.element_ref !== "string" || !/^element:[a-f0-9]{48}$/u.test(record.element_ref) ||
      typeof record.action !== "string" || !["press", "select", "increment", "decrement", "show_menu", "focus"].includes(record.action) ||
      record.accepted !== true || typeof record.job_id !== "string" || !/^job:ui-action-[a-f0-9]{48}$/u.test(record.job_id) ||
      reobserved === null || typeof reobserved !== "object" || Array.isArray(reobserved)) {
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

function parseStoredWriteResult(value: string): WriteResultData {
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem write result is malformed"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem write result is malformed");
  }
  const record = parsed as Record<string, unknown>;
  const precondition = record.precondition;
  if (typeof record.path !== "string" || !isAbsolute(record.path) || record.path.length > 4096 ||
      !Number.isSafeInteger(record.bytes_written) || (record.bytes_written as number) < 0 || (record.bytes_written as number) > 1_048_576 ||
      typeof record.sha256 !== "string" || !/^[a-f0-9]{64}$/u.test(record.sha256) || typeof record.created !== "boolean" ||
      precondition === null || typeof precondition !== "object" || Array.isArray(precondition)) {
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

function parseStoredPatchResult(value: string): PatchResultData {
  let parsed: unknown;
  try { parsed = JSON.parse(value) as unknown; } catch { throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem patch result is malformed"); }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem patch result is malformed");
  }
  const record = parsed as Record<string, unknown>;
  const precondition = record.precondition;
  const files = record.files;
  const changedPaths = record.changed_paths;
  if (typeof record.project_root !== "string" || !isAbsolute(record.project_root) || record.project_root.length > 4096 || record.project_root.includes("\0") ||
      (record.result !== "applied" && record.result !== "no_change") || !Array.isArray(changedPaths) || changedPaths.length > 64 ||
      changedPaths.some((path) => !isSafePatchRelativePath(path)) ||
      precondition === null || typeof precondition !== "object" || Array.isArray(precondition) ||
      typeof (precondition as Record<string, unknown>).checked !== "boolean" || typeof (precondition as Record<string, unknown>).matched !== "boolean" ||
      typeof (precondition as Record<string, unknown>).actual_sha256 !== "string" || !/^[a-f0-9]{64}$/u.test((precondition as Record<string, unknown>).actual_sha256 as string) ||
      ((precondition as Record<string, unknown>).expected_sha256 !== null && (typeof (precondition as Record<string, unknown>).expected_sha256 !== "string" || !/^[a-f0-9]{64}$/u.test((precondition as Record<string, unknown>).expected_sha256 as string))) ||
      !Array.isArray(files) || files.length > 64) {
    throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem patch result is malformed");
  }
  const condition = precondition as Record<string, unknown>;
  const parsedFiles = files.map((file) => {
    if (file === null || typeof file !== "object" || Array.isArray(file)) throw new BrokerError("UNKNOWN_OUTCOME", "Stored filesystem patch file is malformed");
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
    result_class: job.resultClass,
    stdout: output.stdout,
    stderr: output.stderr,
    truncated: output.truncated,
    ...(recovery ? { recovery } : {})
  };
}

function normalizePolicyQueryTarget(value: unknown): NormalizedTarget {
  if (value === undefined) return { kind: "host", reference: "broker" };
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("PRECONDITION_FAILED", "target must be an object");
  }
  const target = value as Record<string, unknown>;
  assertExactArguments(target, ["kind", "reference"]);
  const allowedKinds = new Set<TargetKind>(["host", "path", "project", "process", "job", "task_profile", "app_set", "app", "app_window", "ui_element", "service", "log_source", "package", "power"]);
  if (
    typeof target.kind !== "string" || !allowedKinds.has(target.kind as TargetKind) ||
    typeof target.reference !== "string" || !/^[A-Za-z0-9._:/-]{1,4096}$/u.test(target.reference)
  ) {
    throw new BrokerError("PRECONDITION_FAILED", "target kind and reference must be strings");
  }
  return { kind: target.kind as TargetKind, reference: target.reference };
}
