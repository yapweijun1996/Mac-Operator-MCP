import {
  BrokerError,
  canonicalJson,
  sha256,
  signBrokerResponse,
  verifyRequestAuthentication,
  type AuthenticatedBrokerResponse,
  type BrokerFailure,
  type BrokerRequest,
  type BrokerResult
} from "@mac-operator/contracts";
import { isAbsolute } from "node:path";
import type { BrokerJob, BrokerStore } from "./persistence.js";
import { EdgeKeyring, keyIdentity } from "./edge-keyring.js";
import {
  authorizePrincipalProjection,
  authorizeTarget,
  authorizeTool,
  runtimeToolStates,
  type BrokerPolicy,
  type NormalizedTarget,
  type TargetKind,
  type ToolPolicy
} from "./policy.js";
import { PolicyManager } from "./policy-loader.js";
import { parseBrokerRequest } from "./request-validator.js";
import { FilesystemInspector, normalizeProjectTypes, type FilesystemPathPlan } from "./filesystem-inspector.js";
import { WorkerFilesystemExecutor, type FilesystemExecutor } from "./filesystem-executor.js";
import { inspectSystem } from "./system-inspector.js";
import { WorkerProcessExecutor, type ProcessExecutor } from "./process-executor.js";
import { assertContentDoesNotContainSecrets } from "./secret-policy.js";

export interface BrokerOptions {
  store: BrokerStore;
  policy: BrokerPolicy | PolicyManager;
  edgeAuthenticationKeys: EdgeKeyring;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
  filesystemExecutor?: FilesystemExecutor;
  processExecutor?: ProcessExecutor;
}

export class Broker {
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;
  private readonly filesystemExecutor: FilesystemExecutor;
  private readonly processExecutor: ProcessExecutor;

  constructor(private readonly options: BrokerOptions) {
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? 60_000;
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    this.now = options.now ?? Date.now;
    this.filesystemExecutor = options.filesystemExecutor ?? new WorkerFilesystemExecutor();
    this.processExecutor = options.processExecutor ?? new WorkerProcessExecutor();
  }

  async handle(rawRequest: unknown): Promise<BrokerResult> {
    const startedAt = this.now();
    const policy = this.options.policy instanceof PolicyManager ? this.options.policy.current() : this.options.policy;
    let request: BrokerRequest | undefined;
    let admitted = false;
    let authorized = false;
    try {
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
      authorizeTarget(policy, request.principal.principalId, toolPolicy.requiredScopes, target);
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
            createdAtMs: this.now()
          } as const;
          const created = this.options.store.createJob(jobInput);
          execution.writeJob = created.job;
          execution.writeJobNew = !created.reused;
          this.options.store.linkRequestJob(request.requestId, created.job.jobId, this.now());
        }
      }
      this.options.store.markRequestRunning(request.requestId, this.now());
      if (execution.writeJob && execution.writeJobNew && execution.writeJob.state === "queued") {
        execution.writeJob = this.options.store.startJob(
          execution.writeJob.jobId,
          request.principal.principalId,
          execution.writeJob.revision,
          this.now()
        );
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
                reason: state.enabled ? "enabled" : (state.disabledReason ?? "disabled")
              };
            }),
            permissions: [],
            version: "0.1.0"
          },
          verification: { required: false, status: "not_required", strategy: "capability_state_result_validation" }
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
      case "mac_job_status": {
        if (!execution.job) throw new BrokerError("EXECUTION_FAILED", "Job execution plan is unavailable");
        const tailBytes = (request.arguments.tail_bytes ?? 65_536) as number;
        const output = boundedJobOutput(execution.job, tailBytes);
        return {
          data: jobStatusData(execution.job, output),
          verification: { required: false, status: "verified", strategy: "job_result_validation" },
          truncated: output.truncated,
          auditTarget: `job:${execution.job.jobId}`,
          auditEvidence: { jobState: execution.job.state, jobRevision: execution.job.revision }
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
        this.executionControl(request, execution.target, timeoutMs, job.jobId)
      );
      if (workerResult.operation !== "write") throw new BrokerError("EXECUTION_FAILED", "Filesystem worker returned the wrong result type");
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
      });
      return writeDispatchResult(execution.writeJob, data, false);
    } catch (error) {
      const brokerError = error instanceof BrokerError ? error : new BrokerError("EXECUTION_FAILED", "Filesystem write job failed");
      try {
        execution.writeJob = this.options.store.finishJob(job.jobId, request.principal.principalId, job.revision, {
          state: "unknown",
          resultClass: "unknown",
          finishedAtMs: this.now()
        });
      } catch {
        // Preserve the original error; a running job without a terminal readback is unresolved.
      }
      throw brokerError;
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
        idempotencyKey: request.arguments.idempotency_key as string
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

  private executionControl(
    request: BrokerRequest,
    target: NormalizedTarget,
    timeoutMs: number,
    jobId?: string,
    additionalTargets: readonly NormalizedTarget[] = []
  ) {
    return {
      timeoutMs,
      shouldCancel: () => {
        try {
          this.ensureActiveAuthority(request, target, additionalTargets);
          if (jobId && this.options.store.ownedJob(jobId, request.principal.principalId)?.cancelRequested) return true;
          return false;
        } catch {
          return true;
        }
      }
    };
  }

  private ensureActiveAuthority(
    request: BrokerRequest,
    target: NormalizedTarget,
    additionalTargets: readonly NormalizedTarget[] = []
  ): void {
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
      for (const activeTarget of [target, ...additionalTargets]) {
        authorizeTarget(currentPolicy, request.principal.principalId, tool.requiredScopes, activeTarget);
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
  job?: BrokerJob;
  write?: {
    content: Buffer;
    expectedSha256: string | undefined;
    createOnly: boolean;
    idempotencyKey: string;
  };
  writeJob?: BrokerJob;
  writeJobNew?: boolean;
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

function executionTarget(toolPolicy: ToolPolicy): NormalizedTarget {
  switch (toolPolicy.targetType) {
    case "broker":
    case "policy_query":
      return { kind: "host", reference: "broker" };
    case "path":
      throw new BrokerError("PRECONDITION_FAILED", "Filesystem target requires descriptor-backed planning");
    case "filesystem_roots":
      throw new BrokerError("PRECONDITION_FAILED", "Filesystem roots require descriptor-backed planning");
    case "process":
      return { kind: "process", reference: "all" };
    case "job":
      throw new BrokerError("PRECONDITION_FAILED", "Job target requires Broker-owned job planning");
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

function jobStatusData(job: BrokerJob, output: { stdout: string; stderr: string; truncated: boolean }) {
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
    truncated: output.truncated
  };
}

function normalizePolicyQueryTarget(value: unknown): NormalizedTarget {
  if (value === undefined) return { kind: "host", reference: "broker" };
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("PRECONDITION_FAILED", "target must be an object");
  }
  const target = value as Record<string, unknown>;
  assertExactArguments(target, ["kind", "reference"]);
  const allowedKinds = new Set<TargetKind>(["host", "path", "project", "process", "job", "task_profile", "app", "app_window", "ui_element", "service", "package", "power"]);
  if (
    typeof target.kind !== "string" || !allowedKinds.has(target.kind as TargetKind) ||
    typeof target.reference !== "string" || !/^[A-Za-z0-9._:/-]{1,4096}$/u.test(target.reference)
  ) {
    throw new BrokerError("PRECONDITION_FAILED", "target kind and reference must be strings");
  }
  return { kind: target.kind as TargetKind, reference: target.reference };
}
