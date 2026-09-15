import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmod } from "node:fs/promises";
import { connect, createServer, type Server, type Socket } from "node:net";
import { isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, CONTRACT_VERSION, parseJsonUtf8Strict, PROTOCOL_VERSION, sha256, type ErrorClass } from "@mac-operator/contracts";
import { MacOsNativePeerIpcServer, type NativePeerPolicy } from "./native-peer-ipc-server.js";
import { captureSocketPathIdentity, detachOwnedSocket, removeDetachedSocket, removeStaleSocket, validateSocketParent, type SocketPathIdentity } from "./ipc-server.js";
import { privilegedHelperPayloadTarget, validatePrivilegedHelperPayload, type ApprovalRecord, type BrokerJob, type BrokerStore, type PrivilegedHelperPayload, type RequestRecord } from "./persistence.js";
import { redactLogText } from "./secret-policy.js";
import { isPlainDataRecord } from "./plain-record.js";

export type { PrivilegedHelperPayload } from "./persistence.js";

const HELPER_COMMAND_DOMAIN = "mac-operator-privileged-helper-command-v0.1\0";
const HELPER_RESPONSE_DOMAIN = "mac-operator-privileged-helper-response-v0.1\0";
const HELPER_STATUS_REQUEST_DOMAIN = "mac-operator-privileged-helper-status-request-v0.1\0";
const HELPER_STATUS_RESPONSE_DOMAIN = "mac-operator-privileged-helper-status-response-v0.1\0";
const MAX_COMMAND_AGE_MS = 600_000;
const MAX_COMMAND_BYTES = 256 * 1024;
const MAX_RESPONSE_BYTES = 1 * 1024 * 1024;
const MAX_WARNINGS = 32;
const MAX_EVIDENCE_FIELDS = 32;
const NONCE_PATTERN = /^[A-Za-z0-9._:@/-]{16,128}$/u;
const POLICY_VERSION_PATTERN = /^policy-[A-Za-z0-9._:-]{1,120}$/u;
const APPROVAL_ID_PATTERN = /^approval:[A-Za-z0-9._:-]{1,240}$/u;
const INTENT_ID_PATTERN = /^intent:[A-Za-z0-9._:-]{1,240}$/u;
const SERVICE_TARGET_PATTERN = /^service:[A-Za-z0-9._:@/+\-]{1,255}$/u;
const PACKAGE_TARGET_PATTERN = /^package:[A-Za-z0-9._:@/+\-]{1,255}$/u;

export type PrivilegedHelperOperation = "service_control" | "package_install" | "power";
export type PrivilegedHelperState = "accepted" | "completed" | "failed" | "cancelled" | "unknown";
export type PrivilegedHelperResultClass =
  | "SUCCEEDED"
  | "EXECUTION_FAILED"
  | "CANCELLED"
  | "TIMEOUT"
  | "VERIFICATION_FAILED"
  | "UNKNOWN_OUTCOME";

/**
 * Broker-generated command envelope. It intentionally carries a digest of
 * Broker-validated arguments, never executable paths, shell text, or raw
 * privileged arguments.
 */
export interface UnsignedPrivilegedHelperCommand {
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  commandId: string;
  requestId: string;
  nonce: string;
  nonceExpiresAtMs: number;
  timestampMs: number;
  expiresAtMs: number;
  operation: PrivilegedHelperOperation;
  targetRef: string;
  payload: PrivilegedHelperPayload;
  payloadDigest: string;
  policyVersion: string;
  approvalId: string;
  intentId: string;
}

export interface SignedPrivilegedHelperCommand extends UnsignedPrivilegedHelperCommand {
  authenticationProof: string;
}

export interface PrivilegedHelperExecutionControl {
  timeoutMs: number;
  shouldCancel: () => boolean;
}

export interface PrivilegedHelperVerification {
  status: "verified" | "failed" | "unknown";
  strategy: "allowlisted_postcondition";
  summary?: string;
  readbackHash?: string;
}

export interface PrivilegedHelperExecutionResult {
  operation: PrivilegedHelperOperation;
  targetRef: string;
  state: PrivilegedHelperState;
  resultClass: PrivilegedHelperResultClass;
  evidence: Readonly<Record<string, string | number | boolean | null>>;
  warnings: readonly string[];
  truncated: boolean;
  verification: PrivilegedHelperVerification;
}

export type PrivilegedHelperSuccessResponse = {
  ok: true;
  commandId: string;
  requestId: string;
  result: PrivilegedHelperExecutionResult;
  responseProof: string;
};

export type PrivilegedHelperFailureResponse = {
  ok: false;
  commandId: string;
  requestId: string;
  resultClass: ErrorClass;
  error: { message: string; retryable: boolean };
  responseProof: string;
};

export type PrivilegedHelperResponse = PrivilegedHelperSuccessResponse | PrivilegedHelperFailureResponse;

export interface PrivilegedHelperStatusReadback {
  component: "mac-operator-privileged-helper";
  state: "running";
  runtimeState: "running";
  nativeTransportRequired: true;
  adapterAvailable: false;
  helperSocketPath: string;
  brokerSocketPath: string;
  brokerPeerUid: number;
  brokerPeerGid: number | null;
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  enabledCapabilities: readonly [];
}

export interface UnsignedPrivilegedHelperStatusRequest {
  protocolVersion: typeof PROTOCOL_VERSION;
  contractVersion: typeof CONTRACT_VERSION;
  requestId: string;
  nonce: string;
  timestampMs: number;
  expiresAtMs: number;
  kind: "status";
}

export interface SignedPrivilegedHelperStatusRequest extends UnsignedPrivilegedHelperStatusRequest {
  authenticationProof: string;
}

export type PrivilegedHelperStatusSuccessResponse = {
  ok: true;
  kind: "status";
  requestId: string;
  status: PrivilegedHelperStatusReadback;
  responseProof: string;
};

export type PrivilegedHelperStatusFailureResponse = {
  ok: false;
  kind: "status";
  requestId: string;
  resultClass: ErrorClass;
  error: { message: string; retryable: boolean };
  responseProof: string;
};

export type PrivilegedHelperStatusResponse = PrivilegedHelperStatusSuccessResponse | PrivilegedHelperStatusFailureResponse;

export interface PrivilegedHelperReplayGuard {
  admit(command: Pick<UnsignedPrivilegedHelperCommand, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void;
}

/** A bounded test/local fallback. Production helper wiring should use BrokerStore. */
export class InMemoryPrivilegedHelperReplayGuard implements PrivilegedHelperReplayGuard {
  private readonly accepted = new Map<string, number>();

  constructor(private readonly maxEntries = 4096) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1 || maxEntries > 65_536) {
      throw new Error("Privileged helper replay guard capacity is invalid");
    }
  }

  admit(command: Pick<UnsignedPrivilegedHelperCommand, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void {
    validateReplayInput(command);
    for (const [key, expiry] of this.accepted) {
      if (expiry < command.timestampMs) this.accepted.delete(key);
    }
    const nonceKey = `nonce:${command.nonce}`;
    const requestKey = `request:${command.requestId}`;
    if (this.accepted.has(nonceKey) || this.accepted.has(requestKey)) {
      throw new BrokerError("REPLAY_DENIED", "Privileged helper command nonce or request ID was already accepted");
    }
    if (this.accepted.size + 2 > this.maxEntries) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Privileged helper replay guard is at capacity");
    }
    this.accepted.set(nonceKey, command.nonceExpiresAtMs);
    this.accepted.set(requestKey, command.nonceExpiresAtMs);
  }
}

/** Adapter for the durable BrokerStore nonce ledger. */
export class BrokerStorePrivilegedHelperReplayGuard implements PrivilegedHelperReplayGuard {
  constructor(private readonly store: BrokerStore) {}

  admit(command: Pick<UnsignedPrivilegedHelperCommand, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void {
    validateReplayInput(command);
    this.store.admitPrivilegedHelperCommand({
      requestId: command.requestId,
      nonce: command.nonce,
      acceptedAtMs: command.timestampMs,
      expiresAtMs: command.nonceExpiresAtMs
    });
  }
}

const PRIVILEGED_TOOL_BINDINGS = {
  mac_priv_service_control: { operation: "service_control", targetKind: "service" },
  mac_priv_package_install: { operation: "package_install", targetKind: "package" },
  mac_priv_power: { operation: "power", targetKind: "host" }
} as const satisfies Readonly<Record<string, { operation: PrivilegedHelperOperation; targetKind: string }>>;

/**
 * Broker-owned authority callback for the helper IPC server. The helper must
 * call this before dispatch, while polling cancellation, and before response
 * publication. It reconstructs the original request and Job through the
 * approval binding because the signed helper command intentionally omits
 * principal, session, and raw request identifiers.
 */
export function assertPrivilegedHelperCommandAuthority(
  store: BrokerStore,
  command: UnsignedPrivilegedHelperCommand,
  nowMs = Date.now()
): void {
  if (!store) throw new BrokerError("AUDIT_UNAVAILABLE", "Privileged helper authority store is unavailable");
  validateUnsignedPrivilegedHelperCommand(command);
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper authority clock is invalid");
  }
  if (store.isSwitchDisabled("global") || store.isSwitchDisabled("mutations") || store.isSwitchDisabled("privileged")) {
    throw new BrokerError("REVOKED", "Privileged helper dispatch is disabled by a Broker kill switch");
  }

  const approval = store.approvalRecord(command.approvalId);
  if (!approval || approval.revokedAtMs !== null || approval.expiresAtMs <= nowMs || approval.issuedAtMs > nowMs ||
      approval.approvalClass !== "explicit_privileged_policy" || approval.unattended || approval.usedCount !== 1 ||
      approval.lastRequestId === null) {
    throw new BrokerError("POLICY_DENIED", "Privileged helper approval is not active");
  }
  const request = store.requestRecord(approval.lastRequestId);
  const job = request?.jobId === null || request?.jobId === undefined
    ? undefined
    : store.ownedJob(request.jobId, request.principalId);
  const binding = request === undefined ? undefined : PRIVILEGED_TOOL_BINDINGS[request.tool as keyof typeof PRIVILEGED_TOOL_BINDINGS];
  if (!request || !job || !binding || request.approvalId !== approval.approvalId || request.state !== "RUNNING" ||
      request.mutation !== true || request.policyVersion !== command.policyVersion ||
      job.state !== "running" || job.cancelRequested || job.ownerSessionId !== request.sessionId ||
      job.ownerEdgeId !== request.edgeId || job.tool !== request.tool || job.policyVersion !== request.policyVersion ||
      job.targetRef !== command.targetRef || job.payloadDigest !== command.payloadDigest ||
      binding.operation !== command.operation || binding.targetKind !== approval.targetKind ||
      approval.tool !== request.tool || approval.requestingPrincipalId !== request.principalId ||
      approval.targetRef !== job.targetRef || approval.payloadDigest !== job.payloadDigest ||
      approval.policyVersion !== request.policyVersion || approval.lastRequestId !== request.requestId) {
    if (job?.cancelRequested) throw new BrokerError("CANCELLED", "Privileged helper Job cancellation was requested");
    throw new BrokerError("CONFLICT", "Privileged helper command is not bound to an active Broker Job", true);
  }
  if (store.isRevoked("edge", request.edgeId) ||
      (job.ownerEdgeKeyId !== null && store.isRevoked("edge_key", job.ownerEdgeKeyId)) ||
      store.isRevoked("principal", request.principalId) || store.isRevoked("session", request.sessionId)) {
    throw new BrokerError("REVOKED", "Privileged helper dispatch identity has been revoked");
  }

  const identityDigest = sha256(canonicalJson({
    requestId: request.requestId,
    jobId: job.jobId,
    operation: command.operation,
    targetRef: job.targetRef,
    policyVersion: request.policyVersion
  }));
  const intentDigest = sha256(canonicalJson({
    requestId: request.requestId,
    jobId: job.jobId,
    targetRef: job.targetRef,
    approvalId: approval.approvalId
  }));
  if (command.commandId !== `priv-command:${identityDigest.slice(0, 48)}` ||
      command.requestId !== `request:${identityDigest.slice(0, 48)}` ||
      command.intentId !== `intent:${intentDigest.slice(0, 48)}`) {
    throw new BrokerError("CONFLICT", "Privileged helper command identity proof is mismatched", true);
  }
}

export interface PrivilegedHelperCommandIssueInput {
  requestId: string;
  principalId: string;
  sessionId: string;
  jobId: string;
  /** Optional testable clock value. Production callers should use the factory clock. */
  nowMs?: number;
  /** Optional assertion that the request maps to this exact helper operation. */
  operation?: PrivilegedHelperOperation;
}

export interface BrokerPrivilegedHelperCommandFactoryOptions {
  store: BrokerStore;
  authenticationKey: Buffer;
  /** Optional dynamic check used for key-specific revocation. */
  keyRevocationCheck?: () => boolean;
  /** Optional dynamic check for key validity and active configuration identity. */
  keyAuthorityCheck?: () => void;
  /** Required final Broker authority gate; it may include dynamic kill-switch state. */
  authorizeCommand: (command: UnsignedPrivilegedHelperCommand) => void;
  now?: () => number;
  maxLifetimeMs?: number;
}

/**
 * Converts one persisted, approved, running mutation Job into a signed helper
 * envelope. This is intentionally separate from the helper IPC server: the
 * Broker remains the authority that proves request, approval, intent, Job,
 * principal, session, target, and switch identity before a command is signed.
 */
export class BrokerPrivilegedHelperCommandFactory {
  private readonly now: () => number;
  private readonly maxLifetimeMs: number;
  private readonly authenticationKey: Buffer;
  private readonly options: Omit<BrokerPrivilegedHelperCommandFactoryOptions, "authenticationKey">;
  private disposed = false;

  constructor(options: BrokerPrivilegedHelperCommandFactoryOptions) {
    if (!options.store) throw new Error("Privileged helper command factory requires a BrokerStore");
    if (options.authenticationKey.byteLength < 32) throw new Error("Privileged helper key must contain at least 32 bytes");
    if (typeof options.authorizeCommand !== "function") throw new Error("Privileged helper authority check is required");
    const { authenticationKey, ...safeOptions } = options;
    this.options = safeOptions;
    this.authenticationKey = Buffer.from(authenticationKey);
    this.now = options.now ?? Date.now;
    this.maxLifetimeMs = options.maxLifetimeMs ?? 30_000;
    if (!Number.isSafeInteger(this.maxLifetimeMs) || this.maxLifetimeMs < 1 || this.maxLifetimeMs > MAX_COMMAND_AGE_MS) {
      throw new Error("Privileged helper command lifetime is invalid");
    }
  }

  issue(input: PrivilegedHelperCommandIssueInput): SignedPrivilegedHelperCommand {
    if (this.disposed) throw new BrokerError("CANCELLED", "Privileged helper command factory is disposed");
    const nowMs = input.nowMs ?? this.now();
    this.options.keyAuthorityCheck?.();
    if (this.options.keyRevocationCheck?.()) {
      throw new BrokerError("REVOKED", "Privileged helper key has been revoked");
    }
    if (!Number.isSafeInteger(nowMs) || nowMs < 0 ||
        !/^[A-Za-z0-9._:@/+-]{1,128}$/u.test(input.requestId) ||
        !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.principalId) ||
        !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(input.sessionId) ||
        !/^job:[A-Za-z0-9._-]{1,240}$/u.test(input.jobId)) {
      throw new BrokerError("PRECONDITION_FAILED", "Privileged helper command issue identity is malformed");
    }

    const request = this.options.store.requestRecord(input.requestId);
    if (!request) throw new BrokerError("TARGET_NOT_FOUND", "Privileged helper request record was not found");
    const job = this.options.store.ownedJob(input.jobId, input.principalId);
    if (!job) throw new BrokerError("TARGET_NOT_FOUND", "Privileged helper Job was not found");
    const binding = PRIVILEGED_TOOL_BINDINGS[request.tool as keyof typeof PRIVILEGED_TOOL_BINDINGS];
    if (!binding) throw new BrokerError("UNSUPPORTED_CAPABILITY", "Request tool is not an allowlisted privileged operation");
    if (input.operation !== undefined && input.operation !== binding.operation) {
      throw new BrokerError("PRECONDITION_FAILED", "Requested helper operation does not match the Broker tool");
    }
    const payload = job.privilegedPayload;
    if (payload === undefined || payload.operation !== binding.operation || privilegedHelperPayloadTarget(payload) !== job.targetRef ||
        sha256(canonicalJson(payload)) !== job.payloadDigest) {
      throw new BrokerError("PRECONDITION_FAILED", "Privileged helper Job payload descriptor is missing or mismatched");
    }

    this.assertRunningIdentity(request, job, input, binding.operation);
    if (this.options.store.isSwitchDisabled("global") ||
        this.options.store.isSwitchDisabled("mutations") ||
        this.options.store.isSwitchDisabled("privileged")) {
      throw new BrokerError("REVOKED", "Privileged helper dispatch is disabled by a Broker kill switch");
    }
    if (this.options.store.isRevoked("principal", request.principalId) ||
        this.options.store.isRevoked("session", request.sessionId)) {
      throw new BrokerError("REVOKED", "Privileged helper dispatch identity has been revoked");
    }

    const approval = this.requireApproval(request, binding, job, nowMs);
    const expiresAtMs = Math.min(nowMs + this.maxLifetimeMs, approval.expiresAtMs);
    if (!Number.isSafeInteger(expiresAtMs) || expiresAtMs <= nowMs) {
      throw new BrokerError("AUTH_EXPIRED", "Privileged helper approval does not leave an executable lifetime");
    }
    const identityDigest = sha256(canonicalJson({
      requestId: request.requestId,
      jobId: job.jobId,
      operation: binding.operation,
      targetRef: job.targetRef,
      policyVersion: request.policyVersion
    }));
    const intentDigest = sha256(canonicalJson({
      requestId: request.requestId,
      jobId: job.jobId,
      targetRef: job.targetRef,
      approvalId: approval.approvalId
    }));
    const unsigned: UnsignedPrivilegedHelperCommand = {
      protocolVersion: PROTOCOL_VERSION,
      contractVersion: approval.contractVersion as typeof CONTRACT_VERSION,
      commandId: `priv-command:${identityDigest.slice(0, 48)}`,
      requestId: `request:${identityDigest.slice(0, 48)}`,
      nonce: `helper-nonce:${randomBytes(24).toString("hex")}`,
      nonceExpiresAtMs: expiresAtMs,
      timestampMs: nowMs,
      expiresAtMs,
      operation: binding.operation,
      targetRef: job.targetRef,
      payload,
      payloadDigest: job.payloadDigest,
      policyVersion: request.policyVersion,
      approvalId: approval.approvalId,
      intentId: `intent:${intentDigest.slice(0, 48)}`
    };
    validateUnsignedPrivilegedHelperCommand(unsigned);
    this.options.authorizeCommand(unsigned);
    return signPrivilegedHelperCommand(unsigned, this.authenticationKey);
  }

  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.authenticationKey.fill(0);
  }

  private assertRunningIdentity(
    request: RequestRecord,
    job: BrokerJob,
    input: PrivilegedHelperCommandIssueInput,
    operation: PrivilegedHelperOperation
  ): void {
    if (request.principalId !== input.principalId || request.sessionId !== input.sessionId ||
        request.mutation !== true || request.state !== "RUNNING" || request.jobId !== job.jobId ||
        request.targetRef === null || request.targetRef !== job.targetRef ||
        request.tool !== job.tool || request.policyVersion !== job.policyVersion ||
        job.ownerSessionId !== input.sessionId ||
        job.state !== "running" || job.cancelRequested ||
        job.tool !== `mac_priv_${operation === "service_control" ? "service_control" : operation === "package_install" ? "package_install" : "power"}` ||
        !validTarget(operation, job.targetRef)) {
      throw new BrokerError("CONFLICT", "Privileged helper request and running Job identity do not match");
    }
    // Request.payloadDigest authenticates the complete Edge envelope. The Job
    // and approval payloadDigest bind only the normalized privileged arguments;
    // both domains are checked independently and must not be compared.
  }

  private requireApproval(
    request: RequestRecord,
    binding: { operation: PrivilegedHelperOperation; targetKind: string },
    job: BrokerJob,
    nowMs: number
  ): ApprovalRecord {
    if (!request.approvalId) throw new BrokerError("POLICY_DENIED", "Privileged helper request has no approval binding");
    const approval = this.options.store.approvalRecord(request.approvalId);
    if (!approval || approval.revokedAtMs !== null || approval.expiresAtMs <= nowMs || approval.issuedAtMs > nowMs ||
        approval.approvalClass !== "explicit_privileged_policy" || approval.unattended ||
        approval.usedCount !== 1 || approval.lastRequestId !== request.requestId ||
        approval.requestingPrincipalId !== request.principalId || approval.tool !== request.tool ||
        approval.targetKind !== binding.targetKind || approval.targetRef !== job.targetRef ||
        approval.payloadDigest !== job.payloadDigest || approval.policyVersion !== request.policyVersion) {
      throw new BrokerError("POLICY_DENIED", "Privileged helper approval is missing, expired, revoked, or mismatched");
    }
    return approval;
  }
}

export interface PrivilegedHelperAdapter {
  readonly available: boolean;
  execute(command: UnsignedPrivilegedHelperCommand, control: PrivilegedHelperExecutionControl): Promise<PrivilegedHelperExecutionResult>;
}

/** Default helper adapter. No privileged operation is available implicitly. */
export class FailClosedPrivilegedHelper implements PrivilegedHelperAdapter {
  readonly available = false;

  async execute(_command: UnsignedPrivilegedHelperCommand, _control: PrivilegedHelperExecutionControl): Promise<PrivilegedHelperExecutionResult> {
    throw new BrokerError("PRIVILEGE_DENIED", "Privileged helper operation is not enabled");
  }
}

/**
 * Explicit operation dispatch for a future signed helper implementation.
 * The handlers receive the already validated envelope and cannot receive raw
 * tool arguments or an executable command line through this interface.
 */
export class AllowlistedPrivilegedHelper implements PrivilegedHelperAdapter {
  readonly available: boolean;

  constructor(private readonly handlers: Readonly<{
    service_control?: (command: UnsignedPrivilegedHelperCommand, control: PrivilegedHelperExecutionControl) => Promise<PrivilegedHelperExecutionResult>;
    package_install?: (command: UnsignedPrivilegedHelperCommand, control: PrivilegedHelperExecutionControl) => Promise<PrivilegedHelperExecutionResult>;
    power?: (command: UnsignedPrivilegedHelperCommand, control: PrivilegedHelperExecutionControl) => Promise<PrivilegedHelperExecutionResult>;
  }>) {
    const allowed = new Set(["service_control", "package_install", "power"]);
    if (Object.keys(handlers).some((key) => !allowed.has(key))) {
      throw new Error("Privileged helper handler map contains an unsupported operation");
    }
    this.available = Object.keys(handlers).some((key) => typeof handlers[key as keyof typeof handlers] === "function");
  }

  async execute(command: UnsignedPrivilegedHelperCommand, control: PrivilegedHelperExecutionControl): Promise<PrivilegedHelperExecutionResult> {
    const handler = this.handlers[command.operation];
    if (!handler) throw new BrokerError("PRIVILEGE_DENIED", "Privileged helper operation is not allowlisted");
    return validatePrivilegedHelperExecutionResult(await handler(command, control), command);
  }
}

export interface PrivilegedHelperIpcServerOptions {
  socketPath: string;
  authenticationKey: Buffer;
  replayGuard: PrivilegedHelperReplayGuard;
  adapter: PrivilegedHelperAdapter;
  /** Broker-owned kill-switch/revocation check; absence is unsafe. */
  authorizeCommand: (command: UnsignedPrivilegedHelperCommand) => void;
  /** Optional dynamic helper-key validity and active-configuration check. */
  keyAuthorityCheck?: () => void;
  /** Host-only authenticated status source; never exposed as an MCP operation. */
  readStatus?: () => PrivilegedHelperStatusReadback;
  /** Final Broker/helper authority gate for status requests. */
  authorizeStatus?: () => void;
  peerCredentialVerifier?: { verify(socket: Socket): unknown };
  peerPolicy?: NativePeerPolicy;
  maxRequestBytes?: number;
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
  onError?: (error: unknown) => void;
}

/**
 * Separately authenticated helper channel. OS peer authorization happens
 * before parsing; the HMAC command and durable nonce admission happen before
 * dispatch. It is not registered with the MCP Edge.
 */
export class PrivilegedHelperIpcServer {
  private server: Server | undefined;
  private nativeTransport: MacOsNativePeerIpcServer | undefined;
  private socketIdentity: SocketPathIdentity | undefined;
  private readonly sockets = new Set<Socket>();
  private readonly authenticationKey: Buffer;
  private readonly maxRequestBytes: number;
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;

  constructor(private readonly options: PrivilegedHelperIpcServerOptions) {
    if (!options.peerCredentialVerifier && !options.peerPolicy) {
      throw new Error("Privileged helper IPC requires a peer verifier or native peer policy");
    }
    if (options.authenticationKey.byteLength < 32) throw new Error("Privileged helper key must contain at least 32 bytes");
    this.authenticationKey = Buffer.from(options.authenticationKey);
    if (!options.replayGuard) throw new Error("Privileged helper replay guard is required");
    if (typeof options.authorizeCommand !== "function") throw new Error("Privileged helper authority check is required");
    this.maxRequestBytes = options.maxRequestBytes ?? MAX_COMMAND_BYTES;
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? MAX_COMMAND_AGE_MS;
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    this.now = options.now ?? Date.now;
    if (!Number.isSafeInteger(this.maxRequestBytes) || this.maxRequestBytes < 256 || this.maxRequestBytes > MAX_COMMAND_BYTES * 4 ||
        !Number.isSafeInteger(this.maxRequestAgeMs) || this.maxRequestAgeMs < 1 || this.maxRequestAgeMs > MAX_COMMAND_AGE_MS ||
        !Number.isSafeInteger(this.allowedClockSkewMs) || this.allowedClockSkewMs < 0 || this.allowedClockSkewMs > 60_000) {
      throw new Error("Privileged helper IPC limits are invalid");
    }
  }

  async listen(): Promise<void> {
    if (this.server || this.nativeTransport) throw new Error("Privileged helper IPC server is already running");
    if (this.options.peerPolicy) {
      this.nativeTransport = new MacOsNativePeerIpcServer({
        socketPath: this.options.socketPath,
        peerPolicy: this.options.peerPolicy,
        ...(this.options.onError === undefined ? {} : { onError: this.options.onError }),
        onSocket: (socket) => this.handleAuthenticatedSocket(socket)
      });
      try {
        await this.nativeTransport.listen();
      } catch (error) {
        this.nativeTransport = undefined;
        throw error;
      }
      return;
    }
    await validateSocketParent(this.options.socketPath);
    await removeStaleSocket(this.options.socketPath);
    this.server = createServer((socket) => {
      this.sockets.add(socket);
      socket.once("close", () => this.sockets.delete(socket));
      this.handleSocket(socket);
    });
    await new Promise<void>((resolvePromise, reject) => {
      this.server!.once("error", reject);
      this.server!.listen(this.options.socketPath, resolvePromise);
    });
    try {
      await chmod(this.options.socketPath, 0o600);
      this.socketIdentity = await captureSocketPathIdentity(this.options.socketPath);
    } catch (error) {
      await this.close().catch(() => undefined);
      throw error;
    }
  }

  async close(): Promise<void> {
    const nativeTransport = this.nativeTransport;
    this.nativeTransport = undefined;
    if (nativeTransport) {
      try { await nativeTransport.close(); }
      finally { this.authenticationKey.fill(0); }
      return;
    }
    const server = this.server;
    this.server = undefined;
    const socketIdentity = this.socketIdentity;
    this.socketIdentity = undefined;
    try {
      const detached = await detachOwnedSocket(this.options.socketPath, socketIdentity);
      try {
        for (const socket of this.sockets) socket.destroy();
        this.sockets.clear();
        if (server) await new Promise<void>((resolvePromise, reject) => server.close((error) => {
          if (error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING") reject(error);
          else resolvePromise();
        }));
      } finally {
        await removeDetachedSocket(detached);
      }
    } finally {
      this.authenticationKey.fill(0);
    }
  }

  private handleSocket(socket: Socket): void {
    try {
      this.options.peerCredentialVerifier!.verify(socket);
    } catch {
      socket.destroy();
      return;
    }
    this.handleAuthenticatedSocket(socket);
  }

  private handleAuthenticatedSocket(socket: Socket): void {
    socket.setTimeout(Math.min(this.maxRequestAgeMs + this.allowedClockSkewMs, MAX_COMMAND_AGE_MS + 60_000), () => socket.destroy());
    let chunks: Buffer[] = [];
    let total = 0;
    let handled = false;
    socket.on("data", async (chunk: Buffer) => {
      if (handled) return;
      total += chunk.byteLength;
      if (total > this.maxRequestBytes) {
        handled = true;
        writeResponse(socket, this.failure("OUTPUT_LIMIT", "Privileged helper request exceeded the byte limit", "invalid-command", "invalid-request"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      handled = true;
      socket.pause();
      let raw: unknown;
      try {
        raw = parseJsonUtf8Strict(combined.subarray(0, newline));
      } catch {
        writeResponse(socket, this.failure("PRECONDITION_FAILED", "Privileged helper request is not valid JSON", "invalid-command", "invalid-request"));
        return;
      }
      if (isStatusRequestEnvelope(raw)) {
        let statusRequest: UnsignedPrivilegedHelperStatusRequest | undefined;
        let statusResponse: PrivilegedHelperStatusResponse;
        try {
          statusRequest = unsignedPrivilegedHelperStatusCandidate(raw);
          statusRequest = authenticatePrivilegedHelperStatusRequest(raw, this.authenticationKey, this.now(), this.maxRequestAgeMs, this.allowedClockSkewMs);
          if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
            throw new BrokerError("PRECONDITION_FAILED", "Privileged helper request contained trailing data");
          }
          this.options.keyAuthorityCheck?.();
          this.options.replayGuard.admit({
            requestId: statusRequest.requestId,
            nonce: statusRequest.nonce,
            timestampMs: statusRequest.timestampMs,
            nonceExpiresAtMs: statusRequest.expiresAtMs
          });
          if (!this.options.readStatus || !this.options.authorizeStatus) {
            throw new BrokerError("PRIVILEGE_DENIED", "Privileged helper status readback is not enabled");
          }
          this.options.authorizeStatus();
          statusResponse = statusSuccess(statusRequest, validatePrivilegedHelperStatusReadback(this.options.readStatus()), this.authenticationKey);
        } catch (error) {
          const brokerError = error instanceof BrokerError ? error : new BrokerError("PRECONDITION_FAILED", "Privileged helper status request is invalid");
          const fallback = statusRequest ?? fallbackStatusRequest();
          statusResponse = this.statusFailure(brokerError.errorClass, brokerError.message, fallback.requestId, brokerError.retryable, statusRequest);
        }
        writeStatusResponse(socket, statusResponse);
        return;
      }
      let response: PrivilegedHelperResponse;
      let command: UnsignedPrivilegedHelperCommand | undefined;
      try {
        command = unsignedPrivilegedHelperCommandCandidate(raw);
        command = authenticatePrivilegedHelperCommand(raw, this.authenticationKey, this.now(), this.maxRequestAgeMs, this.allowedClockSkewMs);
        if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
          throw new BrokerError("PRECONDITION_FAILED", "Privileged helper request contained trailing data");
        }
        this.options.keyAuthorityCheck?.();
        this.options.replayGuard.admit(command);
        this.options.authorizeCommand(command);
        let authorityRevoked = false;
        const control: PrivilegedHelperExecutionControl = {
          timeoutMs: Math.max(1, command.expiresAtMs - this.now()),
          shouldCancel: () => {
            if (socket.destroyed || this.now() >= command!.expiresAtMs) return true;
            try {
              this.options.authorizeCommand(command!);
              return false;
            } catch {
              authorityRevoked = true;
              return true;
            }
          }
        };
        if (!this.options.adapter.available) throw new BrokerError("PRIVILEGE_DENIED", "Privileged helper operation is not enabled");
        const result = await this.options.adapter.execute(command, control);
        try {
          this.options.authorizeCommand(command);
        } catch {
          authorityRevoked = true;
        }
        if (authorityRevoked || this.now() >= command.expiresAtMs) {
          throw new BrokerError("UNKNOWN_OUTCOME", "Privileged helper authority changed during execution", true);
        }
        response = success(command, validatePrivilegedHelperExecutionResult(result, command), this.authenticationKey);
      } catch (error) {
        const brokerError = error instanceof BrokerError ? error : new BrokerError("PRECONDITION_FAILED", "Privileged helper command is invalid");
        const fallback = command ?? fallbackCommand();
        response = this.failure(brokerError.errorClass, brokerError.message, fallback.commandId, fallback.requestId, brokerError.retryable, command);
      }
      writeResponse(socket, response);
    });
  }

  private failure(
    errorClass: ErrorClass,
    message: string,
    commandId: string,
    requestId: string,
    retryable = false,
    command?: UnsignedPrivilegedHelperCommand
  ): PrivilegedHelperFailureResponse {
    const body = { ok: false as const, commandId, requestId, resultClass: errorClass, error: { message: boundedMessage(message), retryable } };
    return { ...body, responseProof: responseProof(command, body, this.authenticationKey) };
  }

  private statusFailure(
    errorClass: ErrorClass,
    message: string,
    requestId: string,
    retryable = false,
    request?: UnsignedPrivilegedHelperStatusRequest
  ): PrivilegedHelperStatusFailureResponse {
    const body = { ok: false as const, kind: "status" as const, requestId, resultClass: errorClass, error: { message: boundedMessage(message), retryable } };
    return { ...body, responseProof: statusResponseProof(request, body, this.authenticationKey) };
  }
}

export function signPrivilegedHelperCommand(command: UnsignedPrivilegedHelperCommand, authenticationKey: Buffer): SignedPrivilegedHelperCommand {
  validateUnsignedPrivilegedHelperCommand(command);
  return { ...command, authenticationProof: commandProof(command, authenticationKey) };
}

export function signPrivilegedHelperStatusRequest(
  request: UnsignedPrivilegedHelperStatusRequest,
  authenticationKey: Buffer
): SignedPrivilegedHelperStatusRequest {
  validateUnsignedPrivilegedHelperStatusRequest(request);
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Privileged helper key is invalid");
  return { ...request, authenticationProof: statusRequestProof(request, authenticationKey) };
}

export function authenticatePrivilegedHelperStatusRequest(
  raw: unknown,
  authenticationKey: Buffer,
  nowMs: number,
  maxRequestAgeMs = MAX_COMMAND_AGE_MS,
  allowedClockSkewMs = 5_000
): UnsignedPrivilegedHelperStatusRequest {
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Privileged helper key is invalid");
  const parsed = parseSignedStatusRequest(raw);
  const request = parsed.unsigned;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || request.timestampMs > nowMs + allowedClockSkewMs ||
      nowMs - request.timestampMs > maxRequestAgeMs || request.expiresAtMs <= nowMs ||
      request.expiresAtMs <= request.timestampMs ||
      request.expiresAtMs > request.timestampMs + maxRequestAgeMs + allowedClockSkewMs) {
    throw new BrokerError("AUTH_EXPIRED", "Privileged helper status timestamp is outside the accepted window");
  }
  if (!safeEqualHex(parsed.authenticationProof, statusRequestProof(request, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Privileged helper status authentication failed");
  }
  return request;
}

export function validateUnsignedPrivilegedHelperStatusRequest(request: UnsignedPrivilegedHelperStatusRequest): void {
  const allowed = ["protocolVersion", "contractVersion", "requestId", "nonce", "timestampMs", "expiresAtMs", "kind"];
  if (!isPlainDataRecord(request)) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper status request fields are malformed");
  }
  const keys = Object.keys(request);
  if (keys.length !== allowed.length || allowed.some((key) => !keys.includes(key)) ||
      request.protocolVersion !== PROTOCOL_VERSION || request.contractVersion !== CONTRACT_VERSION ||
      !/^request:status-[A-Za-z0-9._:-]{1,240}$/u.test(request.requestId) || !NONCE_PATTERN.test(request.nonce) ||
      !Number.isSafeInteger(request.timestampMs) || request.timestampMs < 0 ||
      !Number.isSafeInteger(request.expiresAtMs) || request.expiresAtMs <= request.timestampMs ||
      request.kind !== "status") {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper status request fields are malformed");
  }
}

export function validatePrivilegedHelperStatusReadback(status: PrivilegedHelperStatusReadback): PrivilegedHelperStatusReadback {
  const allowed = ["component", "state", "runtimeState", "nativeTransportRequired", "adapterAvailable", "helperSocketPath", "brokerSocketPath", "brokerPeerUid", "brokerPeerGid", "sourceRevision", "contractVersion", "policyVersion", "enabledCapabilities"];
  if (!isPlainDataRecord(status)) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper status readback is malformed");
  }
  const keys = Object.keys(status);
  if (keys.length !== allowed.length || allowed.some((key) => !keys.includes(key)) ||
      status.component !== "mac-operator-privileged-helper" || status.state !== "running" ||
      status.runtimeState !== "running" || status.nativeTransportRequired !== true ||
      status.adapterAvailable !== false || !canonicalStatusPath(status.helperSocketPath) ||
      !canonicalStatusPath(status.brokerSocketPath) || status.helperSocketPath === status.brokerSocketPath ||
      !Number.isSafeInteger(status.brokerPeerUid) || status.brokerPeerUid < 1 || status.brokerPeerUid > 2_147_483_647 ||
      (status.brokerPeerGid !== null && (!Number.isSafeInteger(status.brokerPeerGid) || status.brokerPeerGid < 0 || status.brokerPeerGid > 2_147_483_647)) ||
      !/^[a-f0-9]{40}$/u.test(status.sourceRevision) ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,120}$/u.test(status.contractVersion) ||
      !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(status.policyVersion) ||
      !isDenseArray(status.enabledCapabilities, 0) || status.enabledCapabilities.length !== 0) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper status readback is malformed");
  }
  return status;
}

export function authenticatePrivilegedHelperStatusResponse(
  raw: unknown,
  request: UnsignedPrivilegedHelperStatusRequest,
  authenticationKey: Buffer
): PrivilegedHelperStatusResponse {
  validateUnsignedPrivilegedHelperStatusRequest(request);
  if (authenticationKey.byteLength < 32 || !isPlainDataRecord(raw)) {
    throw new BrokerError("AUTH_INVALID", "Privileged helper status response is invalid");
  }
  const response = raw as Record<string, unknown>;
  if (response.kind !== "status" || response.requestId !== request.requestId || typeof response.responseProof !== "string") {
    throw new BrokerError("AUTH_INVALID", "Privileged helper status response identity is invalid");
  }
  const keys = new Set(Object.keys(response));
  const successKeys = ["ok", "kind", "requestId", "status", "responseProof"];
  const failureKeys = ["ok", "kind", "requestId", "resultClass", "error", "responseProof"];
  const expectedKeys = response.ok === true ? successKeys : response.ok === false ? failureKeys : [];
  if (expectedKeys.length === 0 || keys.size !== expectedKeys.length || expectedKeys.some((key) => !keys.has(key))) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper status response fields are malformed");
  }
  const body = { ...response };
  delete body.responseProof;
  if (!safeEqualHex(response.responseProof as string, statusResponseProof(request, body, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Privileged helper status response authentication failed");
  }
  if (response.ok === true) {
    return {
      ...(response as unknown as PrivilegedHelperStatusSuccessResponse),
      status: validatePrivilegedHelperStatusReadback(response.status as PrivilegedHelperStatusReadback)
    };
  }
  if (response.ok !== false || typeof response.resultClass !== "string" || !isHelperErrorClass(response.resultClass) ||
      !isPlainDataRecord(response.error) ||
      typeof (response.error as Record<string, unknown>).message !== "string" ||
      typeof (response.error as Record<string, unknown>).retryable !== "boolean" ||
      !boundedStatusMessage((response.error as Record<string, unknown>).message as string)) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper status failure is malformed");
  }
  return response as unknown as PrivilegedHelperStatusFailureResponse;
}

/**
 * Reads helper-owned runtime metadata over the separately authenticated local
 * channel. The client fences the socket identity before and after the read so
 * a replacement socket cannot be mistaken for the configured helper.
 */
export interface PrivilegedHelperStatusClientOptions {
  socketPath: string;
  authenticationKey: Buffer;
  now?: () => number;
  timeoutMs?: number;
}

export async function readPrivilegedHelperStatus(options: PrivilegedHelperStatusClientOptions): Promise<PrivilegedHelperStatusReadback> {
  if (options === null || typeof options !== "object" || !canonicalStatusPath(options.socketPath) ||
      !Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper status client options are invalid");
  }
  const timeoutMs = options.timeoutMs ?? 5_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 15_000) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper status timeout is invalid");
  }
  const now = options.now ?? Date.now;
  const timestampMs = now();
  if (!Number.isSafeInteger(timestampMs) || timestampMs < 0) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper status clock is invalid");
  }
  const request: UnsignedPrivilegedHelperStatusRequest = {
    protocolVersion: PROTOCOL_VERSION,
    contractVersion: CONTRACT_VERSION,
    requestId: `request:status-${randomBytes(16).toString("hex")}`,
    nonce: `status-nonce-${randomBytes(16).toString("hex")}`,
    timestampMs,
    expiresAtMs: timestampMs + Math.min(timeoutMs, MAX_COMMAND_AGE_MS),
    kind: "status"
  };
  const signed = signPrivilegedHelperStatusRequest(request, options.authenticationKey);
  let before: SocketPathIdentity;
  try {
    before = await captureSocketPathIdentity(options.socketPath);
  } catch {
    throw new BrokerError("TARGET_NOT_FOUND", "Privileged helper status socket is unavailable");
  }
  const key = Buffer.from(options.authenticationKey);
  try {
    const response = await new Promise<unknown>((resolvePromise, reject) => {
      const socket = connect(options.socketPath);
      const chunks: Buffer[] = [];
      let total = 0;
      let settled = false;
      const fail = (error: unknown) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        reject(error);
      };
      socket.setTimeout(timeoutMs, () => fail(new BrokerError("TIMEOUT", "Privileged helper status readback timed out", true)));
      socket.once("error", fail);
      socket.on("data", (chunk: Buffer) => {
        if (settled) return;
        total += chunk.byteLength;
        if (total > MAX_RESPONSE_BYTES) {
          fail(new BrokerError("OUTPUT_LIMIT", "Privileged helper status response exceeded the byte limit"));
          return;
        }
        chunks.push(chunk);
        const combined = Buffer.concat(chunks);
        const newline = combined.indexOf(0x0a);
        if (newline === -1) return;
        if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
          fail(new BrokerError("AUTH_INVALID", "Privileged helper status response contained trailing data"));
          return;
        }
        settled = true;
        socket.destroy();
        try {
          resolvePromise(parseJsonUtf8Strict(combined.subarray(0, newline)));
        } catch {
          reject(new BrokerError("EXECUTION_FAILED", "Privileged helper status response is not valid JSON"));
        }
      });
      socket.on("close", () => {
        if (!settled) fail(new BrokerError("EXECUTION_FAILED", "Privileged helper status channel closed without a response", true));
      });
      socket.once("connect", () => socket.write(`${JSON.stringify(signed)}\n`));
    });
    const after = await captureSocketPathIdentity(options.socketPath);
    if (before.device !== after.device || before.inode !== after.inode) {
      throw new BrokerError("CONFLICT", "Privileged helper status socket identity changed during readback");
    }
    const verified = authenticatePrivilegedHelperStatusResponse(response, request, key);
    if (!verified.ok) throw new BrokerError(verified.resultClass, verified.error.message, verified.error.retryable);
    return verified.status;
  } finally {
    key.fill(0);
  }
}

export interface PrivilegedHelperCommandClientOptions {
  socketPath: string;
  authenticationKey: Buffer;
  now?: () => number;
  timeoutMs?: number;
}

/**
 * Sends one already-signed Broker command to the helper. This client cannot
 * create authority: the command factory remains the only place that binds
 * approval, Job, target, policy, and kill-switch identity before signing.
 */
export async function executePrivilegedHelperCommand(
  signedCommand: SignedPrivilegedHelperCommand,
  options: PrivilegedHelperCommandClientOptions
): Promise<PrivilegedHelperResponse> {
  if (options === null || typeof options !== "object" || !canonicalStatusPath(options.socketPath) ||
      !Buffer.isBuffer(options.authenticationKey) || options.authenticationKey.byteLength < 32) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper command client options are invalid");
  }
  const timeoutMs = options.timeoutMs ?? 30_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_COMMAND_AGE_MS) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper command timeout is invalid");
  }
  const now = options.now ?? Date.now;
  const nowMs = now();
  if (!Number.isSafeInteger(nowMs) || nowMs < 0) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper command clock is invalid");
  }
  const key = Buffer.from(options.authenticationKey);
  let command: UnsignedPrivilegedHelperCommand;
  try {
    command = authenticatePrivilegedHelperCommand(signedCommand, key, nowMs);
  } catch (error) {
    key.fill(0);
    throw error;
  }
  const serialized = `${JSON.stringify(signedCommand)}\n`;
  if (Buffer.byteLength(serialized, "utf8") > MAX_COMMAND_BYTES) {
    key.fill(0);
    throw new BrokerError("OUTPUT_LIMIT", "Privileged helper command exceeded the byte limit");
  }
  let before: SocketPathIdentity;
  try {
    before = await captureSocketPathIdentity(options.socketPath);
  } catch {
    key.fill(0);
    throw new BrokerError("TARGET_NOT_FOUND", "Privileged helper command socket is unavailable");
  }
  try {
    const response = await exchangeHelperSocket(options.socketPath, serialized, timeoutMs);
    let after: SocketPathIdentity;
    try {
      after = await captureSocketPathIdentity(options.socketPath);
    } catch {
      throw new BrokerError("CONFLICT", "Privileged helper command socket disappeared during execution", true);
    }
    if (before.device !== after.device || before.inode !== after.inode) {
      throw new BrokerError("CONFLICT", "Privileged helper command socket identity changed during execution", true);
    }
    return authenticatePrivilegedHelperResponse(response, command, key);
  } finally {
    key.fill(0);
  }
}

export function authenticatePrivilegedHelperCommand(
  raw: unknown,
  authenticationKey: Buffer,
  nowMs: number,
  maxRequestAgeMs = MAX_COMMAND_AGE_MS,
  allowedClockSkewMs = 5_000
): UnsignedPrivilegedHelperCommand {
  if (authenticationKey.byteLength < 32) throw new BrokerError("AUTH_INVALID", "Privileged helper key is invalid");
  const parsed = parseSignedCommand(raw);
  const command = parsed.unsigned;
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || command.timestampMs > nowMs + allowedClockSkewMs ||
      nowMs - command.timestampMs > maxRequestAgeMs || command.nonceExpiresAtMs <= nowMs || command.expiresAtMs <= nowMs) {
    throw new BrokerError("AUTH_EXPIRED", "Privileged helper command timestamp is outside the accepted window");
  }
  if (command.nonceExpiresAtMs <= command.timestampMs || command.nonceExpiresAtMs > command.timestampMs + maxRequestAgeMs + allowedClockSkewMs ||
      command.expiresAtMs <= command.timestampMs || command.expiresAtMs > command.timestampMs + maxRequestAgeMs + allowedClockSkewMs) {
    throw new BrokerError("AUTH_EXPIRED", "Privileged helper command expiry is invalid");
  }
  if (!safeEqualHex(parsed.authenticationProof, commandProof(command, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Privileged helper command authentication failed");
  }
  return command;
}

export function validateUnsignedPrivilegedHelperCommand(command: UnsignedPrivilegedHelperCommand): void {
  if (command === null || typeof command !== "object" || Array.isArray(command) ||
      command.protocolVersion !== PROTOCOL_VERSION || command.contractVersion !== CONTRACT_VERSION ||
      !/^priv-command:[A-Za-z0-9._:-]{1,240}$/u.test(command.commandId) ||
      !/^request:[A-Za-z0-9._:-]{1,240}$/u.test(command.requestId) || !NONCE_PATTERN.test(command.nonce) ||
      !Number.isSafeInteger(command.nonceExpiresAtMs) || command.nonceExpiresAtMs < 0 ||
      !Number.isSafeInteger(command.timestampMs) || command.timestampMs < 0 ||
      !Number.isSafeInteger(command.expiresAtMs) || command.expiresAtMs < 0 ||
      !["service_control", "package_install", "power"].includes(command.operation) ||
      !validTarget(command.operation, command.targetRef) || !/^[a-f0-9]{64}$/u.test(command.payloadDigest) ||
      !POLICY_VERSION_PATTERN.test(command.policyVersion) || !APPROVAL_ID_PATTERN.test(command.approvalId) ||
      !INTENT_ID_PATTERN.test(command.intentId) || command.expiresAtMs <= command.timestampMs ||
      command.nonceExpiresAtMs <= command.timestampMs) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper command fields are malformed");
  }
  try {
    validatePrivilegedHelperPayload(command.payload);
  } catch {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper command payload is malformed");
  }
  if (command.payload.operation !== command.operation || privilegedHelperPayloadTarget(command.payload) !== command.targetRef ||
      sha256(canonicalJson(command.payload)) !== command.payloadDigest) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper command payload binding is invalid");
  }
}

export function validatePrivilegedHelperExecutionResult(
  result: PrivilegedHelperExecutionResult,
  command?: Pick<UnsignedPrivilegedHelperCommand, "operation" | "targetRef">
): PrivilegedHelperExecutionResult {
  if (!isPlainDataRecord(result) ||
      !["service_control", "package_install", "power"].includes(result.operation) ||
      !["accepted", "completed", "failed", "cancelled", "unknown"].includes(result.state) ||
      !["SUCCEEDED", "EXECUTION_FAILED", "CANCELLED", "TIMEOUT", "VERIFICATION_FAILED", "UNKNOWN_OUTCOME"].includes(result.resultClass) ||
      !validTarget(result.operation, result.targetRef) || !isEvidenceRecord(result.evidence) ||
      !Array.isArray(result.warnings) || result.warnings.length > MAX_WARNINGS || result.warnings.some((warning) => typeof warning !== "string" || warning.length < 1 || warning.length > 512 || warning.includes("\0")) ||
      typeof result.truncated !== "boolean" || !isPlainDataRecord(result.verification) ||
      !["verified", "failed", "unknown"].includes(result.verification.status) || result.verification.strategy !== "allowlisted_postcondition") {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper returned a malformed result");
  }
  if (command && (result.operation !== command.operation || result.targetRef !== command.targetRef)) {
    throw new BrokerError("VERIFICATION_FAILED", "Privileged helper result identity does not match the command");
  }
  if (result.resultClass === "SUCCEEDED" && (result.state !== "accepted" && result.state !== "completed" || result.verification.status !== "verified")) {
    throw new BrokerError("VERIFICATION_FAILED", "Privileged helper success is not postcondition verified");
  }
  if (result.verification.summary !== undefined && (typeof result.verification.summary !== "string" || result.verification.summary.length > 512 || result.verification.summary.includes("\0"))) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper verification summary is malformed");
  }
  if (result.verification.readbackHash !== undefined && !/^[a-f0-9]{64}$/u.test(result.verification.readbackHash)) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper readback hash is malformed");
  }
  const evidence = Object.fromEntries(Object.entries(result.evidence).map(([key, value]) => {
    if (/(?:access[_-]?token|api[_-]?key|authorization|bearer|client[_-]?secret|cookie|credential|hmac[_-]?key|jwt|password|passwd|passphrase|private[_-]?key|refresh[_-]?token|secret|signing[_-]?key|ssh[_-]?key|token)/iu.test(key)) return [key, "[REDACTED]"] as const;
    return [key, typeof value === "string" ? redactLogText(value).text : value] as const;
  }));
  const warnings = result.warnings.map((warning) => redactLogText(warning).text);
  const verification = {
    ...result.verification,
    ...(result.verification.summary === undefined ? {} : { summary: redactLogText(result.verification.summary).text })
  };
  return { ...result, evidence, warnings, verification };
}

export function authenticatePrivilegedHelperResponse(
  raw: unknown,
  command: UnsignedPrivilegedHelperCommand,
  authenticationKey: Buffer
): PrivilegedHelperResponse {
  validateUnsignedPrivilegedHelperCommand(command);
  if (authenticationKey.byteLength < 32 || !isPlainDataRecord(raw)) {
    throw new BrokerError("AUTH_INVALID", "Privileged helper response is invalid");
  }
  const response = raw as Record<string, unknown>;
  if (response.commandId !== command.commandId || response.requestId !== command.requestId || typeof response.responseProof !== "string") {
    throw new BrokerError("AUTH_INVALID", "Privileged helper response identity is invalid");
  }
  const body = { ...response };
  delete body.responseProof;
  if (!safeEqualHex(response.responseProof as string, responseProof(command, body, authenticationKey))) {
    throw new BrokerError("AUTH_INVALID", "Privileged helper response authentication failed");
  }
  if (response.ok === true) {
    if (!isPlainDataRecord(response.result)) throw new BrokerError("EXECUTION_FAILED", "Privileged helper result is malformed");
    const result = validatePrivilegedHelperExecutionResult(response.result as unknown as PrivilegedHelperExecutionResult, command);
    return { ...(response as unknown as PrivilegedHelperSuccessResponse), result };
  }
  if (response.ok !== false || typeof response.resultClass !== "string" || !isPlainDataRecord(response.error) ||
      typeof (response.error as Record<string, unknown>).message !== "string" || typeof (response.error as Record<string, unknown>).retryable !== "boolean") {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper failure is malformed");
  }
  if (!(Object.values(["AUTH_REQUIRED", "AUTH_INVALID", "AUTH_EXPIRED", "REPLAY_DENIED", "REVOKED", "SCOPE_DENIED", "SECRET_BOUNDARY_DENIED", "PATH_DENIED", "NETWORK_DENIED", "PRIVILEGE_DENIED", "POLICY_DENIED", "TARGET_NOT_FOUND", "PRECONDITION_FAILED", "CONFLICT", "TIMEOUT", "OUTPUT_LIMIT", "CANCELLED", "EXECUTION_FAILED", "VERIFICATION_FAILED", "AUDIT_UNAVAILABLE", "UNKNOWN_OUTCOME", "UNSUPPORTED_CAPABILITY"] as const) as readonly string[]).includes(response.resultClass as string)) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper failure class is malformed");
  }
  return response as unknown as PrivilegedHelperFailureResponse;
}

function parseSignedCommand(value: unknown): { unsigned: UnsignedPrivilegedHelperCommand; authenticationProof: string } {
  if (!isPlainDataRecord(value)) throw new BrokerError("PRECONDITION_FAILED", "Privileged helper envelope is malformed");
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    "protocolVersion", "contractVersion", "commandId", "requestId", "nonce", "nonceExpiresAtMs", "timestampMs", "expiresAtMs",
    "operation", "targetRef", "payload", "payloadDigest", "policyVersion", "approvalId", "intentId", "authenticationProof"
  ]);
  if (Object.keys(record).some((key) => !allowed.has(key)) || typeof record.authenticationProof !== "string" || !/^[a-f0-9]{64}$/u.test(record.authenticationProof)) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper envelope is malformed");
  }
  const unsigned = {
    protocolVersion: record.protocolVersion as typeof PROTOCOL_VERSION,
    contractVersion: record.contractVersion as typeof CONTRACT_VERSION,
    commandId: record.commandId as string,
    requestId: record.requestId as string,
    nonce: record.nonce as string,
    nonceExpiresAtMs: record.nonceExpiresAtMs as number,
    timestampMs: record.timestampMs as number,
    expiresAtMs: record.expiresAtMs as number,
    operation: record.operation as PrivilegedHelperOperation,
    targetRef: record.targetRef as string,
    payload: record.payload as PrivilegedHelperPayload,
    payloadDigest: record.payloadDigest as string,
    policyVersion: record.policyVersion as string,
    approvalId: record.approvalId as string,
    intentId: record.intentId as string
  } satisfies UnsignedPrivilegedHelperCommand;
  validateUnsignedPrivilegedHelperCommand(unsigned);
  return { unsigned, authenticationProof: record.authenticationProof as string };
}

/**
 * Recover a structurally valid unsigned helper command before freshness/auth
 * checks so callers can authenticate stable failures. The candidate is never
 * admitted, authorized, or executed by itself.
 */
function unsignedPrivilegedHelperCommandCandidate(raw: unknown): UnsignedPrivilegedHelperCommand | undefined {
  try {
    return parseSignedCommand(raw).unsigned;
  } catch {
    return undefined;
  }
}

function commandProof(command: UnsignedPrivilegedHelperCommand, key: Buffer): string {
  if (key.byteLength < 32) throw new Error("Privileged helper key must contain at least 32 bytes");
  return createHmac("sha256", key).update(HELPER_COMMAND_DOMAIN, "utf8").update(sha256(canonicalJson(command)), "utf8").digest("hex");
}

function responseProof(command: UnsignedPrivilegedHelperCommand | undefined, body: object, key: Buffer): string {
  if (key.byteLength < 32) throw new Error("Privileged helper key must contain at least 32 bytes");
  return createHmac("sha256", key)
    .update(HELPER_RESPONSE_DOMAIN, "utf8")
    .update(command ? sha256(canonicalJson(command)) : "invalid-command", "utf8")
    .update(canonicalJson(body), "utf8")
    .digest("hex");
}

function isStatusRequestEnvelope(value: unknown): boolean {
  return isPlainDataRecord(value) && value.kind === "status";
}

function isDenseArray(value: unknown, maxLength: number): value is readonly unknown[] {
  if (!Array.isArray(value) || value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0) return false;
  const names = Object.getOwnPropertyNames(value);
  if (names.length !== value.length + 1 || Object.keys(value).length !== value.length) return false;
  for (let index = 0; index < value.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor)) return false;
  }
  return true;
}

function statusRequestProof(request: UnsignedPrivilegedHelperStatusRequest, key: Buffer): string {
  if (key.byteLength < 32) throw new Error("Privileged helper key must contain at least 32 bytes");
  return createHmac("sha256", key)
    .update(HELPER_STATUS_REQUEST_DOMAIN, "utf8")
    .update(sha256(canonicalJson(request)), "utf8")
    .digest("hex");
}

function statusResponseProof(
  request: UnsignedPrivilegedHelperStatusRequest | undefined,
  body: object,
  key: Buffer
): string {
  if (key.byteLength < 32) throw new Error("Privileged helper key must contain at least 32 bytes");
  return createHmac("sha256", key)
    .update(HELPER_STATUS_RESPONSE_DOMAIN, "utf8")
    .update(request ? sha256(canonicalJson(request)) : "invalid-status-request", "utf8")
    .update(canonicalJson(body), "utf8")
    .digest("hex");
}

function statusSuccess(
  request: UnsignedPrivilegedHelperStatusRequest,
  status: PrivilegedHelperStatusReadback,
  key: Buffer
): PrivilegedHelperStatusSuccessResponse {
  const body = { ok: true as const, kind: "status" as const, requestId: request.requestId, status };
  return { ...body, responseProof: statusResponseProof(request, body, key) };
}

function writeStatusResponse(socket: Socket, response: PrivilegedHelperStatusResponse): void {
  if (!socket.destroyed) {
    const serialized = `${JSON.stringify(response)}\n`;
    if (Buffer.byteLength(serialized, "utf8") <= MAX_RESPONSE_BYTES) socket.end(serialized);
    else socket.destroy();
  }
}

async function exchangeHelperSocket(socketPath: string, serialized: string, timeoutMs: number): Promise<unknown> {
  return new Promise<unknown>((resolvePromise, reject) => {
    const socket = connect(socketPath);
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };
    socket.setTimeout(timeoutMs, () => fail(new BrokerError("TIMEOUT", "Privileged helper command timed out", true)));
    socket.once("error", (error) => fail(new BrokerError("UNKNOWN_OUTCOME", "Privileged helper command transport failed", true)));
    socket.on("data", (chunk: Buffer) => {
      if (settled) return;
      total += chunk.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        fail(new BrokerError("OUTPUT_LIMIT", "Privileged helper command response exceeded the byte limit"));
        return;
      }
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      if (combined.subarray(newline + 1).some((byte) => !isAsciiWhitespace(byte))) {
        fail(new BrokerError("AUTH_INVALID", "Privileged helper response contained trailing data"));
        return;
      }
      settled = true;
      socket.destroy();
      try {
        resolvePromise(parseJsonUtf8Strict(combined.subarray(0, newline)));
      } catch {
        reject(new BrokerError("EXECUTION_FAILED", "Privileged helper command response is not valid JSON"));
      }
    });
    socket.on("close", () => {
      if (!settled) fail(new BrokerError("UNKNOWN_OUTCOME", "Privileged helper command channel closed without a response", true));
    });
    socket.once("connect", () => socket.write(serialized));
  });
}

function fallbackStatusRequest(): UnsignedPrivilegedHelperStatusRequest {
  return {
    protocolVersion: PROTOCOL_VERSION,
    contractVersion: CONTRACT_VERSION,
    requestId: "request:status-invalid",
    nonce: "invalid-invalid-invalid",
    timestampMs: 0,
    expiresAtMs: 1,
    kind: "status"
  };
}

function canonicalStatusPath(value: unknown): value is string {
  return typeof value === "string" && isAbsolute(value) && resolve(value) === value && !value.includes("\0");
}

function isHelperErrorClass(value: string): value is ErrorClass {
  return (Object.values([
    "AUTH_REQUIRED", "AUTH_INVALID", "AUTH_EXPIRED", "REPLAY_DENIED", "REVOKED", "SCOPE_DENIED",
    "SECRET_BOUNDARY_DENIED", "PATH_DENIED", "NETWORK_DENIED", "PRIVILEGE_DENIED", "POLICY_DENIED",
    "TARGET_NOT_FOUND", "PRECONDITION_FAILED", "CONFLICT", "TIMEOUT", "OUTPUT_LIMIT", "CANCELLED",
    "EXECUTION_FAILED", "VERIFICATION_FAILED", "AUDIT_UNAVAILABLE", "UNKNOWN_OUTCOME", "UNSUPPORTED_CAPABILITY"
  ] as const) as readonly string[]).includes(value);
}

function parseSignedStatusRequest(value: unknown): { unsigned: UnsignedPrivilegedHelperStatusRequest; authenticationProof: string } {
  if (!isPlainDataRecord(value)) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper status envelope is malformed");
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    "protocolVersion", "contractVersion", "requestId", "nonce", "timestampMs", "expiresAtMs", "kind", "authenticationProof"
  ]);
  if (Object.keys(record).some((key) => !allowed.has(key)) || typeof record.authenticationProof !== "string" ||
      !/^[a-f0-9]{64}$/u.test(record.authenticationProof)) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper status envelope is malformed");
  }
  const unsigned = {
    protocolVersion: record.protocolVersion as typeof PROTOCOL_VERSION,
    contractVersion: record.contractVersion as typeof CONTRACT_VERSION,
    requestId: record.requestId as string,
    nonce: record.nonce as string,
    timestampMs: record.timestampMs as number,
    expiresAtMs: record.expiresAtMs as number,
    kind: record.kind as "status"
  } satisfies UnsignedPrivilegedHelperStatusRequest;
  validateUnsignedPrivilegedHelperStatusRequest(unsigned);
  return { unsigned, authenticationProof: record.authenticationProof as string };
}

/**
 * Recover a structurally valid unsigned status request before freshness/auth
 * checks so callers can authenticate stable failures. The candidate is never
 * admitted, authorized, or used for status access by itself.
 */
function unsignedPrivilegedHelperStatusCandidate(raw: unknown): UnsignedPrivilegedHelperStatusRequest | undefined {
  if (!isPlainDataRecord(raw)) return undefined;
  const record = raw as Record<string, unknown>;
  const allowed = [
    "protocolVersion", "contractVersion", "requestId", "nonce", "timestampMs", "expiresAtMs", "kind", "authenticationProof"
  ];
  if (Object.keys(record).length !== allowed.length || allowed.some((key) => !Object.hasOwn(record, key)) ||
      typeof record.authenticationProof !== "string") return undefined;
  const candidate = {
    protocolVersion: record.protocolVersion as typeof PROTOCOL_VERSION,
    contractVersion: record.contractVersion as typeof CONTRACT_VERSION,
    requestId: record.requestId as string,
    nonce: record.nonce as string,
    timestampMs: record.timestampMs as number,
    expiresAtMs: record.expiresAtMs as number,
    kind: record.kind as "status"
  } satisfies UnsignedPrivilegedHelperStatusRequest;
  try {
    validateUnsignedPrivilegedHelperStatusRequest(candidate);
    return candidate;
  } catch {
    return undefined;
  }
}

function success(command: UnsignedPrivilegedHelperCommand, result: PrivilegedHelperExecutionResult, key: Buffer): PrivilegedHelperSuccessResponse {
  const body = { ok: true as const, commandId: command.commandId, requestId: command.requestId, result };
  return { ...body, responseProof: responseProof(command, body, key) };
}

function writeResponse(socket: Socket, response: PrivilegedHelperResponse): void {
  if (!socket.destroyed) {
    const serialized = `${JSON.stringify(response)}\n`;
    if (Buffer.byteLength(serialized, "utf8") <= MAX_RESPONSE_BYTES) socket.end(serialized);
    else socket.destroy();
  }
}

function validateReplayInput(input: Pick<UnsignedPrivilegedHelperCommand, "requestId" | "nonce" | "timestampMs" | "nonceExpiresAtMs">): void {
  if (!/^request:[A-Za-z0-9._:-]{1,240}$/u.test(input.requestId) || !NONCE_PATTERN.test(input.nonce) ||
      !Number.isSafeInteger(input.timestampMs) || input.timestampMs < 0 || !Number.isSafeInteger(input.nonceExpiresAtMs) || input.nonceExpiresAtMs <= input.timestampMs) {
    throw new BrokerError("PRECONDITION_FAILED", "Privileged helper replay admission is malformed");
  }
}

function validTarget(operation: PrivilegedHelperOperation, targetRef: string): boolean {
  if (operation === "service_control") return SERVICE_TARGET_PATTERN.test(targetRef);
  if (operation === "package_install") return PACKAGE_TARGET_PATTERN.test(targetRef);
  return targetRef === "host:local";
}

function isEvidenceRecord(value: unknown): value is Readonly<Record<string, string | number | boolean | null>> {
  if (!isPlainDataRecord(value)) return false;
  const entries = Object.entries(value);
  if (entries.length > MAX_EVIDENCE_FIELDS) return false;
  return entries.every(([key, entry]) => /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/u.test(key) &&
    (entry === null || typeof entry === "boolean" || (typeof entry === "number" && Number.isFinite(entry) && Math.abs(entry) <= Number.MAX_SAFE_INTEGER) ||
      (typeof entry === "string" && entry.length <= 512 && !entry.includes("\0") && !/[\r\n]/u.test(entry))));
}

function safeEqualHex(actual: string, expected: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(actual) || !/^[a-f0-9]{64}$/u.test(expected)) return false;
  return timingSafeEqual(Buffer.from(actual, "hex"), Buffer.from(expected, "hex"));
}

function boundedMessage(value: string): string {
  return value.length <= 512 && !value.includes("\0") ? value : "Privileged helper request failed";
}

function boundedStatusMessage(value: string): boolean {
  return value.length <= 512 && !value.includes("\0") && !/[\r\n]/u.test(value);
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x09 || byte === 0x0a || byte === 0x0c || byte === 0x0d || byte === 0x20;
}

function fallbackCommand(): UnsignedPrivilegedHelperCommand {
  return {
    protocolVersion: PROTOCOL_VERSION,
    contractVersion: CONTRACT_VERSION,
    commandId: "priv-command:invalid",
    requestId: "request:invalid",
    nonce: "invalid-invalid-invalid",
    nonceExpiresAtMs: 1,
    timestampMs: 0,
    expiresAtMs: 1,
    operation: "power",
    targetRef: "host:local",
    payload: { operation: "power", action: "reboot" },
    payloadDigest: sha256(canonicalJson({ operation: "power", action: "reboot" })),
    policyVersion: "policy-invalid",
    approvalId: "approval:invalid",
    intentId: "intent:invalid"
  };
}
