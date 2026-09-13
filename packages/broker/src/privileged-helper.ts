import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { chmod } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { BrokerError, canonicalJson, CONTRACT_VERSION, PROTOCOL_VERSION, sha256, type ErrorClass } from "@mac-operator/contracts";
import { MacOsNativePeerIpcServer, type NativePeerPolicy } from "./native-peer-ipc-server.js";
import { captureSocketPathIdentity, detachOwnedSocket, removeDetachedSocket, removeStaleSocket, validateSocketParent, type SocketPathIdentity } from "./ipc-server.js";
import type { ApprovalRecord, BrokerJob, BrokerStore, RequestRecord } from "./persistence.js";
import { redactLogText } from "./secret-policy.js";

const HELPER_COMMAND_DOMAIN = "mac-operator-privileged-helper-command-v0.1\0";
const HELPER_RESPONSE_DOMAIN = "mac-operator-privileged-helper-response-v0.1\0";
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
        request.payloadDigest !== job.payloadDigest || job.ownerSessionId !== input.sessionId ||
        job.state !== "running" || job.tool !== `mac_priv_${operation === "service_control" ? "service_control" : operation === "package_install" ? "package_install" : "power"}` ||
        !validTarget(operation, job.targetRef)) {
      throw new BrokerError("CONFLICT", "Privileged helper request and running Job identity do not match");
    }
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
    this.server = createServer((socket) => this.handleSocket(socket));
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
    const detached = await detachOwnedSocket(this.options.socketPath, socketIdentity);
    if (server) await new Promise<void>((resolvePromise, reject) => server.close((error) => {
      if (error && (error as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING") reject(error);
      else resolvePromise();
    }));
    try {
      await removeDetachedSocket(detached);
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
      let response: PrivilegedHelperResponse;
      let command: UnsignedPrivilegedHelperCommand | undefined;
      try {
        const raw = JSON.parse(combined.subarray(0, newline).toString("utf8")) as unknown;
        command = authenticatePrivilegedHelperCommand(raw, this.authenticationKey, this.now(), this.maxRequestAgeMs, this.allowedClockSkewMs);
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
}

export function signPrivilegedHelperCommand(command: UnsignedPrivilegedHelperCommand, authenticationKey: Buffer): SignedPrivilegedHelperCommand {
  validateUnsignedPrivilegedHelperCommand(command);
  return { ...command, authenticationProof: commandProof(command, authenticationKey) };
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
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || command.timestampMs > nowMs + allowedClockSkewMs || nowMs - command.timestampMs > maxRequestAgeMs) {
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
}

export function validatePrivilegedHelperExecutionResult(
  result: PrivilegedHelperExecutionResult,
  command?: Pick<UnsignedPrivilegedHelperCommand, "operation" | "targetRef">
): PrivilegedHelperExecutionResult {
  if (result === null || typeof result !== "object" || Array.isArray(result) ||
      !["service_control", "package_install", "power"].includes(result.operation) ||
      !["accepted", "completed", "failed", "cancelled", "unknown"].includes(result.state) ||
      !["SUCCEEDED", "EXECUTION_FAILED", "CANCELLED", "TIMEOUT", "VERIFICATION_FAILED", "UNKNOWN_OUTCOME"].includes(result.resultClass) ||
      !validTarget(result.operation, result.targetRef) || !isEvidenceRecord(result.evidence) ||
      !Array.isArray(result.warnings) || result.warnings.length > MAX_WARNINGS || result.warnings.some((warning) => typeof warning !== "string" || warning.length < 1 || warning.length > 512 || warning.includes("\0")) ||
      typeof result.truncated !== "boolean" || result.verification === null || typeof result.verification !== "object" || Array.isArray(result.verification) ||
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
    if (/password|passwd|token|secret|credential|private|api[_-]?key/iu.test(key)) return [key, "[REDACTED]"] as const;
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
  if (authenticationKey.byteLength < 32 || raw === null || typeof raw !== "object" || Array.isArray(raw)) {
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
    if (response.result === null || typeof response.result !== "object" || Array.isArray(response.result)) throw new BrokerError("EXECUTION_FAILED", "Privileged helper result is malformed");
    const result = validatePrivilegedHelperExecutionResult(response.result as PrivilegedHelperExecutionResult, command);
    return { ...(response as unknown as PrivilegedHelperSuccessResponse), result };
  }
  if (response.ok !== false || typeof response.resultClass !== "string" || !response.error || typeof response.error !== "object" ||
      typeof (response.error as Record<string, unknown>).message !== "string" || typeof (response.error as Record<string, unknown>).retryable !== "boolean") {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper failure is malformed");
  }
  if (!(Object.values(["AUTH_REQUIRED", "AUTH_INVALID", "AUTH_EXPIRED", "REPLAY_DENIED", "REVOKED", "SCOPE_DENIED", "SECRET_BOUNDARY_DENIED", "PATH_DENIED", "NETWORK_DENIED", "PRIVILEGE_DENIED", "POLICY_DENIED", "TARGET_NOT_FOUND", "PRECONDITION_FAILED", "CONFLICT", "TIMEOUT", "OUTPUT_LIMIT", "CANCELLED", "EXECUTION_FAILED", "VERIFICATION_FAILED", "AUDIT_UNAVAILABLE", "UNKNOWN_OUTCOME", "UNSUPPORTED_CAPABILITY"] as const) as readonly string[]).includes(response.resultClass as string)) {
    throw new BrokerError("EXECUTION_FAILED", "Privileged helper failure class is malformed");
  }
  return response as unknown as PrivilegedHelperFailureResponse;
}

function parseSignedCommand(value: unknown): { unsigned: UnsignedPrivilegedHelperCommand; authenticationProof: string } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new BrokerError("PRECONDITION_FAILED", "Privileged helper envelope is malformed");
  const record = value as Record<string, unknown>;
  const allowed = new Set([
    "protocolVersion", "contractVersion", "commandId", "requestId", "nonce", "nonceExpiresAtMs", "timestampMs", "expiresAtMs",
    "operation", "targetRef", "payloadDigest", "policyVersion", "approvalId", "intentId", "authenticationProof"
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
    payloadDigest: record.payloadDigest as string,
    policyVersion: record.policyVersion as string,
    approvalId: record.approvalId as string,
    intentId: record.intentId as string
  } satisfies UnsignedPrivilegedHelperCommand;
  validateUnsignedPrivilegedHelperCommand(unsigned);
  return { unsigned, authenticationProof: record.authenticationProof as string };
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
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
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
    payloadDigest: "0".repeat(64),
    policyVersion: "policy-invalid",
    approvalId: "approval:invalid",
    intentId: "intent:invalid"
  };
}
