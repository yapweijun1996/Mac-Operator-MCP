import { randomBytes } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, decodeUtf8Strict, parseJsonStrict, type ErrorClass } from "@mac-operator/contracts";
import {
  approvalPreviewDigest,
  signApprovalIssuance,
  type UnsignedApprovalIssuance
} from "./approval-authority.js";
import type { ApprovalIpcResponse } from "./approval-ipc-server.js";
import type { ApprovalClass, IssueApprovalInput } from "./persistence.js";
import { validateOwnerSocketParentChain } from "./owner-socket-path.js";

const APPROVAL_CLASSES: readonly ApprovalClass[] = [
  "trusted_write",
  "trusted_gui",
  "trusted_profile",
  "explicit_privileged_policy"
];

export interface ApprovalIpcClientOptions {
  socketPath: string;
  issuerId: string;
  keyId: string;
  authenticationKey: Buffer;
  /** Only an explicit owner-delegated issuer may request unattended profile approvals. */
  allowUnattended?: boolean;
  timeoutMs?: number;
  maxResponseBytes?: number;
  maxRequestAgeMs?: number;
  now?: () => number;
}

export type ApprovalIpcSuccessResponse = Extract<ApprovalIpcResponse, { ok: true }>;

/**
 * Owner-side client for the local approval channel. It never accepts an
 * approval from an MCP request and only emits a signed, single-use issuance.
 */
export class ApprovalIpcClient {
  private readonly authenticationKey: Buffer;
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;
  private readonly maxRequestAgeMs: number;
  private readonly now: () => number;
  private disposed = false;

  constructor(private readonly options: ApprovalIpcClientOptions) {
    if (!isCanonicalAbsolutePath(options.socketPath)) throw new Error("Approval IPC socket path must be canonical");
    if (!/^[A-Za-z0-9._:@/-]{1,128}$/u.test(options.issuerId) ||
        !/^[A-Za-z0-9._:-]{1,128}$/u.test(options.keyId)) {
      throw new Error("Approval issuer identity is malformed");
    }
    if (options.authenticationKey.byteLength < 32) throw new Error("Approval IPC key must contain at least 32 bytes");
    if (options.allowUnattended !== undefined && typeof options.allowUnattended !== "boolean") throw new Error("Approval delegation flag is invalid");
    const timeoutMs = options.timeoutMs ?? 15_000;
    const maxResponseBytes = options.maxResponseBytes ?? 64 * 1024;
    const maxRequestAgeMs = options.maxRequestAgeMs ?? 60_000;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000 ||
        !Number.isSafeInteger(maxResponseBytes) || maxResponseBytes < 256 || maxResponseBytes > 1_048_576 ||
        !Number.isSafeInteger(maxRequestAgeMs) || maxRequestAgeMs < 1 || maxRequestAgeMs > 600_000) {
      throw new Error("Approval IPC client limits are invalid");
    }
    this.authenticationKey = Buffer.from(options.authenticationKey);
    this.timeoutMs = timeoutMs;
    this.maxResponseBytes = maxResponseBytes;
    this.maxRequestAgeMs = maxRequestAgeMs;
    this.now = options.now ?? Date.now;
  }

  /** Wipe the client-owned issuer key after the owner operation completes. */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    this.authenticationKey.fill(0);
  }

  async issue(approval: IssueApprovalInput, signal?: AbortSignal): Promise<ApprovalIpcSuccessResponse> {
    if (this.disposed) throw new BrokerError("CANCELLED", "Approval IPC client is disposed");
    if (approval.approverPrincipalId !== this.options.issuerId) {
      throw new BrokerError("POLICY_DENIED", "Approval approver does not match the configured issuer");
    }
    validateOwnerApproval(approval, this.now(), this.maxRequestAgeMs, this.options.allowUnattended === true);
    const timestampMs = approval.issuedAtMs;
    const unsigned: UnsignedApprovalIssuance = {
      protocolVersion: "0.1",
      requestId: `approval-issue:owner-${randomBytes(18).toString("hex")}`,
      nonce: `approval-nonce:owner-${randomBytes(24).toString("hex")}`,
      nonceExpiresAtMs: timestampMs + this.maxRequestAgeMs,
      issuerId: this.options.issuerId,
      keyId: this.options.keyId,
      timestampMs,
      approval,
      previewDigest: approvalPreviewDigest(approval)
    };
    const signed = signApprovalIssuance(unsigned, this.authenticationKey);
    const identity = await validateApprovalSocketTarget(this.options.socketPath);
    const response = await this.exchange(`${JSON.stringify(signed)}\n`, identity, signal);
    if (!response.ok) {
      throw new BrokerError(response.result_class, response.error.message, response.error.retryable);
    }
    if (response.approval_id !== approval.approvalId || response.expires_at_ms !== approval.expiresAtMs) {
      throw new BrokerError("AUTH_INVALID", "Approval IPC response does not match the requested approval");
    }
    return response;
  }

  private exchange(
    body: string,
    expectedIdentity: { device: number; inode: number },
    signal: AbortSignal | undefined
  ): Promise<ApprovalIpcResponse> {
    return new Promise((resolvePromise, rejectPromise) => {
      const socket = createConnection(this.options.socketPath);
      let settled = false;
      let total = 0;
      const chunks: Buffer[] = [];
      const finish = (error?: Error, value?: ApprovalIpcResponse) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", onAbort);
        socket.destroy();
        if (error) rejectPromise(error);
        else resolvePromise(value!);
      };
      const onAbort = () => finish(new BrokerError("CANCELLED", "Approval IPC request was cancelled"));
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) return onAbort();
      socket.setTimeout(this.timeoutMs, () => finish(new BrokerError("TIMEOUT", "Approval IPC request timed out", true)));
      socket.on("connect", () => {
        void lstat(this.options.socketPath).then((after) => {
          if (!after.isSocket() || after.isSymbolicLink() || after.uid !== process.getuid?.() ||
              after.dev !== expectedIdentity.device || after.ino !== expectedIdentity.inode) {
            finish(new BrokerError("AUTH_INVALID", "Approval IPC target changed while connecting"));
            return;
          }
          socket.write(body);
        }).catch(() => finish(new BrokerError("AUTH_INVALID", "Approval IPC target could not be revalidated")));
      });
      socket.on("data", (chunk: Buffer) => {
        total += chunk.byteLength;
        if (total > this.maxResponseBytes) {
          finish(new BrokerError("OUTPUT_LIMIT", "Approval IPC response exceeded the byte limit"));
          return;
        }
        chunks.push(chunk);
      });
      socket.on("end", () => {
        try {
          const parsed = parseJsonStrict(decodeUtf8Strict(Buffer.concat(chunks)).trim());
          finish(undefined, parseApprovalResponse(parsed));
        } catch (error) {
          finish(error instanceof BrokerError ? error : new BrokerError("AUTH_INVALID", "Approval IPC response is not valid JSON"));
        }
      });
      socket.on("error", () => finish(new BrokerError("EXECUTION_FAILED", "Approval IPC transport failed", true)));
    });
  }
}

function validateOwnerApproval(approval: IssueApprovalInput, nowMs: number, maxRequestAgeMs: number, allowUnattended: boolean): void {
  if (!/^approval:[A-Za-z0-9._:-]{1,240}$/u.test(approval.approvalId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(approval.approverPrincipalId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(approval.requestingPrincipalId) ||
      !/^mac_[a-z0-9_]{1,123}$/u.test(approval.tool) ||
      !/^\d+\.\d+$/u.test(approval.contractVersion) ||
      !validApprovalTarget(approval.targetKind, approval.targetRef) ||
      !/^[a-f0-9]{64}$/u.test(approval.payloadDigest) ||
      !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(approval.policyVersion) ||
      !APPROVAL_CLASSES.includes(approval.approvalClass) || (typeof approval.unattended !== "boolean" || (approval.unattended && (!allowUnattended || approval.approvalClass !== "trusted_profile"))) ||
      !Number.isSafeInteger(approval.issuedAtMs) || approval.issuedAtMs < 0 ||
      !Number.isSafeInteger(approval.expiresAtMs) || approval.expiresAtMs <= approval.issuedAtMs ||
      approval.useLimit !== undefined && approval.useLimit !== 1 ||
      approval.issuedAtMs > nowMs + 5_000 || nowMs - approval.issuedAtMs > maxRequestAgeMs ||
      approval.expiresAtMs <= nowMs) {
    throw new BrokerError("PRECONDITION_FAILED", "Owner approval payload is malformed or stale");
  }
}

function validApprovalTarget(kind: string, reference: string): boolean {
  return ["host", "path", "project", "process", "job", "task_profile", "app_set", "app", "app_window", "ui_element", "service", "package", "power"]
    .includes(kind) && reference.startsWith(`${kind}:`) && reference.length <= 4096 &&
    !reference.includes("\0") && !reference.includes("\n") && !reference.includes("\r");
}

function parseApprovalResponse(value: unknown): ApprovalIpcResponse {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("AUTH_INVALID", "Approval IPC response is malformed");
  }
  const record = value as Record<string, unknown>;
  if (record.ok === true && typeof record.approval_id === "string" && Number.isSafeInteger(record.expires_at_ms) &&
      Number.isSafeInteger(record.revision) && Object.keys(record).every((key) => ["ok", "approval_id", "expires_at_ms", "revision"].includes(key))) {
    return record as unknown as ApprovalIpcSuccessResponse;
  }
  if (record.ok === false && typeof record.result_class === "string" && isErrorRecord(record.error) &&
      Object.keys(record).every((key) => ["ok", "result_class", "error"].includes(key))) {
    return record as ApprovalIpcResponse;
  }
  throw new BrokerError("AUTH_INVALID", "Approval IPC response is malformed");
}

function isErrorRecord(value: unknown): value is { message: string; retryable: boolean } {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).every((key) => ["message", "retryable"].includes(key)) &&
    typeof record.message === "string" && typeof record.retryable === "boolean";
}

async function validateApprovalSocketTarget(socketPath: string): Promise<{ device: number; inode: number }> {
  if (!isCanonicalAbsolutePath(socketPath)) throw new BrokerError("AUTH_INVALID", "Approval IPC socket path is not canonical");
  const parentPath = dirname(socketPath);
  const uid = process.getuid?.();
  if (uid === undefined) {
    throw new BrokerError("AUTH_INVALID", "Approval IPC socket directory failed ownership or permission checks");
  }
  try {
    await validateOwnerSocketParentChain(socketPath, uid);
  } catch {
    throw new BrokerError("AUTH_INVALID", "Approval IPC socket parent chain failed ownership or permission checks");
  }
  const parent = await lstat(parentPath);
  const canonicalParent = await realpath(parentPath).catch(() => { throw new BrokerError("AUTH_INVALID", "Approval IPC socket directory could not be canonicalized"); });
  const canonicalParentStat = await lstat(canonicalParent);
  if (!canonicalParentStat.isDirectory() || canonicalParentStat.dev !== parent.dev || canonicalParentStat.ino !== parent.ino) {
    throw new BrokerError("AUTH_INVALID", "Approval IPC socket directory changed while canonicalizing");
  }
  const socket = await lstat(socketPath);
  if (!socket.isSocket() || socket.isSymbolicLink() || uid === undefined || socket.uid !== uid || (socket.mode & 0o177) !== 0) {
    throw new BrokerError("AUTH_INVALID", "Approval IPC target failed ownership or permission checks");
  }
  return { device: socket.dev, inode: socket.ino };
}

function isCanonicalAbsolutePath(value: string): boolean {
  return isAbsolute(value) && resolve(value) === value && !value.includes("\0");
}

export function approvalIpcClientError(error: unknown): {
  schemaVersion: "0.1";
  ok: false;
  errorClass: ErrorClass;
  message: string;
  retryable: boolean;
} {
  if (error instanceof BrokerError) {
    return { schemaVersion: "0.1", ok: false, errorClass: error.errorClass, message: error.message, retryable: error.retryable };
  }
  return { schemaVersion: "0.1", ok: false, errorClass: "PRECONDITION_FAILED", message: "Approval issuance failed", retryable: false };
}
