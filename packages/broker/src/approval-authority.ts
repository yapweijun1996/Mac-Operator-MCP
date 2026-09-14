import { createHmac, timingSafeEqual } from "node:crypto";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import type { ApprovalRecord, AuthenticatedApprovalIssuance, BrokerStore, IssueApprovalInput } from "./persistence.js";

const APPROVAL_ISSUE_DOMAIN = "mac-operator-approval-issue-v0.1\0";
const MAX_PREVIEW_BYTES = 8 * 1024;

export interface ApprovalIssuerKey {
  issuerId: string;
  keyId: string;
  key: Buffer;
  notBeforeMs: number;
  expiresAtMs: number;
  allowUnattended: boolean;
}

export interface UnsignedApprovalIssuance {
  protocolVersion: "0.1";
  requestId: string;
  nonce: string;
  nonceExpiresAtMs: number;
  issuerId: string;
  keyId: string;
  timestampMs: number;
  approval: IssueApprovalInput;
  previewDigest: string;
}

export interface SignedApprovalIssuance extends UnsignedApprovalIssuance {
  issuanceDigest: string;
  authenticationProof: string;
}

export interface ApprovalAuthorityOptions {
  maxRequestAgeMs?: number;
  allowedClockSkewMs?: number;
  now?: () => number;
}

export interface ApprovalPreview {
  issuerId: string;
  requestingPrincipalId: string;
  tool: string;
  contractVersion: string;
  target: { kind: string; reference: string };
  payloadDigest: string;
  policyVersion: string;
  approvalClass: string;
  unattended: boolean;
  expiresAtMs: number;
  useLimit: number;
}

export class ApprovalAuthority {
  private readonly keys = new Map<string, ApprovalIssuerKey>();
  private readonly maxRequestAgeMs: number;
  private readonly allowedClockSkewMs: number;
  private readonly now: () => number;
  private disposed = false;

  constructor(private readonly store: BrokerStore, keys: readonly ApprovalIssuerKey[], options: ApprovalAuthorityOptions = {}) {
    this.maxRequestAgeMs = options.maxRequestAgeMs ?? 60_000;
    this.allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    this.now = options.now ?? Date.now;
    if (!Number.isSafeInteger(this.maxRequestAgeMs) || this.maxRequestAgeMs < 1 || this.maxRequestAgeMs > 600_000 ||
        !Number.isSafeInteger(this.allowedClockSkewMs) || this.allowedClockSkewMs < 0 || this.allowedClockSkewMs > 60_000) {
      throw new Error("Approval authority time limits are invalid");
    }
    for (const key of keys) this.addKey(key);
  }

  addKey(record: ApprovalIssuerKey): void {
    if (this.disposed) throw new BrokerError("CANCELLED", "Approval authority is disposed");
    if (!/^[A-Za-z0-9._:@/-]{1,128}$/u.test(record.issuerId) ||
        !/^[A-Za-z0-9._:-]{1,128}$/u.test(record.keyId) ||
        record.key.byteLength < 32 ||
        !Number.isSafeInteger(record.notBeforeMs) || record.notBeforeMs < 0 ||
        !Number.isSafeInteger(record.expiresAtMs) || record.expiresAtMs <= record.notBeforeMs ||
        typeof record.allowUnattended !== "boolean") {
      throw new Error("Approval issuer key is invalid");
    }
    const identity = issuerKeyIdentity(record.issuerId, record.keyId);
    if (this.keys.has(identity)) throw new Error("Approval issuer key identity is duplicated");
    this.keys.set(identity, { ...record, key: Buffer.from(record.key) });
  }

  issue(raw: unknown): ApprovalRecord {
    if (this.disposed) throw new BrokerError("CANCELLED", "Approval authority is disposed");
    const issuance = parseSignedIssuance(raw);
    const key = this.keys.get(issuerKeyIdentity(issuance.issuerId, issuance.keyId));
    if (!key) throw new BrokerError("AUTH_INVALID", "Approval issuer key is not trusted");
    if (this.store.isRevoked("approval_key", approvalKeyIdentity(issuance.issuerId, issuance.keyId))) {
      throw new BrokerError("REVOKED", "Approval issuer key has been revoked");
    }
    const nowMs = this.now();
    if (nowMs < key.notBeforeMs || nowMs >= key.expiresAtMs) {
      throw new BrokerError("AUTH_EXPIRED", "Approval issuer key is not currently valid");
    }
    if (issuance.timestampMs > nowMs + this.allowedClockSkewMs || nowMs - issuance.timestampMs > this.maxRequestAgeMs) {
      throw new BrokerError("AUTH_EXPIRED", "Approval issuance timestamp is outside the accepted window");
    }
    if (issuance.nonceExpiresAtMs <= issuance.timestampMs ||
        issuance.nonceExpiresAtMs > issuance.timestampMs + this.maxRequestAgeMs + this.allowedClockSkewMs) {
      throw new BrokerError("AUTH_EXPIRED", "Approval issuance nonce window is invalid");
    }
    if (issuance.issuerId !== issuance.approval.approverPrincipalId ||
        issuance.issuerId === issuance.approval.requestingPrincipalId) {
      throw new BrokerError("POLICY_DENIED", "Approval issuer is not distinct and bound to the approver");
    }
    if (issuance.approval.unattended &&
        (!key.allowUnattended || issuance.approval.approvalClass !== "trusted_profile")) {
      throw new BrokerError("POLICY_DENIED", "Unattended approval requires an authorized profile issuer");
    }
    if (issuance.approval.issuedAtMs !== issuance.timestampMs) {
      throw new BrokerError("PRECONDITION_FAILED", "Approval issue time must match the signed timestamp");
    }
    const unsigned = withoutProof(issuance);
    const expectedDigest = approvalIssuanceDigest(unsigned);
    if (!safeEqualHex(issuance.issuanceDigest, expectedDigest)) {
      throw new BrokerError("AUTH_INVALID", "Approval issuance digest is invalid");
    }
    const expectedPreviewDigest = approvalPreviewDigest(issuance.approval);
    if (!safeEqualHex(issuance.previewDigest, expectedPreviewDigest)) {
      throw new BrokerError("PRECONDITION_FAILED", "Approval preview does not match the signed approval");
    }
    const expectedProof = approvalIssuanceProof(expectedDigest, key.key);
    if (!safeEqualHex(issuance.authenticationProof, expectedProof)) {
      throw new BrokerError("AUTH_INVALID", "Approval issuer authentication failed");
    }
    const record: AuthenticatedApprovalIssuance = {
      protocolVersion: issuance.protocolVersion,
      requestId: issuance.requestId,
      nonce: issuance.nonce,
      nonceExpiresAtMs: issuance.nonceExpiresAtMs,
      issuerId: issuance.issuerId,
      keyId: issuance.keyId,
      timestampMs: issuance.timestampMs,
      issuanceDigest: expectedDigest,
      previewDigest: issuance.previewDigest,
      approval: issuance.approval
    };
    return this.store.issueAuthenticatedApproval(record);
  }

  /** Wipe issuer HMAC keys after the owner-only approval channel shuts down. */
  dispose(): void {
    if (this.disposed) return;
    this.disposed = true;
    for (const record of this.keys.values()) record.key.fill(0);
    this.keys.clear();
  }
}

export function approvalPreview(input: IssueApprovalInput): ApprovalPreview {
  return {
    issuerId: input.approverPrincipalId,
    requestingPrincipalId: input.requestingPrincipalId,
    tool: input.tool,
    contractVersion: input.contractVersion,
    target: { kind: input.targetKind, reference: input.targetRef },
    payloadDigest: input.payloadDigest,
    policyVersion: input.policyVersion,
    approvalClass: input.approvalClass,
    unattended: input.unattended,
    expiresAtMs: input.expiresAtMs,
    useLimit: input.useLimit ?? 1
  };
}

export function approvalPreviewDigest(input: IssueApprovalInput): string {
  const preview = approvalPreview(input);
  const serialized = canonicalJson(preview);
  if (Buffer.byteLength(serialized, "utf8") > MAX_PREVIEW_BYTES) throw new BrokerError("PRECONDITION_FAILED", "Approval preview is too large");
  return sha256(serialized);
}

export function approvalIssuanceDigest(issuance: UnsignedApprovalIssuance): string {
  return sha256(canonicalJson(issuance));
}

export function approvalIssuanceProof(issuanceDigest: string, key: Buffer): string {
  return createHmac("sha256", key).update(APPROVAL_ISSUE_DOMAIN, "utf8").update(issuanceDigest, "utf8").digest("hex");
}

export function signApprovalIssuance(issuance: UnsignedApprovalIssuance, key: Buffer): SignedApprovalIssuance {
  const issuanceDigest = approvalIssuanceDigest(issuance);
  return { ...issuance, issuanceDigest, authenticationProof: approvalIssuanceProof(issuanceDigest, key) };
}

function parseSignedIssuance(value: unknown): SignedApprovalIssuance {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("PRECONDITION_FAILED", "Approval issuance envelope is malformed");
  }
  const record = value as Record<string, unknown>;
  const expectedKeys = new Set([
    "protocolVersion", "requestId", "nonce", "nonceExpiresAtMs", "issuerId", "keyId", "timestampMs",
    "approval", "previewDigest", "issuanceDigest", "authenticationProof"
  ]);
  if (Object.keys(record).some((key) => !expectedKeys.has(key)) ||
      record.protocolVersion !== "0.1" || typeof record.requestId !== "string" ||
      typeof record.nonce !== "string" || typeof record.issuerId !== "string" || typeof record.keyId !== "string" ||
      !Number.isSafeInteger(record.nonceExpiresAtMs) || !Number.isSafeInteger(record.timestampMs) ||
      typeof record.previewDigest !== "string" || typeof record.issuanceDigest !== "string" ||
      typeof record.authenticationProof !== "string" || record.approval === null ||
      typeof record.approval !== "object" || Array.isArray(record.approval)) {
      throw new BrokerError("PRECONDITION_FAILED", "Approval issuance envelope is malformed");
  }
  const approvalRecord = record.approval as Record<string, unknown>;
  const approvalKeys = new Set([
    "approvalId", "approverPrincipalId", "requestingPrincipalId", "tool", "contractVersion",
    "targetKind", "targetRef", "payloadDigest", "policyVersion", "approvalClass", "unattended",
    "issuedAtMs", "expiresAtMs", "useLimit"
  ]);
  if (Object.keys(approvalRecord).some((key) => !approvalKeys.has(key))) {
    throw new BrokerError("PRECONDITION_FAILED", "Approval payload contains an unknown field");
  }
  const requestId = record.requestId as string;
  const nonce = record.nonce as string;
  const nonceExpiresAtMs = record.nonceExpiresAtMs as number;
  const issuerId = record.issuerId as string;
  const keyId = record.keyId as string;
  const timestampMs = record.timestampMs as number;
  const previewDigest = record.previewDigest as string;
  const issuanceDigest = record.issuanceDigest as string;
  const authenticationProof = record.authenticationProof as string;
  return {
    protocolVersion: "0.1",
    requestId,
    nonce,
    nonceExpiresAtMs,
    issuerId,
    keyId,
    timestampMs,
    approval: record.approval as IssueApprovalInput,
    previewDigest,
    issuanceDigest,
    authenticationProof
  };
}

function withoutProof(issuance: SignedApprovalIssuance): UnsignedApprovalIssuance {
  return {
    protocolVersion: issuance.protocolVersion,
    requestId: issuance.requestId,
    nonce: issuance.nonce,
    nonceExpiresAtMs: issuance.nonceExpiresAtMs,
    issuerId: issuance.issuerId,
    keyId: issuance.keyId,
    timestampMs: issuance.timestampMs,
    approval: issuance.approval,
    previewDigest: issuance.previewDigest
  };
}

function issuerKeyIdentity(issuerId: string, keyId: string): string {
  return `${issuerId}:${keyId}`;
}

export function approvalKeyIdentity(issuerId: string, keyId: string): string {
  return issuerKeyIdentity(issuerId, keyId);
}

function safeEqualHex(left: string, right: string): boolean {
  if (!/^[a-f0-9]{64}$/u.test(left) || !/^[a-f0-9]{64}$/u.test(right)) return false;
  const leftBytes = Buffer.from(left, "hex");
  const rightBytes = Buffer.from(right, "hex");
  return timingSafeEqual(leftBytes, rightBytes);
}
