#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { lstat, realpath } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError, sha256, type ErrorClass } from "@mac-operator/contracts";
import { ApprovalIpcClient } from "./approval-ipc-client.js";
import { approvalPreview } from "./approval-authority.js";
import { ApprovalIssuerKeyManager } from "./approval-keyring.js";
import { BrokerStore, type ApprovalClass, type ApprovalPreviewRecord, type ApprovalRecord, type IssueApprovalInput } from "./persistence.js";

const MAX_TIMEOUT_MS = 600_000;
const MAX_TTL_MS = 600_000;
const APPROVAL_CLASSES: readonly ApprovalClass[] = ["trusted_write", "trusted_gui", "trusted_profile", "explicit_privileged_policy"];

export interface ApprovalIssuanceCliCommand {
  kind: "issue";
  databasePath: string;
  socketPath: string;
  keyConfigPath: string;
  issuerId: string;
  keyId: string;
  requestingPrincipalId: string;
  tool: string;
  contractVersion: string;
  targetKind: string;
  targetRef: string;
  payloadDigest: string;
  policyVersion: string;
  approvalClass: ApprovalClass;
  approvalId?: string;
  ttlMs: number;
  timeoutMs: number;
  confirmation: "issue";
}

export interface ApprovalPreviewIssuanceCliCommand {
  kind: "issue-preview";
  databasePath: string;
  socketPath: string;
  keyConfigPath: string;
  issuerId: string;
  keyId: string;
  requestId: string;
  timeoutMs: number;
  confirmation: "issue";
}

export interface ApprovalIssuanceCliResult {
  schemaVersion: "0.1";
  operation: "issue";
  approvalId: string;
  expiresAtMs: number;
  revision: number;
  verified: true;
}

export interface ApprovalIssuanceCliClient {
  issue(approval: IssueApprovalInput): Promise<{ approval_id: string; expires_at_ms: number; revision: number }>;
}

export interface ApprovalConfirmationIO {
  input?: NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  isTTY?: boolean;
  timeoutMs?: number;
}

export type ApprovalConfirmation = (approval: IssueApprovalInput) => Promise<void>;

export const APPROVAL_ISSUANCE_CLI_USAGE = [
  "mac-operator-approval issue --database PATH --socket PATH --key-config PATH --issuer-id ID --key-id ID --requesting-principal ID --tool mac_* --contract-version X.Y --target-kind KIND --target-ref REF --payload-digest SHA256 --policy-version policy-X --approval-class CLASS --ttl-ms N --confirm issue",
  "mac-operator-approval issue --database PATH --socket PATH --key-config PATH --issuer-id ID --key-id ID --request-id REQUEST_ID --confirm issue",
  "The command prints a bounded preview and requires TTY input: APPROVE <approvalId>."
].join("\n");

export function parseApprovalIssuanceCliArgs(args: readonly string[]): ApprovalIssuanceCliCommand {
  if (args.length < 1 || args[0] !== "issue") throw usageError("Only the issue operation is supported");
  const values = new Map<string, string>();
  for (let index = 1; index < args.length; index += 1) {
    const option = args[index];
    if (typeof option !== "string" || !option.startsWith("--") || option.length < 3 || values.has(option)) {
      throw usageError("Approval options are malformed or duplicated");
    }
    const value = args[index + 1];
    if (typeof value !== "string" || value.startsWith("--")) throw usageError(`Missing value for ${option}`);
    values.set(option, value);
    index += 1;
  }
  const required = (option: string): string => {
    const value = values.get(option);
    if (value === undefined || value.length === 0) throw usageError(`${option} is required`);
    return value;
  };
  const databasePath = requiredPath(values, "--database");
  const socketPath = requiredPath(values, "--socket");
  const keyConfigPath = requiredPath(values, "--key-config");
  const issuerId = required("--issuer-id");
  const keyId = required("--key-id");
  const requestingPrincipalId = required("--requesting-principal");
  const tool = required("--tool");
  const contractVersion = required("--contract-version");
  const targetKind = required("--target-kind");
  const targetRef = required("--target-ref");
  const payloadDigest = required("--payload-digest");
  const policyVersion = required("--policy-version");
  const approvalClass = required("--approval-class") as ApprovalClass;
  const confirmation = required("--confirm");
  for (const key of values.keys()) {
    if (!["--database", "--socket", "--key-config", "--issuer-id", "--key-id", "--requesting-principal", "--tool", "--contract-version", "--target-kind", "--target-ref", "--payload-digest", "--policy-version", "--approval-class", "--ttl-ms", "--timeout-ms", "--confirm"].includes(key)) {
      throw usageError("Approval options contain an unsupported field");
    }
  }
  if (!/^[A-Za-z0-9._:@/-]{1,128}$/u.test(issuerId) || !/^[A-Za-z0-9._:-]{1,128}$/u.test(keyId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(requestingPrincipalId) || !/^mac_[a-z0-9_]{1,123}$/u.test(tool) ||
      !/^\d+\.\d+$/u.test(contractVersion) || !/^[a-f0-9]{64}$/u.test(payloadDigest) ||
      !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(policyVersion) || !APPROVAL_CLASSES.includes(approvalClass) ||
      !["host", "path", "project", "process", "job", "task_profile", "app_set", "app", "app_window", "ui_element", "service", "package", "power"].includes(targetKind) ||
      !targetRef.startsWith(`${targetKind}:`) || targetRef.length > 4096 || targetRef.includes("\0") ||
      targetRef.includes("\n") || targetRef.includes("\r") || confirmation !== "issue") {
    throw usageError("Approval fields are malformed or confirmation is missing");
  }
  return {
    kind: "issue", databasePath, socketPath, keyConfigPath, issuerId, keyId, requestingPrincipalId, tool,
    contractVersion, targetKind, targetRef, payloadDigest, policyVersion, approvalClass,
    ttlMs: parseBoundedInteger(values.get("--ttl-ms"), "--ttl-ms", 1, MAX_TTL_MS, 60_000),
    timeoutMs: parseBoundedInteger(values.get("--timeout-ms"), "--timeout-ms", 1, MAX_TIMEOUT_MS, 15_000),
    confirmation: "issue"
  };
}

export function parseApprovalPreviewIssuanceCliArgs(args: readonly string[]): ApprovalPreviewIssuanceCliCommand {
  if (args.length < 1 || args[0] !== "issue") throw usageError("Only the issue operation is supported");
  const values = parseOptionValues(args.slice(1));
  const allowed = ["--database", "--socket", "--key-config", "--issuer-id", "--key-id", "--request-id", "--timeout-ms", "--confirm"];
  for (const key of values.keys()) {
    if (!allowed.includes(key)) throw usageError("Preview approval options contain an unsupported field");
  }
  const requestId = requiredValue(values, "--request-id");
  const issuerId = requiredValue(values, "--issuer-id");
  const keyId = requiredValue(values, "--key-id");
  const confirmation = requiredValue(values, "--confirm");
  if (!/^[A-Za-z0-9._:@/+-]{1,128}$/u.test(requestId) ||
      !/^[A-Za-z0-9._:@/-]{1,128}$/u.test(issuerId) ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(keyId) || confirmation !== "issue") {
    throw usageError("Preview approval fields are malformed or confirmation is missing");
  }
  return {
    kind: "issue-preview",
    databasePath: requiredPath(values, "--database"),
    socketPath: requiredPath(values, "--socket"),
    keyConfigPath: requiredPath(values, "--key-config"),
    issuerId,
    keyId,
    requestId,
    timeoutMs: parseBoundedInteger(values.get("--timeout-ms"), "--timeout-ms", 1, MAX_TIMEOUT_MS, 15_000),
    confirmation: "issue"
  };
}

export async function executeApprovalIssuanceCliCommand(
  command: ApprovalIssuanceCliCommand,
  client: ApprovalIssuanceCliClient,
  now = Date.now(),
  confirm: ApprovalConfirmation
): Promise<ApprovalIssuanceCliResult> {
  const approval: IssueApprovalInput = {
    approvalId: command.approvalId ?? `approval:owner-${randomUUID()}`,
    approverPrincipalId: command.issuerId,
    requestingPrincipalId: command.requestingPrincipalId,
    tool: command.tool,
    contractVersion: command.contractVersion,
    targetKind: command.targetKind,
    targetRef: command.targetRef,
    payloadDigest: command.payloadDigest,
    policyVersion: command.policyVersion,
    approvalClass: command.approvalClass,
    unattended: false,
    issuedAtMs: now,
    expiresAtMs: now + command.ttlMs,
    useLimit: 1
  };
  await confirm(approval);
  const response = await client.issue(approval);
  if (response.approval_id !== approval.approvalId || response.expires_at_ms !== approval.expiresAtMs) {
    throw new BrokerError("AUTH_INVALID", "Approval issuance readback does not match the requested approval");
  }
  return { schemaVersion: "0.1", operation: "issue", approvalId: approval.approvalId, expiresAtMs: approval.expiresAtMs, revision: response.revision, verified: true };
}

export function approvalIssuanceCommandFromPreview(
  command: ApprovalPreviewIssuanceCliCommand,
  preview: ApprovalPreviewRecord,
  now: number
): ApprovalIssuanceCliCommand {
  if (preview.status !== "pending" || !Number.isSafeInteger(now) || now < 0 || preview.expiresAtMs <= now) {
    throw new BrokerError("AUTH_EXPIRED", "Approval preview is no longer live");
  }
  const ttlMs = preview.expiresAtMs - now;
  if (ttlMs < 1 || ttlMs > MAX_TTL_MS) throw new BrokerError("PRECONDITION_FAILED", "Approval preview TTL is outside the supported range");
  return {
    kind: "issue",
    databasePath: command.databasePath,
    socketPath: command.socketPath,
    keyConfigPath: command.keyConfigPath,
    issuerId: command.issuerId,
    keyId: command.keyId,
    requestingPrincipalId: preview.requestingPrincipalId,
    tool: preview.tool,
    contractVersion: preview.contractVersion,
    targetKind: preview.targetKind,
    targetRef: preview.targetRef,
    payloadDigest: preview.payloadDigest,
    policyVersion: preview.policyVersion,
    approvalClass: preview.approvalClass,
    approvalId: `approval:owner-preview-${sha256(preview.requestId).slice(0, 48)}`,
    ttlMs,
    timeoutMs: command.timeoutMs,
    confirmation: "issue"
  };
}

export async function runApprovalIssuanceCli(args: readonly string[]): Promise<ApprovalIssuanceCliResult> {
  const previewCommand = args[0] === "issue" && args.includes("--request-id")
    ? parseApprovalPreviewIssuanceCliArgs(args)
    : undefined;
  const command = previewCommand === undefined ? parseApprovalIssuanceCliArgs(args) : undefined;
  const databasePath = previewCommand?.databasePath ?? command!.databasePath;
  const keyConfigPath = previewCommand?.keyConfigPath ?? command!.keyConfigPath;
  const issuerId = previewCommand?.issuerId ?? command!.issuerId;
  const keyId = previewCommand?.keyId ?? command!.keyId;
  await assertProtectedDatabase(databasePath);
  const store = new BrokerStore(databasePath);
  const keyManager = new ApprovalIssuerKeyManager(keyConfigPath, store);
  let client: ApprovalIpcClient | undefined;
  try {
    const snapshot = await keyManager.restore();
    const issuer = snapshot.keys.find((key) => key.issuerId === issuerId && key.keyId === keyId);
    if (!issuer) throw new BrokerError("AUTH_INVALID", "Requested approval issuer key is not active");
    const timeoutMs = previewCommand?.timeoutMs ?? command!.timeoutMs;
    const socketPath = previewCommand?.socketPath ?? command!.socketPath;
    client = new ApprovalIpcClient({ socketPath, issuerId, keyId, authenticationKey: issuer.key, timeoutMs });
    if (previewCommand !== undefined) {
      const issueNow = Date.now();
      const preview = store.approvalPreview(previewCommand.requestId, issueNow);
      if (!preview) throw new BrokerError("TARGET_NOT_FOUND", "Approval preview was not found or is no longer pending");
      const resolved = approvalIssuanceCommandFromPreview(previewCommand, preview, issueNow);
      const existing = resolved.approvalId === undefined ? undefined : store.approvalRecord(resolved.approvalId);
      if (existing !== undefined) {
        const existingApproval = approvalRecordAsIssueInput(existing);
        if (existing.approverPrincipalId !== issuerId || !approvalMatchesPreview(existing, preview, issueNow)) {
          throw new BrokerError("AUDIT_UNAVAILABLE", "Existing preview approval does not match the pending preview");
        }
        await confirmApprovalPreview(existingApproval);
        const linked = store.markApprovalPreviewIssued(previewCommand.requestId, existing.approvalId, issueNow);
        return {
          schemaVersion: "0.1",
          operation: "issue",
          approvalId: linked.approvalId ?? existing.approvalId,
          expiresAtMs: existing.expiresAtMs,
          revision: existing.revision,
          verified: true
        };
      }
      const result = await executeApprovalIssuanceCliCommand(resolved, client, issueNow, approval => confirmApprovalPreview(approval));
      store.markApprovalPreviewIssued(previewCommand.requestId, result.approvalId, issueNow);
      return result;
    }
    return await executeApprovalIssuanceCliCommand(command!, client, Date.now(), approval => confirmApprovalPreview(approval));
  } finally {
    client?.dispose();
    keyManager.dispose();
    store.close();
  }
}

export async function confirmApprovalPreview(
  approval: IssueApprovalInput,
  options: ApprovalConfirmationIO = {}
): Promise<void> {
  const input = options.input ?? process.stdin;
  const output = options.output ?? process.stdout;
  const isTTY = options.isTTY ?? Boolean((input as NodeJS.ReadableStream & { isTTY?: boolean }).isTTY &&
    (output as NodeJS.WritableStream & { isTTY?: boolean }).isTTY);
  if (!isTTY) throw new BrokerError("POLICY_DENIED", "Interactive owner confirmation requires a TTY");
  const timeoutMs = options.timeoutMs ?? 120_000;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000) {
    throw new BrokerError("PRECONDITION_FAILED", "Owner confirmation timeout is invalid");
  }
  const preview = approvalPreview(approval);
  output.write("OWNER APPROVAL PREVIEW\n");
  output.write(`Approval ID: ${JSON.stringify(approval.approvalId)}\n`);
  output.write(`Issuer: ${JSON.stringify(preview.issuerId)}\n`);
  output.write(`Requesting principal: ${JSON.stringify(preview.requestingPrincipalId)}\n`);
  output.write(`Tool: ${JSON.stringify(preview.tool)}\n`);
  output.write(`Contract: ${JSON.stringify(preview.contractVersion)}\n`);
  output.write(`Target: ${JSON.stringify(preview.target)}\n`);
  output.write(`Payload digest: ${JSON.stringify(preview.payloadDigest)}\n`);
  output.write(`Policy: ${JSON.stringify(preview.policyVersion)}\n`);
  output.write(`Approval class: ${JSON.stringify(preview.approvalClass)}\n`);
  output.write(`Unattended: ${JSON.stringify(preview.unattended)}\n`);
  output.write(`Expires: ${JSON.stringify(new Date(preview.expiresAtMs).toISOString())}\n`);
  output.write(`Use limit: ${JSON.stringify(preview.useLimit)}\n`);
  output.write(`Type APPROVE ${approval.approvalId} to continue: `);
  const response = await readConfirmationLine(input, timeoutMs);
  if (response !== `APPROVE ${approval.approvalId}`) {
    throw new BrokerError("POLICY_DENIED", "Owner approval confirmation did not match the displayed approval");
  }
}

function approvalRecordAsIssueInput(approval: ApprovalRecord): IssueApprovalInput {
  return {
    approvalId: approval.approvalId,
    approverPrincipalId: approval.approverPrincipalId,
    requestingPrincipalId: approval.requestingPrincipalId,
    tool: approval.tool,
    contractVersion: approval.contractVersion,
    targetKind: approval.targetKind,
    targetRef: approval.targetRef,
    payloadDigest: approval.payloadDigest,
    policyVersion: approval.policyVersion,
    approvalClass: approval.approvalClass,
    unattended: approval.unattended,
    issuedAtMs: approval.issuedAtMs,
    expiresAtMs: approval.expiresAtMs,
    useLimit: approval.useLimit
  };
}

function approvalMatchesPreview(approval: ApprovalRecord, preview: ApprovalPreviewRecord, nowMs: number): boolean {
  return approval.requestingPrincipalId === preview.requestingPrincipalId &&
    approval.tool === preview.tool && approval.contractVersion === preview.contractVersion &&
    approval.targetKind === preview.targetKind && approval.targetRef === preview.targetRef &&
    approval.payloadDigest === preview.payloadDigest && approval.policyVersion === preview.policyVersion &&
    approval.approvalClass === preview.approvalClass && approval.unattended === preview.unattended &&
    approval.issuedAtMs <= nowMs && approval.expiresAtMs === preview.expiresAtMs &&
    approval.revokedAtMs === null && approval.usedCount === 0 && approval.useLimit === 1;
}

function readConfirmationLine(input: NodeJS.ReadableStream, timeoutMs: number): Promise<string> {
  const stream = input as NodeJS.ReadableStream & {
    setEncoding?: (encoding: BufferEncoding) => void;
  };
  stream.setEncoding?.("utf8");
  return new Promise((resolvePromise, rejectPromise) => {
    let buffer = "";
    let settled = false;
    const finish = (error?: Error, value?: string) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      stream.removeListener("data", onData);
      stream.removeListener("end", onEnd);
      stream.removeListener("error", onError);
      if (error) rejectPromise(error); else resolvePromise(value!);
    };
    const onData = (chunk: string | Buffer) => {
      buffer += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      if (Buffer.byteLength(buffer, "utf8") > 256) {
        finish(new BrokerError("OUTPUT_LIMIT", "Owner confirmation input exceeded the byte limit"));
        return;
      }
      const newline = buffer.indexOf("\n");
      if (newline >= 0) finish(undefined, buffer.slice(0, newline).replace(/\r$/u, ""));
    };
    const onEnd = () => finish(new BrokerError("CANCELLED", "Owner confirmation input ended"));
    const onError = () => finish(new BrokerError("EXECUTION_FAILED", "Owner confirmation input failed"));
    const timer = setTimeout(() => finish(new BrokerError("TIMEOUT", "Owner confirmation timed out", true)), timeoutMs);
    stream.on("data", onData);
    stream.once("end", onEnd);
    stream.once("error", onError);
  });
}

function requiredPath(values: ReadonlyMap<string, string>, option: string): string {
  const value = values.get(option);
  if (value === undefined || !isAbsolute(value) || resolve(value) !== value || value.includes("\0") || value.includes("\n")) {
    throw usageError(`${option} must be a canonical absolute path`);
  }
  return value;
}

function parseOptionValues(args: readonly string[]): Map<string, string> {
  const values = new Map<string, string>();
  for (let index = 0; index < args.length; index += 2) {
    const option = args[index];
    const value = args[index + 1];
    if (typeof option !== "string" || !option.startsWith("--") || option.length < 3 || values.has(option) ||
        typeof value !== "string" || value.startsWith("--")) {
      throw usageError("Approval options are malformed or duplicated");
    }
    values.set(option, value);
  }
  return values;
}

function requiredValue(values: ReadonlyMap<string, string>, option: string): string {
  const value = values.get(option);
  if (value === undefined || value.length === 0) throw usageError(`${option} is required`);
  return value;
}

function parseBoundedInteger(value: string | undefined, option: string, min: number, max: number, fallback: number): number {
  if (value === undefined) return fallback;
  if (!/^[0-9]{1,6}$/u.test(value)) throw usageError(`${option} is malformed`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw usageError(`${option} is outside the supported range`);
  return parsed;
}

function usageError(message: string): BrokerError {
  return new BrokerError("PRECONDITION_FAILED", message);
}

async function assertProtectedDatabase(path: string): Promise<void> {
  const stat = await lstat(path).catch(() => undefined);
  const uid = process.getuid?.();
  if (!stat || !stat.isFile() || stat.isSymbolicLink() || uid === undefined || stat.uid !== uid || (stat.mode & 0o077) !== 0) {
    throw new BrokerError("POLICY_DENIED", "Approval database is not a protected owner-only file");
  }
  const parentPath = dirname(path);
  const parent = await lstat(parentPath).catch(() => undefined);
  if (!parent || !parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== uid || (parent.mode & 0o077) !== 0) {
    throw new BrokerError("POLICY_DENIED", "Approval database directory is not protected");
  }
  const canonicalParent = await realpath(parentPath).catch(() => undefined);
  if (canonicalParent === undefined) throw new BrokerError("POLICY_DENIED", "Approval database directory is not canonical");
  const canonicalStat = await lstat(canonicalParent);
  if (!canonicalStat.isDirectory() || canonicalStat.dev !== parent.dev || canonicalStat.ino !== parent.ino) {
    throw new BrokerError("POLICY_DENIED", "Approval database directory changed while opening");
  }
}

export async function main(args = process.argv.slice(2)): Promise<void> {
  if (args.length === 1 && (args[0] === "--help" || args[0] === "-h")) {
    process.stdout.write(`${APPROVAL_ISSUANCE_CLI_USAGE}\n`);
    return;
  }
  try {
    const result = await runApprovalIssuanceCli(args);
    process.stdout.write(`${JSON.stringify({ schemaVersion: "0.1", ok: true, result })}\n`);
  } catch (error) {
    const failure: { schemaVersion: "0.1"; ok: false; errorClass: ErrorClass; message: string; retryable: boolean } = error instanceof BrokerError
      ? { schemaVersion: "0.1", ok: false, errorClass: error.errorClass, message: error.message, retryable: error.retryable }
      : { schemaVersion: "0.1", ok: false, errorClass: "PRECONDITION_FAILED", message: "Approval issuance failed", retryable: false };
    process.stderr.write(`${JSON.stringify(failure)}\n`);
    process.exitCode = 1;
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  void main();
}
