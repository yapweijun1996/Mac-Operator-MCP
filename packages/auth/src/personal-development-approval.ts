import { isAbsolute, resolve } from "node:path";
import { ApprovalIpcClient, type ApprovalIssuerRuntimeAssembly, type DevelopmentOperation, type ManagedWorktrees } from "@mac-operator/broker";
import { sha256 } from "@mac-operator/contracts";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const REQUEST_ID = /^[A-Za-z0-9._:@/+\-]{1,128}$/u;
const MAX_APPROVAL_LIFETIME_MS = 630_000;
const CREATION_TOOLS = new Set(["mac_git_worktree_create", "mac_git_branch_create"]);
const EXECUTION_TOOLS = new Set(["mac_codex_run", "mac_test_run", "mac_build_run", "mac_task_run"]);
const LOCAL_GIT_TOOLS = new Set(["mac_git_stage", "mac_git_commit"]);
const FIELDS = ["requestId", "principalId", "sessionId", "tool", "contractVersion", "policyVersion", "targetKind", "targetRef",
  "payloadDigest", "approvalClass", "expiresAtMs", "projectRoot", "worktree", "taskId"];

export interface PersonalDevelopmentApproverOptions {
  principalId: string;
  runtime: ApprovalIssuerRuntimeAssembly;
  socketPath: string;
  worktrees: ManagedWorktrees;
  developmentProjects: readonly string[];
  taskProfiles: readonly string[];
  now?: () => number;
}

/** The V2 OAuth grant delegates only exact local coding operations to this separate issuer. */
export function createPersonalDevelopmentApprover(options: PersonalDevelopmentApproverOptions): (operation: DevelopmentOperation) => Promise<boolean> {
  if (!ID.test(options.principalId) || !stringArray(options.developmentProjects, 16) || options.developmentProjects.length === 0 ||
      options.developmentProjects.some(path => !canonicalPath(path)) || !stringArray(options.taskProfiles, 64) ||
      options.taskProfiles.length === 0 || options.taskProfiles.some(profile => !ID.test(profile)) ||
      new Set(options.developmentProjects).size !== options.developmentProjects.length || new Set(options.taskProfiles).size !== options.taskProfiles.length) {
    throw new Error("Personal development delegation configuration is malformed");
  }
  const projects = new Set(options.developmentProjects);
  const profiles = new Set(options.taskProfiles);
  const { principalId, runtime, socketPath, worktrees } = options;
  const now = options.now ?? Date.now;
  const expectedIssuer = `development-approver-${sha256(principalId).slice(0, 32)}`;
  return async (operation: DevelopmentOperation): Promise<boolean> => {
    if (!plainData(operation) || Object.keys(operation).some(key => !FIELDS.includes(key)) ||
        operation.principalId !== principalId || typeof operation.tool !== "string" || typeof operation.targetKind !== "string" || typeof operation.targetRef !== "string" ||
        typeof operation.requestId !== "string" || !REQUEST_ID.test(operation.requestId) ||
        typeof operation.sessionId !== "string" || !ID.test(operation.sessionId) || operation.contractVersion !== "0.1" ||
        typeof operation.policyVersion !== "string" || !/^policy-[A-Za-z0-9._:-]{1,120}$/u.test(operation.policyVersion) ||
        typeof operation.payloadDigest !== "string" || !/^[a-f0-9]{64}$/u.test(operation.payloadDigest) || !projects.has(operation.projectRoot) ||
        !Number.isSafeInteger(operation.expiresAtMs) || operation.taskId !== undefined && (typeof operation.taskId !== "string" || !ID.test(operation.taskId))) return false;
    const issuedAtMs = now();
    if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0 || operation.expiresAtMs <= issuedAtMs) return false;
    const creation = CREATION_TOOLS.has(operation.tool);
    const execution = EXECUTION_TOOLS.has(operation.tool);
    const localGit = LOCAL_GIT_TOOLS.has(operation.tool);
    if (!creation && !execution && !localGit && operation.tool !== "mac_git_worktree_remove") return false;
    if (operation.approvalClass !== (execution ? "trusted_profile" : "trusted_write")) return false;
    if (operation.tool === "mac_task_run") {
      if (operation.targetKind !== "task_profile" || !operation.targetRef.startsWith("task_profile:") ||
          !profiles.has(operation.targetRef.slice("task_profile:".length))) return false;
    } else if (operation.targetKind !== "project" || operation.targetRef !== `project:${localGit ? operation.worktree : operation.projectRoot}`) return false;
    if (creation) {
      if (operation.taskId === undefined || operation.worktree !== undefined) return false;
    } else {
      if (!canonicalPath(operation.worktree) || operation.worktree === operation.projectRoot || !localGit && operation.taskId === undefined) return false;
      try {
        const record = worktrees.require(operation.worktree, operation.projectRoot, principalId, operation.taskId);
        if (record.state !== "active" || record.owner !== principalId || record.projectRoot !== operation.projectRoot ||
            record.worktree !== operation.worktree || !ID.test(record.taskId)) return false;
      } catch { return false; }
    }
    const keys = runtime.keyManager.current().keys.filter(key => key.keyId === "personal-development-1" &&
      key.issuerId === expectedIssuer && key.allowUnattended === true);
    if (keys.length !== 1) throw new Error("Personal development requires its separate delegated issuer");
    const issuer = keys[0]!;
    const expiresAtMs = Math.min(operation.expiresAtMs, issuedAtMs + MAX_APPROVAL_LIFETIME_MS, issuer.expiresAtMs);
    if (issuedAtMs < issuer.notBeforeMs || expiresAtMs <= issuedAtMs) return false;
    const client = new ApprovalIpcClient({ socketPath, issuerId: issuer.issuerId, keyId: issuer.keyId,
      authenticationKey: issuer.key, allowUnattended: true, timeoutMs: 5_000, now });
    try {
      await client.issue({ approvalId: `approval:development-${sha256(operation.requestId).slice(0, 48)}`,
        approverPrincipalId: issuer.issuerId, requestingPrincipalId: operation.principalId, tool: operation.tool,
        contractVersion: operation.contractVersion, targetKind: operation.targetKind, targetRef: operation.targetRef,
        payloadDigest: operation.payloadDigest, policyVersion: operation.policyVersion, approvalClass: operation.approvalClass,
        unattended: true, issuedAtMs, expiresAtMs, useLimit: 1 });
      return true;
    } finally { client.dispose(); }
  };
}

function canonicalPath(value: unknown): value is string {
  return typeof value === "string" && value.length > 1 && value.length <= 4096 && !/[\x00-\x1f]/u.test(value) && isAbsolute(value) && resolve(value) === value;
}
function plainData(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null) && Object.getOwnPropertySymbols(value).length === 0 &&
    Object.keys(value).length === Object.getOwnPropertyNames(value).length &&
    Object.getOwnPropertyNames(value).every(key => { const descriptor = Object.getOwnPropertyDescriptor(value, key); return descriptor !== undefined && "value" in descriptor; });
}
function stringArray(value: unknown, max: number): value is string[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > max || Object.getOwnPropertySymbols(value).length !== 0 ||
      Object.keys(value).length !== value.length || Object.getOwnPropertyNames(value).length !== value.length + 1) return false;
  return Array.from({ length: value.length }, (_, index) => Object.getOwnPropertyDescriptor(value, String(index))).every(descriptor =>
    descriptor !== undefined && "value" in descriptor && typeof descriptor.value === "string");
}
