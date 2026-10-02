import { sha256 } from "@mac-operator/contracts";
import type { IssueApprovalInput } from "./persistence.js";

export const DEVELOPMENT_ISSUER_KEY_ID = "personal-development-1";
const WRITE_TOOLS = new Set(["mac_git_worktree_create", "mac_git_branch_create", "mac_git_worktree_remove", "mac_git_stage", "mac_git_commit"]);
const EXECUTION_TOOLS = new Set(["mac_codex_run", "mac_test_run", "mac_build_run", "mac_task_run"]);

/** This issuer can never authorize a host command or any HIGH_RISK operation. */
export function isDevelopmentDelegatedApproval(approval: IssueApprovalInput, issuerId: string, keyId: string): boolean {
  return keyId === DEVELOPMENT_ISSUER_KEY_ID && issuerId === `development-approver-${sha256(approval.requestingPrincipalId).slice(0, 32)}` &&
    approval.approverPrincipalId === issuerId && approval.unattended === true &&
    approval.expiresAtMs - approval.issuedAtMs <= 630_000 &&
    (WRITE_TOOLS.has(approval.tool) && approval.approvalClass === "trusted_write" && approval.targetKind === "project" ||
      EXECUTION_TOOLS.has(approval.tool) && approval.approvalClass === "trusted_profile" &&
      (approval.tool === "mac_task_run" ? approval.targetKind === "task_profile" : approval.targetKind === "project"));
}
