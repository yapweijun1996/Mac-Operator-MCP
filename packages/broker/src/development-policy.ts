import type { Scope } from "@mac-operator/contracts";
import type { ToolPolicy } from "./policy.js";

export type DevelopmentPermissionTier = "READ" | "SAFE_WRITE" | "AGENT_RUN" | "HIGH_RISK";

const definitions: readonly [string, DevelopmentPermissionTier, readonly Scope[]][] = [
  ["mac_git_worktree_create", "SAFE_WRITE", ["mac.project.write", "mac.git.write"]],
  ["mac_git_worktree_list", "READ", ["mac.project.read", "mac.git.read"]],
  ["mac_git_worktree_remove", "SAFE_WRITE", ["mac.project.write", "mac.git.write"]],
  ["mac_git_branch_create", "SAFE_WRITE", ["mac.project.write", "mac.git.write"]],
  ["mac_codex_preflight", "READ", ["mac.project.read", "mac.agent.read"]],
  ["mac_codex_run", "AGENT_RUN", ["mac.project.read", "mac.project.write", "mac.agent.run"]],
  ["mac_test_run", "AGENT_RUN", ["mac.project.read", "mac.project.write", "mac.task.run"]],
  ["mac_build_run", "AGENT_RUN", ["mac.project.read", "mac.project.write", "mac.task.run"]],
  ["mac_pr_prepare", "READ", ["mac.project.read", "mac.git.read", "mac.job.read"]],
  ["mac_execution_audit", "READ", ["mac.project.read", "mac.audit.read"]]
];

export const DEVELOPMENT_TOOL_NAMES = definitions.map(([name]) => name);
export const DEVELOPMENT_EXECUTION_TOOLS = ["mac_codex_run", "mac_test_run", "mac_build_run"];

export function developmentTier(tool: string): DevelopmentPermissionTier | undefined {
  return definitions.find(([name]) => name === tool)?.[1];
}

/** Authority is additive and disabled until the operator configures the gateway. */
export const developmentToolPolicies: readonly ToolPolicy[] = definitions.map(([tool, tier, requiredScopes]) => ({
  tool, contractVersion: "0.1", requiredScopes, targetType: "project", enabled: false, implemented: true,
  mutation: tier !== "READ",
  capabilityFamilies: tier === "READ" ? ["read"] : tier === "HIGH_RISK" ? ["write", "network", "destructive"] :
    tier === "AGENT_RUN" ? ["write", "process", "network"] : ["write"],
  approvalPolicy: tier === "READ" ? "trusted_read" : tier === "HIGH_RISK" ? "explicit_privileged_policy" :
    tier === "AGENT_RUN" ? "trusted_profile" : "trusted_write",
  timeoutMs: tier === "AGENT_RUN" ? 600_000 : 30_000,
  outputCapBytes: tier === "AGENT_RUN" ? 65_536 : 131_072
}));
