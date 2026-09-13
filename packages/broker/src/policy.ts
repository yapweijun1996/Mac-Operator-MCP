import { BrokerError, PLANNED_TOOL_NAMES, type CapabilityFamily, type RuntimeToolState, type Scope } from "@mac-operator/contracts";
import type { BrokerStore, SwitchName } from "./persistence.js";
import type { FilesystemRootPolicy } from "./filesystem-inspector.js";

export interface ToolPolicy {
  tool: string;
  contractVersion: "0.1";
  requiredScopes: readonly Scope[];
  capabilityFamilies: readonly CapabilityFamily[];
  targetType: "broker" | "policy_query" | "path" | "filesystem_roots" | "project" | "process" | "service" | "log_source" | "app_set" | "app" | "app_window" | "ui_element" | "docker_runtime" | "docker_object" | "job" | "task_profile";
  mutation: boolean;
  approvalPolicy: "trusted_read" | "trusted_write" | "trusted_gui" | "trusted_profile" | "explicit_privileged_policy";
  outputCapBytes: number;
  timeoutMs: number;
  implemented: boolean;
  enabled: boolean;
}

export interface BrokerPolicy {
  revision: number;
  version: string;
  audience: string;
  trustedEdgeIds: ReadonlySet<string>;
  trustedEdgeKeys: ReadonlyMap<string, { notBeforeMs: number; expiresAtMs: number }>;
  principalGrants: ReadonlyMap<string, PrincipalGrant>;
  targetRules: readonly TargetRule[];
  filesystemRoots: readonly FilesystemRootPolicy[];
  killSwitches: Readonly<Record<SwitchName, boolean>>;
  tools: ReadonlyMap<string, ToolPolicy>;
}

export interface PrincipalGrant {
  principalId: string;
  issuer: string;
  scopes: readonly Scope[];
  enabled: boolean;
}

export type TargetKind = "host" | "path" | "project" | "process" | "job" | "task_profile" | "app_set" | "app" | "app_window" | "ui_element" | "service" | "log_source" | "docker_runtime" | "docker_object" | "package" | "power";

export interface NormalizedTarget {
  kind: TargetKind;
  reference: string;
}

export interface TargetRule {
  ruleId: string;
  effect: "allow" | "deny";
  principalId: string;
  scope: Scope;
  target: NormalizedTarget;
}

export function authorizePrincipalProjection(
  policy: BrokerPolicy,
  principalId: string,
  issuer: string,
  projectedScopes: readonly Scope[]
): void {
  const grant = policy.principalGrants.get(principalId);
  if (!grant || !grant.enabled || grant.issuer !== issuer) {
    throw new BrokerError("AUTH_INVALID", "Principal authority is invalid");
  }
  if (projectedScopes.some((scope) => !grant.scopes.includes(scope))) {
    throw new BrokerError("SCOPE_DENIED", "Edge projected authority outside the Broker grant");
  }
}

const SWITCH_BY_FAMILY: Record<CapabilityFamily, SwitchName> = {
  read: "global",
  write: "mutations",
  process: "process",
  network: "network",
  gui: "gui",
  destructive: "destructive",
  privileged: "privileged"
};

export function authorizeTool(
  store: BrokerStore,
  policy: BrokerPolicy,
  toolName: string,
  contractVersion: string,
  principalScopes: readonly Scope[]
): ToolPolicy {
  if (store.isSwitchDisabled("global") || policy.killSwitches.global) throw new BrokerError("REVOKED", "Broker admission is disabled");
  const tool = policy.tools.get(toolName);
  if (!tool || !tool.implemented) throw new BrokerError("UNSUPPORTED_CAPABILITY", "Tool is not implemented");
  if (!tool.enabled) throw new BrokerError("POLICY_DENIED", "Tool is not enabled");
  if (contractVersion !== tool.contractVersion) throw new BrokerError("UNSUPPORTED_CAPABILITY", "Contract version is not supported");
  for (const scope of tool.requiredScopes) {
    if (!principalScopes.includes(scope)) throw new BrokerError("SCOPE_DENIED", `Required scope is missing: ${scope}`);
  }
  for (const family of tool.capabilityFamilies) {
    const switchName = SWITCH_BY_FAMILY[family];
    if (switchName !== "global" && (store.isSwitchDisabled(switchName) || policy.killSwitches[switchName])) {
      throw new BrokerError("REVOKED", `${family} capability is disabled`);
    }
  }
  return tool;
}

export function authorizeTarget(
  policy: BrokerPolicy,
  principalId: string,
  scopes: readonly Scope[],
  target: NormalizedTarget
): void {
  const matchingRules = policy.targetRules.filter((rule) =>
    rule.principalId === principalId &&
    scopes.includes(rule.scope) &&
    rule.target.kind === target.kind &&
    rule.target.reference === target.reference
  );
  if (matchingRules.some((rule) => rule.effect === "deny")) {
    throw new BrokerError("POLICY_DENIED", "Target is explicitly denied");
  }
  for (const scope of scopes) {
    if (!matchingRules.some((rule) => rule.scope === scope && rule.effect === "allow")) {
      throw new BrokerError("POLICY_DENIED", "Target is not allowed for every required scope");
    }
  }
}

export function runtimeToolStates(policy: BrokerPolicy): RuntimeToolState[] {
  return PLANNED_TOOL_NAMES.map((toolName) => {
    const tool = policy.tools.get(toolName);
    return {
      tool: toolName,
      planned: true,
      implemented: tool?.implemented ?? false,
      enabled: tool?.enabled ?? false,
      ...(!tool?.enabled ? { disabledReason: tool?.implemented ? "disabled_by_policy" : "not_implemented" } : {})
    };
  });
}
