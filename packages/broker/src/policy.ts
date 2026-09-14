import { BrokerError, CAPABILITY_FAMILIES, CONTRACT_VERSION, PLANNED_TOOL_NAMES, SCOPES, type CapabilityFamily, type RuntimeToolState, type Scope } from "@mac-operator/contracts";
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

const TARGET_TYPES = new Set<ToolPolicy["targetType"]>([
  "broker", "policy_query", "path", "filesystem_roots", "project", "process", "service", "log_source",
  "app_set", "app", "app_window", "ui_element", "docker_runtime", "docker_object", "job", "task_profile"
]);
const APPROVAL_POLICIES = new Set<ToolPolicy["approvalPolicy"]>([
  "trusted_read", "trusted_write", "trusted_gui", "trusted_profile", "explicit_privileged_policy"
]);
const SWITCH_NAMES = ["global", "mutations", "process", "network", "gui", "destructive", "privileged"] as const;

/**
 * Validate the runtime policy shape at the authority boundary. Signed policy
 * loading already validates its source document, but Broker callers may also
 * provide an in-memory policy and may mutate a Map after construction. A
 * malformed ToolPolicy must therefore fail closed before it can authorize a
 * request or advertise a capability.
 */
export function validateBrokerPolicy(policy: BrokerPolicy): void {
  if (policy === null || typeof policy !== "object" ||
      !Number.isSafeInteger(policy.revision) || policy.revision < 0 ||
      typeof policy.version !== "string" || policy.version.length < 1 || policy.version.length > 128 ||
      typeof policy.audience !== "string" || policy.audience.length < 1 || policy.audience.length > 256 ||
      !(policy.trustedEdgeIds instanceof Set) || !(policy.trustedEdgeKeys instanceof Map) ||
      !(policy.principalGrants instanceof Map) || !Array.isArray(policy.targetRules) ||
      !Array.isArray(policy.filesystemRoots) || !(policy.tools instanceof Map) ||
      policy.killSwitches === null || typeof policy.killSwitches !== "object" ||
      SWITCH_NAMES.some((name) => typeof policy.killSwitches[name] !== "boolean")) {
    throw new BrokerError("POLICY_DENIED", "Active Broker policy is malformed");
  }
  for (const [name, tool] of policy.tools) validateToolPolicy(name, tool);
}

/**
 * Copy policy authority at a trust-boundary handoff. JavaScript Map, Set, and
 * nested arrays remain mutable even when their containing object is frozen;
 * callers must never retain the Broker's active authority by reference.
 */
export function cloneBrokerPolicy(policy: BrokerPolicy): BrokerPolicy {
  validateBrokerPolicy(policy);
  return {
    revision: policy.revision,
    version: policy.version,
    audience: policy.audience,
    trustedEdgeIds: new Set(policy.trustedEdgeIds),
    trustedEdgeKeys: new Map([...policy.trustedEdgeKeys].map(([identity, window]) => [identity, { ...window }])),
    principalGrants: new Map([...policy.principalGrants].map(([principalId, grant]) => [principalId, {
      ...grant,
      scopes: [...grant.scopes]
    }])),
    targetRules: policy.targetRules.map((rule) => ({ ...rule, target: { ...rule.target } })),
    filesystemRoots: policy.filesystemRoots.map((root) => ({
      ...root,
      denyRelativePaths: [...root.denyRelativePaths]
    })),
    killSwitches: { ...policy.killSwitches },
    tools: new Map([...policy.tools].map(([name, tool]) => [name, {
      ...tool,
      requiredScopes: [...tool.requiredScopes],
      capabilityFamilies: [...tool.capabilityFamilies]
    }]))
  };
}

function validateToolPolicy(name: string, tool: ToolPolicy): void {
  if (!PLANNED_TOOL_NAMES.includes(name as (typeof PLANNED_TOOL_NAMES)[number]) ||
      tool === null || typeof tool !== "object" || tool.tool !== name ||
      tool.contractVersion !== CONTRACT_VERSION ||
      !Array.isArray(tool.requiredScopes) || tool.requiredScopes.length < 1 ||
      new Set(tool.requiredScopes).size !== tool.requiredScopes.length ||
      tool.requiredScopes.some((scope) => !SCOPES.includes(scope)) ||
      !Array.isArray(tool.capabilityFamilies) || tool.capabilityFamilies.length < 1 ||
      new Set(tool.capabilityFamilies).size !== tool.capabilityFamilies.length ||
      tool.capabilityFamilies.some((family) => !CAPABILITY_FAMILIES.includes(family)) ||
      !TARGET_TYPES.has(tool.targetType) || typeof tool.mutation !== "boolean" ||
      !APPROVAL_POLICIES.has(tool.approvalPolicy) ||
      !Number.isSafeInteger(tool.outputCapBytes) || tool.outputCapBytes < 1 || tool.outputCapBytes > 8 * 1024 * 1024 ||
      !Number.isSafeInteger(tool.timeoutMs) || tool.timeoutMs < 1 || tool.timeoutMs > 600_000 ||
      typeof tool.implemented !== "boolean" || typeof tool.enabled !== "boolean" ||
      (tool.enabled && !tool.implemented)) {
    throw new BrokerError("POLICY_DENIED", "Active Broker policy contains a malformed tool policy");
  }
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

export function isCapabilityFamilyDisabled(
  store: BrokerStore,
  policy: BrokerPolicy,
  families: readonly CapabilityFamily[]
): boolean {
  return families.some((family) => {
    const switchName = SWITCH_BY_FAMILY[family];
    return store.isSwitchDisabled(switchName) || policy.killSwitches[switchName];
  });
}

export function authorizeTool(
  store: BrokerStore,
  policy: BrokerPolicy,
  toolName: string,
  contractVersion: string,
  principalScopes: readonly Scope[]
): ToolPolicy {
  validateBrokerPolicy(policy);
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
