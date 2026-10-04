import { resolve } from "node:path";
import { BrokerError, CAPABILITY_FAMILIES, CONTRACT_VERSION, PLANNED_TOOL_NAMES, SCOPES, type CapabilityFamily, type RuntimeToolState, type Scope } from "@mac-operator/contracts";
import type { BrokerStore, SwitchName } from "./persistence.js";
import type { FilesystemRootPolicy } from "./filesystem-inspector.js";
import { isPlainDataRecord } from "./plain-record.js";
import { isConcreteGuiTargetReference, isDesktopGuiPolicyScope, isDesktopGuiTargetReference, isSignedPolicyTargetReference } from "./target-authority.js";

export interface ToolPolicy {
  tool: string;
  contractVersion: "0.1";
  requiredScopes: readonly Scope[];
  capabilityFamilies: readonly CapabilityFamily[];
  targetType: "broker" | "policy_query" | "path" | "filesystem_roots" | "project" | "process" | "service" | "package" | "log_source" | "app_set" | "app" | "app_window" | "ui_element" | "docker_runtime" | "docker_object" | "job" | "task_profile";
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
  /** Optional finite, same-kind set for a parameterized signed rule. */
  targetConstraint?: TargetConstraint;
}

export interface TargetConstraint {
  mode: "finite_set";
  references: readonly string[];
}

const TARGET_TYPES = new Set<ToolPolicy["targetType"]>([
  "broker", "policy_query", "path", "filesystem_roots", "project", "process", "service", "package", "log_source",
  "app_set", "app", "app_window", "ui_element", "docker_runtime", "docker_object", "job", "task_profile"
]);
const APPROVAL_POLICIES = new Set<ToolPolicy["approvalPolicy"]>([
  "trusted_read", "trusted_write", "trusted_gui", "trusted_profile", "explicit_privileged_policy"
]);
const SWITCH_NAMES = ["global", "mutations", "process", "network", "gui", "destructive", "privileged"] as const;
const TARGET_KINDS = new Set<NormalizedTarget["kind"]>([
  "host", "path", "project", "process", "job", "task_profile", "app_set", "app", "app_window", "ui_element",
  "service", "log_source", "docker_runtime", "docker_object", "package", "power"
]);
const POLICY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const MAX_TARGET_CONSTRAINT_REFERENCES = 64;

/**
 * Validate the runtime policy shape at the authority boundary. Signed policy
 * loading already validates its source document, but Broker callers may also
 * provide an in-memory policy and may mutate a Map after construction. A
 * malformed ToolPolicy must therefore fail closed before it can authorize a
 * request or advertise a capability.
 */
export function validateBrokerPolicy(policy: BrokerPolicy): void {
  if (policy === null || typeof policy !== "object" ||
      !hasOnlyKeys(policy, ["revision", "version", "audience", "trustedEdgeIds", "trustedEdgeKeys", "principalGrants", "targetRules", "filesystemRoots", "killSwitches", "tools"]) ||
      !Number.isSafeInteger(policy.revision) || policy.revision < 0 ||
      typeof policy.version !== "string" || policy.version.length < 1 || policy.version.length > 128 ||
      typeof policy.audience !== "string" || policy.audience.length < 1 || policy.audience.length > 256 ||
      !(policy.trustedEdgeIds instanceof Set) || !(policy.trustedEdgeKeys instanceof Map) ||
      !(policy.principalGrants instanceof Map) || !isDenseArray(policy.targetRules, 4096) ||
      !isDenseArray(policy.filesystemRoots, 128) || !(policy.tools instanceof Map) ||
      policy.killSwitches === null || typeof policy.killSwitches !== "object" ||
      !hasOnlyKeys(policy.killSwitches, SWITCH_NAMES) ||
      SWITCH_NAMES.some((name) => typeof policy.killSwitches[name] !== "boolean")) {
    throw new BrokerError("POLICY_DENIED", "Active Broker policy is malformed");
  }
  if ([...policy.trustedEdgeIds].some((edgeId) => !isPolicyId(edgeId)) ||
      [...policy.trustedEdgeKeys].some(([identity, window]) =>
        !isPolicyKeyIdentity(identity) || !hasOnlyKeys(window, ["notBeforeMs", "expiresAtMs"]) ||
        !Number.isSafeInteger(window.notBeforeMs) || window.notBeforeMs < 0 ||
        !Number.isSafeInteger(window.expiresAtMs) || window.expiresAtMs <= window.notBeforeMs)) {
    throw new BrokerError("POLICY_DENIED", "Active Broker policy contains malformed key authority");
  }
  const grantIds = new Set<string>();
  for (const [principalId, grant] of policy.principalGrants) {
    if (!isPolicyId(principalId) || grantIds.has(principalId) || grant === null || typeof grant !== "object" ||
        !hasOnlyKeys(grant, ["principalId", "issuer", "scopes", "enabled"]) || grant.principalId !== principalId ||
        !isPolicyId(grant.issuer) || !isDenseArray(grant.scopes, SCOPES.length) || grant.scopes.length < 1 ||
        new Set(grant.scopes).size !== grant.scopes.length || grant.scopes.some((scope: unknown) => typeof scope !== "string" || !SCOPES.includes(scope as Scope)) ||
        typeof grant.enabled !== "boolean") {
      throw new BrokerError("POLICY_DENIED", "Active Broker policy contains malformed principal authority");
    }
    grantIds.add(principalId);
  }
  const rootIds = new Set<string>();
  for (const root of policy.filesystemRoots) {
    if (root === null || typeof root !== "object" || !hasOnlyKeys(root, ["rootId", "path", "metadata", "contentRead", "write", "denyRelativePaths"]) ||
        !isPolicyId(root.rootId) || rootIds.has(root.rootId) || !isCanonicalAbsolutePath(root.path) ||
        typeof root.metadata !== "boolean" || typeof root.contentRead !== "boolean" ||
        (root.write !== undefined && typeof root.write !== "boolean") ||
        !isDenseArray(root.denyRelativePaths, 4096) || new Set(root.denyRelativePaths).size !== root.denyRelativePaths.length ||
        root.denyRelativePaths.some((relativePath: unknown) => !isSafeRelativePath(relativePath))) {
      throw new BrokerError("POLICY_DENIED", "Active Broker policy contains malformed filesystem authority");
    }
    rootIds.add(root.rootId);
  }
  const ruleIds = new Set<string>();
  for (const rule of policy.targetRules) {
    if (rule === null || typeof rule !== "object" || !hasOnlyKeys(rule, ["ruleId", "effect", "principalId", "scope", "target", "targetConstraint"]) ||
        !isPolicyId(rule.ruleId) || ruleIds.has(rule.ruleId) ||
        (rule.effect !== "allow" && rule.effect !== "deny") || !isPolicyId(rule.principalId) ||
        !policy.principalGrants.has(rule.principalId) || !SCOPES.includes(rule.scope) ||
        !policy.principalGrants.get(rule.principalId)!.scopes.includes(rule.scope) ||
        !isPolicyTarget(rule.target, rootIds) || !isPolicyRuleTargetReference(rule.target) ||
        (isDesktopGuiTargetReference(rule.target) && !isDesktopGuiPolicyScope(rule.scope)) ||
        !isTargetConstraint(rule.target, rule.targetConstraint)) {
      throw new BrokerError("POLICY_DENIED", "Active Broker policy contains malformed target authority");
    }
    ruleIds.add(rule.ruleId);
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
    targetRules: policy.targetRules.map((rule) => ({
      ...rule,
      target: { ...rule.target },
      ...(rule.targetConstraint === undefined ? {} : {
        targetConstraint: { ...rule.targetConstraint, references: [...rule.targetConstraint.references] }
      })
    })),
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
      !hasOnlyKeys(tool, ["tool", "contractVersion", "requiredScopes", "capabilityFamilies", "targetType", "mutation", "approvalPolicy", "outputCapBytes", "timeoutMs", "implemented", "enabled"]) ||
      tool.contractVersion !== CONTRACT_VERSION ||
      !isDenseArray(tool.requiredScopes, SCOPES.length) || tool.requiredScopes.length < 1 ||
      new Set(tool.requiredScopes).size !== tool.requiredScopes.length ||
      tool.requiredScopes.some((scope) => !SCOPES.includes(scope)) ||
      !isDenseArray(tool.capabilityFamilies, CAPABILITY_FAMILIES.length) || tool.capabilityFamilies.length < 1 ||
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

function hasOnlyKeys(value: unknown, keys: readonly string[]): boolean {
  if (!isPlainDataRecord(value)) return false;
  const allowed = new Set(keys);
  return Object.keys(value).every((key) => allowed.has(key));
}

function isDenseArray(value: unknown, maxLength: number): value is readonly unknown[] {
  try {
    if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype ||
        value.length > maxLength || Object.getOwnPropertySymbols(value).length > 0) return false;
    const names = Object.getOwnPropertyNames(value);
    if (names.length !== value.length + 1 || Object.keys(value).length !== value.length) return false;
    for (let index = 0; index < value.length; index += 1) {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (descriptor === undefined || !("value" in descriptor)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function isKnownScopeList(value: unknown): value is readonly Scope[] {
  return isDenseArray(value, SCOPES.length) &&
    new Set(value).size === value.length &&
    value.every((scope) => typeof scope === "string" && SCOPES.includes(scope as Scope));
}

function isPolicyId(value: unknown): value is string {
  return typeof value === "string" && POLICY_ID_PATTERN.test(value);
}

function isPolicyKeyIdentity(value: unknown): value is string {
  return typeof value === "string" && value.length >= 3 && value.length <= 257 &&
    /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}:[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value);
}

function isCanonicalAbsolutePath(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 4_096 &&
    value.startsWith("/") && resolve(value) === value && !value.includes("\0") && !value.includes("\n");
}

function isSafeRelativePath(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 4_096 &&
    !value.includes("\0") && !value.startsWith("/") && resolve("/", value) === `/${value}`;
}

function isPolicyTarget(value: unknown, filesystemRootIds: ReadonlySet<string>): value is NormalizedTarget {
  if (value === null || typeof value !== "object" || !hasOnlyKeys(value, ["kind", "reference"])) return false;
  const target = value as NormalizedTarget;
  if (!TARGET_KINDS.has(target.kind) || typeof target.reference !== "string" ||
      target.reference.length < 1 || target.reference.length > 4_096 || target.reference.includes("\0") ||
      target.reference.includes("*") || /[\r\n]/u.test(target.reference)) return false;
  if (target.kind === "path" && !filesystemRootIds.has(target.reference)) return false;
  return true;
}

function isPolicyRuleTargetReference(target: NormalizedTarget): boolean {
  return isSignedPolicyTargetReference(target);
}

function isTargetConstraint(target: NormalizedTarget, constraint: unknown): constraint is TargetConstraint | undefined {
  if (constraint === undefined) return true;
  if (isDesktopGuiTargetReference(target)) return false;
  if (constraint === null || typeof constraint !== "object" ||
      !hasOnlyKeys(constraint, ["mode", "references"])) return false;
  const candidate = constraint as TargetConstraint;
  if (candidate.mode !== "finite_set" || !isDenseArray(candidate.references, MAX_TARGET_CONSTRAINT_REFERENCES) ||
      candidate.references.length < 1 || new Set(candidate.references).size !== candidate.references.length ||
      !isLexicallySorted(candidate.references) || !candidate.references.includes(target.reference)) {
    return false;
  }
  return candidate.references.every((reference) =>
    typeof reference === "string" && !isDesktopGuiTargetReference({ kind: target.kind, reference }) &&
    isSignedPolicyTargetReference({ kind: target.kind, reference }));
}

function isLexicallySorted(values: readonly string[]): boolean {
  for (let index = 1; index < values.length; index += 1) {
    if (values[index - 1]! >= values[index]!) return false;
  }
  return true;
}

export function authorizePrincipalProjection(
  policy: BrokerPolicy,
  principalId: string,
  issuer: string,
  projectedScopes: readonly Scope[]
): void {
  validateBrokerPolicy(policy);
  if (!isPolicyId(principalId) || !isPolicyId(issuer) || !isKnownScopeList(projectedScopes)) {
    throw new BrokerError("AUTH_INVALID", "Principal authority projection is malformed");
  }
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
  validateBrokerPolicy(policy);
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
  if (!isKnownScopeList(principalScopes)) {
    throw new BrokerError("AUTH_INVALID", "Principal scopes are malformed");
  }
  if (store.isSwitchDisabled("global") || policy.killSwitches.global) throw new BrokerError("REVOKED", "Broker admission is disabled");
  const tool = policy.tools.get(toolName);
  if (!tool || !tool.implemented) throw new BrokerError("UNSUPPORTED_CAPABILITY", "Tool is not implemented");
  if (!tool.enabled) throw new BrokerError("POLICY_DENIED", "Tool is not enabled", false, "TOOL_DISABLED");
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

/** Which mac_capabilities list tells a caller what it may target (static names only). */
function authorizedListFor(kind: NormalizedTarget["kind"]): string {
  if (kind === "log_source") return "authorized_log_sources";
  if (kind === "service") return "authorized_services";
  return "authorized_roots and authorized_projects";
}

export function authorizeTarget(
  policy: BrokerPolicy,
  principalId: string,
  scopes: readonly Scope[],
  target: NormalizedTarget
): void {
  validateBrokerPolicy(policy);
  if (!isPolicyId(principalId) || !isKnownScopeList(scopes) ||
      !isPolicyTarget(target, new Set(policy.filesystemRoots.map((root) => root.rootId))) ||
      isDesktopGuiTargetReference(target)) {
    throw new BrokerError("POLICY_DENIED", "Target authority is malformed");
  }
  const grant = policy.principalGrants.get(principalId);
  if (!grant || !grant.enabled) {
    throw new BrokerError("POLICY_DENIED", "Principal authority is not enabled");
  }
  if (scopes.some((scope) => !grant.scopes.includes(scope))) {
    throw new BrokerError("SCOPE_DENIED", "Principal scope is not granted");
  }
  const matchingRules = policy.targetRules.filter((rule) =>
    rule.principalId === principalId &&
    scopes.includes(rule.scope) &&
    rule.target.kind === target.kind &&
    (rule.targetConstraint?.mode === "finite_set"
      ? rule.targetConstraint.references.includes(target.reference)
      : rule.target.reference === target.reference ||
        (isDesktopGuiTargetReference(rule.target) && isConcreteGuiTargetReference(target)) ||
        (rule.target.kind === "docker_object" && rule.target.reference === "all" && target.kind === "docker_object"))
  );
  if (matchingRules.some((rule) => rule.effect === "deny")) {
    throw new BrokerError("POLICY_DENIED", "Target is explicitly denied", false, "TARGET_EXPLICITLY_DENIED");
  }
  for (const scope of scopes) {
    if (!matchingRules.some((rule) => rule.scope === scope && rule.effect === "allow")) {
      throw new BrokerError("POLICY_DENIED", `Target is not allowed for every required scope; mac_capabilities lists ${authorizedListFor(target.kind)}`, false, "TARGET_NOT_AUTHORIZED");
    }
  }
}

/** Capability discovery checks authority without resolving or launching an application. */
export function guiCapabilityProbeTarget(policy: BrokerPolicy, target: NormalizedTarget): NormalizedTarget {
  if (!isDesktopGuiTargetReference(target)) return target;
  validateBrokerPolicy(policy);
  const denied = new Set(policy.targetRules.filter(rule => rule.effect === "deny" && rule.target.kind === target.kind)
    .flatMap(rule => rule.targetConstraint?.references ?? [rule.target.reference]));
  for (let index = 0; index <= denied.size; index += 1) {
    const bundle = `bundle:dev.macoperator.capability-probe.${index}`;
    const reference = target.kind === "app" ? bundle : `window:${bundle}`;
    if (!denied.has(reference)) return { kind: target.kind, reference };
  }
  throw new BrokerError("POLICY_DENIED", "GUI capability probe target is unavailable");
}

export function runtimeToolStates(policy: BrokerPolicy): RuntimeToolState[] {
  validateBrokerPolicy(policy);
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
