import { lstatSync, realpathSync } from "node:fs";
import { isAbsolute, relative, resolve, sep } from "node:path";
import type { BrokerPolicy, PolicyDocument } from "@mac-operator/broker";
import { canonicalJson, type Scope } from "@mac-operator/contracts";
import { developmentPolicyScopes, developmentTools } from "./contracts.js";
import { buildO1TargetRules, w1FilesystemRoots, w1ProjectRoot, type GuiAccess } from "./w1-policy.js";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const PROJECT_SCOPES: readonly Scope[] = ["mac.project.read", "mac.project.write", "mac.git.read", "mac.git.write",
  "mac.package.read", "mac.files.write", "mac.agent.read", "mac.agent.run", "mac.task.run", "mac.audit.read", "mac.job.read", "mac.job.cancel"];

export interface V2PolicyConfiguration {
  developmentProjects: readonly string[];
  stateRoot: string;
  worktreeRoot: string;
  taskProfiles: readonly string[];
}

/** Ordinary filesystem tools never gain authority over gateway control state or other tasks. */
export function v2FilesystemRoots(ownerProjectRoot: string, config: V2PolicyConfiguration): PolicyDocument["filesystem_roots"] {
  const safe = validateConfiguration(ownerProjectRoot, config);
  const roots = w1FilesystemRoots(ownerProjectRoot);
  for (const [index, path] of safe.developmentProjects.entries()) {
    if (path !== ownerProjectRoot) roots.push({ root_id: `gateway-project-${index}`, path, metadata: true,
      content_read: true, write: true, deny_relative_paths: [] });
  }
  for (const root of roots) {
    const denied = new Set(root.deny_relative_paths);
    for (const protectedPath of [safe.stateRoot, safe.worktreeRoot]) {
      if (contained(protectedPath, root.path)) throw new Error("V2 ordinary filesystem root cannot enter gateway storage");
      if (contained(root.path, protectedPath)) denied.add(relative(root.path, protectedPath));
    }
    root.deny_relative_paths = [...denied].sort();
  }
  return roots;
}

export function buildV2TargetRules(principalId: string, filesystemRoots: PolicyDocument["filesystem_roots"], ownerProjectRoot: string,
  config: V2PolicyConfiguration, guiAccess: GuiAccess = "browsers", dockerReadAccess = false): PolicyDocument["target_rules"] {
  if (!ID.test(principalId)) throw new Error("V2 principal identity is malformed");
  const safe = validateConfiguration(ownerProjectRoot, config);
  const expectedRoots = v2FilesystemRoots(ownerProjectRoot, safe);
  if (canonicalJson(filesystemRoots) !== canonicalJson(expectedRoots)) throw new Error("V2 filesystem roots do not match protected configuration");
  const rules = buildO1TargetRules(principalId, filesystemRoots, ownerProjectRoot, guiAccess, dockerReadAccess);
  for (const [index, project] of safe.developmentProjects.entries()) {
    const root = filesystemRoots.find(candidate => candidate.path === project && candidate.write === true);
    if (root === undefined) throw new Error("V2 development source root is unavailable");
    if (project !== ownerProjectRoot) rules.push({ rule_id: `owner-v2-${index}-files`, effect: "allow", principal_id: principalId,
      scope: "mac.files.write", target: { kind: "path", reference: root.root_id } });
    for (const [scopeIndex, scope] of PROJECT_SCOPES.entries()) {
      rules.push({ rule_id: `owner-v2-${index}-${scopeIndex}`, effect: "allow", principal_id: principalId, scope,
        target: { kind: "project", reference: project } });
    }
  }
  rules.push({ rule_id: "owner-v2-task-profiles", effect: "allow", principal_id: principalId, scope: "mac.task.run",
    target: { kind: "task_profile", reference: safe.taskProfiles[0]! },
    target_constraint: { mode: "finite_set", references: [...safe.taskProfiles] } });
  return rules;
}

/** Preserve signature envelope inputs; the operator signs the returned concrete document separately. */
export function buildV2PolicyDocument(base: PolicyDocument, principalId: string, issuerId: string, config: V2PolicyConfiguration,
  guiAccess: GuiAccess = "browsers", dockerReadAccess = false): PolicyDocument {
  if (!ID.test(principalId) || !ID.test(issuerId)) throw new Error("V2 grant identity is malformed");
  const ownerProjectRoot = base.filesystem_roots.find(root => root.root_id === "owner-project")?.path;
  if (ownerProjectRoot === undefined) throw new Error("V2 requires an existing owner project");
  const roots = v2FilesystemRoots(ownerProjectRoot, config);
  return {
    ...base,
    trusted_edge_keys: base.trusted_edge_keys.map(key => ({ ...key })),
    principal_grants: [{ principal_id: principalId, issuer: issuerId, scopes: [...developmentPolicyScopes(dockerReadAccess)], enabled: true }],
    filesystem_roots: roots,
    target_rules: buildV2TargetRules(principalId, roots, ownerProjectRoot, config, guiAccess, dockerReadAccess),
    tool_enablement: developmentTools(dockerReadAccess).map(tool => ({ tool, enabled: true })),
    kill_switches: { global: false, mutations: false, process: false, network: false, gui: false, destructive: true, privileged: true }
  };
}

/** A signed document still has to match the independently protected operator configuration. */
export function assertV2Policy(policy: BrokerPolicy, principalId: string, issuerId: string, config: V2PolicyConfiguration,
  guiAccess: GuiAccess = "browsers", dockerReadAccess = false): void {
  const grants = [...policy.principalGrants.values()];
  if (grants.length !== 1 || grants[0]?.principalId !== principalId || grants[0]?.issuer !== issuerId || !grants[0]?.enabled ||
      canonicalJson([...grants[0].scopes].sort()) !== canonicalJson([...developmentPolicyScopes(dockerReadAccess)].sort())) throw new Error("V2 principal grant mismatch");
  const enabled = [...policy.tools.values()].filter(tool => tool.enabled).map(tool => tool.tool).sort();
  if (canonicalJson(enabled) !== canonicalJson([...developmentTools(dockerReadAccess)].sort())) throw new Error("V2 tool set mismatch");
  const project = policy.filesystemRoots.find(root => root.rootId === "owner-project")?.path;
  if (project === undefined) throw new Error("V2 owner project root mismatch");
  const roots = v2FilesystemRoots(project, config);
  const actualRoots = policy.filesystemRoots.map(root => ({ root_id: root.rootId, path: root.path, metadata: root.metadata,
    content_read: root.contentRead, write: root.write, deny_relative_paths: root.denyRelativePaths }));
  if (canonicalJson(actualRoots) !== canonicalJson(roots)) throw new Error("V2 filesystem roots mismatch");
  const rules = buildV2TargetRules(principalId, roots, project, config, guiAccess, dockerReadAccess);
  const actualRules = policy.targetRules.map(rule => ({ rule_id: rule.ruleId, effect: rule.effect, principal_id: rule.principalId,
    scope: rule.scope, target: rule.target, ...(rule.targetConstraint === undefined ? {} : { target_constraint: rule.targetConstraint }) }));
  if (canonicalJson(actualRules) !== canonicalJson(rules)) throw new Error("V2 target rules mismatch");
  if (canonicalJson(policy.killSwitches) !== canonicalJson({ global: false, mutations: false, process: false, network: false,
    gui: false, destructive: true, privileged: true })) throw new Error("V2 kill-switch boundary mismatch");
}

function validateConfiguration(ownerProjectRoot: string, config: V2PolicyConfiguration): V2PolicyConfiguration {
  w1ProjectRoot(ownerProjectRoot);
  if (!plainRecord(config) || Object.keys(config).sort().join(",") !== "developmentProjects,stateRoot,taskProfiles,worktreeRoot" ||
      !stringArray(config.developmentProjects, 16) || config.developmentProjects.length === 0 ||
      new Set(config.developmentProjects).size !== config.developmentProjects.length || !stringArray(config.taskProfiles, 64) ||
      config.taskProfiles.length === 0 || new Set(config.taskProfiles).size !== config.taskProfiles.length ||
      config.taskProfiles.some(profile => !ID.test(profile))) throw new Error("V2 operator configuration is malformed");
  const projects = config.developmentProjects.map(w1ProjectRoot);
  for (const path of [config.stateRoot, config.worktreeRoot]) {
    if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path || realpathSync(path) !== path || !lstatSync(path).isDirectory()) {
      throw new Error("V2 gateway storage must be a canonical non-symlink directory");
    }
  }
  for (const project of [ownerProjectRoot, ...projects]) {
    if (contained(config.stateRoot, project) || contained(config.worktreeRoot, project)) throw new Error("V2 project cannot enter gateway storage");
  }
  return { developmentProjects: [...projects], stateRoot: config.stateRoot, worktreeRoot: config.worktreeRoot, taskProfiles: [...config.taskProfiles].sort() };
}

function contained(root: string, path: string): boolean {
  const delta = relative(root, path);
  return delta === "" || delta !== ".." && !delta.startsWith(`..${sep}`) && !isAbsolute(delta);
}
function plainRecord(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return (prototype === Object.prototype || prototype === null) && Object.getOwnPropertySymbols(value).length === 0 &&
    Object.keys(value).length === Object.getOwnPropertyNames(value).length &&
    Object.getOwnPropertyNames(value).every(key => { const descriptor = Object.getOwnPropertyDescriptor(value, key); return descriptor !== undefined && "value" in descriptor; });
}
function stringArray(value: unknown, max: number): value is string[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > max || Object.getOwnPropertySymbols(value).length !== 0 ||
      Object.keys(value).length !== value.length || Object.getOwnPropertyNames(value).length !== value.length + 1) return false;
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (descriptor === undefined || !("value" in descriptor) || typeof descriptor.value !== "string") return false;
  }
  return true;
}
