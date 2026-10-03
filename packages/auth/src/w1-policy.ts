import { lstatSync, realpathSync } from "node:fs";
import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import type { BrokerPolicy, PolicyDocument } from "@mac-operator/broker";
import { canonicalJson } from "@mac-operator/contracts";
import { G1_SCOPES, G1_TOOLS, O1_SCOPES, O1_TOOLS, W1_SCOPES, W1_TOOLS } from "./contracts.js";
import { buildR1TargetRules, r1FilesystemRoots } from "./r1-policy.js";

export type GuiAccess = "browsers" | "desktop";

export function w1ProjectRoot(path: string): string {
  if (!isAbsolute(path) || resolve(path) !== path) throw new Error("Personal write project path must be absolute and canonical");
  const projectRoot = realpathSync(path);
  if (projectRoot !== path) throw new Error("Personal write project path must not be a symlink");
  const home = realpathSync(homedir());
  const withinHome = relative(home, projectRoot);
  if (!withinHome || withinHome === ".." || withinHome.startsWith(`..${sep}`) || isAbsolute(withinHome)) {
    throw new Error("Personal write project must be inside the owner home");
  }
  if (!lstatSync(projectRoot).isDirectory()) throw new Error("Personal write project must be a directory");
  let gitEntry;
  try { gitEntry = lstatSync(join(projectRoot, ".git")); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") throw new Error("Personal write project must be a Git repository");
    throw error;
  }
  if (!gitEntry.isDirectory()) throw new Error("Personal write project must have its own Git directory");
  return projectRoot;
}

export function w1FilesystemRoots(projectRoot: string): PolicyDocument["filesystem_roots"] {
  return [
    ...r1FilesystemRoots(),
    { root_id: "owner-project", path: projectRoot, metadata: true, content_read: true, write: true, deny_relative_paths: [] }
  ];
}

export function buildW1TargetRules(
  principalId: string,
  filesystemRoots: PolicyDocument["filesystem_roots"],
  projectRoot: string
): PolicyDocument["target_rules"] {
  return [
    ...buildR1TargetRules(principalId, filesystemRoots, projectRoot).filter(rule => rule.scope !== "mac.docker.read"),
    { rule_id: "owner-w1-file-path", effect: "allow", principal_id: principalId, scope: "mac.files.write", target: { kind: "path", reference: "owner-project" } },
    { rule_id: "owner-w1-file-project", effect: "allow", principal_id: principalId, scope: "mac.files.write", target: { kind: "project", reference: projectRoot } },
    { rule_id: "owner-w1-project", effect: "allow", principal_id: principalId, scope: "mac.project.write", target: { kind: "project", reference: projectRoot } },
    { rule_id: "owner-w1-git", effect: "allow", principal_id: principalId, scope: "mac.git.write", target: { kind: "project", reference: projectRoot } },
    { rule_id: "owner-w1-job-cancel", effect: "allow", principal_id: principalId, scope: "mac.job.cancel", target: { kind: "job", reference: "owned" } }
  ];
}

export function buildG1TargetRules(
  principalId: string,
  filesystemRoots: PolicyDocument["filesystem_roots"],
  projectRoot: string,
  guiAccess: GuiAccess = "browsers"
): PolicyDocument["target_rules"] {
  assertGuiAccess(guiAccess);
  const rules = buildW1TargetRules(principalId, filesystemRoots, projectRoot);
  if (guiAccess === "desktop") {
    rules.push(
      { rule_id: "owner-g1-desktop-open", effect: "allow", principal_id: principalId, scope: "mac.app.control", target: { kind: "app", reference: "desktop" } },
      { rule_id: "owner-g1-desktop-focus", effect: "allow", principal_id: principalId, scope: "mac.app.control", target: { kind: "app_window", reference: "desktop" } },
      { rule_id: "owner-g1-desktop-observe", effect: "allow", principal_id: principalId, scope: "mac.ui.observe", target: { kind: "app_window", reference: "desktop" } },
      { rule_id: "owner-g1-desktop-control", effect: "allow", principal_id: principalId, scope: "mac.ui.control", target: { kind: "app_window", reference: "desktop" } }
    );
    return rules;
  }
  for (const appId of ["bundle:com.google.Chrome", "bundle:com.apple.Safari"]) {
    rules.push(
      { rule_id: `owner-g1-open-${appId}`, effect: "allow", principal_id: principalId, scope: "mac.app.control", target: { kind: "app", reference: appId } },
      { rule_id: `owner-g1-focus-${appId}`, effect: "allow", principal_id: principalId, scope: "mac.app.control", target: { kind: "app_window", reference: `window:${appId}` } },
      { rule_id: `owner-g1-observe-${appId}`, effect: "allow", principal_id: principalId, scope: "mac.ui.observe", target: { kind: "app_window", reference: `window:${appId}` } },
      { rule_id: `owner-g1-control-${appId}`, effect: "allow", principal_id: principalId, scope: "mac.ui.control", target: { kind: "app_window", reference: `window:${appId}` } }
    );
  }
  return rules;
}

export function buildO1TargetRules(principalId: string, filesystemRoots: PolicyDocument["filesystem_roots"], projectRoot: string,
  guiAccess: GuiAccess = "browsers"): PolicyDocument["target_rules"] {
  return [...buildG1TargetRules(principalId, filesystemRoots, projectRoot, guiAccess),
    { rule_id: "owner-terminal", effect: "allow", principal_id: principalId, scope: "mac.terminal.exec",
      target: { kind: "host", reference: "owner-terminal" } }];
}

export function assertO1Policy(policy: BrokerPolicy, principalId: string, issuerId: string, guiAccess: GuiAccess = "browsers"): void {
  assertPersonalWritePolicy(policy, principalId, issuerId, true, true, guiAccess);
}

export function assertW1Policy(policy: BrokerPolicy, principalId: string, issuerId: string): void {
  assertPersonalWritePolicy(policy, principalId, issuerId, false);
}

export function assertG1Policy(policy: BrokerPolicy, principalId: string, issuerId: string, guiAccess: GuiAccess = "browsers"): void {
  assertPersonalWritePolicy(policy, principalId, issuerId, true, false, guiAccess);
}

function assertGuiAccess(guiAccess: GuiAccess): void {
  if (guiAccess !== "browsers" && guiAccess !== "desktop") throw new Error("Personal GUI access mode is invalid");
}

function assertPersonalWritePolicy(policy: BrokerPolicy, principalId: string, issuerId: string, guiProfile: boolean,
  ownerTerminal = false, guiAccess: GuiAccess = "browsers"): void {
  assertGuiAccess(guiAccess);
  const expectedScopes = ownerTerminal ? O1_SCOPES : guiProfile ? G1_SCOPES : W1_SCOPES;
  const expectedTools = ownerTerminal ? O1_TOOLS : guiProfile ? G1_TOOLS : W1_TOOLS;
  const grants = [...policy.principalGrants.values()];
  if (grants.length !== 1 || grants[0]?.principalId !== principalId || grants[0]?.issuer !== issuerId || !grants[0]?.enabled ||
      canonicalJson([...grants[0].scopes].sort()) !== canonicalJson([...expectedScopes].sort())) {
    throw new Error("Personal write principal grant mismatch");
  }
  const enabled = [...policy.tools.values()].filter(tool => tool.enabled).map(tool => tool.tool).sort();
  if (canonicalJson(enabled) !== canonicalJson([...expectedTools].sort())) {
    throw new Error("Personal write tool set mismatch");
  }
  const projectRoot = policy.filesystemRoots.find(root => root.rootId === "owner-project")?.path;
  if (projectRoot === undefined || w1ProjectRoot(projectRoot) !== projectRoot) {
    throw new Error("Personal write project root mismatch");
  }
  const expectedRoots = w1FilesystemRoots(projectRoot);
  const actualRoots = policy.filesystemRoots.map(root => ({ root_id: root.rootId, path: root.path,
    metadata: root.metadata, content_read: root.contentRead, write: root.write, deny_relative_paths: root.denyRelativePaths }));
  if (canonicalJson(actualRoots) !== canonicalJson(expectedRoots)) {
    throw new Error("Personal write filesystem roots mismatch");
  }
  const expectedRules = ownerTerminal ? buildO1TargetRules(principalId, expectedRoots, projectRoot, guiAccess) : guiProfile ? buildG1TargetRules(principalId, expectedRoots, projectRoot, guiAccess) : buildW1TargetRules(principalId, expectedRoots, projectRoot);
  const actualRules = policy.targetRules.map(rule => ({ rule_id: rule.ruleId, effect: rule.effect,
    principal_id: rule.principalId, scope: rule.scope, target: rule.target,
    ...(rule.targetConstraint === undefined ? {} : { target_constraint: rule.targetConstraint }) }));
  if (canonicalJson(actualRules) !== canonicalJson(expectedRules)) {
    throw new Error("Personal write target rules mismatch");
  }
  const switches = policy.killSwitches;
  if (switches.global || switches.mutations || switches.process || switches.network ||
      switches.gui === guiProfile || !switches.destructive || !switches.privileged) {
    throw new Error("Personal write kill-switch boundary mismatch");
  }
}
