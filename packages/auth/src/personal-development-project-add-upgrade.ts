import { createPrivateKey, sign } from "node:crypto";
import { copyFile, mkdir, open, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerServiceInstanceLock, BrokerStore, PolicyBundleVerifier, PolicyManager, type SignedPolicyBundle } from "@mac-operator/broker";
import { validateEdgeServiceStartupConfig } from "@mac-operator/edge";
import { configSchema, developmentTools, scopesForGrantProfile } from "./contracts.js";
import { AuthStore, assertPrivateDirectory } from "./store.js";
import { readAuthFile } from "./cli.js";
import { assertV2Policy, buildV2PolicyDocument } from "./v2-policy.js";
import { developmentPolicyConfiguration, loadPersonalDevelopmentRuntimeConfig, type PersonalDevelopmentRuntimeConfig } from "./personal-development-runtime.js";
import { desktopGrantsForUnchangedGuiPolicy } from "./desktop-grant-migration.js";

const PUSH_SCOPE = "mac.git.push";
const MAX_ADDED_PROJECTS = 4;

/**
 * Offline opt-in for an existing V2 installation. Signs one new policy revision that adds exact-path development projects
 * (project-scoped read/write, Git, agent, job and audit rules) and denies `mac.git.push` on every added project. The
 * replacement runtime config must differ from the installed one only by those appended projects, so tools, scopes, keys,
 * kill switches, task profiles, engine identity and every existing project rule stay byte-identical.
 * Existing OAuth grants keep their scopes. Keep a complete stopped-state backup for rollback; a per-file copy is also
 * written next to the state as `project-add-backup-<revision>`.
 */
export async function upgradePersonalDevelopmentProjectAdd(root: string, packageRoot: string, sourceRevision: string,
  nextRuntimeConfigPath: string): Promise<{ revision: number; addedProjects: string[]; backup: string }> {
  const result = await migratePersonalDevelopmentConfig(root, packageRoot, sourceRevision, nextRuntimeConfigPath, {
    name: "development_project_add", assertRuntime: assertRuntimeAppendOnly,
    assertPolicy: (before, after, installed, _next, changed) => assertOnlyProjectsAdded(before, after, installed.developmentProjects.length, changed, _next.ownerProjectRoot) });
  return { revision: result.revision, addedProjects: result.changedProjects, backup: result.backup };
}

export interface DevelopmentConfigMigration {
  /** Audit tool suffix; also names the backup directory. */
  name: string;
  /** Throws unless `next` differs from `installed` only as this migration allows; returns the affected projects. */
  assertRuntime(installed: PersonalDevelopmentRuntimeConfig, next: PersonalDevelopmentRuntimeConfig): string[];
  /** Throws unless the signed policy changes only as this migration allows. */
  assertPolicy(before: SignedPolicyBundle["payload"], after: SignedPolicyBundle["payload"], installed: PersonalDevelopmentRuntimeConfig,
    next: PersonalDevelopmentRuntimeConfig, changed: string[]): void;
}

/** Shared offline flow: verify, rebuild the V2 policy from a replacement runtime config, sign revision+1, back up, switch atomically. */
export async function migratePersonalDevelopmentConfig(root: string, packageRoot: string, sourceRevision: string, nextRuntimeConfigPath: string,
  migration: DevelopmentConfigMigration): Promise<{ revision: number; changedProjects: string[]; backup: string }> {
  assertPrivateDirectory(root);
  if (!/^[a-f0-9]{7,64}$/u.test(sourceRevision)) throw new Error("Source revision required");
  const data = join(root, "personal");
  const lock = await BrokerServiceInstanceLock.acquire(join(data, "run/service.lock"));
  let store: BrokerStore | undefined;
  try {
    const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
    if (config.grantProfile !== "v2") throw new Error("Project add requires an existing V2 installation");
    const installed = loadPersonalDevelopmentRuntimeConfig(join(data, "development-runtime.json"));
    const next = loadPersonalDevelopmentRuntimeConfig(nextRuntimeConfigPath);
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(packageRoot, "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(data, "policy-public.pem") });
    const prior = await verifier.verifyFile(join(data, "policy.json"));
    const nextConfiguration = developmentPolicyConfiguration(next);
    if (canonicalJson(installed) === canonicalJson(next)) {
      assertV2Policy(prior.policy, config.principalId, config.issuerId, nextConfiguration, config.guiAccess, config.dockerReadAccess);
      return { revision: prior.policy.revision, changedProjects: [], backup: "" };
    }
    const addedProjects = migration.assertRuntime(installed, next);
    assertV2Policy(prior.policy, config.principalId, config.issuerId, developmentPolicyConfiguration(installed), config.guiAccess, config.dockerReadAccess);
    const original = JSON.parse(readAuthFile(join(data, "policy.json")).toString()) as SignedPolicyBundle;
    const now = Date.now();
    const rebuilt = buildV2PolicyDocument(original.payload, config.principalId, config.issuerId, nextConfiguration, config.guiAccess, config.dockerReadAccess);
    const payload = { ...rebuilt, revision: original.payload.revision + 1, issued_at_ms: now };
    migration.assertPolicy(original.payload, payload, installed, next, addedProjects);
    const bytes = Buffer.from(canonicalJson(payload));
    const privateBytes = readAuthFile(join(root, "personal-policy-private.key"));
    let bundle: SignedPolicyBundle;
    try { bundle = { ...original, payload, payload_digest: sha256(bytes), signature: sign(null, bytes, createPrivateKey(privateBytes)).toString("base64") }; }
    finally { privateBytes.fill(0); }
    const verified = verifier.verify(bundle);
    assertV2Policy(verified.policy, config.principalId, config.issuerId, nextConfiguration, config.guiAccess, config.dockerReadAccess);
    const previousEdge = validateEdgeServiceStartupConfig(JSON.parse(readAuthFile(join(data, "edge-service.json")).toString()));
    if (previousEdge.dataRoot !== data || previousEdge.runtimeRoot !== join(data, "run") || previousEdge.policyVersion !== prior.policy.version) {
      throw new Error("Existing Edge binding does not match the signed policy");
    }
    const edge = validateEdgeServiceStartupConfig({ ...previousEdge, packageRoot, contractsDirectory: join(packageRoot, "tool-contracts"),
      sourceRevision, policyVersion: verified.policy.version });
    const edgeSettings = JSON.parse(readAuthFile(join(root, "auth/edge-auth-settings.json")).toString()) as Record<string, unknown>;
    const policyInput = JSON.parse(readAuthFile(join(root, "auth/broker-policy-input.json")).toString()) as Record<string, unknown>;
    const backup = await backupFiles(root, data, payload.revision - 1, migration.name.replaceAll("_", "-"));
    store = new BrokerStore(join(data, "broker.sqlite"), { runtimeFence: true,
      auditAnchor: { path: join(data, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readAuthFile(join(data, "audit.key"), 32) } } });
    const manager = new PolicyManager(prior.policy, store);
    manager.restore(prior);
    const requestId = `${migration.name.replaceAll("_", "-")}-${payload.revision}`;
    store.appendAudit({ requestId, principalId: config.principalId, tool: `internal_${migration.name}`, eventType: "intent", decision: "allow",
      resultClass: "INTENT_RECORDED", targetRef: "host:development-projects", policyVersion: verified.policy.version, timestampMs: now,
      evidence: { sourceRevision, priorPolicyVersion: prior.policy.version, changedProjects: addedProjects, backup } });
    manager.activate(verified);
    await replaceJson(join(data, "development-runtime.json"), next);
    await replaceJson(join(data, "policy.json"), bundle);
    await replaceJson(join(data, "edge-service.json"), edge);
    await replaceJson(join(root, "auth/edge-auth-settings.json"), edgeSettings);
    await replaceJson(join(root, "auth/broker-policy-input.json"), { ...policyInput, principal: payload.principal_grants[0], target_rules: payload.target_rules,
      enabled_tools: [...developmentTools(config.dockerReadAccess)], filesystem_roots: payload.filesystem_roots });
    const authStore = new AuthStore(join(root, "auth"));
    let browserGrantCount = 0;
    let desktopGrantCount = 0;
    try {
      const grants = authStore.browserGrants().filter(grant => !grant.revoked && grant.principalId === config.principalId && grant.policyVersion === prior.policy.version);
      browserGrantCount = grants.length;
      const desktopGrants = desktopGrantsForUnchangedGuiPolicy(authStore, config.guiAccess, config.principalId, prior.policy, verified.policy);
      desktopGrantCount = desktopGrants.length;
      authStore.transaction(() => {
        for (const grant of grants) authStore.put("browser_grant", grant.id, { ...grant, policyVersion: verified.policy.version });
        for (const grant of desktopGrants) authStore.put("desktop_grant", grant.id, { ...grant, policyVersion: verified.policy.version });
      });
    } finally { authStore.close(); }
    store.appendAudit({ requestId, principalId: config.principalId, tool: `internal_${migration.name}`, eventType: "completion", decision: "allow",
      resultClass: "SUCCEEDED", targetRef: "host:development-projects", policyVersion: verified.policy.version, timestampMs: Date.now(),
      evidence: { sourceRevision, changedProjects: addedProjects, browserGrantCount, desktopGrantCount, existingOAuthScopesExpanded: false } });
    return { revision: payload.revision, changedProjects: addedProjects, backup };
  } finally { store?.close(); await lock.close(); }
}

/** The replacement config may only append projects, all push-denied; nothing else may differ from the installed config. */
export function assertRuntimeAppendOnly(installed: PersonalDevelopmentRuntimeConfig, next: PersonalDevelopmentRuntimeConfig): string[] {
  const count = installed.developmentProjects.length;
  const added = next.developmentProjects.slice(count);
  if (added.length === 0 || added.length > MAX_ADDED_PROJECTS ||
      canonicalJson(next.developmentProjects.slice(0, count)) !== canonicalJson(installed.developmentProjects)) {
    throw new Error("Project add must append 1-4 projects and keep existing projects in order");
  }
  const { developmentProjects: _a, gitPushDeniedProjects: deniedBefore, ...restBefore } = installed;
  const { developmentProjects: _b, gitPushDeniedProjects: deniedAfter, ...restAfter } = next;
  if (canonicalJson(restBefore) !== canonicalJson(restAfter)) throw new Error("Project add would change runtime configuration beyond the project list");
  if (canonicalJson([...deniedAfter].sort()) !== canonicalJson([...deniedBefore, ...added].sort())) {
    throw new Error("Added projects must be denied Git push and existing push authority must stay unchanged");
  }
  return added;
}

type PolicyPayload = SignedPolicyBundle["payload"];

/**
 * The new document may differ only by rules and filesystem roots of the appended projects. Read rules are numbered per root,
 * so adding a root renumbers existing `owner-r1-N` identifiers; rules are therefore compared by content, not identifier.
 */
export function assertOnlyProjectsAdded(before: PolicyPayload, after: PolicyPayload, oldCount: number, added: string[], ownerProjectRoot: string): void {
  void oldCount;
  const { revision: _a, issued_at_ms: _b, target_rules: rulesBefore, filesystem_roots: rootsBefore, ...restBefore } = before;
  const { revision: _c, issued_at_ms: _d, target_rules: rulesAfter, filesystem_roots: rootsAfter, ...restAfter } = after;
  if (canonicalJson(restBefore) !== canonicalJson(restAfter)) throw new Error("Project add would change authority other than projects");
  const addedRoots = rootsAfter.filter(root => !rootsBefore.some(old => canonicalJson(old) === canonicalJson(root)));
  if (canonicalJson(rootsAfter.filter(root => addedRoots.every(extra => extra.root_id !== root.root_id))) !== canonicalJson(rootsBefore) ||
      addedRoots.some(root => !added.includes(root.path) || root.path === ownerProjectRoot || !root.root_id.startsWith("gateway-project-"))) {
    throw new Error("Project add would change filesystem roots beyond the added projects");
  }
  const addedRootIds = new Set(addedRoots.map(root => root.root_id));
  const counts = new Map<string, number>();
  const contentKey = (rule: PolicyPayload["target_rules"][number]): string => {
    const { rule_id: _id, ...content } = rule;
    return canonicalJson(content);
  };
  for (const rule of rulesBefore) counts.set(contentKey(rule), (counts.get(contentKey(rule)) ?? 0) + 1);
  const addedRules: PolicyPayload["target_rules"] = [];
  for (const rule of rulesAfter) {
    const key = contentKey(rule);
    const remaining = counts.get(key) ?? 0;
    if (remaining > 0) counts.set(key, remaining - 1); else addedRules.push(rule);
  }
  if ([...counts.values()].some(remaining => remaining !== 0)) throw new Error("Project add would remove or change existing target rules");
  if (addedRules.length === 0 || addedRules.some(rule => rule.effect !== "allow" || rule.scope === PUSH_SCOPE || rule.target_constraint !== undefined ||
      !(rule.target.kind === "project" && added.includes(rule.target.reference) ||
        rule.target.kind === "path" && addedRootIds.has(rule.target.reference)))) {
    throw new Error("Project add would grant more than project rules without Git push");
  }
}

async function backupFiles(root: string, data: string, revision: number, name: string): Promise<string> {
  const directory = join(data, `${name}-backup-${revision}`);
  await mkdir(directory, { mode: 0o700 });
  const manifest: Record<string, string> = {};
  for (const file of [join(data, "development-runtime.json"), join(data, "policy.json"), join(data, "edge-service.json"),
    join(root, "auth/edge-auth-settings.json"), join(root, "auth/broker-policy-input.json")]) {
    const name = file.slice(root.length + 1).replaceAll("/", "__");
    await copyFile(file, join(directory, name));
    manifest[name] = sha256(readAuthFile(file, 4 * 1024 * 1024));
  }
  await replaceJson(join(directory, "MANIFEST.json"), manifest);
  return directory;
}

async function replaceJson(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.project-add-${process.pid}`;
  const file = await open(temporary, "wx", 0o600);
  try { await file.writeFile(`${JSON.stringify(value, null, 2)}\n`); await file.sync(); }
  finally { await file.close(); }
  await rename(temporary, path);
  const directory = await open(dirname(path), "r");
  try { await directory.sync(); } finally { await directory.close(); }
}
