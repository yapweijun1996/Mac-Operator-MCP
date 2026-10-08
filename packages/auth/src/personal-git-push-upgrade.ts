import { createPrivateKey, sign } from "node:crypto";
import { open, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerServiceInstanceLock, BrokerStore, PolicyBundleVerifier, PolicyManager, type SignedPolicyBundle } from "@mac-operator/broker";
import { validateEdgeServiceStartupConfig } from "@mac-operator/edge";
import { configSchema, developmentTools, scopesForGrantProfile } from "./contracts.js";
import { AuthStore, assertPrivateDirectory } from "./store.js";
import { readAuthFile } from "./cli.js";
import { assertV2Policy, buildV2PolicyDocument } from "./v2-policy.js";
import { developmentPolicyConfiguration, loadPersonalDevelopmentRuntimeConfig } from "./personal-development-runtime.js";
import { desktopGrantsForUnchangedGuiPolicy } from "./desktop-grant-migration.js";

const PUSH_TOOL = "mac_git_push";
const PUSH_SCOPE = "mac.git.push";

/**
 * Offline opt-in for an existing V2 installation signed before `mac_git_push` existed. Signs one new policy revision
 * that adds exactly the push tool, the `mac.git.push` scope on the principal grant, and one `mac.git.push` target rule
 * per already-allowed development project. Filesystem roots, kill switches, keys and every other rule must be unchanged.
 * Existing OAuth grants keep their scopes, so the owner has to reconnect once to receive `mac.git.push`.
 * Keep a complete stopped-state backup for rollback.
 */
export async function upgradePersonalGitPush(root: string, packageRoot: string, sourceRevision: string): Promise<void> {
  assertPrivateDirectory(root);
  if (!/^[a-f0-9]{7,64}$/u.test(sourceRevision)) throw new Error("Source revision required");
  const data = join(root, "personal");
  const lock = await BrokerServiceInstanceLock.acquire(join(data, "run/service.lock"));
  let store: BrokerStore | undefined;
  try {
    const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
    if (config.grantProfile !== "v2") throw new Error("Git push upgrade requires an existing V2 installation");
    const configuration = developmentPolicyConfiguration(loadPersonalDevelopmentRuntimeConfig(join(data, "development-runtime.json")));
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(packageRoot, "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(data, "policy-public.pem") });
    const prior = await verifier.verifyFile(join(data, "policy.json"));
    const enabled = [...prior.policy.tools.values()].filter(tool => tool.enabled).map(tool => tool.tool).sort();
    if (enabled.includes(PUSH_TOOL)) { assertV2Policy(prior.policy, config.principalId, config.issuerId, configuration, config.guiAccess, config.dockerReadAccess); return; }
    // Refuse anything that is not exactly the previous signed V2 authority, so this cannot widen other authority.
    if (canonicalJson(enabled) !== canonicalJson(developmentTools(config.dockerReadAccess).filter(tool => tool !== PUSH_TOOL).sort())) {
      throw new Error("Existing signed tool set is not the expected pre-push V2 set");
    }
    const original = JSON.parse(readAuthFile(join(data, "policy.json")).toString()) as SignedPolicyBundle;
    const now = Date.now();
    const rebuilt = buildV2PolicyDocument(original.payload, config.principalId, config.issuerId, configuration, config.guiAccess, config.dockerReadAccess);
    const payload = { ...rebuilt, revision: original.payload.revision + 1, issued_at_ms: now };
    assertOnlyPushAdded(original.payload, payload);
    const bytes = Buffer.from(canonicalJson(payload));
    const privateBytes = readAuthFile(join(root, "personal-policy-private.key"));
    let bundle: SignedPolicyBundle;
    try { bundle = { ...original, payload, payload_digest: sha256(bytes), signature: sign(null, bytes, createPrivateKey(privateBytes)).toString("base64") }; }
    finally { privateBytes.fill(0); }
    const verified = verifier.verify(bundle);
    assertV2Policy(verified.policy, config.principalId, config.issuerId, configuration, config.guiAccess, config.dockerReadAccess);
    const previousEdge = validateEdgeServiceStartupConfig(JSON.parse(readAuthFile(join(data, "edge-service.json")).toString()));
    if (previousEdge.dataRoot !== data || previousEdge.runtimeRoot !== join(data, "run") || previousEdge.policyVersion !== prior.policy.version) {
      throw new Error("Existing Edge binding does not match the signed policy");
    }
    // OAuth consent for V2 stays the coding set: it never includes the owner terminal scope, unlike the policy grant.
    const scopes = [...scopesForGrantProfile("v2", config.dockerReadAccess)];
    const edge = validateEdgeServiceStartupConfig({ ...previousEdge, packageRoot, contractsDirectory: join(packageRoot, "tool-contracts"),
      sourceRevision, oauthScopes: scopes, policyVersion: verified.policy.version });
    const edgeSettings = JSON.parse(readAuthFile(join(root, "auth/edge-auth-settings.json")).toString()) as Record<string, unknown>;
    const policyInput = JSON.parse(readAuthFile(join(root, "auth/broker-policy-input.json")).toString()) as Record<string, unknown>;
    store = new BrokerStore(join(data, "broker.sqlite"), { runtimeFence: true,
      auditAnchor: { path: join(data, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readAuthFile(join(data, "audit.key"), 32) } } });
    const manager = new PolicyManager(prior.policy, store);
    manager.restore(prior);
    const requestId = `git-push-upgrade-${payload.revision}`;
    store.appendAudit({ requestId, principalId: config.principalId, tool: "internal_git_push_upgrade", eventType: "intent", decision: "allow",
      resultClass: "INTENT_RECORDED", targetRef: "host:git-push", policyVersion: verified.policy.version, timestampMs: now,
      evidence: { sourceRevision, priorPolicyVersion: prior.policy.version } });
    manager.activate(verified);
    await replaceJson(join(data, "policy.json"), bundle);
    await replaceJson(join(data, "edge-service.json"), edge);
    await replaceJson(join(root, "auth/edge-auth-settings.json"), { ...edgeSettings, oauthScopes: scopes });
    await replaceJson(join(root, "auth/broker-policy-input.json"), { ...policyInput, principal: payload.principal_grants[0], target_rules: payload.target_rules,
      enabled_tools: [...developmentTools(config.dockerReadAccess)], filesystem_roots: payload.filesystem_roots });
    // Retained GUI consent is bound to the policy version; the new revision grants it nothing more.
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
    store.appendAudit({ requestId, principalId: config.principalId, tool: "internal_git_push_upgrade", eventType: "completion", decision: "allow",
      resultClass: "SUCCEEDED", targetRef: "host:git-push", policyVersion: verified.policy.version, timestampMs: Date.now(),
      evidence: { sourceRevision, browserGrantCount, desktopGrantCount, existingOAuthScopesExpanded: false } });
  } finally { store?.close(); await lock.close(); }
}

type PolicyPayload = SignedPolicyBundle["payload"];

/** The new document may differ from the signed one only by the push tool, the push scope and per-project push rules. */
function assertOnlyPushAdded(before: PolicyPayload, after: PolicyPayload): void {
  const { revision: _a, issued_at_ms: _b, tool_enablement: toolsBefore, principal_grants: grantsBefore, target_rules: rulesBefore, ...restBefore } = before;
  const { revision: _c, issued_at_ms: _d, tool_enablement: toolsAfter, principal_grants: grantsAfter, target_rules: rulesAfter, ...restAfter } = after;
  if (canonicalJson(restBefore) !== canonicalJson(restAfter)) throw new Error("Git push upgrade would change authority other than push");
  const addedTools = toolsAfter.filter(entry => !toolsBefore.some(old => old.tool === entry.tool));
  if (canonicalJson(addedTools) !== canonicalJson([{ tool: PUSH_TOOL, enabled: true }]) ||
      canonicalJson(toolsBefore.filter(entry => toolsAfter.some(next => next.tool === entry.tool))) !== canonicalJson(toolsAfter.filter(entry => entry.tool !== PUSH_TOOL))) {
    throw new Error("Git push upgrade would change the tool set beyond push");
  }
  if (grantsBefore.length !== 1 || grantsAfter.length !== 1) throw new Error("Git push upgrade requires exactly one principal grant");
  const [grantBefore] = grantsBefore;
  const [grantAfter] = grantsAfter;
  if (canonicalJson({ ...grantBefore, scopes: undefined }) !== canonicalJson({ ...grantAfter, scopes: undefined }) ||
      canonicalJson([...grantBefore!.scopes, PUSH_SCOPE].sort()) !== canonicalJson([...grantAfter!.scopes].sort())) {
    throw new Error("Git push upgrade would change the principal grant beyond the push scope");
  }
  const addedRules = rulesAfter.filter(rule => !rulesBefore.some(old => canonicalJson(old) === canonicalJson(rule)));
  const keptRules = rulesAfter.filter(rule => rule.scope !== PUSH_SCOPE);
  if (addedRules.length === 0 || addedRules.some(rule => rule.scope !== PUSH_SCOPE || rule.effect !== "allow" || rule.target.kind !== "project") ||
      canonicalJson(keptRules) !== canonicalJson(rulesBefore)) {
    throw new Error("Git push upgrade would change target rules beyond project push rules");
  }
}

async function replaceJson(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.git-push-upgrade-${process.pid}`;
  const file = await open(temporary, "wx", 0o600);
  try { await file.writeFile(`${JSON.stringify(value, null, 2)}\n`); await file.sync(); }
  finally { await file.close(); }
  await rename(temporary, path);
  const directory = await open(dirname(path), "r");
  try { await directory.sync(); } finally { await directory.close(); }
}
