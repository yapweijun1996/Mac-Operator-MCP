import { createPrivateKey, sign } from "node:crypto";
import { open, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { ApprovalIssuerKeyManager, BrokerServiceInstanceLock, BrokerStore, PolicyBundleVerifier, PolicyManager,
  provisionAuthenticationKey, type SignedPolicyBundle } from "@mac-operator/broker";
import { validateEdgeServiceStartupConfig } from "@mac-operator/edge";
import { configSchema, developmentTools, scopesForGrantProfile } from "./contracts.js";
import { AuthStore, assertPrivateDirectory } from "./store.js";
import { readAuthFile } from "./cli.js";
import { assertO1Policy } from "./w1-policy.js";
import { assertV2Policy, buildV2PolicyDocument } from "./v2-policy.js";
import { createPersonalDevelopmentRuntime, developmentPolicyConfiguration, loadPersonalDevelopmentRuntimeConfig } from "./personal-development-runtime.js";
import { desktopGrantsForUnchangedGuiPolicy } from "./desktop-grant-migration.js";

/** Offline opt-in only. The operator must retain a full stopped-state backup for rollback. */
export async function upgradePersonalDevelopment(root: string, packageRoot: string, sourceRevision: string, runtimeConfigPath: string): Promise<void> {
  assertPrivateDirectory(root);
  if (!/^[a-f0-9]{7,64}$/u.test(sourceRevision)) throw new Error("Development upgrade requires a source revision");
  const development = loadPersonalDevelopmentRuntimeConfig(runtimeConfigPath);
  const configuration = developmentPolicyConfiguration(development);
  const data = join(root, "personal");
  const lock = await BrokerServiceInstanceLock.acquire(join(data, "run/service.lock"));
  let store: BrokerStore | undefined;
  let keyManager: ApprovalIssuerKeyManager | undefined;
  try {
    const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
    if (config.grantProfile !== "o1" && config.grantProfile !== "v2") throw new Error("Development upgrade requires an existing O1 installation");
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(packageRoot, "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(data, "policy-public.pem") });
    const prior = await verifier.verifyFile(join(data, "policy.json"));
    if (prior.policy.filesystemRoots.find(value => value.rootId === "owner-project")?.path !== development.ownerProjectRoot) throw new Error("Development upgrade owner project mismatch");
    if (config.grantProfile === "v2") {
      assertV2Policy(prior.policy, config.principalId, config.issuerId, configuration, config.guiAccess, config.dockerReadAccess);
      if (canonicalJson(loadPersonalDevelopmentRuntimeConfig(join(data, "development-runtime.json"))) !== canonicalJson(development)) throw new Error("Installed development runtime differs from retry");
      return;
    }
    assertO1Policy(prior.policy, config.principalId, config.issuerId, config.guiAccess, config.dockerReadAccess);
    // Validate real Engine, image, provider and protected roots before touching signed authority.
    const runtime = await createPersonalDevelopmentRuntime(development, config.principalId);
    await runtime.runner.close(); await runtime.gateway.close();
    const original = JSON.parse(readAuthFile(join(data, "policy.json")).toString()) as SignedPolicyBundle;
    const now = Date.now();
    const payload = { ...buildV2PolicyDocument(original.payload, config.principalId, config.issuerId, configuration, config.guiAccess, config.dockerReadAccess),
      revision: original.payload.revision + 1, issued_at_ms: now };
    const bytes = Buffer.from(canonicalJson(payload));
    const privateBytes = readAuthFile(join(root, "personal-policy-private.key"));
    let bundle: SignedPolicyBundle;
    try { bundle = { ...original, payload, payload_digest: sha256(bytes), signature: sign(null, bytes, createPrivateKey(privateBytes)).toString("base64") }; }
    finally { privateBytes.fill(0); }
    const verified = verifier.verify(bundle);
    assertV2Policy(verified.policy, config.principalId, config.issuerId, configuration, config.guiAccess, config.dockerReadAccess);
    const previousEdge = validateEdgeServiceStartupConfig(JSON.parse(readAuthFile(join(data, "edge-service.json")).toString()));
    if (previousEdge.dataRoot !== data || previousEdge.runtimeRoot !== join(data, "run")) throw new Error("Development migration does not relocate existing state");
    const edge = validateEdgeServiceStartupConfig({ ...previousEdge, packageRoot, contractsDirectory: join(packageRoot, "tool-contracts"),
      sourceRevision, oauthScopes: [...scopesForGrantProfile("v2", config.dockerReadAccess)], policyVersion: verified.policy.version });
    const keyConfig = JSON.parse(readAuthFile(join(data, "approval-keys.json")).toString()) as { schemaVersion: "0.1"; revision: number; keys: Record<string, unknown>[] };
    if (keyConfig.keys.length !== 2 || keyConfig.keys.filter(key => key.allowUnattended === false).length !== 1 ||
        keyConfig.keys.filter(key => key.keyId === "personal-terminal-1" && key.issuerId === `terminal-approver-${sha256(config.principalId).slice(0, 32)}` && key.allowUnattended === true).length !== 1 ||
        keyConfig.keys.some(key => typeof key.path !== "string" || ![join(data, "approval.key"), join(data, "terminal-approval.key")].includes(key.path))) throw new Error("Existing approval issuer boundary mismatch");
    store = new BrokerStore(join(data, "broker.sqlite"), { runtimeFence: true,
      auditAnchor: { path: join(data, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readAuthFile(join(data, "audit.key"), 32) } } });
    const manager = new PolicyManager(prior.policy, store); manager.restore(prior);
    const requestId = `development-upgrade-${payload.revision}`;
    store.appendAudit({ requestId, principalId: config.principalId, tool: "internal_development_upgrade", eventType: "intent", decision: "allow",
      resultClass: "INTENT_RECORDED", targetRef: "host:development-gateway", policyVersion: verified.policy.version, timestampMs: now,
      evidence: { sourceRevision, evidenceSha256: development.evidenceSha256, imageId: development.imageId, priorPolicyVersion: prior.policy.version } });
    const keyPath = join(data, "development-approval.key");
    await provisionAuthenticationKey(keyPath);
    await replaceJson(join(data, "approval-keys.json"), { ...keyConfig, revision: keyConfig.revision + 1,
      keys: [...keyConfig.keys, { issuerId: `development-approver-${sha256(config.principalId).slice(0, 32)}`, keyId: "personal-development-1",
        path: keyPath, notBeforeMs: now - 5000, expiresAtMs: now + 365 * 86400000, allowUnattended: true }] });
    keyManager = new ApprovalIssuerKeyManager(join(data, "approval-keys.json"), store); await keyManager.activate();
    manager.activate(verified);
    await replaceJson(join(data, "development-runtime.json"), development);
    await replaceJson(join(data, "policy.json"), bundle);
    await replaceJson(join(data, "edge-service.json"), edge);
    await replaceJson(join(root, "auth/edge-auth-settings.json"), { ...JSON.parse(readAuthFile(join(root, "auth/edge-auth-settings.json")).toString()), grantProfile: "v2", oauthScopes: [...scopesForGrantProfile("v2", config.dockerReadAccess)] });
    await replaceJson(join(root, "auth/broker-policy-input.json"), { principal: payload.principal_grants[0], target_rules: payload.target_rules,
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
    // Existing OAuth grants retain their original scopes; reconnecting is a separate consent.
    await replaceJson(join(root, "auth/auth-config.json"), { ...config, grantProfile: "v2" });
    store.appendAudit({ requestId, principalId: config.principalId, tool: "internal_development_upgrade", eventType: "completion", decision: "allow",
      resultClass: "SUCCEEDED", targetRef: "host:development-gateway", policyVersion: verified.policy.version, timestampMs: Date.now(),
      evidence: { sourceRevision, evidenceSha256: development.evidenceSha256, browserGrantCount, desktopGrantCount, existingOAuthScopesExpanded: false } });
  } finally { keyManager?.dispose(); store?.close(); await lock.close(); }
}

async function replaceJson(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.development-upgrade-${process.pid}`;
  const file = await open(temporary, "wx", 0o600);
  try { await file.writeFile(`${JSON.stringify(value, null, 2)}\n`); await file.sync(); }
  finally { await file.close(); }
  await rename(temporary, path);
  const directory = await open(dirname(path), "r");
  try { await directory.sync(); } finally { await directory.close(); }
}
