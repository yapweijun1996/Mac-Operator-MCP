import { createPrivateKey, sign } from "node:crypto";
import { open, rename, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerServiceInstanceLock, BrokerStore, PolicyBundleVerifier, PolicyManager, type SignedPolicyBundle } from "@mac-operator/broker";
import { validateEdgeServiceStartupConfig } from "@mac-operator/edge";
import { configSchema, ownerTools, scopesForGrantProfile, developmentTools, developmentPolicyScopes } from "./contracts.js";
import { AuthStore, assertPrivateDirectory } from "./store.js";
import { readAuthFile } from "./cli.js";
import { assertO1Policy, buildO1TargetRules } from "./w1-policy.js";
import { assertV2Policy, buildV2TargetRules } from "./v2-policy.js";
import { loadPersonalDevelopmentRuntimeConfig, developmentPolicyConfiguration } from "./personal-development-runtime.js";
import { desktopGrantsForUnchangedGuiPolicy } from "./desktop-grant-migration.js";

/** Offline owner opt-in. Existing OAuth grants retain their original scopes. */
export async function upgradePersonalDockerRead(root: string, packageRoot: string, sourceRevision: string) {
  assertPrivateDirectory(root);
  if (!/^[a-f0-9]{7,64}$/u.test(sourceRevision)) throw new Error("Source revision required");
  const data = join(root, "personal");
  const lock = await BrokerServiceInstanceLock.acquire(join(data, "run/service.lock"));
  let store: BrokerStore | undefined;
  let authStore: AuthStore | undefined;
  try {
    const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
    if (! ["o1", "v2"].includes(config.grantProfile) || new URL(config.issuer).pathname !== "/") throw new Error("Docker read upgrade requires the root O1 or V2 installation");
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(packageRoot, "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(data, "policy-public.pem") });
    const prior = await verifier.verifyFile(join(data, "policy.json"));
    const development = config.grantProfile === "v2"
      ? developmentPolicyConfiguration(loadPersonalDevelopmentRuntimeConfig(join(data, "development-runtime.json"))) : undefined;
    const assertPolicy = (policy: typeof prior.policy, docker: boolean | undefined) => development
      ? assertV2Policy(policy, config.principalId, config.issuerId, development, config.guiAccess, docker)
      : assertO1Policy(policy, config.principalId, config.issuerId, config.guiAccess, docker);
    const tools = development ? developmentTools(true) : ownerTools(true);
    const oauthScopes = scopesForGrantProfile(config.grantProfile, true);
    assertPolicy(prior.policy, config.dockerReadAccess);
    if (config.dockerReadAccess) return { changed: false, policyVersion: prior.policy.version, reconnectRequired: true };
    const original = JSON.parse(readAuthFile(join(data, "policy.json")).toString()) as SignedPolicyBundle;
    const project = prior.policy.filesystemRoots.find(value => value.rootId === "owner-project")!.path;
    const now = Date.now();
    const payload = { ...original.payload, revision: original.payload.revision + 1, issued_at_ms: now,
      principal_grants: [{ principal_id: config.principalId, issuer: config.issuerId, scopes: [...(development ? developmentPolicyScopes(true) : oauthScopes)], enabled: true }],
      target_rules: development
        ? buildV2TargetRules(config.principalId, original.payload.filesystem_roots, project, development, config.guiAccess, true)
        : buildO1TargetRules(config.principalId, original.payload.filesystem_roots, project, config.guiAccess, true),
      tool_enablement: tools.map(tool => ({ tool, enabled: true })) };
    if (canonicalJson(payload.target_rules.filter(rule => rule.scope !== "mac.docker.read")) !== canonicalJson(original.payload.target_rules)) {
      throw new Error("Docker upgrade changed unrelated target authority");
    }
    const bytes = Buffer.from(canonicalJson(payload));
    const privateBytes = readAuthFile(join(root, "personal-policy-private.key"));
    let bundle: SignedPolicyBundle;
    try { bundle = { ...original, payload, payload_digest: sha256(bytes), signature: sign(null, bytes, createPrivateKey(privateBytes)).toString("base64") }; }
    finally { privateBytes.fill(0); }
    const verified = verifier.verify(bundle);
    assertPolicy(verified.policy, true);
    const previousEdge = validateEdgeServiceStartupConfig(JSON.parse(readAuthFile(join(data, "edge-service.json")).toString()));
    if (previousEdge.dataRoot !== data || previousEdge.runtimeRoot !== join(data, "run") || previousEdge.policyVersion !== prior.policy.version) {
      throw new Error("Existing Edge binding does not match the signed policy");
    }
    const edge = validateEdgeServiceStartupConfig({ ...previousEdge, packageRoot, contractsDirectory: join(packageRoot, "tool-contracts"),
      sourceRevision, policyVersion: verified.policy.version, oauthScopes: [...oauthScopes] });
    const nextConfig = configSchema.parse({ ...config, dockerReadAccess: true });
    const input = JSON.parse(readAuthFile(join(root, "auth/broker-policy-input.json")).toString());
    const settings = JSON.parse(readAuthFile(join(root, "auth/edge-auth-settings.json")).toString());
    store = new BrokerStore(join(data, "broker.sqlite"), { runtimeFence: true,
      auditAnchor: { path: join(data, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readAuthFile(join(data, "audit.key"), 32) } } });
    const manager = new PolicyManager(prior.policy, store); manager.restore(prior);
    authStore = new AuthStore(join(root, "auth"));
    const desktop = desktopGrantsForUnchangedGuiPolicy(authStore, config.guiAccess, config.principalId, prior.policy, verified.policy);
    const browser = authStore.browserGrants().filter(grant => !grant.revoked && grant.principalId === config.principalId && grant.policyVersion === prior.policy.version);
    const requestId = `docker-read-upgrade-${payload.revision}`;
    store.appendAudit({ requestId, principalId: config.principalId, tool: "internal_docker_read_upgrade", eventType: "intent", decision: "allow",
      resultClass: "INTENT_RECORDED", targetRef: "docker_runtime:local", policyVersion: verified.policy.version,
      timestampMs: now, evidence: { sourceRevision, priorPolicyVersion: prior.policy.version, existingOAuthScopesExpanded: false } });
    manager.activate(verified);
    await replaceJson(join(data, "policy.json"), bundle);
    await replaceJson(join(data, "edge-service.json"), edge);
    await replaceJson(join(root, "auth/broker-policy-input.json"), { ...input, principal: payload.principal_grants[0], target_rules: payload.target_rules, enabled_tools: [...tools] });
    await replaceJson(join(root, "auth/edge-auth-settings.json"), { ...settings, oauthScopes: [...oauthScopes] });
    authStore.transaction(() => {
      for (const grant of browser) authStore!.put("browser_grant", grant.id, { ...grant, policyVersion: verified.policy.version });
      for (const grant of desktop) authStore!.put("desktop_grant", grant.id, { ...grant, policyVersion: verified.policy.version });
    });
    await replaceJson(join(root, "auth/auth-config.json"), nextConfig);
    store.appendAudit({ requestId, principalId: config.principalId, tool: "internal_docker_read_upgrade", eventType: "completion", decision: "allow",
      resultClass: "SUCCEEDED", targetRef: "docker_runtime:local", policyVersion: verified.policy.version, timestampMs: Date.now(),
      evidence: { sourceRevision, existingOAuthScopesExpanded: false, reconnectRequired: true } });
    return { changed: true, policyVersion: verified.policy.version, reconnectRequired: true };
  } finally { authStore?.close(); store?.close(); await lock.close(); }
}
async function replaceJson(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.docker-read-upgrade-${process.pid}`;
  const file = await open(temporary, "wx", 0o600);
  try {
    try { await file.writeFile(`${JSON.stringify(value, null, 2)}\n`); await file.sync(); } finally { await file.close(); }
    await rename(temporary, path);
    const directory = await open(dirname(path), "r");
    try { await directory.sync(); } finally { await directory.close(); }
  } finally { await rm(temporary, { force: true }); }
}
