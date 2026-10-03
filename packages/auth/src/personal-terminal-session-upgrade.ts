import { createPrivateKey, sign } from "node:crypto";
import { open, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerServiceInstanceLock, BrokerStore, PolicyBundleVerifier, PolicyManager, type SignedPolicyBundle } from "@mac-operator/broker";
import { validateEdgeServiceStartupConfig } from "@mac-operator/edge";
import { configSchema, ownerTools, developmentTools } from "./contracts.js";
import { AuthStore, assertPrivateDirectory } from "./store.js";
import { readAuthFile } from "./cli.js";
import { assertO1Policy } from "./w1-policy.js";
import { assertV2Policy } from "./v2-policy.js";
import { developmentPolicyConfiguration, loadPersonalDevelopmentRuntimeConfig } from "./personal-development-runtime.js";
import { desktopGrantsForUnchangedGuiPolicy } from "./desktop-grant-migration.js";

const SESSION_TOOL = "mac_terminal_session";

/**
 * Offline opt-in for an existing O1 or V2 installation signed before `mac_terminal_session`
 * existed. Signs one new policy revision that only appends that tool; scopes, targets, grants,
 * keys and OAuth consent are unchanged because the tool reuses `mac.terminal.exec`. Keep a
 * complete stopped-state backup for rollback.
 */
export async function upgradePersonalTerminalSessions(root: string, packageRoot: string, sourceRevision: string): Promise<void> {
  assertPrivateDirectory(root);
  if (!/^[a-f0-9]{7,64}$/u.test(sourceRevision)) throw new Error("Source revision required");
  const data = join(root, "personal");
  const lock = await BrokerServiceInstanceLock.acquire(join(data, "run/service.lock"));
  let store: BrokerStore | undefined;
  try {
    const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
    if (config.grantProfile !== "o1" && config.grantProfile !== "v2") throw new Error("Terminal session upgrade requires an existing O1 or V2 installation");
    const fullTools = config.grantProfile === "v2" ? developmentTools(config.dockerReadAccess) : ownerTools(config.dockerReadAccess);
    const assertCurrent = (policy: Parameters<typeof assertO1Policy>[0]): void => config.grantProfile === "v2"
      ? assertV2Policy(policy, config.principalId, config.issuerId,
        developmentPolicyConfiguration(loadPersonalDevelopmentRuntimeConfig(join(data, "development-runtime.json"))), config.guiAccess, config.dockerReadAccess)
      : assertO1Policy(policy, config.principalId, config.issuerId, config.guiAccess, config.dockerReadAccess);
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(packageRoot, "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(data, "policy-public.pem") });
    const prior = await verifier.verifyFile(join(data, "policy.json"));
    const enabled = [...prior.policy.tools.values()].filter(tool => tool.enabled).map(tool => tool.tool).sort();
    if (enabled.includes(SESSION_TOOL)) { assertCurrent(prior.policy); return; }
    // Refuse anything that is not exactly the previous signed tool set, so this cannot widen other authority.
    if (canonicalJson(enabled) !== canonicalJson(fullTools.filter(tool => tool !== SESSION_TOOL).sort())) {
      throw new Error("Existing signed tool set is not the expected pre-session set");
    }
    const original = JSON.parse(readAuthFile(join(data, "policy.json")).toString()) as SignedPolicyBundle;
    const now = Date.now();
    const payload = { ...original.payload, revision: original.payload.revision + 1, issued_at_ms: now,
      tool_enablement: [...original.payload.tool_enablement, { tool: SESSION_TOOL, enabled: true }] };
    const bytes = Buffer.from(canonicalJson(payload));
    const privateBytes = readAuthFile(join(root, "personal-policy-private.key"));
    let bundle: SignedPolicyBundle;
    try { bundle = { ...original, payload, payload_digest: sha256(bytes), signature: sign(null, bytes, createPrivateKey(privateBytes)).toString("base64") }; }
    finally { privateBytes.fill(0); }
    const verified = verifier.verify(bundle);
    assertCurrent(verified.policy);
    const previousEdge = validateEdgeServiceStartupConfig(JSON.parse(readAuthFile(join(data, "edge-service.json")).toString()));
    if (previousEdge.dataRoot !== data || previousEdge.runtimeRoot !== join(data, "run") || previousEdge.policyVersion !== prior.policy.version) {
      throw new Error("Existing Edge binding does not match the signed policy");
    }
    const edge = validateEdgeServiceStartupConfig({ ...previousEdge, packageRoot, contractsDirectory: join(packageRoot, "tool-contracts"),
      sourceRevision, policyVersion: verified.policy.version });
    const policyInput = JSON.parse(readAuthFile(join(root, "auth/broker-policy-input.json")).toString()) as Record<string, unknown>;
    store = new BrokerStore(join(data, "broker.sqlite"), { runtimeFence: true,
      auditAnchor: { path: join(data, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readAuthFile(join(data, "audit.key"), 32) } } });
    const manager = new PolicyManager(prior.policy, store);
    manager.restore(prior);
    const requestId = `terminal-session-upgrade-${payload.revision}`;
    store.appendAudit({ requestId, principalId: config.principalId, tool: "internal_terminal_session_upgrade", eventType: "intent",
      decision: "allow", resultClass: "INTENT_RECORDED", targetRef: "host:owner-terminal", policyVersion: verified.policy.version, timestampMs: now,
      evidence: { sourceRevision, priorPolicyVersion: prior.policy.version, profile: config.grantProfile } });
    manager.activate(verified);
    await replaceJson(join(data, "policy.json"), bundle);
    await replaceJson(join(data, "edge-service.json"), edge);
    await replaceJson(join(root, "auth/broker-policy-input.json"), { ...policyInput, enabled_tools: [...fullTools] });
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
    store.appendAudit({ requestId, principalId: config.principalId, tool: "internal_terminal_session_upgrade", eventType: "completion",
      decision: "allow", resultClass: "SUCCEEDED", targetRef: "host:owner-terminal", policyVersion: verified.policy.version, timestampMs: Date.now(),
      evidence: { sourceRevision, browserGrantCount, desktopGrantCount, scopesExpanded: false } });
  } finally { store?.close(); await lock.close(); }
}

async function replaceJson(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.terminal-session-upgrade-${process.pid}`;
  const file = await open(temporary, "wx", 0o600);
  try { await file.writeFile(`${JSON.stringify(value, null, 2)}\n`); await file.sync(); }
  finally { await file.close(); }
  await rename(temporary, path);
  const directory = await open(dirname(path), "r");
  try { await directory.sync(); } finally { await directory.close(); }
}
