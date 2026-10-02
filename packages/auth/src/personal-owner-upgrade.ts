import { createPrivateKey, sign } from "node:crypto";
import { rename, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { ApprovalIssuerKeyManager, BrokerServiceInstanceLock, BrokerStore, PolicyBundleVerifier, PolicyManager,
  provisionAuthenticationKey, type SignedPolicyBundle } from "@mac-operator/broker";
import { validateEdgeServiceStartupConfig } from "@mac-operator/edge";
import { configSchema, O1_SCOPES, O1_TOOLS } from "./contracts.js";
import { AuthStore, assertPrivateDirectory } from "./store.js";
import { readAuthFile } from "./cli.js";
import { assertG1Policy, assertO1Policy, buildO1TargetRules, w1FilesystemRoots } from "./w1-policy.js";

/** Offline, explicit owner opt-in. Run against a protected backup before switching releases. */
export async function upgradePersonalOwnerTerminal(root: string, packageRoot: string, sourceRevision: string): Promise<void> {
  assertPrivateDirectory(root);
  const data = join(root, "personal");
  const lock = await BrokerServiceInstanceLock.acquire(join(data, "run/service.lock"));
  let store: BrokerStore | undefined;
  let keyManager: ApprovalIssuerKeyManager | undefined;
  try {
    const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
    if (config.grantProfile !== "g1" && config.grantProfile !== "o1") throw new Error("Owner terminal upgrade requires an existing G1 installation");
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(packageRoot, "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(data, "policy-public.pem") });
    const prior = await verifier.verifyFile(join(data, "policy.json"));
    if (config.grantProfile === "o1") {
      try { assertO1Policy(prior.policy, config.principalId, config.issuerId); }
      catch { throw new Error("Existing O1 policy does not match; if it predates mac_terminal_session run the terminal-sessions upgrade"); }
      return;
    }
    assertG1Policy(prior.policy, config.principalId, config.issuerId);
    store = new BrokerStore(join(data, "broker.sqlite"), { runtimeFence: true,
      auditAnchor: { path: join(data, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readAuthFile(join(data, "audit.key"), 32) } } });
    const policyManager = new PolicyManager(prior.policy, store);
    policyManager.restore(prior);
    const original = JSON.parse(readAuthFile(join(data, "policy.json")).toString()) as SignedPolicyBundle;
    const now = Date.now();
    const project = prior.policy.filesystemRoots.find(value => value.rootId === "owner-project")!.path;
    const payload = { ...original.payload, revision: original.payload.revision + 1, issued_at_ms: now,
      principal_grants: [{ principal_id: config.principalId, issuer: config.issuerId, scopes: [...O1_SCOPES], enabled: true }],
      target_rules: buildO1TargetRules(config.principalId, w1FilesystemRoots(project), project),
      tool_enablement: O1_TOOLS.map(tool => ({ tool, enabled: true })) };
    const bytes = Buffer.from(canonicalJson(payload));
    const privateBytes = readAuthFile(join(root, "personal-policy-private.key"));
    let bundle: SignedPolicyBundle;
    try { bundle = { ...original, payload, payload_digest: sha256(bytes), signature: sign(null, bytes, createPrivateKey(privateBytes)).toString("base64") }; }
    finally { privateBytes.fill(0); }
    const verified = verifier.verify(bundle);
    assertO1Policy(verified.policy, config.principalId, config.issuerId);
    const previousEdge = validateEdgeServiceStartupConfig(JSON.parse(readAuthFile(join(data, "edge-service.json")).toString()));
    const rebased: Record<string, unknown> = { ...previousEdge, dataRoot: data, runtimeRoot: join(data, "run") };
    for (const field of ["brokerSocketPath", "authenticationKeyPath", "tlsCertificatePath", "tlsPrivateKeyPath",
      "oauthStatusKeyPath", "oauthStatusLocalCaPath", "serviceStatusSocketPath", "serviceStatusKeyPath"] as const) {
      const path = previousEdge[field];
      if (path === undefined) continue;
      if (!path.startsWith(`${previousEdge.dataRoot}/`)) throw new Error("Personal state path is outside its protected data root");
      rebased[field] = `${data}${path.slice(previousEdge.dataRoot.length)}`;
    }
    const edge = validateEdgeServiceStartupConfig({ ...rebased,
      packageRoot, contractsDirectory: join(packageRoot, "tool-contracts"), sourceRevision,
      oauthScopes: [...O1_SCOPES], policyVersion: verified.policy.version, ipcTimeoutMs: 180000 });
    const issuer = JSON.parse(readAuthFile(join(data, "approval-issuer.json")).toString());
    if (issuer.enabled !== true || issuer.keyConfigPath !== join(previousEdge.dataRoot, "approval-keys.json") ||
        issuer.socketPath !== join(previousEdge.runtimeRoot, "approval.sock")) throw new Error("Existing approval startup paths mismatch");
    const keyConfig = JSON.parse(readAuthFile(join(data, "approval-keys.json")).toString()) as {
      schemaVersion: "0.1"; revision: number; keys: Record<string, unknown>[];
    };
    if (keyConfig.keys.length !== 1 || keyConfig.keys[0]!.allowUnattended !== false) throw new Error("Existing attended issuer boundary mismatch");
    if (keyConfig.keys[0]!.path !== join(previousEdge.dataRoot, "approval.key")) throw new Error("Existing attended issuer key path mismatch");
    const terminalKeyPath = join(data, "terminal-approval.key");
    await provisionAuthenticationKey(terminalKeyPath);
    await replaceJson(join(data, "approval-keys.json"), { ...keyConfig, revision: keyConfig.revision + 1,
      keys: [{ ...keyConfig.keys[0]!, path: join(data, "approval.key") }, { issuerId: `terminal-approver-${sha256(config.principalId).slice(0, 32)}`, keyId: "personal-terminal-1",
        path: terminalKeyPath, notBeforeMs: now - 5000, expiresAtMs: now + 365 * 86400000, allowUnattended: true }] });
    keyManager = new ApprovalIssuerKeyManager(join(data, "approval-keys.json"), store);
    await keyManager.activate();
    policyManager.activate(verified);
    await replaceJson(join(data, "policy.json"), bundle);
    await replaceJson(join(data, "edge-service.json"), edge);
    await replaceJson(join(data, "approval-issuer.json"), { schemaVersion: "0.1", enabled: true,
      keyConfigPath: join(data, "approval-keys.json"), socketPath: join(data, "run/approval.sock") });
    await replaceJson(join(root, "auth/edge-auth-settings.json"), { ...JSON.parse(readAuthFile(join(root, "auth/edge-auth-settings.json")).toString()),
      grantProfile: "o1", oauthScopes: [...O1_SCOPES] });
    await replaceJson(join(root, "auth/broker-policy-input.json"), { principal: payload.principal_grants[0], target_rules: payload.target_rules,
      enabled_tools: [...O1_TOOLS], filesystem_roots: payload.filesystem_roots });
    const authStore = new AuthStore(join(root, "auth"));
    try {
      const grants = authStore.browserGrants().filter(grant => !grant.revoked && grant.principalId === config.principalId && grant.policyVersion === prior.policy.version);
      if (grants.length > 0) {
        const requestId = `owner-terminal-browser-grants-${payload.revision}`;
        store.appendAudit({ requestId, principalId: config.principalId, tool: "internal_owner_terminal_upgrade", eventType: "intent",
          decision: "allow", resultClass: "INTENT_RECORDED", targetRef: "host:owner-terminal", policyVersion: verified.policy.version,
          evidence: { browserGrantCount: grants.length, priorPolicyVersion: prior.policy.version }, timestampMs: Date.now() });
        authStore.transaction(() => { for (const grant of grants) authStore.put("browser_grant", grant.id, { ...grant, policyVersion: verified.policy.version }); });
        store.appendAudit({ requestId, principalId: config.principalId, tool: "internal_owner_terminal_upgrade", eventType: "completion",
          decision: "allow", resultClass: "SUCCEEDED", targetRef: "host:owner-terminal", policyVersion: verified.policy.version,
          evidence: { browserGrantCount: grants.length }, timestampMs: Date.now() });
      }
    } finally { authStore.close(); }
    await replaceJson(join(root, "auth/auth-config.json"), { ...config, grantProfile: "o1" });
  } finally { keyManager?.dispose(); store?.close(); await lock.close(); }
}

async function replaceJson(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.owner-upgrade-${process.pid}`;
  await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  await rename(temporary, path);
}
