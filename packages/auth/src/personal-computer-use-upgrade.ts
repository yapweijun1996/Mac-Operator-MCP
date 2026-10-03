import { createPrivateKey, randomUUID, sign } from "node:crypto";
import { open, rename, rm } from "node:fs/promises";
import { dirname, join } from "node:path";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerServiceInstanceLock, BrokerStore, PolicyBundleVerifier, PolicyManager, type SignedPolicyBundle } from "@mac-operator/broker";
import { validateEdgeServiceStartupConfig } from "@mac-operator/edge";
import { configSchema } from "./contracts.js";
import { AuthStore, assertPrivateDirectory } from "./store.js";
import { readAuthFile } from "./cli.js";
import { assertG1Policy, assertO1Policy, buildG1TargetRules, buildO1TargetRules } from "./w1-policy.js";
import { assertV2Policy, buildV2TargetRules } from "./v2-policy.js";
import { developmentPolicyConfiguration, loadPersonalDevelopmentRuntimeConfig } from "./personal-development-runtime.js";

/** Explicit offline owner consent; existing browser grants never become desktop grants. */
export async function upgradePersonalComputerUse(root: string, packageRoot: string, sourceRevision: string): Promise<{
  policyVersion: string; desktopGrantId: string; changed: boolean;
}> {
  assertPrivateDirectory(root);
  if (!/^[a-f0-9]{7,64}$/u.test(sourceRevision)) throw new Error("Source revision required");
  const data = join(root, "personal");
  const lock = await BrokerServiceInstanceLock.acquire(join(data, "run/service.lock"));
  let store: BrokerStore | undefined;
  let authStore: AuthStore | undefined;
  try {
    const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
    if (!["g1", "o1", "v2"].includes(config.grantProfile)) throw new Error("Computer use requires a GUI-enabled personal profile");
    const runtime = config.grantProfile === "v2"
      ? developmentPolicyConfiguration(loadPersonalDevelopmentRuntimeConfig(join(data, "development-runtime.json"))) : undefined;
    const assertCurrent = (policy: Parameters<typeof assertO1Policy>[0], access: "browsers" | "desktop"): void => {
      if (runtime) assertV2Policy(policy, config.principalId, config.issuerId, runtime, access, config.dockerReadAccess);
      else (config.grantProfile === "o1" ? assertO1Policy : assertG1Policy)(policy, config.principalId, config.issuerId, access, config.dockerReadAccess);
    };
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(packageRoot, "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(data, "policy-public.pem") });
    const prior = await verifier.verifyFile(join(data, "policy.json"));
    assertCurrent(prior.policy, config.guiAccess ?? "browsers");
    const previousEdge = validateEdgeServiceStartupConfig(JSON.parse(readAuthFile(join(data, "edge-service.json")).toString()));
    if (previousEdge.dataRoot !== data || previousEdge.runtimeRoot !== join(data, "run") || previousEdge.policyVersion !== prior.policy.version) {
      throw new Error("Existing Edge binding does not match the signed policy");
    }
    store = new BrokerStore(join(data, "broker.sqlite"), { runtimeFence: true,
      auditAnchor: { path: join(data, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readAuthFile(join(data, "audit.key"), 32) } } });
    const manager = new PolicyManager(prior.policy, store);
    manager.restore(prior);
    authStore = new AuthStore(join(root, "auth"));
    let verified = prior;
    const now = Date.now();
    let changed = false;
    let upgradeRequestId: string | undefined;
    if (config.guiAccess !== "desktop") {
      const original = JSON.parse(readAuthFile(join(data, "policy.json")).toString()) as SignedPolicyBundle;
      const project = prior.policy.filesystemRoots.find(value => value.rootId === "owner-project")!.path;
      const targetRules = runtime
        ? buildV2TargetRules(config.principalId, original.payload.filesystem_roots, project, runtime, "desktop", config.dockerReadAccess)
        : (config.grantProfile === "o1" ? buildO1TargetRules : buildG1TargetRules)(config.principalId,
          original.payload.filesystem_roots, project, "desktop", config.dockerReadAccess);
      const guiScopes = new Set(["mac.app.control", "mac.ui.observe", "mac.ui.control"]);
      if (canonicalJson(targetRules.filter(rule => !guiScopes.has(rule.scope))) !==
          canonicalJson(original.payload.target_rules.filter(rule => !guiScopes.has(rule.scope)))) {
        throw new Error("Computer-use migration cannot change non-GUI targets");
      }
      const payload = { ...original.payload, revision: original.payload.revision + 1, issued_at_ms: now, target_rules: targetRules };
      const bytes = Buffer.from(canonicalJson(payload));
      const privateBytes = readAuthFile(join(root, "personal-policy-private.key"));
      let bundle: SignedPolicyBundle;
      try { bundle = { ...original, payload, payload_digest: sha256(bytes), signature: sign(null, bytes, createPrivateKey(privateBytes)).toString("base64") }; }
      finally { privateBytes.fill(0); }
      verified = verifier.verify(bundle);
      assertCurrent(verified.policy, "desktop");
      // Validate every replacement before the first durable policy transition.
      // Cross-file interruption still requires the stopped-state deployment backup.
      const edge = validateEdgeServiceStartupConfig({ ...previousEdge, packageRoot,
        contractsDirectory: join(packageRoot, "tool-contracts"), sourceRevision, policyVersion: verified.policy.version });
      const input = JSON.parse(readAuthFile(join(root, "auth/broker-policy-input.json")).toString()) as Record<string, unknown>;
      const nextConfig = configSchema.parse({ ...config, guiAccess: "desktop" });
      upgradeRequestId = `computer-use-upgrade-${payload.revision}`;
      store.appendAudit({ requestId: upgradeRequestId, principalId: config.principalId, tool: "internal_computer_use_upgrade", eventType: "intent",
        decision: "allow", resultClass: "INTENT_RECORDED", targetRef: "app_window:desktop", policyVersion: verified.policy.version,
        timestampMs: now, evidence: { sourceRevision, priorPolicyVersion: prior.policy.version, scopesExpanded: false } });
      manager.activate(verified);
      await replaceJson(join(data, "policy.json"), bundle);
      await replaceJson(join(data, "edge-service.json"), edge);
      await replaceJson(join(root, "auth/broker-policy-input.json"), { ...input, target_rules: targetRules });
      await replaceJson(join(root, "auth/auth-config.json"), nextConfig);
      changed = true;
    }
    const existing = authStore.desktopGrants().find(grant => !grant.revoked && grant.principalId === config.principalId &&
      grant.policyVersion === verified.policy.version);
    const desktopGrantId = existing?.id ?? `gui-session:${randomUUID()}`;
    if (!existing) {
      const consentRequestId = `computer-use-owner-${randomUUID()}`;
      store.appendAudit({ requestId: consentRequestId, principalId: config.principalId, tool: "internal_computer_use_consent", eventType: "intent",
        decision: "allow", resultClass: "INTENT_RECORDED", targetRef: "app_window:desktop", policyVersion: verified.policy.version,
        timestampMs: now, evidence: { desktopGrantId, persistent: true, sourceRevision } });
      authStore.put("desktop_grant", desktopGrantId, { id: desktopGrantId, principalId: config.principalId,
        policyVersion: verified.policy.version, consentRequestId, createdAt: now, revoked: false });
      store.appendAudit({ requestId: consentRequestId, principalId: config.principalId, tool: "internal_computer_use_consent",
        eventType: "completion", decision: "allow", resultClass: "SUCCEEDED", targetRef: "app_window:desktop",
        policyVersion: verified.policy.version, timestampMs: Date.now(), evidence: { desktopGrantId, persistent: true, sourceRevision } });
      changed = true;
    }
    if (upgradeRequestId) store.appendAudit({ requestId: upgradeRequestId, principalId: config.principalId,
      tool: "internal_computer_use_upgrade", eventType: "completion", decision: "allow", resultClass: "SUCCEEDED",
      targetRef: "app_window:desktop", policyVersion: verified.policy.version, timestampMs: Date.now(),
      evidence: { desktopGrantId, sourceRevision, persistent: true, browserGrantsExpanded: false, changed } });
    return { policyVersion: verified.policy.version, desktopGrantId, changed };
  } finally { authStore?.close(); store?.close(); await lock.close(); }
}

async function replaceJson(path: string, value: unknown): Promise<void> {
  const temporary = `${path}.computer-use-upgrade-${process.pid}`;
  const file = await open(temporary, "wx", 0o600);
  try {
    try { await file.writeFile(`${JSON.stringify(value, null, 2)}\n`); await file.sync(); }
    finally { await file.close(); }
    await rename(temporary, path);
    const directory = await open(dirname(path), "r");
    try { await directory.sync(); } finally { await directory.close(); }
  } finally { await rm(temporary, { force: true }); }
}
