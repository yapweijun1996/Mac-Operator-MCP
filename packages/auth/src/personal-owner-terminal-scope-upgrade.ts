import { open, rename } from "node:fs/promises";
import { dirname, join } from "node:path";
import { BrokerServiceInstanceLock, PolicyBundleVerifier } from "@mac-operator/broker";
import { validateEdgeServiceStartupConfig } from "@mac-operator/edge";
import { configSchema, scopesForGrantProfile } from "./contracts.js";
import { assertPrivateDirectory } from "./store.js";
import { readAuthFile } from "./cli.js";
import { assertV2Policy } from "./v2-policy.js";
import { developmentPolicyConfiguration, loadPersonalDevelopmentRuntimeConfig } from "./personal-development-runtime.js";

/**
 * Offline owner opt-in that adds `mac.terminal.exec` to the default `/mcp` consent of a V2 installation. The signed policy
 * already grants the scope and tools, so no policy revision is signed: the existing strict V2 assertion must pass unchanged
 * and only the OAuth scope advertisement changes. Existing OAuth grants keep their scopes; the owner reconnects once.
 * It is mutually exclusive with the independent `/terminal/mcp` connection. Keep a complete stopped-state backup for rollback.
 */
export async function enablePersonalOwnerTerminalScope(root: string, packageRoot: string, sourceRevision: string): Promise<void> {
  assertPrivateDirectory(root);
  if (!/^[a-f0-9]{7,64}$/u.test(sourceRevision)) throw new Error("Source revision required");
  const data = join(root, "personal");
  const lock = await BrokerServiceInstanceLock.acquire(join(data, "run/service.lock"));
  const authPath = join(root, "auth/auth-config.json");
  const edgePath = join(data, "edge-service.json");
  const settingsPath = join(root, "auth/edge-auth-settings.json");
  try {
    const authBytes = readAuthFile(authPath);
    const edgeBytes = readAuthFile(edgePath);
    const settingsBytes = readAuthFile(settingsPath);
    const auth = configSchema.parse(JSON.parse(authBytes.toString()));
    if (auth.grantProfile !== "v2" || new URL(auth.issuer).pathname !== "/" || auth.ownerTerminalConnection === true) {
      throw new Error("Terminal scope requires the root V2 connection without a separate terminal connection");
    }
    const edge = validateEdgeServiceStartupConfig(JSON.parse(edgeBytes.toString()));
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(packageRoot, "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(data, "policy-public.pem") });
    const verified = await verifier.verifyFile(join(data, "policy.json"));
    if (edge.policyVersion !== verified.policy.version || edge.dataRoot !== data || edge.runtimeRoot !== join(data, "run")) {
      throw new Error("Existing signed policy binding required");
    }
    assertV2Policy(verified.policy, auth.principalId, auth.issuerId,
      developmentPolicyConfiguration(loadPersonalDevelopmentRuntimeConfig(join(data, "development-runtime.json"))), auth.guiAccess, auth.dockerReadAccess);
    const scopes = [...scopesForGrantProfile("v2", auth.dockerReadAccess, true)];
    const nextEdge = validateEdgeServiceStartupConfig({ ...edge, packageRoot, contractsDirectory: join(packageRoot, "tool-contracts"),
      sourceRevision, oauthScopes: scopes });
    const nextAuth = configSchema.parse({ ...auth, ownerTerminalScope: true });
    const nextSettings = { ...(JSON.parse(settingsBytes.toString()) as Record<string, unknown>), oauthScopes: scopes };
    // Startup rejects a mismatched Auth/Edge pair, so an interrupted write never widens live authority.
    try {
      await replaceJson(edgePath, nextEdge);
      await replaceJson(settingsPath, nextSettings);
      await replaceJson(authPath, nextAuth);
    } catch (error) {
      await replaceBytes(edgePath, edgeBytes); await replaceBytes(settingsPath, settingsBytes); await replaceBytes(authPath, authBytes);
      throw error;
    }
  } finally { await lock.close(); }
}

async function replaceJson(path: string, value: unknown): Promise<void> { await replaceBytes(path, Buffer.from(`${JSON.stringify(value, null, 2)}\n`)); }

async function replaceBytes(path: string, bytes: Buffer): Promise<void> {
  const temporary = `${path}.terminal-scope-${process.pid}`;
  const file = await open(temporary, "wx", 0o600);
  try { await file.writeFile(bytes); await file.sync(); } finally { await file.close(); }
  await rename(temporary, path);
  const directory = await open(dirname(path), "r");
  try { await directory.sync(); } finally { await directory.close(); }
}
