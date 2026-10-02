import { rename, writeFile, unlink } from "node:fs/promises";
import { join } from "node:path";
import { BrokerServiceInstanceLock, PolicyBundleVerifier } from "@mac-operator/broker";
import { validateEdgeServiceStartupConfig } from "@mac-operator/edge";
import { configSchema } from "./contracts.js";
import { readAuthFile } from "./cli.js";
import { assertPrivateDirectory } from "./store.js";
import { assertV2Policy } from "./v2-policy.js";
import { developmentPolicyConfiguration, loadPersonalDevelopmentRuntimeConfig } from "./personal-development-runtime.js";

/** Explicit offline opt-in. Keep a complete stopped-state backup for release rollback. */
export async function enablePersonalTerminalConnection(root: string, packageRoot: string, sourceRevision: string): Promise<void> {
  assertPrivateDirectory(root);
  if (!/^[a-f0-9]{7,64}$/u.test(sourceRevision)) throw new Error("Source revision required");
  const data = join(root, "personal");
  const lock = await BrokerServiceInstanceLock.acquire(join(data, "run/service.lock"));
  const authPath = join(root, "auth/auth-config.json");
  const edgePath = join(data, "edge-service.json");
  try {
    const authBytes = readAuthFile(authPath);
    const edgeBytes = readAuthFile(edgePath);
    const auth = configSchema.parse(JSON.parse(authBytes.toString()));
    const edge = validateEdgeServiceStartupConfig(JSON.parse(edgeBytes.toString()));
    if (auth.grantProfile !== "v2" || new URL(auth.issuer).pathname !== "/" ||
        edge.oauthIssuer !== auth.issuer || edge.resourceServerUrl !== auth.resource || edge.issuerId !== auth.issuerId ||
        edge.dataRoot !== data || edge.runtimeRoot !== join(data, "run")) throw new Error("Existing V2 connection binding required");
    const verifier = await PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(packageRoot, "schemas"),
      expectedKeyId: "personal-policy-1", publicKeyPath: join(data, "policy-public.pem") });
    const verified = await verifier.verifyFile(join(data, "policy.json"));
    if (edge.policyVersion !== verified.policy.version) throw new Error("Existing signed policy binding required");
    assertV2Policy(verified.policy, auth.principalId, auth.issuerId,
      developmentPolicyConfiguration(loadPersonalDevelopmentRuntimeConfig(join(data, "development-runtime.json"))));
    const nextAuth = configSchema.parse({ ...auth, ownerTerminalConnection: true });
    const nextEdge = validateEdgeServiceStartupConfig({ ...edge, ownerTerminalConnection: true,
      packageRoot, contractsDirectory: join(packageRoot, "tool-contracts"), sourceRevision });
    // Startup rejects any interrupted pair, so partial configuration never widens live authority.
    try {
      await replace(edgePath, Buffer.from(`${JSON.stringify(nextEdge, null, 2)}\n`));
      await replace(authPath, Buffer.from(`${JSON.stringify(nextAuth, null, 2)}\n`));
    } catch (error) {
      await replace(edgePath, edgeBytes);
      await replace(authPath, authBytes);
      throw error;
    }
  } finally { await lock.close(); }
}

async function replace(path: string, bytes: Buffer): Promise<void> {
  const temporary = `${path}.terminal-connection-${process.pid}`;
  await writeFile(temporary, bytes, { mode: 0o600, flag: "wx" });
  try { await rename(temporary, path); }
  finally { await unlink(temporary).catch(error => { if (error.code !== "ENOENT") throw error; }); }
}
