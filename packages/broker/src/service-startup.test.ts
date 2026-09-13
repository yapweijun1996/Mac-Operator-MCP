import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeAuthenticationKeyManager, writeEdgeAuthenticationKeyConfig, type EdgeAuthenticationKeyConfig } from "./edge-keyring-config.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { BrokerStore } from "./persistence.js";
import { PolicyBundleVerifier, PolicyManager, type PolicyDocument, type SignedPolicyBundle } from "./policy-loader.js";
import {
  createBrokerServiceFromStartupConfig,
  loadBrokerServiceStartupConfig,
  validateBrokerServiceStartupConfig,
  type BrokerServiceStartupConfig
} from "./service-startup.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

test("Broker service startup config is strict, canonical, and root-bound", () => {
  const config = baseConfig("/Users/operator/package", "/Users/operator/data", "/Users/operator/runtime");
  assert.deepEqual(validateBrokerServiceStartupConfig(config), config);
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, unexpected: true } as never), /unknown field/u);
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, brokerSocketPath: "/Users/operator/runtime/../escape.sock" }), /canonical/u);
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, policyBundlePath: "/Users/operator/other/policy.json" }), /configured roots/u);
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, edgeServiceId: "system/com.mac-operator.edge" }), /launchd identity/u);
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, expectedEdgeUid: 0 }), /positive non-root/u);
});

test("Broker service startup config loader rejects weak and symlinked files", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-service-config-loader-"));
  const configPath = join(root, "service.json");
  const config = baseConfig(root, join(root, "data"), join(root, "runtime"));
  try {
    await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
    assert.deepEqual(await loadBrokerServiceStartupConfig(configPath), config);
    await chmod(configPath, 0o644);
    await assert.rejects(loadBrokerServiceStartupConfig(configPath), /owner-only/u);
    const linkPath = join(root, "service-link.json");
    await symlink(configPath, linkPath);
    await assert.rejects(loadBrokerServiceStartupConfig(linkPath), /owner-only/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Broker service startup restores signed authority before native runtime start", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("native Broker service startup is a macOS boundary");
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "mac-service-startup-"));
  const dataRoot = join(root, "data");
  const runtimeRoot = join(root, "runtime");
  await mkdir(dataRoot, { mode: 0o700 });
  await mkdir(runtimeRoot, { mode: 0o700 });
  const now = Date.now();
  const config = baseConfig(repositoryRoot, await realpath(dataRoot), await realpath(runtimeRoot));
  const keyPath = join(dataRoot, "edge.key");
  const edgeConfigPath = join(dataRoot, "edge-keys.json");
  const policyKeyPath = join(dataRoot, "policy-key.pem");
  const policyBundlePath = join(dataRoot, "policy.json");
  const databasePath = config.brokerDatabasePath;
  let activationStore: BrokerStore | undefined;
  let assembly: Awaited<ReturnType<typeof createBrokerServiceFromStartupConfig>> | undefined;
  try {
    await provisionAuthenticationKey(keyPath);
    const edgeKey = await loadAuthenticationKey(keyPath);
    const edgeConfig: EdgeAuthenticationKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        edgeId: "edge-1", keyId: "edge-key-1", keySource: "file", path: keyPath,
        keyDigest: sha256(edgeKey), notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
      }]
    };
    await writeEdgeAuthenticationKeyConfig(edgeConfigPath, edgeConfig);
    const keyPair = generateKeyPairSync("ed25519");
    await writeFile(policyKeyPath, keyPair.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    const document = policyDocument(now);
    const bundle = signedBundle(document, keyPair.privateKey);
    await writeFile(policyBundlePath, `${JSON.stringify(bundle)}\n`, { mode: 0o600 });
    activationStore = new BrokerStore(databasePath);
    const edgeManager = new EdgeAuthenticationKeyManager(edgeConfigPath, activationStore, () => now);
    await edgeManager.activate();
    const verifier = await PolicyBundleVerifier.create({
      schemaDirectory: join(repositoryRoot, "schemas"),
      expectedKeyId: "policy-key-1",
      publicKeyPem: keyPair.publicKey.export({ type: "spki", format: "pem" }),
      now: () => now
    });
    const verified = verifier.verify(bundle);
    const policyManager = new PolicyManager(createDefaultPolicy("edge-1"), activationStore, () => now);
    policyManager.activate(verified);
    activationStore.close();
    activationStore = undefined;

    assembly = await createBrokerServiceFromStartupConfig({
      config,
      now: () => now,
      commandExecutor: new FakeLaunchdExecutor(`gui/${config.expectedEdgeUid}/com.mac-operator.edge`)
    });
    assert.equal(assembly.service.readback().policyVersion, "policy-1");
    assert.ok(assembly.service.readback().enabledCapabilities.includes("mac_health"));
    await assembly.service.start();
    assert.equal(assembly.service.readback().runtimeState, "running");
  } finally {
    if (assembly) await assembly.close();
    activationStore?.close();
    await rm(root, { recursive: true, force: true });
  }
});

function baseConfig(packageRoot: string, dataRoot: string, runtimeRoot: string): BrokerServiceStartupConfig {
  const uid = process.getuid?.() ?? 501;
  return {
    schemaVersion: "0.1",
    packageRoot: resolve(packageRoot),
    dataRoot: resolve(dataRoot),
    runtimeRoot: resolve(runtimeRoot),
    brokerDatabasePath: resolve(join(dataRoot, "broker.sqlite")),
    brokerSocketPath: resolve(join(runtimeRoot, "broker.sock")),
    edgeId: "edge-1",
    edgeServiceId: `gui/${uid}/com.mac-operator.edge`,
    expectedEdgeUid: uid,
    ...(process.getgid?.() === undefined ? {} : { expectedEdgeGid: process.getgid() }),
    edgeKeyConfigPath: resolve(join(dataRoot, "edge-keys.json")),
    policyBundlePath: resolve(join(dataRoot, "policy.json")),
    policySchemaDirectory: resolve(join(packageRoot, "schemas")),
    policyVerificationKeyId: "policy-key-1",
    policyVerificationKeyPath: resolve(join(dataRoot, "policy-key.pem")),
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1"
  };
}

function policyDocument(now: number): PolicyDocument {
  return {
    schema_version: "0.1",
    revision: 1,
    audience: "mac-operator-broker",
    issued_at_ms: now,
    trusted_edge_keys: [{ edge_id: "edge-1", key_id: "edge-key-1", not_before_ms: now - 1_000, expires_at_ms: now + 60_000 }],
    principal_grants: [{ principal_id: "principal-1", issuer: "test-issuer", scopes: ["mac.control.read"], enabled: true }],
    target_rules: [{ rule_id: "allow-host", effect: "allow", principal_id: "principal-1", scope: "mac.control.read", target: { kind: "host", reference: "broker" } }],
    filesystem_roots: [],
    tool_enablement: [
      { tool: "mac_health", enabled: true },
      { tool: "mac_capabilities", enabled: true },
      { tool: "mac_policy_explain", enabled: true }
    ],
    kill_switches: { global: false, mutations: false, process: false, network: false, gui: false, destructive: false, privileged: false }
  };
}

function signedBundle(document: PolicyDocument, privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"]): SignedPolicyBundle {
  const payloadBytes = Buffer.from(canonicalJson(document), "utf8");
  return {
    bundle_version: "0.1",
    key_id: "policy-key-1",
    algorithm: "Ed25519",
    payload_digest: sha256(payloadBytes),
    payload: document,
    signature: sign(null, payloadBytes, privateKey).toString("base64")
  };
}

class FakeLaunchdExecutor {
  constructor(private readonly serviceId: string) {}

  async run(_command: ProcessExecutionRequest): Promise<ProcessExecutionResult> {
    return {
      state: "completed",
      resultClass: "SUCCEEDED",
      exitCode: 0,
      signal: null,
      stdout: `${this.serviceId} = {\n\tstate = running\n\tpid = ${process.pid}\n}`,
      stderr: "",
      truncated: false,
      durationMs: 1,
      processId: process.pid,
      processGroupId: process.pid,
      terminationObserved: true
    };
  }
}
