import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { chmod, mkdir, mkdtemp, realpath, rm, stat, symlink, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalJson, parseJsonUtf8Strict, sha256, signRequest, verifyBrokerResponse, type AuthenticatedBrokerResponse, type Scope } from "@mac-operator/contracts";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeAuthenticationKeyManager, writeEdgeAuthenticationKeyConfig, type EdgeAuthenticationKeyConfig } from "./edge-keyring-config.js";
import {
  createKeychainAuditAnchorKeySource,
  loadAuthenticationKey,
  provisionAuthenticationKey,
  provisionKeychainAuthenticationKey,
  retireKeychainAuthenticationKey
} from "./credentials.js";
import { BrokerStore } from "./persistence.js";
import { PolicyBundleVerifier, PolicyManager, type PolicyDocument, type SignedPolicyBundle } from "./policy-loader.js";
import {
  createBrokerServiceFromStartupConfig,
  brokerSandboxProtectedFilesystemRoots,
  loadBrokerServiceStartupConfig,
  validateBrokerServiceStartupConfig,
  type BrokerServiceStartupConfig
} from "./service-startup.js";
import { readBrokerStatus } from "./broker-status-ipc.js";
import { VirtualizationGuestAttestationKeyManager, writeVirtualizationGuestAttestationKeyConfig, type VirtualizationGuestAttestationKeyConfig } from "./virtualization-guest-attestation-keyring.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";
import { TaskProfileRegistry, type TaskProfile } from "./task-profile.js";
import type { TaskIsolationProof } from "./task-runner.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

test("Broker service startup config is strict, canonical, and root-bound", () => {
  const config = baseConfig("/Users/operator/package", "/Users/operator/data", "/Users/operator/runtime");
  assert.deepEqual(validateBrokerServiceStartupConfig(config), config);
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, unexpected: true } as never), /unknown field/u);
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, brokerSocketPath: "/Users/operator/runtime/../escape.sock" }), /canonical/u);
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, policyBundlePath: "/Users/operator/other/policy.json" }), /configured roots/u);
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, edgeServiceId: "system/com.mac-operator.edge" }), /launchd identity/u);
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, expectedEdgeUid: 0 }), /positive non-root/u);
  assert.equal(validateBrokerServiceStartupConfig({ ...config, guestAttestationKeyConfigPath: join(config.dataRoot, "guest-attestation-keys.json") }).guestAttestationKeyConfigPath, join(config.dataRoot, "guest-attestation-keys.json"));
  assert.throws(() => validateBrokerServiceStartupConfig({ ...config, guestAttestationKeyConfigPath: "/Users/operator/other/guest-keys.json" }), /configured roots/u);
});

test("Broker startup derives protected sandbox roots from its validated state roots", () => {
  const config = baseConfig("/Users/operator/package", "/Users/operator/data", "/Users/operator/runtime");
  assert.deepEqual(brokerSandboxProtectedFilesystemRoots(config), [config.packageRoot, config.dataRoot, config.runtimeRoot]);
});

test("Broker startup rejects competing task isolation runners", async () => {
  const config = baseConfig("/Users/operator/package", "/Users/operator/data", "/Users/operator/runtime");
  await assert.rejects(
    createBrokerServiceFromStartupConfig({
      config,
      sandboxTaskRunner: {},
      virtualizationGuest: {
        image: { path: "/Users/operator/data/guest.img", expectedSha256: "a".repeat(64), runtimeVersion: "macos-test" },
        enabled: false,
        hostEvidenceAccepted: false
      }
    }),
    /cannot configure sandbox and virtualization task runners together/u
  );
});

test("Broker startup rejects task profiles without an isolated runner", async () => {
  const config = baseConfig("/Users/operator/package", "/Users/operator/data", "/Users/operator/runtime");
  await assert.rejects(
    createBrokerServiceFromStartupConfig({
      config,
      taskProfileRegistry: new TaskProfileRegistry([])
    }),
    /cannot configure task profiles without an isolated task runner/u
  );
});

test("Broker startup rejects a malformed task profile registry", async () => {
  const config = baseConfig("/Users/operator/package", "/Users/operator/data", "/Users/operator/runtime");
  await assert.rejects(
    createBrokerServiceFromStartupConfig({
      config,
      sandboxTaskRunner: {},
      taskProfileRegistry: {} as TaskProfileRegistry
    }),
    /Task profile registry is malformed/u
  );
});

test("Broker service startup config loader rejects weak and symlinked files", async () => {
  const root = await mkdtemp(join(tmpdir(), "mscl-"));
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
  const root = await mkdtemp(join(tmpdir(), "mss-"));
  const dataRoot = join(root, "data");
  const runtimeRoot = join(root, "runtime");
  await mkdir(dataRoot, { mode: 0o700 });
  await mkdir(runtimeRoot, { mode: 0o700 });
  const now = Date.now();
  const canonicalDataRoot = await realpath(dataRoot);
  const canonicalRuntimeRoot = await realpath(runtimeRoot);
  let config = baseConfig(repositoryRoot, canonicalDataRoot, canonicalRuntimeRoot);
  const keyPath = join(dataRoot, "edge.key");
  const edgeConfigPath = join(dataRoot, "edge-keys.json");
  const policyKeyPath = join(dataRoot, "policy-key.pem");
  const policyBundlePath = join(dataRoot, "policy.json");
  const guestKeyPath = join(canonicalDataRoot, "guest-key.pem");
  const guestKeyConfigPath = join(canonicalDataRoot, "guest-attestation-keys.json");
  const databasePath = config.brokerDatabasePath;
  let activationStore: BrokerStore | undefined;
  let assembly: Awaited<ReturnType<typeof createBrokerServiceFromStartupConfig>> | undefined;
  let taskAssembly: Awaited<ReturnType<typeof createBrokerServiceFromStartupConfig>> | undefined;
  let auditKeyDigest: string | undefined;
  try {
    await provisionAuthenticationKey(keyPath);
    const statusKey = await provisionAuthenticationKey(config.statusKeyPath);
    config = { ...config, statusKeyDigest: statusKey.digest };
    const auditKey = await provisionKeychainAuthenticationKey(
      config.auditAnchorKeyService,
      config.auditAnchorKeyAccount,
      process.execPath
    );
    auditKeyDigest = auditKey.digest;
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
    const document = policyDocument(now, { taskEnabled: process.env.MOPS_REAL_SANDBOX === "1" });
    const bundle = signedBundle(document, keyPair.privateKey);
    await writeFile(policyBundlePath, `${JSON.stringify(bundle)}\n`, { mode: 0o600 });
    const guestKeys = generateKeyPairSync("ed25519");
    const guestPublicKey = Buffer.from(guestKeys.publicKey.export({ type: "spki", format: "pem" }));
    await writeFile(guestKeyPath, guestPublicKey, { mode: 0o600 });
    const guestKeyConfig: VirtualizationGuestAttestationKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        keyId: "guest-key-1",
        path: guestKeyPath,
        publicKeyDigest: sha256(guestPublicKey),
        notBeforeMs: now - 1_000,
        expiresAtMs: now + 60_000
      }]
    };
    await writeVirtualizationGuestAttestationKeyConfig(guestKeyConfigPath, guestKeyConfig);
    const auditAnchor = {
      path: config.auditAnchorPath,
      keySource: createKeychainAuditAnchorKeySource(
        config.auditAnchorKeyService,
        config.auditAnchorKeyAccount,
        config.auditAnchorKeyId
      )
    };
    activationStore = new BrokerStore(databasePath, { auditAnchor });
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
    const guestManager = new VirtualizationGuestAttestationKeyManager(guestKeyConfigPath, activationStore, () => now);
    await guestManager.activate();
    config = { ...config, guestAttestationKeyConfigPath: guestKeyConfigPath };
    activationStore.close();
    activationStore = undefined;

    assembly = await createBrokerServiceFromStartupConfig({
      config,
      now: () => now,
      commandExecutor: new FakeLaunchdExecutor(`gui/${config.expectedEdgeUid}/com.mac-operator.edge`),
      virtualizationGuest: {
        image: {
          path: join(canonicalDataRoot, "guest.img"),
          expectedSha256: "a".repeat(64),
          runtimeVersion: "macos-26.2-vz-1"
        },
        enabled: false,
        hostEvidenceAccepted: true
      }
    });
    assert.equal(assembly.service.readback().policyVersion, "policy-1");
    assert.ok(assembly.service.readback().enabledCapabilities.includes("mac_health"));
    assert.equal(assembly.guestAttestationKeyManager?.current().document.revision, 1);
    assert.equal(assembly.virtualizationGuestRuntime?.available, false);
    await assembly.service.start();
    assert.equal(assembly.service.readback().runtimeState, "running");
    assert.equal((await stat(config.statusSocketPath)).isSocket(), true);
    const statusAuthenticationKey = await loadAuthenticationKey(config.statusKeyPath);
    try {
      const statusReadback = await readBrokerStatus({ socketPath: config.statusSocketPath, authenticationKey: statusAuthenticationKey, now: () => now });
      assert.equal(statusReadback.state, "running");
      assert.equal(statusReadback.runtimeState, "running");
    } finally {
      statusAuthenticationKey.fill(0);
    }

    if (process.env.MOPS_REAL_SANDBOX === "1") {
      await assembly.close();
      assembly = undefined;

    const taskRootPath = join(root, "task-root");
    await mkdir(taskRootPath, { mode: 0o700 });
    const taskRoot = await realpath(taskRootPath);
    taskAssembly = await createBrokerServiceFromStartupConfig({
      config,
      now: () => now,
      commandExecutor: new FakeLaunchdExecutor(`gui/${config.expectedEdgeUid}/com.mac-operator.edge`),
      sandboxTaskRunner: {
        enabled: true,
        hostEvidenceAccepted: true,
        allowedEnvironmentKeys: [],
        isolationProof: startupSandboxProof()
      },
      taskProfileRegistry: new TaskProfileRegistry([startupTaskProfile(taskRoot)])
    });
    assert.equal(taskAssembly.sandboxTaskRunner?.available, true);
    await taskAssembly.service.start();

    const argumentsValue = { profile: "tests.startup", cwd: taskRoot, args: [], async: false };
    taskAssembly.store.issueApproval({
      approvalId: "approval:startup-task",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_task_run",
      contractVersion: "0.1",
      targetKind: "task_profile",
      targetRef: "task_profile:tests.startup",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-1",
      approvalClass: "trusted_profile",
      unattended: false,
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 60_000
    });
    const requestKey = await loadAuthenticationKey(keyPath);
    const request = signRequest({
      protocolVersion: "0.1",
      requestId: "startup-task-request",
      contractVersion: "0.1",
      tool: "mac_task_run",
      arguments: argumentsValue,
      principal: {
        principalId: "principal-1",
        sessionId: "startup-task-session",
        issuer: "test-issuer",
        audience: "mac-operator-broker",
        scopes: ["mac.control.read", "mac.task.run"],
        issuedAtMs: now - 1_000,
        expiresAtMs: now + 60_000,
        edgeId: "edge-1"
      },
      timestampMs: now,
      nonce: "startup-task-nonce",
      policyAudience: "mac-operator-broker",
      policyVersion: "policy-1",
      authenticationKeyId: "edge-key-1"
    }, requestKey);
    try {
      const envelope = await sendNativeBrokerRequest(config.brokerSocketPath, request);
      assert.equal(verifyBrokerResponse(request, envelope, requestKey), true);
      assert.equal(envelope.response.ok, true, JSON.stringify(envelope.response));
      if (envelope.response.ok) {
        const data = envelope.response.data as { profile: string; stdout: string };
        assert.equal(data.profile, "tests.startup");
        assert.equal(data.stdout, "startup-sandbox\n");
        assert.equal(envelope.response.verification.status, "verified");
      }
      const jobId = taskAssembly.store.requestRecord("startup-task-request")?.jobId;
      assert.ok(jobId);
      assert.equal(taskAssembly.store.ownedJob(jobId, "principal-1")?.state, "completed");
    } finally {
      requestKey.fill(0);
    }
    }
  } finally {
    if (assembly) await assembly.close();
    if (taskAssembly) await taskAssembly.close();
    activationStore?.close();
    if (auditKeyDigest !== undefined) {
      await retireKeychainAuthenticationKey(
        config.auditAnchorKeyService,
        config.auditAnchorKeyAccount,
        auditKeyDigest
      ).catch(() => undefined);
    }
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
    statusSocketPath: resolve(join(runtimeRoot, "broker-status.sock")),
    statusKeyPath: resolve(join(dataRoot, "broker-status.key")),
    statusKeyDigest: "0".repeat(64),
    auditAnchorPath: resolve(join(dataRoot, "broker-audit.anchor")),
    auditAnchorKeyService: "com.mac-operator.test",
    auditAnchorKeyAccount: "audit:service-startup",
    auditAnchorKeyId: "audit-key-1",
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

function policyDocument(now: number, options: { taskEnabled?: boolean } = {}): PolicyDocument {
  const taskEnabled = options.taskEnabled === true;
  const scopes: Scope[] = taskEnabled ? ["mac.control.read", "mac.task.run"] : ["mac.control.read"];
  return {
    schema_version: "0.1",
    revision: 1,
    audience: "mac-operator-broker",
    issued_at_ms: now,
    trusted_edge_keys: [{ edge_id: "edge-1", key_id: "edge-key-1", not_before_ms: now - 1_000, expires_at_ms: now + 60_000 }],
    principal_grants: [{ principal_id: "principal-1", issuer: "test-issuer", scopes, enabled: true }],
    target_rules: [
      { rule_id: "allow-host", effect: "allow", principal_id: "principal-1", scope: "mac.control.read", target: { kind: "host", reference: "broker" } },
      ...(taskEnabled ? [{ rule_id: "allow-startup-task", effect: "allow" as const, principal_id: "principal-1", scope: "mac.task.run" as const, target: { kind: "task_profile" as const, reference: "tests.startup" } }] : [])
    ],
    filesystem_roots: [],
    tool_enablement: [
      { tool: "mac_health", enabled: true },
      { tool: "mac_capabilities", enabled: true },
      { tool: "mac_policy_explain", enabled: true },
      ...(taskEnabled ? [{ tool: "mac_task_run", enabled: true }] : [])
    ],
    kill_switches: { global: false, mutations: false, process: false, network: false, gui: false, destructive: false, privileged: false }
  };
}

function startupTaskProfile(root: string): TaskProfile {
  return {
    schemaVersion: "0.1",
    profile: "tests.startup",
    executable: "/usr/bin/printf",
    fixedArgs: ["startup-sandbox\\n"],
    allowedCwdRoots: [root],
    allowedArgumentPattern: "^$",
    maxArguments: 0,
    environment: {},
    filesystemRoots: [root],
    networkPolicy: "none",
    networkAllowlist: [],
    credentialPolicy: "none",
    processTreePolicy: "single_process",
    sandboxProfile: "deny-default-v0.1",
    timeoutMs: 5_000,
    outputCapBytes: 1_024,
    verificationStrategy: "exit_status_and_declared_task_verification",
    enabled: true
  };
}

function startupSandboxProof(): TaskIsolationProof {
  return {
    schemaVersion: "0.1",
    sandboxMechanism: "sandbox-exec",
    sandboxProfile: "deny-default-v0.1",
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    persistence: "isolated",
    credentialIsolation: "sandbox-exec-empty-env-deny-secret-zones-v1",
    processTree: "owned",
    processTreePolicy: "single_process",
    evidenceRef: "evidence://service-startup-task-profile"
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

async function sendNativeBrokerRequest(
  socketPath: string,
  request: unknown
): Promise<AuthenticatedBrokerResponse> {
  const body = `${JSON.stringify(request)}\n`;
  return await new Promise<AuthenticatedBrokerResponse>((resolveResponse, reject) => {
    const socket = createConnection(socketPath);
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const finish = (error?: Error, value?: AuthenticatedBrokerResponse): void => {
      if (settled) return;
      settled = true;
      socket.destroy();
      if (error) reject(error);
      else if (value !== undefined) resolveResponse(value);
      else reject(new Error("Native Broker response was empty"));
    };
    socket.setTimeout(15_000, () => finish(new Error("Native Broker request timed out")));
    socket.once("connect", () => socket.write(body));
    socket.on("data", (chunk: Buffer) => {
      total += chunk.byteLength;
      if (total > 4 * 1024 * 1024) finish(new Error("Native Broker response exceeded the test cap"));
      else chunks.push(chunk);
    });
    socket.once("error", (error) => finish(error));
    socket.once("end", () => {
      try {
        const parsed = parseJsonUtf8Strict(Buffer.concat(chunks));
        if (!isAuthenticatedBrokerResponse(parsed)) throw new Error("Native Broker response envelope is malformed");
        finish(undefined, parsed);
      } catch (error) {
        finish(error instanceof Error ? error : new Error("Native Broker response is invalid"));
      }
    });
  });
}

function isAuthenticatedBrokerResponse(value: unknown): value is AuthenticatedBrokerResponse {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record.protocolVersion === "0.1" &&
    typeof record.requestPayloadDigest === "string" &&
    typeof record.authenticationKeyId === "string" &&
    typeof record.responseDigest === "string" &&
    typeof record.authenticationProof === "string" &&
    record.response !== null && typeof record.response === "object" && !Array.isArray(record.response);
}
