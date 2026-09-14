import assert from "node:assert/strict";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import { cp, chmod, lstat, mkdtemp, mkdir, readFile, realpath, rm, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import tls from "node:tls";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import {
  EdgeAuthenticationKeyManager,
  ProcessSupervisor,
  BrokerStore,
  capturePeerProcessIdentity,
  createKeychainAuditAnchorKeySource,
  loadAuthenticationKey,
  provisionAuthenticationKey,
  provisionKeychainAuthenticationKey,
  readBrokerStatus,
  renderLaunchdPlist,
  retireKeychainAuthenticationKey,
  writeEdgeAuthenticationKeyConfig,
  createDefaultPolicy,
  type EdgeAuthenticationKeyConfig,
  type LaunchdServiceConfig,
  type ProcessExecutionRequest,
  type ProcessExecutionResult
} from "./index.js";
import { PolicyBundleVerifier, PolicyManager } from "./policy-loader.js";

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const realInstallEnabled = process.platform === "darwin" && process.env.MOPS_REAL_INSTALL === "1";

/**
 * Starts both reviewed LaunchAgent entrypoints in an isolated temporary
 * package. The test is opt-in because bootstrap/bootout changes the user's
 * launchd domain, even though cleanup is bounded and always attempted.
 */
test("opt-in packaged Edge and Broker LaunchAgents start, authenticate, and cleanly stop", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("installed service smoke requires macOS launchd and native peer credentials");
    return;
  }
  if (!realInstallEnabled) {
    t.skip("set MOPS_REAL_INSTALL=1 to mutate only temporary user LaunchAgents");
    return;
  }
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || uid < 1 || gid === undefined) throw new Error("POSIX user identity is unavailable");
  const edgeServiceId = `gui/${uid}/com.mac-operator.edge`;
  const brokerServiceId = `gui/${uid}/com.mac-operator.broker`;
  const supervisor = new ProcessSupervisor({ allowedEnvironmentKeys: [] });
  const existingEdge = await servicePresence(supervisor, edgeServiceId);
  const existingBroker = await servicePresence(supervisor, brokerServiceId);
  if (existingEdge || existingBroker) {
    t.skip("fixed Mac-Operator LaunchAgent label is already loaded; no service was changed");
    return;
  }

  // The native Darwin socket limit is 104 bytes; a short /tmp prefix keeps
  // the generated runtime paths below that limit without relaxing validation.
  const root = await mkdtemp("/tmp/mops-");
  const dataRoot = join(root, "data");
  const runtimeRoot = join(root, "runtime");
  const logRoot = join(root, "logs");
  const edgePackageRoot = join(root, "edge-package");
  const brokerPackageRoot = join(root, "broker-package");
  const edgeDist = join(edgePackageRoot, "dist");
  const brokerDist = join(brokerPackageRoot, "dist");
  const edgeContracts = join(edgePackageRoot, "tool-contracts");
  const brokerSchemas = join(brokerPackageRoot, "schemas");
  const edgePlistPath = join(root, "edge.plist");
  const brokerPlistPath = join(root, "broker.plist");
  const databasePath = join(dataRoot, "broker.sqlite");
  const brokerSocketPath = join(runtimeRoot, "broker.sock");
  const statusSocketPath = join(runtimeRoot, "broker-status.sock");
  const statusKeyPath = join(dataRoot, "broker-status.key");
  const auditAnchorPath = join(dataRoot, "broker-audit.anchor");
  const edgeKeyPath = join(dataRoot, "edge.key");
  const edgeKeyConfigPath = join(dataRoot, "edge-keys.json");
  const policyBundlePath = join(dataRoot, "policy.json");
  const policyVerificationKeyPath = join(dataRoot, "policy-key.pem");
  const certificatePath = join(dataRoot, "edge.crt");
  const privateKeyPath = join(dataRoot, "edge-private.key");
  const edgeConfigPath = join(edgeDist, "edge-service.json");
  const brokerConfigPath = join(brokerDist, "broker-service.json");
  let edgeBootstrapped = false;
  let brokerBootstrapped = false;
  let store: BrokerStore | undefined;
  let auditKeyDigest: string | undefined;
  const auditAnchorKeyService = "com.mac-operator.test";
  const auditAnchorKeyAccount = `audit:packaged-${uid}`;
  const auditAnchorKeyId = "audit-key-1";
  try {
    for (const directory of [dataRoot, runtimeRoot, logRoot, edgePackageRoot, brokerPackageRoot]) {
      await mkdir(directory, { recursive: true, mode: 0o700 });
      await chmod(directory, 0o700);
    }
    const canonicalDataRoot = await realpath(dataRoot);
    const canonicalRuntimeRoot = await realpath(runtimeRoot);
    await cp(join(repositoryRoot, "packages/edge/dist"), edgeDist, { recursive: true });
    await cp(join(repositoryRoot, "packages/broker/dist"), brokerDist, { recursive: true });
    await cp(join(repositoryRoot, "packages/edge/package.json"), join(edgePackageRoot, "package.json"));
    await cp(join(repositoryRoot, "packages/broker/package.json"), join(brokerPackageRoot, "package.json"));
    await cp(join(repositoryRoot, "tool-contracts"), edgeContracts, { recursive: true });
    await cp(join(repositoryRoot, "schemas"), brokerSchemas, { recursive: true });
    const sharedNodeModules = join(root, "node_modules");
    await installTestDependencies(sharedNodeModules, [
      "@modelcontextprotocol/client", "@modelcontextprotocol/express",
      "@modelcontextprotocol/node", "@modelcontextprotocol/server", "express", "jose", "zod"
    ]);
    await installTestDependencies(sharedNodeModules, ["ajv", "ajv-formats"]);
    await createTestCertificate(certificatePath, privateKeyPath);

    const edgeKey = await provisionAuthenticationKey(edgeKeyPath);
    const statusKey = await provisionAuthenticationKey(statusKeyPath);
    const auditKey = await provisionKeychainAuthenticationKey(
      auditAnchorKeyService,
      auditAnchorKeyAccount,
      process.execPath
    );
    auditKeyDigest = auditKey.digest;
    const now = Date.now();
    const edgeKeyBytes = await loadAuthenticationKey(edgeKeyPath);
    try {
      const edgeConfig: EdgeAuthenticationKeyConfig = {
        schemaVersion: "0.1",
        revision: 1,
        keys: [{
          edgeId: "edge-1",
          keyId: "edge-key-1",
          keySource: "file",
          path: edgeKeyPath,
          keyDigest: sha256(edgeKeyBytes),
          notBeforeMs: now - 5_000,
          expiresAtMs: now + 600_000
        }]
      };
      await writeEdgeAuthenticationKeyConfig(edgeKeyConfigPath, edgeConfig);
    } finally {
      edgeKeyBytes.fill(0);
    }

    const policyKeyPair = generateKeyPairSync("ed25519");
    await writeFile(policyVerificationKeyPath, policyKeyPair.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    const policy = createSmokePolicy(now);
    const payloadBytes = Buffer.from(canonicalJson(policy), "utf8");
    const signedBundle = {
      bundle_version: "0.1" as const,
      key_id: "policy-key-1",
      algorithm: "Ed25519" as const,
      payload_digest: sha256(payloadBytes),
      payload: policy,
      signature: sign(null, payloadBytes, policyKeyPair.privateKey).toString("base64")
    };
    await writeFile(policyBundlePath, `${JSON.stringify(signedBundle)}\n`, { mode: 0o600 });

    store = new BrokerStore(databasePath, {
      auditAnchor: {
        path: auditAnchorPath,
        keySource: createKeychainAuditAnchorKeySource(
          auditAnchorKeyService,
          auditAnchorKeyAccount,
          auditAnchorKeyId
        )
      }
    });
    const edgeManager = new EdgeAuthenticationKeyManager(edgeKeyConfigPath, store, () => now);
    await edgeManager.activate();
    const policyVerifier = await PolicyBundleVerifier.create({
      schemaDirectory: brokerSchemas,
      expectedKeyId: "policy-key-1",
      publicKeyPem: policyKeyPair.publicKey.export({ type: "spki", format: "pem" }),
      now: () => now
    });
    const verifiedPolicy = policyVerifier.verify(signedBundle);
    const policyManager = new PolicyManager(createDefaultPolicy("edge-1"), store, () => now);
    policyManager.activate(verifiedPolicy);
    store.close();
    store = undefined;

    const nodePath = await realpath(process.execPath);
    const edgeEntrypoint = await realpath(join(edgeDist, "service-main.js"));
    const brokerEntrypoint = await realpath(join(brokerDist, "service-main.js"));
    const edgePort = await reservePort();
    const edgeConfig = {
      schemaVersion: "0.1",
      packageRoot: await realpath(edgePackageRoot),
      dataRoot: await realpath(dataRoot),
      runtimeRoot: await realpath(runtimeRoot),
      edgeId: "edge-1",
      brokerAudience: "mac-operator-broker",
      brokerSocketPath: join(canonicalRuntimeRoot, "broker.sock"),
      authenticationKeyPath: join(canonicalDataRoot, "edge.key"),
      authenticationKeyId: "edge-key-1",
      authenticationKeyDigest: edgeKey.digest,
      contractsDirectory: await realpath(edgeContracts),
      tlsCertificatePath: join(canonicalDataRoot, "edge.crt"),
      tlsPrivateKeyPath: join(canonicalDataRoot, "edge-private.key"),
      bindHost: "127.0.0.1",
      bindPort: edgePort,
      resourceServerUrl: "https://edge.example.test/mcp",
      oauthIssuer: "https://issuer.example.test",
      issuerId: "test-issuer",
      authorizationEndpoint: "https://issuer.example.test/authorize",
      tokenEndpoint: "https://issuer.example.test/token",
      jwksUri: "https://issuer.example.test/jwks",
      allowedHosts: ["edge.example.test"],
      allowedOrigins: ["client.example.test"],
      policyVersion: "policy-1",
      sourceRevision: "e57684a",
      contractVersion: "0.1",
      ipcTimeoutMs: 5_000,
      maxIpcResponseBytes: 1_048_576,
      rateLimitWindowMs: 60_000,
      rateLimitMaxRequests: 100,
      rateLimitMaxKeys: 100
    };
    const brokerConfig = {
      schemaVersion: "0.1",
      packageRoot: await realpath(brokerPackageRoot),
      dataRoot: await realpath(dataRoot),
      runtimeRoot: await realpath(runtimeRoot),
      brokerDatabasePath: join(canonicalDataRoot, "broker.sqlite"),
      brokerSocketPath: join(canonicalRuntimeRoot, "broker.sock"),
      statusSocketPath: join(canonicalRuntimeRoot, "broker-status.sock"),
      statusKeyPath: join(canonicalDataRoot, "broker-status.key"),
      statusKeyDigest: statusKey.digest,
      auditAnchorPath: join(canonicalDataRoot, "broker-audit.anchor"),
      auditAnchorKeyService,
      auditAnchorKeyAccount,
      auditAnchorKeyId,
      edgeId: "edge-1",
      edgeServiceId,
      expectedEdgeUid: uid,
      expectedEdgeGid: gid,
      edgeKeyConfigPath: join(canonicalDataRoot, "edge-keys.json"),
      policyBundlePath: join(canonicalDataRoot, "policy.json"),
      policySchemaDirectory: await realpath(brokerSchemas),
      policyVerificationKeyId: "policy-key-1",
      policyVerificationKeyPath: join(canonicalDataRoot, "policy-key.pem"),
      sourceRevision: "e57684a",
      contractVersion: "0.1"
    };
    await writeFile(edgeConfigPath, `${JSON.stringify(edgeConfig)}\n`, { mode: 0o600 });
    await writeFile(brokerConfigPath, `${JSON.stringify(brokerConfig)}\n`, { mode: 0o600 });

    const edgeService = serviceConfig("edge", nodePath, edgeEntrypoint, root, logRoot);
    const brokerService = serviceConfig("broker", nodePath, brokerEntrypoint, root, logRoot);
    await writeFile(edgePlistPath, renderLaunchdPlist(edgeService), { mode: 0o600 });
    await writeFile(brokerPlistPath, renderLaunchdPlist(brokerService), { mode: 0o600 });

    const edgeBootstrap = await launchctl(supervisor, ["bootstrap", `gui/${uid}`, edgePlistPath]);
    edgeBootstrapped = true;
    assert.equal(edgeBootstrap.exitCode, 0);
    const edgeReadback = await waitForRunning(supervisor, edgeServiceId);
    assert.equal(edgeReadback.program, nodePath);
    assert.deepEqual(edgeReadback.arguments, [nodePath, edgeEntrypoint]);
    assert.equal(edgeReadback.type, "LaunchAgent");
    assert.ok(edgeReadback.pid !== null);
    const edgeIdentity = capturePeerProcessIdentity(edgeReadback.pid);
    assert.equal(edgeIdentity.pid, edgeReadback.pid);
    await waitForTls(edgePort, 10_000);

    const brokerBootstrap = await launchctl(supervisor, ["bootstrap", `gui/${uid}`, brokerPlistPath]);
    brokerBootstrapped = true;
    assert.equal(brokerBootstrap.exitCode, 0);
    const brokerReadback = await waitForRunning(supervisor, brokerServiceId);
    assert.equal(brokerReadback.program, nodePath);
    assert.deepEqual(brokerReadback.arguments, [nodePath, brokerEntrypoint]);
    assert.equal(brokerReadback.type, "LaunchAgent");
    assert.ok(brokerReadback.pid !== null);
    const brokerIdentity = capturePeerProcessIdentity(brokerReadback.pid);
    assert.equal(brokerIdentity.pid, brokerReadback.pid);
    await waitForSocket(brokerSocketPath, 10_000);
    await waitForSocket(statusSocketPath, 10_000);
    for (const socketPath of [brokerSocketPath, statusSocketPath]) {
      const socket = await lstat(socketPath);
      assert.equal(socket.uid, uid);
      assert.equal(socket.mode & 0o777, 0o600);
    }
    const statusAuthenticationKey = await loadAuthenticationKey(statusKeyPath);
    try {
      const status = await readBrokerStatus({ socketPath: statusSocketPath, authenticationKey: statusAuthenticationKey });
      assert.equal(status.state, "running");
      assert.equal(status.runtimeState, "running");
      assert.deepEqual(status.enabledCapabilities, []);
      assert.equal(status.sourceRevision, "e57684a");
    } finally {
      statusAuthenticationKey.fill(0);
    }
  } finally {
    let cleanupError: unknown;
    try {
      if (brokerBootstrapped) {
        const result = await launchctl(supervisor, ["bootout", brokerServiceId]);
        assert.equal(result.exitCode, 0, "Broker LaunchAgent bootout must succeed");
        brokerBootstrapped = false;
      }
      if (edgeBootstrapped) {
        const result = await launchctl(supervisor, ["bootout", edgeServiceId]);
        assert.equal(result.exitCode, 0, "Edge LaunchAgent bootout must succeed");
        edgeBootstrapped = false;
      }
      await waitForAbsent(supervisor, brokerServiceId, 5_000);
      await waitForAbsent(supervisor, edgeServiceId, 5_000);
    } catch (error) {
      cleanupError = error;
    } finally {
      store?.close();
      if (auditKeyDigest !== undefined) {
        await retireKeychainAuthenticationKey(auditAnchorKeyService, auditAnchorKeyAccount, auditKeyDigest).catch(() => undefined);
      }
      await rm(root, { recursive: true, force: true });
    }
    if (cleanupError !== undefined) throw cleanupError;
  }
});

function serviceConfig(
  component: "edge" | "broker",
  nodePath: string,
  entrypoint: string,
  workingDirectory: string,
  logRoot: string
): LaunchdServiceConfig {
  return {
    label: `com.mac-operator.${component}`,
    program: nodePath,
    programArguments: [nodePath, entrypoint],
    workingDirectory,
    stdoutPath: join(logRoot, `${component}.out.log`),
    stderrPath: join(logRoot, `${component}.err.log`),
    runAtLoad: true,
    keepAlive: true,
    throttleIntervalSeconds: 1
  };
}

async function createTestCertificate(certificatePath: string, privateKeyPath: string): Promise<void> {
  await execFileAsync(
    "/usr/bin/openssl",
    [
      "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", privateKeyPath,
      "-out", certificatePath, "-days", "1", "-subj", "/CN=edge.example.test",
      "-addext", "subjectAltName=DNS:edge.example.test"
    ],
    { cwd: "/", env: { PATH: "/usr/bin:/bin" }, timeout: 10_000, maxBuffer: 64 * 1024 }
  );
  await chmod(certificatePath, 0o600);
  await chmod(privateKeyPath, 0o600);
}

async function installTestDependencies(nodeModules: string, dependencies: readonly string[]): Promise<void> {
  await mkdir(join(nodeModules, "@mac-operator"), { recursive: true, mode: 0o700 });
  await cp(join(repositoryRoot, "packages/contracts"), join(nodeModules, "@mac-operator/contracts"), { recursive: true });
  const copied = new Set<string>(["@mac-operator/contracts"]);
  const copyDependency = async (dependency: string): Promise<void> => {
    if (copied.has(dependency)) return;
    copied.add(dependency);
    const parts = dependency.split("/");
    const source = join(repositoryRoot, "node_modules", ...parts);
    const destination = join(nodeModules, dependency);
    await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
    await cp(source, destination, { recursive: true });
    const packageJson = JSON.parse(await readFile(join(source, "package.json"), "utf8")) as {
      dependencies?: Record<string, string>;
      optionalDependencies?: Record<string, string>;
    };
    for (const child of Object.keys({ ...packageJson.dependencies, ...packageJson.optionalDependencies })) {
      try {
        await copyDependency(child);
      } catch (error) {
        if (packageJson.optionalDependencies?.[child] === undefined) throw error;
      }
    }
  };
  for (const dependency of dependencies) {
    await copyDependency(dependency);
  }
}

async function servicePresence(supervisor: ProcessSupervisor, serviceId: string): Promise<boolean> {
  const result = await launchctl(supervisor, ["print", serviceId]);
  if (result.exitCode === 0 && result.state === "completed") return true;
  const diagnostic = `${result.stdout}\n${result.stderr}`;
  if (result.exitCode !== 0 && /Could not find service|No such process|not found/iu.test(diagnostic)) return false;
  throw new Error("launchctl presence check could not establish absence");
}

async function waitForAbsent(supervisor: ProcessSupervisor, serviceId: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (!await servicePresence(supervisor, serviceId)) return;
    await new Promise((resolveRetry) => setTimeout(resolveRetry, 50));
  }
  throw new Error(`${serviceId} remained loaded after bounded bootout`);
}

async function launchctl(supervisor: ProcessSupervisor, args: readonly string[]): Promise<ProcessExecutionResult> {
  const command: ProcessExecutionRequest = {
    executable: "/bin/launchctl",
    args,
    cwd: "/",
    environment: {},
    timeoutMs: 5_000,
    outputCapBytes: 131_072
  };
  return supervisor.run(command);
}

async function waitForRunning(supervisor: ProcessSupervisor, serviceId: string) {
  const { readLaunchdJobReadback } = await import("./launchd-readback.js");
  const deadline = Date.now() + 10_000;
  let lastState = "unknown";
  while (Date.now() < deadline) {
    try {
      const readback = await readLaunchdJobReadback(serviceId, { executor: supervisor });
      lastState = readback.state;
      if (readback.state === "running" && readback.pid !== null) return readback;
    } catch {
      // launchd may not expose the job until bootstrap registration completes.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  }
  throw new Error(`LaunchAgent ${serviceId} did not reach running state (last state: ${lastState})`);
}

async function waitForSocket(path: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if ((await stat(path)).isSocket()) return;
    } catch {
      // The service may still be assembling its native listeners.
    }
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
  }
  throw new Error(`Timed out waiting for native service socket: ${path}`);
}

async function waitForTls(port: number, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      await new Promise<void>((resolveTls, rejectTls) => {
        const socket = tls.connect({ host: "127.0.0.1", port, servername: "edge.example.test", rejectUnauthorized: false });
        const finish = (error?: Error) => {
          socket.destroy();
          error === undefined ? resolveTls() : rejectTls(error);
        };
        socket.once("secureConnect", () => finish());
        socket.once("error", (error) => finish(error));
      });
      return;
    } catch {
      await new Promise((resolveRetry) => setTimeout(resolveRetry, 50));
    }
  }
  throw new Error(`Timed out waiting for Edge HTTPS listener on port ${port}`);
}

async function reservePort(): Promise<number> {
  const net = await import("node:net");
  const server = net.createServer();
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Unable to reserve a local Edge port");
  const port = address.port;
  await new Promise<void>((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  return port;
}

function createSmokePolicy(now: number) {
  return {
    schema_version: "0.1" as const,
    revision: 1,
    audience: "mac-operator-broker",
    issued_at_ms: now,
    trusted_edge_keys: [{ edge_id: "edge-1", key_id: "edge-key-1", not_before_ms: now - 5_000, expires_at_ms: now + 600_000 }],
    principal_grants: [],
    target_rules: [],
    filesystem_roots: [],
    tool_enablement: [],
    kill_switches: { global: false, mutations: false, process: false, network: false, gui: false, destructive: false, privileged: false }
  };
}
