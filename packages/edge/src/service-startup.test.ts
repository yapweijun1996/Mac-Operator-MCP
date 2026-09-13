import assert from "node:assert/strict";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { sha256 } from "@mac-operator/contracts";
import {
  createEdgeServiceFromStartupConfig,
  loadEdgeServiceStartupConfig,
  validateEdgeServiceStartupConfig,
  type EdgeServiceStartupConfig
} from "./service-startup.js";

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

test("Edge service startup config is strict, canonical, and root-bound", () => {
  const config = baseConfig("/Users/operator/package", "/Users/operator/data", "/Users/operator/runtime");
  assert.deepEqual(validateEdgeServiceStartupConfig(config), config);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, unexpected: true } as never), /unknown field/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, brokerSocketPath: "/Users/operator/runtime/../escape.sock" }), /canonical/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, tlsPrivateKeyPath: "/Users/operator/other/edge.key" }), /escaped/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, jwksUri: "http://issuer.example.test/jwks" }), /HTTPS/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, bindPort: 0 }), /out of bounds/u);
});

test("Edge service startup config loader rejects weak and symlinked files", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-edge-config-loader-"));
  const configPath = join(root, "service.json");
  const config = baseConfig(root, join(root, "data"), join(root, "runtime"));
  try {
    await writeFile(configPath, JSON.stringify(config), { mode: 0o600 });
    assert.deepEqual(await loadEdgeServiceStartupConfig(configPath), config);
    await chmod(configPath, 0o644);
    await assert.rejects(loadEdgeServiceStartupConfig(configPath), /owner-only/u);
    const linkPath = join(root, "service-link.json");
    await symlink(configPath, linkPath);
    await assert.rejects(loadEdgeServiceStartupConfig(linkPath), /owner-only/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Edge service startup assembles protected TLS and IPC bindings and owns listener lifecycle", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-edge-startup-"));
  const dataRoot = join(root, "data");
  const runtimeRoot = join(root, "runtime");
  await mkdir(dataRoot, { mode: 0o700 });
  await mkdir(runtimeRoot, { mode: 0o700 });
  const key = Buffer.alloc(32, 0x51);
  const authenticationKeyPath = join(dataRoot, "edge-auth.key");
  const certificatePath = join(dataRoot, "edge.crt");
  const privateKeyPath = join(dataRoot, "edge.key");
  const port = await reservePort();
  let assembly: Awaited<ReturnType<typeof createEdgeServiceFromStartupConfig>> | undefined;
  try {
    await writeFile(authenticationKeyPath, key, { mode: 0o600 });
    await createTestCertificate(dataRoot, certificatePath, privateKeyPath);
    await chmod(certificatePath, 0o600);
    await chmod(privateKeyPath, 0o600);
    const canonicalDataRoot = await realpath(dataRoot);
    const config = baseConfig(await realpath(repositoryRoot), canonicalDataRoot, await realpath(runtimeRoot), {
      authenticationKeyPath: join(canonicalDataRoot, "edge-auth.key"),
      tlsCertificatePath: join(canonicalDataRoot, "edge.crt"),
      tlsPrivateKeyPath: join(canonicalDataRoot, "edge.key"),
      bindPort: port,
      authenticationKeyDigest: sha256(key)
    });
    assembly = await createEdgeServiceFromStartupConfig({ config });
    assert.equal(assembly.service.readback().state, "stopped");
    await assembly.service.start();
    assert.deepEqual(assembly.service.readback(), {
      component: "mac-operator-edge",
      state: "running",
      sourceRevision: config.sourceRevision,
      contractVersion: config.contractVersion,
      policyVersion: config.policyVersion,
      bindHost: config.bindHost,
      bindPort: port,
      listening: true
    });
    await assembly.close();
    assert.equal(assembly.service.readback().state, "stopped");
  } finally {
    if (assembly) await assembly.close().catch(() => undefined);
    key.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});

function baseConfig(packageRoot: string, dataRoot: string, runtimeRoot: string, overrides: Partial<EdgeServiceStartupConfig> = {}): EdgeServiceStartupConfig {
  const data = resolve(dataRoot);
  const runtime = resolve(runtimeRoot);
  const packagePath = resolve(packageRoot);
  const authKey = resolve(join(data, "edge-auth.key"));
  const certificate = resolve(join(data, "edge.crt"));
  const privateKey = resolve(join(data, "edge.key"));
  return {
    schemaVersion: "0.1",
    packageRoot: packagePath,
    dataRoot: data,
    runtimeRoot: runtime,
    edgeId: "edge-1",
    brokerAudience: "mac-operator-broker",
    brokerSocketPath: resolve(join(runtime, "broker.sock")),
    authenticationKeyPath: authKey,
    authenticationKeyId: "edge-key-1",
    authenticationKeyDigest: "a".repeat(64),
    contractsDirectory: resolve(join(packagePath, "tool-contracts")),
    tlsCertificatePath: certificate,
    tlsPrivateKeyPath: privateKey,
    bindHost: "127.0.0.1",
    bindPort: 44_321,
    resourceServerUrl: "https://edge.example.test/mcp",
    oauthIssuer: "https://issuer.example.test/",
    issuerId: "issuer-prod",
    authorizationEndpoint: "https://issuer.example.test/authorize",
    tokenEndpoint: "https://issuer.example.test/token",
    jwksUri: "https://issuer.example.test/.well-known/jwks.json",
    allowedHosts: ["edge.example.test"],
    allowedOrigins: ["client.example.test"],
    policyVersion: "policy-1",
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1",
    ipcTimeoutMs: 5_000,
    maxIpcResponseBytes: 2 * 1024 * 1024,
    rateLimitWindowMs: 60_000,
    rateLimitMaxRequests: 120,
    rateLimitMaxKeys: 10_000,
    ...overrides
  };
}

async function reservePort(): Promise<number> {
  const net = await import("node:net");
  const server = net.createServer();
  await new Promise<void>((resolveListen, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("Unable to reserve a local port");
  const port = address.port;
  await new Promise<void>((resolveClose, reject) => server.close((error) => error ? reject(error) : resolveClose()));
  return port;
}

async function createTestCertificate(directory: string, certificatePath: string, privateKeyPath: string): Promise<void> {
  await execFileAsync(
    "/usr/bin/openssl",
    ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", privateKeyPath, "-out", certificatePath, "-days", "1", "-subj", "/CN=edge.example.test", "-addext", "subjectAltName=DNS:edge.example.test"],
    { cwd: directory, env: { PATH: "/usr/bin:/bin" }, timeout: 10_000, maxBuffer: 64 * 1024 }
  );
}
