import assert from "node:assert/strict";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { EventEmitter } from "node:events";
import { chmod, mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { sha256 } from "@mac-operator/contracts";
import {
  EdgeServiceEntrypoint,
  createEdgeServiceFromStartupConfig,
  loadEdgeServiceStartupConfig,
  validateEdgeServiceStartupConfig,
  type EdgeServiceStartupConfig
} from "./service-startup.js";
import type { HttpsMcpEdge } from "./https-edge.js";
import { readEdgeStatus } from "./edge-status-ipc.js";

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

test("Edge service startup config is strict, canonical, and root-bound", () => {
  const config = baseConfig("/Users/operator/package", "/Users/operator/data", "/Users/operator/runtime");
  assert.deepEqual(validateEdgeServiceStartupConfig(config), config);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, unexpected: true } as never), /unknown field/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, brokerSocketPath: "/Users/operator/runtime/../escape.sock" }), /canonical/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, tlsPrivateKeyPath: "/Users/operator/other/edge.key" }), /escaped/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, jwksUri: "http://issuer.example.test/jwks" }), /HTTPS/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, oauthScopes: ["mac.control.read"], requiredScopes: ["mac.files.read"] }), /not advertised/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, bindPort: 0 }), /out of bounds/u);
});

test("Edge service startup config rejects inherited, accessor, and sparse authority data", () => {
  const config = baseConfig("/Users/operator/package", "/Users/operator/data", "/Users/operator/runtime");
  const inherited = Object.create(config) as Record<string, unknown>;
  assert.throws(() => validateEdgeServiceStartupConfig(inherited), /config is malformed/u);

  const accessor = { ...config } as Record<string, unknown>;
  Object.defineProperty(accessor, "bindPort", { enumerable: true, get: () => 44_321 });
  assert.throws(() => validateEdgeServiceStartupConfig(accessor), /config is malformed/u);

  const sparseHosts = new Array(1) as string[];
  assert.throws(
    () => validateEdgeServiceStartupConfig({ ...config, allowedHosts: sparseHosts }),
    /allowlist must not be empty/u
  );
});

test("owner OAuth issuer requires a root-bound authenticated revocation channel", () => {
  const base = { ...baseConfig("/Users/operator/package", "/Users/operator/data", "/Users/operator/runtime"), issuerId: "mac-operator-auth" };
  assert.throws(() => validateEdgeServiceStartupConfig(base));
  const config = { ...base, oauthStatusUrl: new URL("/oauth/status", base.oauthIssuer).href,
    oauthStatusKeyPath: "/Users/operator/data/status.key", oauthStatusKeyDigest: "a".repeat(64) };
  assert.throws(() => validateEdgeServiceStartupConfig(config), /requires the loopback channel/u);
  const loopback = { ...config, oauthStatusLocalUrl: "https://127.0.0.1:3444/oauth/status",
    oauthStatusLocalServerName: "issuer.example.test", oauthStatusLocalCaPath: "/Users/operator/data/status-ca.crt" };
  assert.deepEqual(validateEdgeServiceStartupConfig(loopback), loopback);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, oauthStatusUrl: "https://other.example.test/oauth/status" }));
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, oauthStatusKeyPath: "/Users/operator/other/status.key" }));
  assert.throws(() => validateEdgeServiceStartupConfig({ ...loopback, oauthStatusLocalUrl: "https://localhost:3444/oauth/status" }), /fixed local boundary/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...loopback, oauthStatusLocalServerName: "other.example.test" }), /fixed local boundary/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...loopback, oauthStatusLocalCaPath: "/Users/operator/other/status-ca.crt" }), /fixed local boundary/u);
  assert.throws(() => validateEdgeServiceStartupConfig({ ...config, oauthStatusLocalUrl: "https://127.0.0.1:3444/oauth/status" }), /incomplete/u);
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
  const serviceStatusKey = Buffer.alloc(32, 0x52);
  const authenticationKeyPath = join(dataRoot, "edge-auth.key");
  const serviceStatusKeyPath = join(dataRoot, "edge-status.key");
  const certificatePath = join(dataRoot, "edge.crt");
  const privateKeyPath = join(dataRoot, "edge.key");
  const port = await reservePort();
  let assembly: Awaited<ReturnType<typeof createEdgeServiceFromStartupConfig>> | undefined;
  try {
    await writeFile(authenticationKeyPath, key, { mode: 0o600 });
    await writeFile(serviceStatusKeyPath, serviceStatusKey, { mode: 0o600 });
    await createTestCertificate(dataRoot, certificatePath, privateKeyPath);
    await chmod(certificatePath, 0o600);
    await chmod(privateKeyPath, 0o600);
    const canonicalDataRoot = await realpath(dataRoot);
    const config = baseConfig(await realpath(repositoryRoot), canonicalDataRoot, await realpath(runtimeRoot), {
      authenticationKeyPath: join(canonicalDataRoot, "edge-auth.key"),
      tlsCertificatePath: join(canonicalDataRoot, "edge.crt"),
      tlsPrivateKeyPath: join(canonicalDataRoot, "edge.key"),
      serviceStatusSocketPath: join(await realpath(runtimeRoot), "s.sock"),
      serviceStatusKeyPath: join(canonicalDataRoot, "edge-status.key"),
      serviceStatusKeyDigest: sha256(serviceStatusKey),
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
    assert.deepEqual(
      await readEdgeStatus({ socketPath: config.serviceStatusSocketPath!, authenticationKey: serviceStatusKey }),
      assembly.service.readback()
    );
    await assembly.close();
    assert.equal(assembly.service.readback().state, "stopped");
  } finally {
    if (assembly) await assembly.close().catch(() => undefined);
    key.fill(0);
    serviceStatusKey.fill(0);
    await rm(root, { recursive: true, force: true });
  }
});

test("Edge service serializes stop behind an in-flight start", async () => {
  const port = 44_322;
  const emitter = new EventEmitter();
  let listening = false;
  let closeCalls = 0;
  Object.defineProperty(emitter, "listening", { configurable: false, enumerable: true, get: () => listening });
  const server = Object.assign(emitter, {
    address: () => listening ? { address: "127.0.0.1", family: "IPv4", port } : null,
    listen: () => {
      setTimeout(() => {
        listening = true;
        emitter.emit("listening");
      }, 20);
    },
    close: (callback: (error?: Error) => void) => {
      closeCalls += 1;
      listening = false;
      callback();
    }
  }) as unknown as import("node:https").Server;
  let edge: HttpsMcpEdge;
  edge = {
    server,
    handler: { close: async () => {} },
    close: async () => {
      await edge.handler.close();
      if (!server.listening) return;
      await new Promise<void>((resolveClose, rejectClose) => {
        server.close((error) => error ? rejectClose(error) : resolveClose());
      });
    }
  } as HttpsMcpEdge;
  const service = new EdgeServiceEntrypoint(edge, {
    bindHost: "127.0.0.1",
    bindPort: port,
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1",
    policyVersion: "policy-1"
  });

  const starting = service.start();
  const stopping = service.stop();
  await Promise.all([starting, stopping]);
  assert.equal(service.state, "stopped");
  assert.equal(server.listening, false);
  assert.equal(closeCalls, 1);
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
