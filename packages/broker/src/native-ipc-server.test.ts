import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { signRequest, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { capturePeerProcessIdentity } from "./peer-credentials.js";
import { MacOsNativeBrokerIpcServer } from "./native-ipc-server.js";
import { BrokerStore } from "./persistence.js";
import { createMacOsNativeBrokerRuntime } from "./runtime.js";

test("macOS runtime factory selects the native Broker IPC channel", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-native-runtime-"));
  const socketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const now = Date.now();
  const key = randomBytes(32);
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1", keyId: "edge-key-1", key,
      notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const { allowedProcessIdentity: _identity, ...pidOnlyPolicy } = currentProcessPeerPolicy();
  assert.throws(
    () => createMacOsNativeBrokerRuntime({ socketPath, broker, edgeId: "edge-1", peerPolicy: pidOnlyPolicy }),
    /explicit peer process identity/u
  );
  const { runtime, brokerChannel } = createMacOsNativeBrokerRuntime({
    socketPath,
    broker,
    edgeId: "edge-1",
    peerPolicy: currentProcessPeerPolicy()
  });
  await runtime.start();
  try {
    assert.equal(runtime.state, "running");
    assert.equal(brokerChannel instanceof MacOsNativeBrokerIpcServer, true);
    assert.equal((await stat(socketPath)).mode & 0o777, 0o600);
  } finally {
    await runtime.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("native IPC accepts a peer-authenticated fd through public Socket({ fd })", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-native-ipc-"));
  const socketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1",
      keyId: "edge-key-1",
      key,
      notBeforeMs: now - 1_000,
      expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const server = new MacOsNativeBrokerIpcServer({
    socketPath,
    broker,
    peerPolicy: currentProcessPeerPolicy()
  });
  await server.listen();
  try {
    assert.equal((await stat(socketPath)).mode & 0o777, 0o600);
    const unsigned: UnsignedBrokerRequest = {
      protocolVersion: "0.1",
      requestId: "native-ipc-request-1",
      contractVersion: "0.1",
      tool: "mac_health",
      arguments: {},
      principal: {
        principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer",
        audience: "mac-operator-broker", scopes: ["mac.control.read"],
        issuedAtMs: now - 1_000, expiresAtMs: now + 60_000, edgeId: "edge-1"
      },
      timestampMs: now,
      nonce: "native-ipc-nonce-1",
      policyAudience: "mac-operator-broker",
      policyVersion: "policy-0.1",
      authenticationKeyId: "edge-key-1"
    };
    const response = JSON.parse(await send(socketPath, `${JSON.stringify(signRequest(unsigned, key))}\n`)) as {
      response: { ok: boolean; tool: string };
    };
    assert.equal(response.response.ok, true);
    assert.equal(response.response.tool, "mac_health");
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("native IPC accepts a separately spawned Edge bound to its PID start-time identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-native-ipc-cross-process-"));
  const socketPath = join(directory, "broker.sock");
  const readyPath = join(directory, "ready");
  const keyPath = join(directory, "edge.key");
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  await writeFile(keyPath, key, { mode: 0o600 });
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1", keyId: "edge-key-1", key,
      notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const childScript = [
    'import { createConnection } from "node:net";',
    'import { readFile, stat } from "node:fs/promises";',
    'const [socketPath, readyPath, keyPath, contractsModule] = process.argv.slice(1);',
    'const { signRequest, verifyBrokerResponse } = await import(contractsModule);',
    'const deadline = Date.now() + 5000;',
    'while (true) { try { await stat(readyPath); break; } catch { if (Date.now() >= deadline) process.exit(2); await new Promise((resolve) => setTimeout(resolve, 10)); } }',
    'const key = await readFile(keyPath);',
    'const now = Date.now();',
    'const request = signRequest({ protocolVersion: "0.1", requestId: "cross-process-request", contractVersion: "0.1", tool: "mac_health", arguments: {}, principal: { principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer", audience: "mac-operator-broker", scopes: ["mac.control.read"], issuedAtMs: now - 1000, expiresAtMs: now + 60000, edgeId: "edge-1" }, timestampMs: now, nonce: "cross-process-nonce", policyAudience: "mac-operator-broker", policyVersion: "policy-0.1", authenticationKeyId: "edge-key-1" }, key);',
    'const socket = createConnection(socketPath);',
    'let response = "";',
    'socket.setEncoding("utf8");',
    'socket.on("data", (chunk) => { response += chunk; });',
    'socket.on("error", () => process.exit(3));',
    'socket.on("end", () => { try { const envelope = JSON.parse(response); if (!verifyBrokerResponse(request, envelope, key)) process.exit(4); process.stdout.write(JSON.stringify(envelope.response)); } catch { process.exit(5); } });',
    'socket.on("connect", () => socket.end(JSON.stringify(request) + "\\n"));'
  ].join("\n");
  const child = spawn(process.execPath, ["--input-type=module", "-e", childScript, socketPath, readyPath, keyPath, pathToFileURL(join(repositoryRoot, "packages/contracts/dist/index.js")).href], {
    cwd: "/",
    env: { PATH: process.env.PATH ?? "" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  if (child.pid === undefined || child.stdout === null || child.stderr === null) {
    child.kill("SIGKILL");
    throw new Error("Edge fixture did not expose a process identity");
  }
  const identity = await waitForProcessIdentity(child.pid);
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  const server = new MacOsNativeBrokerIpcServer({
    socketPath,
    broker,
    peerPolicy: { expectedUid: uid, expectedGid: gid, allowedProcessIdentity: identity }
  });
  await server.listen();
  try {
    await writeFile(readyPath, "ready\n", { mode: 0o600 });
    const output = await collectChildOutput(child, 5_000);
    const result = JSON.parse(output) as { ok: boolean; tool: string; result_class: string };
    assert.equal(result.ok, true);
    assert.equal(result.tool, "mac_health");
    assert.equal(result.result_class, "SUCCEEDED");
  } finally {
    if (!child.killed && child.exitCode === null) child.kill("SIGKILL");
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("native IPC fails closed when the bound Edge identity exits", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-native-ipc-peer-loss-"));
  const socketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1"),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1", keyId: "edge-key-1", key: randomBytes(32),
      notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const child = spawn("/bin/sleep", ["5"], {
    cwd: "/",
    env: { PATH: "/usr/bin:/bin" },
    stdio: "ignore"
  });
  if (child.pid === undefined) throw new Error("Peer-loss fixture did not expose a process identity");
  const identity = await waitForProcessIdentity(child.pid);
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error("POSIX identity is unavailable");
  let resolveLost: ((value: ReturnType<typeof capturePeerProcessIdentity>) => void) | undefined;
  const lost = new Promise<ReturnType<typeof capturePeerProcessIdentity>>((resolve) => { resolveLost = resolve; });
  const { runtime } = createMacOsNativeBrokerRuntime({
    socketPath,
    broker,
    edgeId: "edge-1",
    peerIdentityMonitorIntervalMs: 25,
    peerPolicy: { expectedUid: uid, allowedProcessIdentity: identity },
    onPeerIdentityLost: (observed) => resolveLost?.(observed)
  });
  await runtime.start();
  try {
    child.kill("SIGTERM");
    const observed = await Promise.race([
      lost,
      new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error("Peer identity loss was not observed")), 2_000))
    ]);
    assert.deepEqual(observed, identity);
    assert.equal(store.isRevoked("edge", "edge-1"), true);
    await assert.rejects(stat(socketPath), (error: unknown) => (error as NodeJS.ErrnoException).code === "ENOENT");
  } finally {
    if (!child.killed && child.exitCode === null) child.kill("SIGKILL");
    await runtime.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("native IPC drops a denied peer before parsing or auditing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-native-ipc-"));
  const socketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1", keyId: "edge-key-1", key: randomBytes(32),
      notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const server = new MacOsNativeBrokerIpcServer({
    socketPath,
    broker,
    peerPolicy: { expectedUid: process.getuid?.() ?? -1, allowedProcessIds: new Set([process.pid + 1]) }
  });
  await server.listen();
  try {
    try {
      assert.equal(await send(socketPath, "not-json\n"), "");
    } catch (error) {
      assert.match(String((error as NodeJS.ErrnoException).code), /^(?:EPIPE|ECONNRESET)$/u);
    }
    assert.deepEqual(store.auditRows(), []);
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("native IPC rejects a PID identity replacement before parsing or auditing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-native-ipc-identity-deny-"));
  const socketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1", keyId: "edge-key-1", key: randomBytes(32),
      notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const identity = capturePeerProcessIdentity(process.pid);
  const server = new MacOsNativeBrokerIpcServer({
    socketPath,
    broker,
    peerPolicy: {
      expectedUid: process.getuid?.() ?? -1,
      allowedProcessIdentity: { ...identity, startTimeMicros: identity.startTimeMicros + 1 }
    }
  });
  try {
    await assert.rejects(server.listen(), /process identity changed/u);
    assert.deepEqual(store.auditRows(), []);
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("native IPC refuses an unsafe parent directory", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-native-ipc-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1"),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1", keyId: "edge-key-1", key: randomBytes(32),
      notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  const server = new MacOsNativeBrokerIpcServer({
    socketPath: join(directory, "broker.sock"),
    broker,
    peerPolicy: currentProcessPeerPolicy()
  });
  try {
    await chmod(directory, 0o770);
    await assert.rejects(server.listen(), /must not be writable/u);
  } finally {
    store.close();
    await chmod(directory, 0o700);
    await rm(directory, { recursive: true, force: true });
  }
});

function currentProcessPeerPolicy(): {
  expectedUid: number;
  expectedGid: number;
  allowedProcessIds: ReadonlySet<number>;
  allowedProcessIdentity: ReturnType<typeof capturePeerProcessIdentity>;
} {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  return {
    expectedUid: uid,
    expectedGid: gid,
    allowedProcessIds: new Set([process.pid]),
    allowedProcessIdentity: capturePeerProcessIdentity(process.pid)
  };
}

function send(socketPath: string, body: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = createConnection(socketPath);
    let response = "";
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(body));
    socket.on("data", (chunk: string) => { response += chunk; });
    socket.on("end", () => resolve(response.trim()));
    socket.on("error", reject);
  });
}

async function waitForProcessIdentity(pid: number): Promise<ReturnType<typeof capturePeerProcessIdentity>> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    try {
      return capturePeerProcessIdentity(pid);
    } catch {
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
  throw new Error("Edge fixture process identity was unavailable");
}

function collectChildOutput(child: ReturnType<typeof spawn>, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let output = "";
    let errorOutput = "";
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Edge fixture timed out"));
    }, timeoutMs);
    child.stdout?.on("data", (chunk: Buffer) => {
      output += chunk.toString("utf8");
      if (Buffer.byteLength(output, "utf8") > 131_072) {
        child.kill("SIGKILL");
        clearTimeout(timer);
        reject(new Error("Edge fixture output exceeded the test cap"));
      }
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      errorOutput += chunk.toString("utf8");
      if (Buffer.byteLength(errorOutput, "utf8") > 16_384) child.kill("SIGKILL");
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      if (code !== 0 || signal !== null) {
        reject(new Error(`Edge fixture exited unexpectedly: ${code ?? "null"}/${signal ?? "none"}`));
      } else {
        resolve(output);
      }
    });
  });
}
