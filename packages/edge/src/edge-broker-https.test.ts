import assert from "node:assert/strict";
import { promisify } from "node:util";
import { execFile, spawn } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import https from "node:https";
import { once } from "node:events";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { Client, StreamableHTTPClientTransport, type FetchLike } from "@modelcontextprotocol/client";
import { canonicalJson, sha256, type PrincipalContext } from "@mac-operator/contracts";
import { BrokerIpcServer, BrokerStore, Broker, createDefaultPolicy, EdgeKeyring, MacOsNativeBrokerIpcServer, MacOsPeerCredentialVerifier, capturePeerProcessIdentity, type FilesystemExecutor } from "@mac-operator/broker";
import { AuthenticatedIpcBrokerGateway, BrokerIpcClient, EdgeRequestFactory, createHttpsMcpEdge } from "./index.js";
import { ToolContractRegistry } from "./contract-registry.js";
import { createJwtAccessTokenVerifier } from "./jwt-verifier.js";

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const contracts = await ToolContractRegistry.load(resolve(repositoryRoot, "tool-contracts"));

test("authenticated HTTPS Edge reaches the Broker through signed local IPC", async () => {
  const directory = await mkdtemp(join(tmpdir(), "e2e-"));
  const tlsDirectory = join(directory, "tls");
  await mkdir(tlsDirectory, { mode: 0o700 });
  const socketPath = join(directory, "broker.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = Buffer.alloc(32, 0x41);
  const now = Date.now();
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] } as const;
  const policyBase = createDefaultPolicy("edge-1", true, ["mac.control.read", "mac.files.write", "mac.job.read"], ["edge-key-1"], [root]);
  const writeTool = policyBase.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...policyBase,
    tools: new Map(policyBase.tools).set("mac_write_file_atomic", { ...writeTool, enabled: true })
  };
  const mutationPath = join(directory, "https-mutation.txt");
  const mutationContent = "https-kill-switch";
  const mutationArguments = { path: mutationPath, content: mutationContent, idempotency_key: "https-active-kill-switch", encoding: "utf8", create_only: true };
  const filesystemExecutor: FilesystemExecutor = {
    stat: async () => { throw new Error("Unexpected stat"); },
    read: async () => { throw new Error("Unexpected read"); },
    write: async (_plan, _content, _expectedSha256, _createOnly, control) => {
      store.setSwitch("mutations", true, "https-active-kill-switch", now);
      assert.equal(control.shouldCancel(), true);
      return {
        operation: "write",
        path: mutationPath,
        bytesWritten: mutationContent.length,
        sha256: sha256(mutationContent),
        created: true,
        expectedSha256: null,
        expectedMatched: true,
        rootId: "test-root",
        device: "1",
        inode: "1"
      };
    }
  };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1",
      keyId: "edge-key-1",
      key,
      notBeforeMs: now - 60_000,
      expiresAtMs: now + 300_000
    }]),
    now: () => now,
    filesystemExecutor
  });
  const brokerServer = process.platform === "darwin"
    ? new MacOsNativeBrokerIpcServer({
      socketPath,
      broker,
      peerPolicy: currentProcessNativePolicy()
    })
    : new BrokerIpcServer({
      socketPath,
      broker,
      peerCredentialVerifier: currentProcessVerifier()
    });
  const requestFactory = new EdgeRequestFactory({
    authenticationKey: key,
    authenticationKeyId: "edge-key-1",
    brokerAudience: "mac-operator-broker",
    policyVersion: () => "policy-0.1",
    now: () => now,
    randomId: (() => {
      let sequence = 0;
      return () => `e2e-${++sequence}`;
    })()
  });
  const replayPrincipal: PrincipalContext = {
    principalId: "principal-1",
    sessionId: "session-1",
    issuer: "test-issuer",
    audience: "mac-operator-broker",
    scopes: ["mac.control.read"],
    issuedAtMs: now - 1_000,
    expiresAtMs: now + 300_000,
    edgeId: "edge-1"
  };
  const brokerClient = new BrokerIpcClient(
    socketPath,
    (request, response) => requestFactory.verifyResponse(request, response)
  );
  const gateway = new AuthenticatedIpcBrokerGateway(
    requestFactory,
    brokerClient
  );
  const issuer = new URL("https://issuer.example.test");
  const resourceServerUrl = new URL("https://edge.example.test/mcp");
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const publicJwk = await exportJWK(publicKey);
  const accessToken = await new SignJWT({
    sid: "session-1",
    azp: "client-1",
    scope: "mac.control.read mac.files.write mac.job.read"
  })
    .setProtectedHeader({ alg: "RS256", kid: "e2e-key", typ: "at+jwt" })
    .setIssuer(issuer.href)
    .setAudience(resourceServerUrl.href)
    .setSubject("principal-1")
    .setIssuedAt()
    .setExpirationTime("5 minutes")
    .setJti("e2e-token-1")
    .sign(privateKey);
  const tls = await createTestCertificate(tlsDirectory);
  const edge = createHttpsMcpEdge({
    edgeId: "edge-1",
    brokerAudience: "mac-operator-broker",
    resourceServerUrl,
    contracts,
    gateway,
    bindHost: "127.0.0.1",
    allowedHosts: ["edge.example.test"],
    allowedOrigins: ["client.example.test"],
    tlsCertificate: await readFile(tls.certificatePath),
    tlsPrivateKey: await readFile(tls.keyPath),
    oauthIssuer: issuer,
    tokenVerifier: createJwtAccessTokenVerifier({
      issuer,
      issuerId: "test-issuer",
      resourceServerUrl,
      jwks: { keys: [{ ...publicJwk, kid: "e2e-key", alg: "RS256", use: "sig" }] }
    }),
    oauthMetadata: {
      issuer: issuer.href,
      authorization_endpoint: "https://issuer.example.test/authorize",
      token_endpoint: "https://issuer.example.test/token",
      response_types_supported: ["code"]
    }
  });
  const client = new Client(
    { name: "mac-operator-edge-broker-e2e", version: "1.0.0" },
    { capabilities: {}, versionNegotiation: { mode: { pin: "2026-07-28" } } }
  );
  let transport: StreamableHTTPClientTransport | undefined;
  await brokerServer.listen();
  try {
    edge.server.listen(0, "127.0.0.1");
    await once(edge.server, "listening");
    const address = edge.server.address();
    assert.ok(address && typeof address === "object");
    transport = new StreamableHTTPClientTransport(
      new URL(`https://edge.example.test:${address.port}${resourceServerUrl.pathname}`),
      {
        authProvider: { token: async () => accessToken },
        fetch: createPinnedFetch(address.port),
        onInsufficientScope: "throw"
      }
    );
    await client.connect(transport);
    const listed = await client.listTools();
    assert.deepEqual(listed.tools.map((tool) => tool.name), ["mac_capabilities", "mac_health", "mac_job_status", "mac_write_file_atomic"]);
    const result = await client.callTool({ name: "mac_health", arguments: {} });
    const text = result.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(text);
    const payload = JSON.parse(text.text) as { ok: boolean; tool: string; result_class: string };
    assert.equal(payload.ok, true);
    assert.equal(payload.tool, "mac_health");
    assert.equal(payload.result_class, "SUCCEEDED");
    assert.equal(JSON.stringify(store.auditRows()).includes(accessToken), false);

    store.issueApproval({
      approvalId: "approval:https-active-kill-switch",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(mutationArguments)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: now - 1_000,
      expiresAtMs: now + 1_000
    });
    const activeMutation = await client.callTool({ name: "mac_write_file_atomic", arguments: mutationArguments });
    const activeMutationText = activeMutation.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(activeMutationText);
    const activeMutationPayload = JSON.parse(activeMutationText.text) as { ok: boolean; result_class: string };
    assert.equal(activeMutationPayload.ok, false);
    assert.equal(activeMutationPayload.result_class, "CANCELLED");
    const activeMutationJob = store.ownedJobByIdempotencyKey("https-active-kill-switch", "principal-1");
    assert.ok(activeMutationJob);
    assert.equal(activeMutationJob.state, "unknown");
    assert.equal(await readFile(mutationPath).catch(() => undefined), undefined);
    store.setSwitch("mutations", false, "https-active-kill-switch-reset", now);

    const queuedArguments = { path: join(directory, "https-queued.txt"), content: "queued", idempotency_key: "https-queued-mutation", encoding: "utf8", create_only: true };
    const queuedJobId = "job:https-queued-mutation";
    store.createJob({
      jobId: queuedJobId,
      edgeId: "edge-1",
      edgeKeyId: "edge-1:edge-key-1",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_write_file_atomic",
      targetRef: "path:test-root",
      policyVersion: "policy-0.1",
      payloadDigest: sha256(canonicalJson(queuedArguments)),
      idempotencyKey: queuedArguments.idempotency_key,
      createdAtMs: now
    });
    store.setSwitch("mutations", true, "https-queued-kill-switch", now);
    const queuedStatus = await client.callTool({ name: "mac_job_status", arguments: { job_id: queuedJobId, tail_bytes: 128 } });
    const queuedStatusText = queuedStatus.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(queuedStatusText);
    const queuedStatusPayload = JSON.parse(queuedStatusText.text) as { ok: boolean; data?: { state?: string } };
    assert.equal(queuedStatusPayload.ok, true);
    assert.equal(queuedStatusPayload.data?.state, "cancelled");
    store.setSwitch("mutations", false, "https-queued-kill-switch-reset", now);

    const replayRequest = requestFactory.create("mac_health", {}, replayPrincipal);
    assert.equal((await brokerClient.call(replayRequest)).ok, true);
    const replayed = await brokerClient.call(replayRequest);
    assert.equal(replayed.ok, false);
    if (!replayed.ok) assert.equal(replayed.result_class, "REPLAY_DENIED");

    const edgeRevokedQueuedJobId = "job:https-edge-revoked-queued";
    store.createJob({
      jobId: edgeRevokedQueuedJobId,
      edgeId: "edge-1",
      edgeKeyId: "edge-1:edge-key-1",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_write_file_atomic",
      targetRef: "path:test-root",
      policyVersion: "policy-0.1",
      payloadDigest: sha256(canonicalJson({ idempotency_key: "https-edge-revoked-queued" })),
      idempotencyKey: "https-edge-revoked-queued",
      createdAtMs: now
    });
    broker.revokeEdge("edge-1", "https-edge-revocation", now);
    assert.equal(store.ownedJob(edgeRevokedQueuedJobId, "principal-1")?.state, "cancelled");
    const revokedResult = await client.callTool({ name: "mac_health", arguments: {} });
    const revokedText = revokedResult.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(revokedText);
    const revokedPayload = JSON.parse(revokedText.text) as { ok: boolean; result_class: string };
    assert.equal(revokedPayload.ok, false);
    assert.equal(revokedPayload.result_class, "REVOKED");
  } finally {
    await client.close().catch(() => undefined);
    await transport?.close().catch(() => undefined);
    await edge.close().catch(() => undefined);
    await brokerServer.close().catch(() => undefined);
    store.close();
    key.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});

test("separate Edge process reaches the native Broker through authenticated HTTPS", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("separate native Edge/Broker processes require macOS peer credentials");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "e2e-cross-process-"));
  const tlsDirectory = join(directory, "tls");
  await mkdir(tlsDirectory, { mode: 0o700 });
  const socketPath = join(directory, "broker.sock");
  const readyPath = join(directory, "edge.ready");
  const keyPath = join(directory, "edge.key");
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const edgeModule = pathToFileURL(join(repositoryRoot, "packages/edge/dist/index.js")).href;
  const contractsDirectory = resolve(repositoryRoot, "tool-contracts");
  const key = Buffer.alloc(32, 0x52);
  await writeFile(keyPath, key, { mode: 0o600 });
  const tls = await createTestCertificate(tlsDirectory);
  const port = await reservePort();
  const now = Date.now();
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1",
      keyId: "edge-key-1",
      key,
      notBeforeMs: now - 60_000,
      expiresAtMs: now + 300_000
    }]),
    now: () => now
  });
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const publicJwk = { ...(await exportJWK(publicKey)), kid: "cross-process-key", alg: "RS256", use: "sig" };
  const issuer = new URL("https://issuer.example.test");
  const resourceServerUrl = new URL("https://edge.example.test/mcp");
  const accessToken = await new SignJWT({
    sid: "cross-process-session",
    azp: "cross-process-client",
    scope: "mac.control.read"
  })
    .setProtectedHeader({ alg: "RS256", kid: "cross-process-key", typ: "at+jwt" })
    .setIssuer(issuer.href)
    .setAudience(resourceServerUrl.href)
    .setSubject("principal-1")
    .setIssuedAt()
    .setExpirationTime("5 minutes")
    .setJti("cross-process-token-1")
    .sign(privateKey);
  const childScript = [
    'import { readFile, writeFile } from "node:fs/promises";',
    'const [edgeModule, contractsDirectory, socketPath, readyPath, keyPath, keyDigest, certificatePath, privateKeyPath, portText, publicJwkText] = process.argv.slice(1);',
    'const { AuthenticatedIpcBrokerGateway, BrokerIpcClient, EdgeRequestFactory, ToolContractRegistry, createHttpsMcpEdge, createJwtAccessTokenVerifier } = await import(edgeModule);',
    'let edge; let requestFactory; let stopping = false;',
    'try {',
    '  const contracts = await ToolContractRegistry.load(contractsDirectory);',
    '  requestFactory = await EdgeRequestFactory.fromProtectedKeyFile({ authenticationKeyPath: keyPath, expectedAuthenticationKeyDigest: keyDigest, authenticationKeyId: "edge-key-1", brokerAudience: "mac-operator-broker", policyVersion: () => "policy-0.1" });',
    '  const brokerClient = new BrokerIpcClient(socketPath, (request, response) => requestFactory.verifyResponse(request, response));',
    '  const gateway = new AuthenticatedIpcBrokerGateway(requestFactory, brokerClient);',
    '  const issuer = new URL("https://issuer.example.test");',
    '  const resourceServerUrl = new URL("https://edge.example.test/mcp");',
    '  const publicJwk = JSON.parse(publicJwkText);',
    '  edge = createHttpsMcpEdge({ edgeId: "edge-1", brokerAudience: "mac-operator-broker", resourceServerUrl, contracts, gateway, bindHost: "127.0.0.1", allowedHosts: ["edge.example.test"], allowedOrigins: ["client.example.test"], tlsCertificate: await readFile(certificatePath), tlsPrivateKey: await readFile(privateKeyPath), oauthIssuer: issuer, tokenVerifier: createJwtAccessTokenVerifier({ issuer, issuerId: "test-issuer", resourceServerUrl, jwks: { keys: [publicJwk] } }), oauthMetadata: { issuer: issuer.href, authorization_endpoint: "https://issuer.example.test/authorize", token_endpoint: "https://issuer.example.test/token", response_types_supported: ["code"] } });',
    '  await new Promise((resolve, reject) => { edge.server.once("error", reject); edge.server.listen(Number(portText), "127.0.0.1", resolve); });',
    '  await writeFile(readyPath, JSON.stringify({ port: Number(portText) }) + "\\n", { mode: 0o600 });',
    '  await new Promise((resolve) => { const stop = () => { if (stopping) return; stopping = true; resolve(); }; process.once("SIGTERM", stop); process.once("SIGINT", stop); });',
    '  await edge.close();',
    '  requestFactory.dispose();',
    '} catch (error) { process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\\n`); process.exitCode = 2; }'
  ].join("\n");
  const child = spawn(process.execPath, ["--input-type=module", "-e", childScript, edgeModule, contractsDirectory, socketPath, readyPath, keyPath, sha256(key), tls.certificatePath, tls.keyPath, String(port), JSON.stringify(publicJwk)], {
    cwd: "/",
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
    stdio: ["ignore", "pipe", "pipe"]
  });
  const childStderr: Buffer[] = [];
  child.stderr?.on("data", (chunk: Buffer) => childStderr.push(chunk));
  let brokerServer: MacOsNativeBrokerIpcServer | undefined;
  const client = new Client(
    { name: "mac-operator-edge-cross-process", version: "1.0.0" },
    { capabilities: {}, versionNegotiation: { mode: { pin: "2026-07-28" } } }
  );
  let transport: StreamableHTTPClientTransport | undefined;
  try {
    if (child.pid === undefined || child.stderr === null) throw new Error("Edge child did not expose a process identity");
    const identity = await waitForProcessIdentity(child.pid);
    const uid = process.getuid?.();
    const gid = process.getgid?.();
    if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
    brokerServer = new MacOsNativeBrokerIpcServer({
      socketPath,
      broker,
      peerPolicy: { expectedUid: uid, expectedGid: gid, allowedProcessIdentity: identity }
    });
    await brokerServer.listen();
    await waitForFile(readyPath, 5_000);
    transport = new StreamableHTTPClientTransport(
      new URL(`https://edge.example.test:${port}${resourceServerUrl.pathname}`),
      {
        authProvider: { token: async () => accessToken },
        fetch: createPinnedFetch(port),
        onInsufficientScope: "throw"
      }
    );
    await client.connect(transport);
    const result = await client.callTool({ name: "mac_health", arguments: {} });
    const text = result.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(text);
    const payload = JSON.parse(text.text) as { ok: boolean; tool: string; result_class: string };
    assert.equal(payload.ok, true);
    assert.equal(payload.tool, "mac_health");
    assert.equal(payload.result_class, "SUCCEEDED");
    assert.equal(JSON.stringify(store.auditRows()).includes(accessToken), false);
  } catch (error) {
    const diagnostic = Buffer.concat(childStderr).toString("utf8").trim();
    const audit = JSON.stringify(store.auditRows());
    const message = `${error instanceof Error ? error.message : String(error)}; audit: ${audit}`;
    throw diagnostic.length === 0 ? new Error(message) : new Error(`${message}; Edge child stderr: ${diagnostic}`);
  } finally {
    await client.close().catch(() => undefined);
    await transport?.close().catch(() => undefined);
    await stopChild(child);
    await brokerServer?.close().catch(() => undefined);
    store.close();
    key.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});

async function createTestCertificate(directory: string): Promise<{ certificatePath: string; keyPath: string }> {
  const certificatePath = join(directory, "edge.crt");
  const keyPath = join(directory, "edge.key");
  await execFileAsync(
    "/usr/bin/openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-nodes",
      "-keyout",
      keyPath,
      "-out",
      certificatePath,
      "-days",
      "1",
      "-subj",
      "/CN=edge.example.test",
      "-addext",
      "subjectAltName=DNS:edge.example.test"
    ],
    {
      cwd: "/",
      env: { PATH: "/usr/bin:/bin" },
      timeout: 10_000,
      maxBuffer: 64 * 1024
    }
  );
  return { certificatePath, keyPath };
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

async function waitForFile(path: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (true) {
    try {
      await stat(path);
      return;
    } catch {
      if (Date.now() >= deadline) throw new Error(`Timed out waiting for ${path}`);
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

async function waitForProcessIdentity(pid: number): Promise<ReturnType<typeof capturePeerProcessIdentity>> {
  const deadline = Date.now() + 5_000;
  while (true) {
    try {
      return capturePeerProcessIdentity(pid);
    } catch {
      if (Date.now() >= deadline) throw new Error("Timed out waiting for child process identity");
      await new Promise((resolve) => setTimeout(resolve, 10));
    }
  }
}

async function stopChild(child: ReturnType<typeof spawn>): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  child.kill("SIGTERM");
  await Promise.race([
    once(child, "exit").then(() => undefined),
    new Promise<void>((resolve) => setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
      resolve();
    }, 2_000))
  ]);
}

function currentProcessVerifier(): MacOsPeerCredentialVerifier {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  return new MacOsPeerCredentialVerifier({
    expectedUid: uid,
    expectedGid: gid,
    allowedProcessIds: new Set([process.pid])
  });
}

function currentProcessNativePolicy(): {
  expectedUid: number;
  expectedGid: number;
  allowedProcessIdentity: ReturnType<typeof capturePeerProcessIdentity>;
} {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  return {
    expectedUid: uid,
    expectedGid: gid,
    allowedProcessIdentity: capturePeerProcessIdentity(process.pid)
  };
}

function createPinnedFetch(port: number): FetchLike {
  return async (input, init = {}) => {
    const target = typeof input === "string" ? new URL(input) : new URL(input.href);
    const headers = new Headers(init.headers);
    headers.set("Host", "edge.example.test");
    headers.set("Origin", "https://client.example.test");
    const requestBody = init.body === undefined
      ? undefined
      : typeof init.body === "string"
        ? Buffer.from(init.body)
        : init.body as Uint8Array;
    return await new Promise<Response>((resolveResponse, reject) => {
      const request = https.request({
        hostname: "127.0.0.1",
        port,
        path: `${target.pathname}${target.search}`,
        method: init.method ?? "GET",
        headers: Object.fromEntries(headers),
        rejectUnauthorized: false,
        agent: false
      }, (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.on("end", () => {
          const responseHeaders = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (value !== undefined) responseHeaders.set(name, Array.isArray(value) ? value.join(", ") : value);
          }
          resolveResponse(new Response(Buffer.concat(chunks), {
            status: response.statusCode ?? 500,
            ...(response.statusMessage === undefined ? {} : { statusText: response.statusMessage }),
            headers: responseHeaders
          }));
        });
      });
      request.once("error", rejectError => reject(rejectError));
      if (init.signal) {
        if (init.signal.aborted) {
          request.destroy();
          reject(init.signal.reason ?? new Error("Request aborted"));
          return;
        }
        init.signal.addEventListener("abort", () => request.destroy(init.signal?.reason), { once: true });
      }
      if (requestBody !== undefined) request.write(requestBody);
      request.end();
    });
  };
}
