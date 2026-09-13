import assert from "node:assert/strict";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import https from "node:https";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { exportJWK, generateKeyPair, SignJWT } from "jose";
import { Client, StreamableHTTPClientTransport, type FetchLike } from "@modelcontextprotocol/client";
import type { PrincipalContext } from "@mac-operator/contracts";
import { BrokerIpcServer, BrokerStore, Broker, createDefaultPolicy, EdgeKeyring, MacOsNativeBrokerIpcServer, MacOsPeerCredentialVerifier, capturePeerProcessIdentity } from "@mac-operator/broker";
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
    scope: "mac.control.read"
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
    assert.deepEqual(listed.tools.map((tool) => tool.name), ["mac_capabilities", "mac_health"]);
    const result = await client.callTool({ name: "mac_health", arguments: {} });
    const text = result.content?.find((item): item is { type: "text"; text: string } => item.type === "text");
    assert.ok(text);
    const payload = JSON.parse(text.text) as { ok: boolean; tool: string; result_class: string };
    assert.equal(payload.ok, true);
    assert.equal(payload.tool, "mac_health");
    assert.equal(payload.result_class, "SUCCEEDED");
    assert.equal(JSON.stringify(store.auditRows()).includes(accessToken), false);
    const replayRequest = requestFactory.create("mac_health", {}, replayPrincipal);
    assert.equal((await brokerClient.call(replayRequest)).ok, true);
    const replayed = await brokerClient.call(replayRequest);
    assert.equal(replayed.ok, false);
    if (!replayed.ok) assert.equal(replayed.result_class, "REPLAY_DENIED");
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
