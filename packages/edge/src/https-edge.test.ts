import assert from "node:assert/strict";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import https from "node:https";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import test from "node:test";
import type { AuthInfo } from "@modelcontextprotocol/server";
import type { BrokerResult } from "@mac-operator/contracts";
import { Client, StreamableHTTPClientTransport, type FetchLike } from "@modelcontextprotocol/client";
import { ToolContractRegistry } from "./contract-registry.js";
import { createHttpsMcpEdge, type HttpsMcpEdgeOptions } from "./https-edge.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const contracts = await ToolContractRegistry.load(resolve(repositoryRoot, "tool-contracts"));

test("HTTPS Edge rejects malformed transport and policy configuration before startup", () => {
  assert.throws(() => createHttpsMcpEdge({
    ...baseOptions(),
    resourceServerUrl: new URL("http://edge.example.test/mcp")
  }), /must use HTTPS/u);
  assert.throws(() => createHttpsMcpEdge({
    ...baseOptions(),
    allowedHosts: ["https://edge.example.test"]
  }), /Host allowlist contains an invalid hostname/u);
  assert.throws(() => createHttpsMcpEdge({
    ...baseOptions(),
    allowedOrigins: ["https://client.example.test"]
  }), /Origin allowlist contains an invalid hostname/u);
  assert.throws(() => createHttpsMcpEdge({
    ...baseOptions(),
    allowedHosts: ["other.example.test"]
  }), /include the public resource hostname/u);
  assert.throws(() => createHttpsMcpEdge({
    ...baseOptions(),
    tlsCertificate: ""
  }), /TLS certificate and private key must not be empty/u);
});

test("HTTPS Edge normalizes case and rejects host-list syntax smuggling", () => {
  assert.throws(() => createHttpsMcpEdge({
    ...baseOptions(),
    allowedHosts: ["edge.example.test:443"]
  }), /Host allowlist contains an invalid hostname/u);
  assert.throws(() => createHttpsMcpEdge({
    ...baseOptions(),
    allowedOrigins: ["client.example.test/path"]
  }), /Origin allowlist contains an invalid hostname/u);
  assert.throws(() => createHttpsMcpEdge({
    ...baseOptions(),
    allowedOrigins: ["client.example.test", " client.example.test"]
  }), /Origin allowlist contains an invalid hostname/u);
});

test("official MCP client discovers Broker-enabled tools over HTTPS", async () => {
  const tlsDirectory = await mkdtemp(join(tmpdir(), "mac-operator-edge-tls-"));
  const edgeOptions = baseOptions();
  edgeOptions.gateway = {
    async execute(tool): Promise<BrokerResult> {
      return {
        ok: true,
        request_id: `integration-${tool}`,
        tool,
        result_class: "SUCCEEDED",
        data: tool === "mac_capabilities"
          ? { capabilities: [{ name: "mac_health", enabled: true }] }
          : { overall: "healthy", components: [] },
        warnings: [],
        truncated: false,
        verification: {},
        duration_ms: 1
      };
    }
  };
  const { certificatePath, keyPath } = await createTestCertificate(tlsDirectory);
  edgeOptions.tlsCertificate = await readFile(certificatePath);
  edgeOptions.tlsPrivateKey = await readFile(keyPath);
  const edge = createHttpsMcpEdge(edgeOptions);
  const client = new Client(
    { name: "mac-operator-integration-probe", version: "1.0.0" },
    { capabilities: {}, versionNegotiation: { mode: { pin: "2026-07-28" } } }
  );
  let transport: StreamableHTTPClientTransport | undefined;
  try {
    edge.server.listen(0, "127.0.0.1");
    await once(edge.server, "listening");
    const address = edge.server.address();
    assert.ok(address && typeof address === "object");
    transport = new StreamableHTTPClientTransport(
      new URL(`https://edge.example.test:${address.port}${edgeOptions.resourceServerUrl.pathname}`),
      {
        authProvider: { token: async () => "integration-token" },
        fetch: createPinnedFetch(address.port),
        onInsufficientScope: "throw"
      }
    );
    await client.connect(transport);
    assert.equal(client.getServerVersion()?.name, "Mac-Operator-MCP");
    assert.equal(client.getServerVersion()?.version, "0.1.0");
    assert.equal(client.getNegotiatedProtocolVersion(), "2026-07-28");
    const listed = await client.listTools();
    assert.deepEqual(listed.tools.map((tool) => tool.name), ["mac_health"]);
  } finally {
    await client.close().catch(() => undefined);
    await transport?.close().catch(() => undefined);
    await edge.close().catch(() => undefined);
    await rm(tlsDirectory, { recursive: true, force: true });
  }
});

const execFileAsync = promisify(execFile);

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
    return await new Promise<Response>((resolve, reject) => {
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
          resolve(new Response(Buffer.concat(chunks), {
            status: response.statusCode ?? 500,
            ...(response.statusMessage === undefined ? {} : { statusText: response.statusMessage }),
            headers: responseHeaders
          }));
        });
      });
      request.once("error", reject);
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

function baseOptions(): HttpsMcpEdgeOptions {
  const resourceServerUrl = new URL("https://edge.example.test/mcp");
  const authInfo: AuthInfo = {
    token: "test-token",
    clientId: "client-1",
    scopes: ["mac.control.read"],
    expiresAt: Math.floor(Date.now() / 1_000) + 60,
    resource: resourceServerUrl,
    extra: {
      principalId: "principal-1",
      issuer: "issuer-1",
      sessionId: "session-1",
      issuedAtMs: Date.now()
    }
  };
  return {
    edgeId: "edge-1",
    brokerAudience: "mac-operator-broker",
    resourceServerUrl,
    contracts,
    gateway: {
      async execute(): Promise<BrokerResult> {
        return {
          ok: false,
          request_id: "test",
          tool: "mac_health",
          result_class: "EXECUTION_FAILED",
          error: { message: "test", retryable: true },
          duration_ms: 0
        };
      }
    },
    bindHost: "0.0.0.0",
    allowedHosts: ["EDGE.EXAMPLE.TEST"],
    allowedOrigins: ["CLIENT.EXAMPLE.TEST"],
    tlsCertificate: "test-certificate",
    tlsPrivateKey: "test-private-key",
    tokenVerifier: {
      async verifyAccessToken(): Promise<AuthInfo> {
        return authInfo;
      }
    },
    oauthMetadata: {
      issuer: "https://issuer.example.test",
      authorization_endpoint: "https://issuer.example.test/authorize",
      token_endpoint: "https://issuer.example.test/token",
      response_types_supported: ["code"]
    }
  };
}
