import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import type { AuthInfo } from "@modelcontextprotocol/server";
import type { BrokerResult } from "@mac-operator/contracts";
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
      issuer: "https://issuer.example.test",
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
