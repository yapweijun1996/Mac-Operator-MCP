import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { BrokerError, type BrokerResult, type PrincipalContext } from "@mac-operator/contracts";
import { McpServer, type AuthInfo } from "@modelcontextprotocol/server";
import { ToolContractRegistry } from "./contract-registry.js";
import type { BrokerGateway } from "./gateway.js";
import { createGovernedMcpServerFactory, mapGatewayError } from "./mcp-server.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

test("MCP factory advertises only Broker-enabled tools and never forwards bearer tokens", async () => {
  const observedPrincipals: PrincipalContext[] = [];
  const gateway: BrokerGateway = {
    async execute(tool, _argumentsValue, principal): Promise<BrokerResult> {
      observedPrincipals.push(principal);
      assert.equal(tool, "mac_capabilities");
      return {
        ok: true,
        request_id: "capability-request",
        tool,
        result_class: "SUCCEEDED",
        data: {
          capabilities: [
            { name: "mac_health", enabled: true },
            { name: "mac_policy_explain", enabled: false }
          ]
        },
        warnings: [],
        truncated: false,
        verification: {},
        duration_ms: 1
      };
    }
  };
  const resourceServerUrl = new URL("https://edge.example.test/mcp");
  const factory = createGovernedMcpServerFactory({
    edgeId: "edge-1",
    brokerAudience: "mac-operator-broker",
    resourceServerUrl,
    contracts: await ToolContractRegistry.load(resolve(repositoryRoot, "tool-contracts")),
    gateway
  });
  const authInfo: AuthInfo = {
    token: "must-not-cross-the-edge",
    clientId: "client-1",
    scopes: ["mac.control.read"],
    expiresAt: Math.floor(Date.now() / 1_000) + 60,
    resource: resourceServerUrl,
    extra: {
      principalId: "principal-1",
      issuer: "issuer-1",
      sessionId: "session-1",
      issuedAtMs: Date.now() - 1_000
    }
  };
  const created = await factory({ era: "modern", authInfo });
  assert.ok(created instanceof McpServer);
  assert.notEqual(created.toolInputSchemaJson("mac_health"), undefined);
  assert.equal(created.toolInputSchemaJson("mac_policy_explain"), undefined);
  assert.equal(JSON.stringify(observedPrincipals).includes(authInfo.token), false);
});

test("MCP factory fails closed without verified authentication context", async () => {
  const factory = createGovernedMcpServerFactory({
    edgeId: "edge-1",
    brokerAudience: "mac-operator-broker",
    resourceServerUrl: new URL("https://edge.example.test/mcp"),
    contracts: await ToolContractRegistry.load(resolve(repositoryRoot, "tool-contracts")),
    gateway: { async execute() { throw new Error("must not execute"); } }
  });
  await assert.rejects(async () => { await factory({ era: "modern" }); }, /Authenticated MCP context is required/u);
});

test("MCP gateway errors map to the stable Broker failure envelope", () => {
  assert.deepEqual(mapGatewayError("mac_health", new BrokerError("TIMEOUT", "Broker request timed out", true)), {
    ok: false,
    request_id: "edge-error",
    tool: "mac_health",
    result_class: "TIMEOUT",
    error: { message: "Broker request timed out", retryable: true },
    duration_ms: 0
  });
  assert.deepEqual(mapGatewayError("mac_health", new Error("private transport detail")), {
    ok: false,
    request_id: "edge-error",
    tool: "mac_health",
    result_class: "EXECUTION_FAILED",
    error: { message: "Edge-to-Broker execution failed", retryable: true },
    duration_ms: 0
  });
});
