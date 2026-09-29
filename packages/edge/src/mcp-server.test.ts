import assert from "node:assert/strict";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { BrokerError, type BrokerResult, type PrincipalContext } from "@mac-operator/contracts";
import { InMemoryTransport, McpServer, type AuthInfo } from "@modelcontextprotocol/server";
import { Client } from "@modelcontextprotocol/client";
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
          protocol_version: "0.1",
          contract_version: "0.1",
          capabilities: [
            { name: "mac_health", scopes: ["mac.control.read"], planned: true, implemented: true, enabled: true, contract_version: "0.1" },
            { name: "mac_policy_explain", scopes: ["mac.policy.explain"], planned: true, implemented: true, enabled: false, contract_version: "0.1" }
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

test("MCP client receives browser screenshots as image content without duplicate structured image data", async () => {
  const imageData = Buffer.concat([Buffer.from([0xff, 0xd8]), Buffer.alloc(100, 0), Buffer.from([0xff, 0xd9])]).toString("base64");
  const resourceServerUrl = new URL("https://edge.example.test/mcp");
  const gateway: BrokerGateway = {
    async execute(tool): Promise<BrokerResult> {
      if (tool === "mac_capabilities") return {
        ok: true, request_id: "capability-request", tool, result_class: "SUCCEEDED",
        data: { protocol_version: "0.1", contract_version: "0.1", capabilities: [
          { name: "mac_ui_observe", scopes: ["mac.ui.observe"], planned: true, implemented: true,
            enabled: true, contract_version: "0.1" }
        ] }, warnings: [], truncated: false, verification: {}, duration_ms: 1
      };
      assert.equal(tool, "mac_ui_observe");
      return {
        ok: true, request_id: "observe-request", tool, result_class: "SUCCEEDED",
        data: { app_id: "bundle:com.google.Chrome", window_id: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
          window_title: "Example Domain", focused: true, nodes: [], truncated: false,
          screenshot: { mode: "active_window", mime_type: "image/jpeg", image_base64: imageData,
            screen_width: 800, screen_height: 600, window_x: 0, window_y: 0, window_width: 800,
            window_height: 600, capture_width: 1600, capture_height: 1200, image_width: 1600, image_height: 1200 } },
        warnings: [], truncated: false,
        verification: { required: false, status: "not_required", strategy: "accessibility_snapshot_validation" }, duration_ms: 1
      };
    }
  };
  const factory = createGovernedMcpServerFactory({ edgeId: "edge-1", brokerAudience: "mac-operator-broker",
    resourceServerUrl, contracts: await ToolContractRegistry.load(resolve(repositoryRoot, "tool-contracts")), gateway });
  const authInfo: AuthInfo = { token: "test-token", clientId: "client-1", scopes: ["mac.ui.observe"],
    expiresAt: Math.floor(Date.now() / 1000) + 60, resource: resourceServerUrl,
    extra: { principalId: "owner", issuer: "issuer-1", sessionId: "session-1", issuedAtMs: Date.now() - 1000 } };
  const server = await factory({ era: "modern", authInfo });
  const client = new Client({ name: "visual-test", version: "1.0.0" }, { capabilities: {} });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const result = await client.callTool({ name: "mac_ui_observe", arguments: { app_id: "bundle:com.google.Chrome" } });
    assert.equal(result.isError, undefined);
    assert.equal(result.content[1]?.type, "image");
    assert.equal(result.content[1]?.type === "image" ? result.content[1].data : undefined, imageData);
    assert.equal(JSON.stringify(result.structuredContent).includes(imageData), false);
    assert.equal(result.content[0]?.type === "text" ? result.content[0].text.includes(imageData) : true, false);
  } finally {
    await client.close();
    await server.close();
  }
});

test("MCP factory rejects an enabled Broker capability with an incompatible contract version", async () => {
  const resourceServerUrl = new URL("https://edge.example.test/mcp");
  const factory = createGovernedMcpServerFactory({
    edgeId: "edge-1",
    brokerAudience: "mac-operator-broker",
    resourceServerUrl,
    contracts: await ToolContractRegistry.load(resolve(repositoryRoot, "tool-contracts")),
    gateway: {
      async execute(): Promise<BrokerResult> {
        return {
          ok: true,
          request_id: "capability-request",
          tool: "mac_capabilities",
          result_class: "SUCCEEDED",
          data: {
            protocol_version: "0.1",
            contract_version: "0.1",
            capabilities: [{ name: "mac_health", scopes: ["mac.control.read"], planned: true, implemented: true, enabled: true, contract_version: "9.9" }]
          },
          warnings: [],
          truncated: false,
          verification: {},
          duration_ms: 1
        };
      }
    }
  });
  await assert.rejects(
    Promise.resolve(factory({
      era: "modern",
      authInfo: {
        token: "test-token",
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
      }
    })),
    /contract version is incompatible/u
  );
});

test("MCP factory rejects Broker capability scopes that drift from the contract", async () => {
  const resourceServerUrl = new URL("https://edge.example.test/mcp");
  const factory = createGovernedMcpServerFactory({
    edgeId: "edge-1",
    brokerAudience: "mac-operator-broker",
    resourceServerUrl,
    contracts: await ToolContractRegistry.load(resolve(repositoryRoot, "tool-contracts")),
    gateway: {
      async execute(): Promise<BrokerResult> {
        return {
          ok: true,
          request_id: "capability-request",
          tool: "mac_capabilities",
          result_class: "SUCCEEDED",
          data: {
            protocol_version: "0.1",
            contract_version: "0.1",
            capabilities: [{ name: "mac_health", scopes: ["mac.files.read"], planned: true, implemented: true, enabled: true, contract_version: "0.1" }]
          },
          warnings: [],
          truncated: false,
          verification: {},
          duration_ms: 1
        };
      }
    }
  });
  await assert.rejects(
    Promise.resolve(factory({
      era: "modern",
      authInfo: {
        token: "test-token",
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
      }
    })),
    /capability scopes are incompatible/u
  );
});

test("MCP factory rejects an enabled capability with an incomplete runtime state", async () => {
  const resourceServerUrl = new URL("https://edge.example.test/mcp");
  const factory = createGovernedMcpServerFactory({
    edgeId: "edge-1",
    brokerAudience: "mac-operator-broker",
    resourceServerUrl,
    contracts: await ToolContractRegistry.load(resolve(repositoryRoot, "tool-contracts")),
    gateway: {
      async execute(): Promise<BrokerResult> {
        return {
          ok: true,
          request_id: "capability-request",
          tool: "mac_capabilities",
          result_class: "SUCCEEDED",
          data: {
            protocol_version: "0.1",
            contract_version: "0.1",
            capabilities: [{ name: "mac_health", scopes: ["mac.control.read"], planned: true, implemented: false, enabled: true, contract_version: "0.1" }]
          },
          warnings: [],
          truncated: false,
          verification: {},
          duration_ms: 1
        };
      }
    }
  });
  await assert.rejects(
    Promise.resolve(factory({
      era: "modern",
      authInfo: {
        token: "test-token",
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
      }
    })),
    /capability state is inconsistent/u
  );
});

test("MCP factory rejects duplicate or unknown capability entries", async () => {
  const resourceServerUrl = new URL("https://edge.example.test/mcp");
  const contracts = await ToolContractRegistry.load(resolve(repositoryRoot, "tool-contracts"));
  const authContext = {
    era: "modern" as const,
    authInfo: {
      token: "test-token",
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
    }
  };
  const valid = { name: "mac_health", scopes: ["mac.control.read"], planned: true, implemented: true, enabled: false, contract_version: "0.1" };
  const duplicateFactory = createGovernedMcpServerFactory({
    edgeId: "edge-1", brokerAudience: "mac-operator-broker", resourceServerUrl, contracts,
    gateway: { async execute() {
      return {
        ok: true, request_id: "capability-request", tool: "mac_capabilities", result_class: "SUCCEEDED",
        data: { protocol_version: "0.1", contract_version: "0.1", capabilities: [valid, valid] },
        warnings: [], truncated: false, verification: {}, duration_ms: 1
      };
    } }
  });
  await assert.rejects(Promise.resolve(duplicateFactory(authContext)), /duplicate/u);

  const unknownFactory = createGovernedMcpServerFactory({
    edgeId: "edge-1", brokerAudience: "mac-operator-broker", resourceServerUrl, contracts,
    gateway: { async execute() {
      return {
        ok: true, request_id: "capability-request", tool: "mac_capabilities", result_class: "SUCCEEDED",
        data: { protocol_version: "0.1", contract_version: "0.1", capabilities: [{ ...valid, name: "mac_unknown" }] },
        warnings: [], truncated: false, verification: {}, duration_ms: 1
      };
    } }
  });
  await assert.rejects(Promise.resolve(unknownFactory(authContext)), /not registered/u);
});

test("MCP factory rejects non-data capability envelopes", async () => {
  const resourceServerUrl = new URL("https://edge.example.test/mcp");
  const contracts = await ToolContractRegistry.load(resolve(repositoryRoot, "tool-contracts"));
  const authContext = {
    era: "modern" as const,
    authInfo: {
      token: "test-token",
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
    }
  };
  const accessorCapability = {
    name: "mac_health",
    scopes: ["mac.control.read"],
    planned: true,
    implemented: true,
    enabled: false,
    contract_version: "0.1"
  } as Record<string, unknown>;
  Object.defineProperty(accessorCapability, "name", { enumerable: true, get: () => "mac_health" });
  const accessorFactory = createGovernedMcpServerFactory({
    edgeId: "edge-1", brokerAudience: "mac-operator-broker", resourceServerUrl, contracts,
    gateway: { async execute() {
      return {
        ok: true, request_id: "capability-request", tool: "mac_capabilities", result_class: "SUCCEEDED",
        data: { protocol_version: "0.1", contract_version: "0.1", capabilities: [accessorCapability] },
        warnings: [], truncated: false, verification: {}, duration_ms: 1
      };
    } }
  });
  await assert.rejects(Promise.resolve(accessorFactory(authContext)), /capability item is malformed/u);

  const sparseCapabilities = new Array(1);
  const sparseFactory = createGovernedMcpServerFactory({
    edgeId: "edge-1", brokerAudience: "mac-operator-broker", resourceServerUrl, contracts,
    gateway: { async execute() {
      return {
        ok: true, request_id: "capability-request", tool: "mac_capabilities", result_class: "SUCCEEDED",
        data: { protocol_version: "0.1", contract_version: "0.1", capabilities: sparseCapabilities },
        warnings: [], truncated: false, verification: {}, duration_ms: 1
      };
    } }
  });
  await assert.rejects(Promise.resolve(sparseFactory(authContext)), /capability response list is malformed/u);
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
