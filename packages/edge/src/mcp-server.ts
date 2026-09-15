import { BrokerError, CONTRACT_VERSION, PROTOCOL_VERSION, type BrokerFailure, type BrokerResult, type BrokerSuccess, type PrincipalContext } from "@mac-operator/contracts";
import {
  McpServer,
  fromJsonSchema,
  type McpServerFactory,
  type ServerContext
} from "@modelcontextprotocol/server";
import type { ToolContractRegistry } from "./contract-registry.js";
import type { BrokerGateway } from "./gateway.js";
import { projectPrincipal } from "./principal.js";
import { isPlainDataArray, isPlainDataRecord } from "./plain-record.js";

interface CapabilityState {
  name: string;
  planned: boolean;
  implemented: boolean;
  enabled: boolean;
  contractVersion: string | null;
}

export interface GovernedMcpServerOptions {
  edgeId: string;
  brokerAudience: string;
  resourceServerUrl: URL;
  contracts: ToolContractRegistry;
  gateway: BrokerGateway;
}

export function createGovernedMcpServerFactory(options: GovernedMcpServerOptions): McpServerFactory {
  return async (requestContext) => {
    if (!requestContext.authInfo) throw new Error("Authenticated MCP context is required");
    const principal = projectPrincipal(requestContext.authInfo, options);
    const capabilities = await options.gateway.execute("mac_capabilities", {}, principal, requestContext.requestInfo?.signal);
    if (!capabilities.ok) throw new Error(`Broker capability discovery failed: ${capabilities.result_class}`);
    const enabledTools = readEnabledTools(capabilities, options.contracts);
    const server = new McpServer({ name: "Mac-Operator-MCP", version: "0.1.0" });
    for (const toolName of enabledTools) {
      const contract = options.contracts.get(toolName);
      if (!contract) continue;
      server.registerTool(
        toolName,
        {
          description: contract.purpose,
          inputSchema: fromJsonSchema<Record<string, unknown>>(contract.inputSchema),
          outputSchema: fromJsonSchema<Record<string, unknown>>(contract.outputSchema),
          annotations: {
            readOnlyHint: contract.safetyClass === "read_only",
            destructiveHint: contract.safetyClass === "destructive",
            idempotentHint: contract.idempotent,
            openWorldHint: contract.networkPolicy !== "none"
          }
        },
        async (argumentsValue, toolContext) => executeTool(
          options.gateway,
          toolName,
          argumentsValue,
          principal,
          toolContext
        )
      );
    }
    return server;
  };
}

async function executeTool(
  gateway: BrokerGateway,
  toolName: string,
  argumentsValue: Record<string, unknown>,
  principal: PrincipalContext,
  context: ServerContext
) {
  let result: BrokerResult;
  try {
    result = await gateway.execute(toolName, argumentsValue, principal, context.mcpReq.signal);
  } catch (error) {
    result = mapGatewayError(toolName, error);
  }
  if (!result.ok) {
    return {
      isError: true as const,
      content: [{ type: "text" as const, text: JSON.stringify(result) }]
    };
  }
  return {
    content: [{ type: "text" as const, text: JSON.stringify(result) }],
    structuredContent: result as BrokerSuccess & Record<string, unknown>
  };
}

export function mapGatewayError(tool: string, error: unknown): BrokerFailure {
  if (error instanceof BrokerError) {
    return {
      ok: false,
      request_id: "edge-error",
      tool,
      result_class: error.errorClass,
      error: { message: error.message, retryable: error.retryable },
      duration_ms: 0
    };
  }
  return {
    ok: false,
    request_id: "edge-error",
    tool,
    result_class: "EXECUTION_FAILED",
    error: { message: "Edge-to-Broker execution failed", retryable: true },
    duration_ms: 0
  };
}

function readEnabledTools(result: BrokerSuccess, contracts: ToolContractRegistry): string[] {
  if (!isPlainDataRecord(result.data)) {
    throw new Error("Broker capability response data is malformed");
  }
  const capabilities = result.data.capabilities;
  if (!isPlainDataArray(capabilities, 128)) throw new Error("Broker capability response list is malformed");
  const data = result.data;
  if (data.protocol_version !== PROTOCOL_VERSION || data.contract_version !== CONTRACT_VERSION) {
    throw new Error("Broker capability response version is incompatible");
  }
  const parsed = capabilities.map(parseCapability);
  const enabled: string[] = [];
  const seen = new Set<string>();
  for (const item of parsed) {
    if (seen.has(item.name)) {
      throw new Error(`Broker capability list contains a duplicate: ${item.name}`);
    }
    seen.add(item.name);
    const contract = contracts.get(item.name);
    if (!contract) {
      throw new Error(`Broker capability is not registered: ${item.name}`);
    }
    if (!item.enabled) continue;
    if (!item.planned || !item.implemented) {
      throw new Error(`Broker capability state is inconsistent for ${item.name}`);
    }
    if (item.contractVersion !== contract.schemaVersion || item.contractVersion !== CONTRACT_VERSION) {
      throw new Error(`Broker capability contract version is incompatible for ${item.name}`);
    }
    enabled.push(item.name);
  }
  return [...new Set(enabled)].sort();
}

function parseCapability(value: unknown): CapabilityState {
  if (!isPlainDataRecord(value)) {
    throw new Error("Broker capability item is malformed");
  }
  const record = value;
  const keys = Object.keys(record).sort();
  if (keys.length !== 5 || keys.join(",") !== "contract_version,enabled,implemented,name,planned" ||
      typeof record.name !== "string" || record.name.length < 1 || record.name.length > 128 ||
      !/^mac_[a-z0-9_]+$/u.test(record.name) || typeof record.planned !== "boolean" ||
      typeof record.implemented !== "boolean" || typeof record.enabled !== "boolean" ||
      (record.contract_version !== null && (typeof record.contract_version !== "string" || record.contract_version.length > 64))) {
    throw new Error("Broker capability item is malformed");
  }
  return {
    name: record.name,
    planned: record.planned,
    implemented: record.implemented,
    enabled: record.enabled,
    contractVersion: record.contract_version as string | null
  };
}
