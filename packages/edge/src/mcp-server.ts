import { BrokerError, type BrokerFailure, type BrokerResult, type BrokerSuccess, type PrincipalContext } from "@mac-operator/contracts";
import {
  McpServer,
  fromJsonSchema,
  type McpServerFactory,
  type ServerContext
} from "@modelcontextprotocol/server";
import type { ToolContractRegistry } from "./contract-registry.js";
import type { BrokerGateway } from "./gateway.js";
import { projectPrincipal } from "./principal.js";

interface CapabilityState {
  name: string;
  enabled: boolean;
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
    const enabledTools = readEnabledTools(capabilities);
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

function readEnabledTools(result: BrokerSuccess): string[] {
  if (result.data === null || typeof result.data !== "object" || Array.isArray(result.data)) {
    throw new Error("Broker capability response data is malformed");
  }
  const capabilities = (result.data as Record<string, unknown>).capabilities;
  if (!Array.isArray(capabilities)) throw new Error("Broker capability response list is malformed");
  const parsed = capabilities.map(parseCapability);
  return [...new Set(parsed.filter((item) => item.enabled).map((item) => item.name))].sort();
}

function parseCapability(value: unknown): CapabilityState {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Broker capability item is malformed");
  }
  const record = value as Record<string, unknown>;
  if (typeof record.name !== "string" || typeof record.enabled !== "boolean") {
    throw new Error("Broker capability item is malformed");
  }
  return { name: record.name, enabled: record.enabled };
}
