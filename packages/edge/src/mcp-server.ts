import { BrokerError, CONTRACT_VERSION, isCompatibleVersionPair, isSupportedContractVersion, PROTOCOL_VERSION, SCOPES, type BrokerFailure, type BrokerResult, type BrokerSuccess, type PrincipalContext } from "@mac-operator/contracts";
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
  scopes: readonly string[];
  planned: boolean;
  implemented: boolean;
  enabled: boolean;
  contractVersion: string | null;
}

const CAPABILITY_CACHE_TTL_MS = 30_000;
const MAX_CAPABILITY_CACHE_ENTRIES = 256;

export interface GovernedMcpServerOptions {
  edgeId: string;
  brokerAudience: string;
  resourceServerUrl: URL;
  contracts: ToolContractRegistry;
  gateway: BrokerGateway;
}

export function createGovernedMcpServerFactory(options: GovernedMcpServerOptions): McpServerFactory {
  /**
   * MCP HTTP requests create a fresh server instance. Keep the last verified
   * capability projection per principal/session so a later Broker revocation
   * can reach the requested tool and produce its stable `REVOKED` envelope
   * instead of failing during server construction. Every actual tool call
   * still crosses the Broker and rechecks current authority.
   */
  const capabilityCache = new Map<string, { enabledTools: readonly string[]; expiresAtMs: number }>();
  return async (requestContext) => {
    if (!requestContext.authInfo) throw new Error("Authenticated MCP context is required");
    const principal = projectPrincipal(requestContext.authInfo, options);
    const cacheKey = capabilityCacheKey(principal);
    const cached = capabilityCache.get(cacheKey);
    let enabledTools: readonly string[] | undefined;
    if (cached !== undefined && cached.expiresAtMs > Date.now()) {
      enabledTools = cached.enabledTools;
    } else {
      const capabilities = await options.gateway.execute("mac_capabilities", {}, principal, requestContext.requestInfo?.signal);
      if (capabilities.ok) {
        enabledTools = readEnabledTools(capabilities, options.contracts);
        capabilityCache.set(cacheKey, { enabledTools, expiresAtMs: Date.now() + CAPABILITY_CACHE_TTL_MS });
        while (capabilityCache.size > MAX_CAPABILITY_CACHE_ENTRIES) {
          const oldest = capabilityCache.keys().next().value;
          if (oldest === undefined) break;
          capabilityCache.delete(oldest);
        }
      } else if (cached !== undefined) {
        // Preserve a previously verified projection only as a routing aid;
        // Broker authorization on the actual tool call remains authoritative.
        enabledTools = cached.enabledTools;
      } else {
        if (capabilities.result_class === "REVOKED") {
          throw new BrokerError("REVOKED", "Broker capability discovery was revoked");
        }
        throw new Error(`Broker capability discovery failed: ${capabilities.result_class}`);
      }
    }
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

function capabilityCacheKey(principal: PrincipalContext): string {
  return [principal.edgeId, principal.principalId, principal.sessionId, [...principal.scopes].sort().join(",")].join("\u0000");
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
  if ((toolName === "mac_ui_observe" || toolName === "mac_ui_action") && isPlainDataRecord(result.data) && isPlainDataRecord(result.data.screenshot)) {
    const screenshot = result.data.screenshot;
    if (screenshot.mime_type === "image/jpeg" && typeof screenshot.image_base64 === "string") {
      const { image_base64: imageData, ...metadata } = screenshot;
      const safeResult = { ...result, data: { ...result.data, screenshot: metadata } };
      return {
        content: [
          { type: "text" as const, text: JSON.stringify(safeResult) },
          { type: "image" as const, data: imageData, mimeType: "image/jpeg" as const }
        ],
        structuredContent: safeResult as BrokerSuccess & Record<string, unknown>
      };
    }
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
  if (!isCompatibleVersionPair("capability_discovery", data.protocol_version, data.contract_version)) {
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
    if (JSON.stringify(item.scopes) !== JSON.stringify(contract.requiredScopes)) {
      throw new Error(`Broker capability scopes are incompatible for ${item.name}`);
    }
    if (!item.enabled) continue;
    if (!item.planned || !item.implemented) {
      throw new Error(`Broker capability state is inconsistent for ${item.name}`);
    }
    if (item.contractVersion !== contract.schemaVersion || !isSupportedContractVersion(item.contractVersion)) {
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
  const allowedKeys = new Set(["contract_version", "enabled", "implemented", "name", "planned", "reason", "scopes"]);
  const requiredKeys = ["contract_version", "enabled", "implemented", "name", "planned", "scopes"];
  if (keys.length < requiredKeys.length || keys.length > allowedKeys.size || keys.some((key) => !allowedKeys.has(key)) ||
      requiredKeys.some((key) => !Object.prototype.hasOwnProperty.call(record, key)) ||
      typeof record.name !== "string" || record.name.length < 1 || record.name.length > 128 ||
      !/^mac_[a-z0-9_]+$/u.test(record.name) || typeof record.planned !== "boolean" ||
      typeof record.implemented !== "boolean" || typeof record.enabled !== "boolean" ||
      (record.contract_version !== null && (typeof record.contract_version !== "string" || record.contract_version.length > 64)) ||
      (!isPlainDataArray(record.scopes, SCOPES.length) || record.scopes.length < 1 ||
        new Set(record.scopes).size !== record.scopes.length ||
        record.scopes.some((scope) => typeof scope !== "string" || !SCOPES.includes(scope as typeof SCOPES[number]))) ||
      (record.reason !== undefined && (typeof record.reason !== "string" || record.reason.length > 128))) {
    throw new Error("Broker capability item is malformed");
  }
  return {
    name: record.name,
    scopes: record.scopes as string[],
    planned: record.planned,
    implemented: record.implemented,
    enabled: record.enabled,
    contractVersion: record.contract_version as string | null
  };
}
