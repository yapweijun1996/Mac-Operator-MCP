import { createServer, type Server as HttpsServer } from "node:https";
import type { NextFunction, Request, Response } from "express";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { BrokerError, O1_SCOPES, ownerTerminalOAuthContext, SCOPES } from "@mac-operator/contracts";
import {
  createMcpExpressApp,
  getOAuthProtectedResourceMetadataUrl,
  requireBearerAuth,
  type OAuthTokenVerifier
} from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import {
  buildOAuthProtectedResourceMetadata,
  classifyInboundRequest,
  createMcpHandler,
  PROTOCOL_VERSION_META_KEY,
  type McpHttpHandler,
  type OAuthMetadata
} from "@modelcontextprotocol/server";
import type { GovernedMcpServerOptions } from "./mcp-server.js";
import { createGovernedMcpServerFactory } from "./mcp-server.js";
import { projectPrincipal } from "./principal.js";
import { FixedWindowRateLimiter, rateLimitKey, type RateLimitOptions } from "./rate-limiter.js";
import { isPlainDataArray, isPlainDataRecord } from "./plain-record.js";

const EDGE_REQUEST_TIMEOUT_MS = 30_000;
const EDGE_HEADERS_TIMEOUT_MS = 10_000;
const EDGE_KEEP_ALIVE_TIMEOUT_MS = 5_000;
const EDGE_MAX_REQUESTS_PER_SOCKET = 100;
const OWNER_TERMINAL_LEGACY_PROTOCOL = "2025-06-18";

interface AdditionalMcpEndpoint extends Pick<HttpsMcpEdgeOptions,
  "resourceServerUrl" | "oauthIssuer" | "tokenVerifier" | "oauthMetadata"> {
  /** Compatibility is restricted to the independent owner terminal resource. */
  legacyProtocol?: typeof OWNER_TERMINAL_LEGACY_PROTOCOL;
}

export interface HttpsMcpEdgeOptions extends GovernedMcpServerOptions {
  bindHost: string;
  allowedHosts: string[];
  allowedOrigins: string[];
  tlsCertificate: Buffer | string;
  tlsPrivateKey: Buffer | string;
  /** The authorization-server issuer must match oauthMetadata.issuer exactly. */
  oauthIssuer: URL;
  tokenVerifier: OAuthTokenVerifier;
  oauthMetadata: OAuthMetadata;
  /** Scopes required to initialize this MCP endpoint. Individual tools still enforce their own scopes. */
  requiredScopes?: string[];
  rateLimit?: RateLimitOptions;
  /** Separate OAuth resources use separate SDK handlers and bearer verifiers. */
  additionalEndpoints?: AdditionalMcpEndpoint[];
}

export interface HttpsMcpEdge {
  server: HttpsServer;
  handler: McpHttpHandler;
  close(): Promise<void>;
}

export function createHttpsMcpEdge(options: HttpsMcpEdgeOptions): HttpsMcpEdge {
  const validated = validateOptions(options);
  const app = createMcpExpressApp({
    host: options.bindHost,
    allowedHosts: validated.allowedHosts,
    allowedOrigins: validated.allowedOrigins,
    jsonLimit: "1mb"
  });
  app.disable("x-powered-by");
  const primary = options;
  if ("legacyProtocol" in primary) throw new Error("Primary MCP endpoint cannot enable legacy compatibility");
  const handlers: McpHttpHandler[] = [];
  const endpoints = [{ options: primary, legacyProtocol: undefined }, ...(primary.additionalEndpoints ?? []).map(endpoint => ({
    options: { ...primary, ...endpoint }, legacyProtocol: endpoint.legacyProtocol
  }))];
  if (new Set(endpoints.map(endpoint => endpoint.options.resourceServerUrl.pathname)).size !== endpoints.length ||
      new Set(endpoints.map(endpoint => endpoint.options.oauthIssuer.href)).size !== endpoints.length) {
    throw new Error("OAuth endpoint resources and issuers must be distinct");
  }
  for (const { options, legacyProtocol } of endpoints) {
    const validated = validateOptions(options);
    if (legacyProtocol !== undefined) validateOwnerTerminalCompatibility(primary, options, legacyProtocol);
    const metadataOptions = {
      oauthMetadata: options.oauthMetadata,
      resourceServerUrl: options.resourceServerUrl,
      scopesSupported: options.oauthMetadata.scopes_supported ?? [...SCOPES],
      resourceName: "Mac-Operator-MCP"
    };
    const serveResourceMetadata = (_request: Request, response: Response) => {
      response.setHeader("Cache-Control", "no-store");
      response.json(buildOAuthProtectedResourceMetadata(metadataOptions));
    };
    if (options.resourceServerUrl.href === primary.resourceServerUrl.href) {
      app.get("/.well-known/oauth-protected-resource", serveResourceMetadata);
    }
    app.get(new URL(getOAuthProtectedResourceMetadataUrl(options.resourceServerUrl)).pathname, serveResourceMetadata);
    const issuerPath = options.oauthIssuer.pathname.replace(/\/$/u, "");
    app.get(`/.well-known/oauth-authorization-server${issuerPath}`, (_request, response) => {
      response.setHeader("Cache-Control", "no-store");
      response.json(options.oauthMetadata);
    });

    const handler = createMcpHandler(createGovernedMcpServerFactory(options), {
      legacy: legacyProtocol === undefined ? "reject" : "stateless",
      responseMode: "json"
    });
    handlers.push(handler);
    const nodeHandler = toNodeHandler(handler);
    const bearerAuth = requireBearerAuth({
      verifier: options.tokenVerifier,
      requiredScopes: validated.requiredScopes,
      resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(options.resourceServerUrl)
    });
    const rateLimiter = new FixedWindowRateLimiter(options.rateLimit);
    app.all(options.resourceServerUrl.pathname, (_request: Request, response: Response, next: NextFunction) => {
      response.setHeader("Cache-Control", "no-store");
      next();
    }, (_request: Request, response: Response, next: NextFunction) => {
      advertiseFullScopesOnChallenge(response, metadataOptions.scopesSupported);
      next();
    }, bearerAuth, (request: Request, response: Response, next: NextFunction) => {
      const auth = (request as Request & { auth?: AuthInfo }).auth;
      const identity = auth?.clientId ?? readPrincipalId(auth) ?? "authenticated";
      const decision = rateLimiter.consume(rateLimitKey(identity));
      if (!decision.allowed) {
        response.setHeader("Retry-After", String(Math.max(1, Math.ceil(decision.retryAfterMs / 1_000))));
        response.status(429).json({ error: "rate_limit_exceeded" });
        return;
      }
      void (async () => {
        if (legacyProtocol !== undefined && !validateOwnerTerminalRequest(request, response)) return;
        // The MCP SDK deliberately converts factory failures to an internal
        // JSON-RPC error. Probe only a session-less session-start request so a
        // Broker revocation remains a stable authorization response at the
        // HTTPS boundary; all other requests still use the SDK handler.
        if (isSessionStartRequest(request)) {
          const auth = (request as Request & { auth?: AuthInfo }).auth;
          if (auth) {
            try {
              const principal = projectPrincipal(auth, options);
              const capabilities = await options.gateway.execute("mac_capabilities", {}, principal);
              if (!capabilities.ok && capabilities.result_class === "REVOKED") {
                response.status(403).json({ error: "revoked", result_class: "REVOKED" });
                return;
              }
            } catch (error) {
              if (error instanceof BrokerError && error.errorClass === "REVOKED") {
                response.status(403).json({ error: "revoked", result_class: "REVOKED" });
                return;
              }
              next(error);
              return;
            }
          }
        }
        await nodeHandler(request, response, request.body);
      })().catch(next);
    });
  }
  app.use((error: unknown, _request: Request, response: Response, _next: NextFunction) => {
    if (response.headersSent) {
      response.end();
      return;
    }
    const bodyFailure = classifyJsonBodyFailure(error);
    if (bodyFailure !== undefined) {
      response.status(bodyFailure.status).json({ error: bodyFailure.error });
      return;
    }
    response.status(500).json({ error: "internal_server_error" });
  });

  const server = createServer({
    cert: options.tlsCertificate,
    key: options.tlsPrivateKey,
    minVersion: "TLSv1.3"
  }, app);
  server.requestTimeout = EDGE_REQUEST_TIMEOUT_MS;
  server.headersTimeout = EDGE_HEADERS_TIMEOUT_MS;
  server.keepAliveTimeout = EDGE_KEEP_ALIVE_TIMEOUT_MS;
  server.maxRequestsPerSocket = EDGE_MAX_REQUESTS_PER_SOCKET;
  return {
    server,
    handler: handlers[0]!,
    async close() {
      await Promise.all(handlers.map(handler => handler.close()));
      if (!server.listening) return;
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  };
}

function validateOwnerTerminalCompatibility(primary: HttpsMcpEdgeOptions, endpoint: HttpsMcpEdgeOptions, protocol: string): void {
  const terminal = ownerTerminalOAuthContext(primary.oauthIssuer);
  const scopes = endpoint.oauthMetadata.scopes_supported ?? [];
  if (protocol !== OWNER_TERMINAL_LEGACY_PROTOCOL ||
      primary.resourceServerUrl.href !== new URL("mcp", primary.oauthIssuer).href ||
      endpoint.resourceServerUrl.href !== terminal.resource.href || endpoint.oauthIssuer.href !== terminal.issuer.href ||
      scopes.length !== O1_SCOPES.length || new Set(scopes).size !== scopes.length ||
      scopes.some(scope => !O1_SCOPES.includes(scope as typeof O1_SCOPES[number]))) {
    throw new Error("Legacy compatibility requires the exact independent owner terminal resource and O1 profile");
  }
}

function validateOwnerTerminalRequest(request: Request, response: Response): boolean {
  if (request.method !== "POST") return true;
  const body = request.body;
  const id = isPlainDataRecord(body) && (typeof body.id === "string" || typeof body.id === "number") ? body.id : null;
  const reject = (message: string): false => {
    response.status(400).json({ jsonrpc: "2.0", id, error: { code: -32600, message } });
    return false;
  };
  // A single HTTP request must not bypass per-request admission/rate limits.
  if (Array.isArray(request.body)) return reject("MCP batches are not supported");
  const protocol = request.get("MCP-Protocol-Version");
  const method = request.get("Mcp-Method");
  const name = request.get("Mcp-Name");
  const route = classifyInboundRequest({ httpMethod: request.method, body: request.body,
    ...(protocol === undefined ? {} : { protocolVersionHeader: protocol }),
    ...(method === undefined ? {} : { mcpMethodHeader: method }),
    ...(name === undefined ? {} : { mcpNameHeader: name }) });
  if (route.kind === "reject") {
    response.status(route.httpStatus).json({ jsonrpc: "2.0", id,
      error: { code: route.code, message: route.message } });
    return false;
  }
  if (route.kind === "modern") return true;
  if (isPlainDataRecord(body) && body.method === "initialize") {
    // The SDK classifies malformed modern initialization envelopes as legacy.
    // An explicit modern claim must never gain the legacy compatibility path.
    if (isPlainDataRecord(body.params) && isPlainDataRecord(body.params._meta) &&
        Object.hasOwn(body.params._meta, PROTOCOL_VERSION_META_KEY)) {
      return reject("Invalid modern initialization envelope");
    }
    if (!isPlainDataRecord(body.params) || body.params.protocolVersion !== OWNER_TERMINAL_LEGACY_PROTOCOL ||
        (protocol !== undefined && protocol !== OWNER_TERMINAL_LEGACY_PROTOCOL)) {
      return reject("Unsupported owner terminal protocol version");
    }
  } else if (protocol !== OWNER_TERMINAL_LEGACY_PROTOCOL) {
    return reject("Owner terminal requests require the negotiated MCP-Protocol-Version");
  }
  return true;
}

/**
 * The SDK derives the 401 challenge scope from requiredScopes, the minimum needed to
 * initialize. Clients such as Claude request exactly the challenged scope, so a profile
 * above the minimum (W1/G1) would never be offered its write or GUI scopes. Rewrite only
 * missing/invalid-token challenges; insufficient_scope keeps the minimum.
 */
function advertiseFullScopesOnChallenge(response: Response, scopesSupported: readonly string[]): void {
  if (scopesSupported.length === 0) return;
  const setHeader = response.setHeader.bind(response);
  response.setHeader = ((name: string, value: number | string | readonly string[]) => {
    if (name.toLowerCase() === "www-authenticate" && typeof value === "string" && !value.includes('error="insufficient_scope"')) {
      return setHeader(name, value.replace(/scope="[^"]*"/u, `scope="${scopesSupported.join(" ")}"`));
    }
    return setHeader(name, value);
  }) as Response["setHeader"];
}

function hasMcpSessionId(request: Request): boolean {
  const value = request.headers["mcp-session-id"];
  return typeof value === "string" ? value.length > 0 : Array.isArray(value) && value.length > 0;
}

function isSessionStartRequest(request: Request): boolean {
  if (request.method?.toUpperCase() !== "POST" || hasMcpSessionId(request) || !isPlainDataRecord(request.body)) return false;
  const method = request.body.method;
  return method === "initialize" || method === "server/discover";
}

function readPrincipalId(auth: AuthInfo | undefined): string | undefined {
  const value = auth?.extra?.principalId;
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value) ? value : undefined;
}

function validateOptions(options: HttpsMcpEdgeOptions): {
  allowedHosts: string[];
  allowedOrigins: string[];
  oauthIssuer: URL;
  requiredScopes: string[];
} {
  if (typeof options.bindHost !== "string" || options.bindHost.length === 0 || options.bindHost.includes("\0")) {
    throw new Error("MCP bind host must be a non-empty safe hostname");
  }
  validateHttpsUrl(options.resourceServerUrl, "MCP resource server URL");
  if (!options.resourceServerUrl.pathname.startsWith("/") || options.resourceServerUrl.pathname === "/") {
    throw new Error("MCP resource server URL must use a dedicated path");
  }
  if (options.resourceServerUrl.hostname.length === 0) {
    throw new Error("MCP resource server URL must include a hostname");
  }
  const allowedHosts = validateHostnameList(options.allowedHosts, "MCP Host");
  const allowedOrigins = validateHostnameList(options.allowedOrigins, "MCP Origin");
  if (!allowedHosts.includes(options.resourceServerUrl.hostname.toLowerCase())) {
    throw new Error("MCP Host allowlist must include the public resource hostname");
  }
  if (!hasTlsMaterial(options.tlsCertificate) || !hasTlsMaterial(options.tlsPrivateKey)) {
    throw new Error("MCP TLS certificate and private key must not be empty");
  }
  const oauthIssuer = validateHttpsUrl(options.oauthIssuer, "MCP OAuth issuer URL");
  const metadataIssuer = validateHttpsUrl(options.oauthMetadata.issuer, "MCP OAuth metadata issuer URL");
  if (metadataIssuer.href !== oauthIssuer.href) {
    throw new Error("MCP OAuth metadata issuer must match the configured issuer");
  }
  validateHttpsUrl(options.oauthMetadata.authorization_endpoint, "MCP OAuth authorization endpoint");
  validateHttpsUrl(options.oauthMetadata.token_endpoint, "MCP OAuth token endpoint");
  const requiredScopes = options.requiredScopes ?? ["mac.control.read"];
  if (!isPlainDataArray(requiredScopes, SCOPES.length) || requiredScopes.length === 0 ||
      new Set(requiredScopes).size !== requiredScopes.length ||
      requiredScopes.some(scope => typeof scope !== "string" || !(SCOPES as readonly string[]).includes(scope))) {
    throw new Error("MCP required scopes are invalid");
  }
  return { allowedHosts, allowedOrigins, oauthIssuer, requiredScopes: [...requiredScopes] };
}

function validateHttpsUrl(value: unknown, label: string): URL {
  let parsed: URL;
  try {
    parsed = value instanceof URL ? new URL(value.href) : new URL(String(value));
  } catch {
    throw new Error(`${label} must be a valid HTTPS URL`);
  }
  if (parsed.protocol !== "https:") throw new Error(`${label} must use HTTPS`);
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error(`${label} must be an HTTPS URL without credentials, query, or fragment`);
  }
  return parsed;
}

function validateHostnameList(values: string[], label: string): string[] {
  if (!isPlainDataArray(values, 64) || values.length === 0) throw new Error(`${label} allowlist must not be empty`);
  const normalized = values.map((value) => {
    if (typeof value !== "string" || value.length === 0 || value !== value.trim() || value.includes("\0")) {
      throw new Error(`${label} allowlist contains an invalid hostname`);
    }
    let parsed: URL;
    try {
      parsed = new URL(`https://${value}`);
    } catch {
      throw new Error(`${label} allowlist contains an invalid hostname`);
    }
    if (
      parsed.hostname.length === 0 ||
      parsed.hostname !== value.toLowerCase() ||
      parsed.username ||
      parsed.password ||
      parsed.port ||
      parsed.pathname !== "/" ||
      parsed.search ||
      parsed.hash
    ) {
      throw new Error(`${label} allowlist contains an invalid hostname`);
    }
    return parsed.hostname;
  });
  return [...new Set(normalized)].sort();
}

function hasTlsMaterial(value: Buffer | string): boolean {
  return Buffer.isBuffer(value) ? value.byteLength > 0 : typeof value === "string" && value.length > 0;
}

function classifyJsonBodyFailure(error: unknown): { status: 400 | 413; error: "invalid_json" | "request_too_large" } | undefined {
  if (error === null || typeof error !== "object") return undefined;
  const type = (error as { type?: unknown }).type;
  if (type === "entity.too.large") return { status: 413, error: "request_too_large" };
  if (type === "entity.parse.failed") return { status: 400, error: "invalid_json" };
  return undefined;
}
