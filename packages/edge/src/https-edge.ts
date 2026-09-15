import { createServer, type Server as HttpsServer } from "node:https";
import type { NextFunction, Request, Response } from "express";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { SCOPES } from "@mac-operator/contracts";
import {
  createMcpExpressApp,
  getOAuthProtectedResourceMetadataUrl,
  mcpAuthMetadataRouter,
  requireBearerAuth,
  type OAuthTokenVerifier
} from "@modelcontextprotocol/express";
import { toNodeHandler } from "@modelcontextprotocol/node";
import {
  createMcpHandler,
  type McpHttpHandler,
  type OAuthMetadata
} from "@modelcontextprotocol/server";
import type { GovernedMcpServerOptions } from "./mcp-server.js";
import { createGovernedMcpServerFactory } from "./mcp-server.js";
import { FixedWindowRateLimiter, type RateLimitOptions } from "./rate-limiter.js";
import { isPlainDataArray } from "./plain-record.js";

const EDGE_REQUEST_TIMEOUT_MS = 30_000;
const EDGE_HEADERS_TIMEOUT_MS = 10_000;
const EDGE_KEEP_ALIVE_TIMEOUT_MS = 5_000;
const EDGE_MAX_REQUESTS_PER_SOCKET = 100;

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
  rateLimit?: RateLimitOptions;
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
  app.use(mcpAuthMetadataRouter({
    oauthMetadata: options.oauthMetadata,
    resourceServerUrl: options.resourceServerUrl,
    scopesSupported: [...SCOPES],
    resourceName: "Mac-Operator-MCP"
  }));

  const handler = createMcpHandler(createGovernedMcpServerFactory(options), {
    legacy: "reject",
    responseMode: "json"
  });
  const nodeHandler = toNodeHandler(handler);
  const bearerAuth = requireBearerAuth({
    verifier: options.tokenVerifier,
    requiredScopes: ["mac.control.read"],
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(options.resourceServerUrl)
  });
  const rateLimiter = new FixedWindowRateLimiter(options.rateLimit);
  app.all(options.resourceServerUrl.pathname, (_request: Request, response: Response, next: NextFunction) => {
    response.setHeader("Cache-Control", "no-store");
    next();
  }, bearerAuth, (request: Request, response: Response, next: NextFunction) => {
    const auth = (request as Request & { auth?: AuthInfo }).auth;
    const identity = auth?.clientId ?? readPrincipalId(auth) ?? "authenticated";
    const decision = rateLimiter.consume(identity);
    if (!decision.allowed) {
      response.setHeader("Retry-After", String(Math.max(1, Math.ceil(decision.retryAfterMs / 1_000))));
      response.status(429).json({ error: "rate_limit_exceeded" });
      return;
    }
    void nodeHandler(request, response, request.body).catch(next);
  });
  app.use((_error: unknown, _request: Request, response: Response, _next: NextFunction) => {
    if (response.headersSent) {
      response.end();
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
    handler,
    async close() {
      await handler.close();
      if (!server.listening) return;
      await new Promise<void>((resolve, reject) => {
        server.close((error) => error ? reject(error) : resolve());
      });
    }
  };
}

function readPrincipalId(auth: AuthInfo | undefined): string | undefined {
  const value = auth?.extra?.principalId;
  return typeof value === "string" && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value) ? value : undefined;
}

function validateOptions(options: HttpsMcpEdgeOptions): {
  allowedHosts: string[];
  allowedOrigins: string[];
  oauthIssuer: URL;
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
  return { allowedHosts, allowedOrigins, oauthIssuer };
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
