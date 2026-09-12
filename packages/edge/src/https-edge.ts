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

export interface HttpsMcpEdgeOptions extends GovernedMcpServerOptions {
  bindHost: string;
  allowedHosts: string[];
  allowedOrigins: string[];
  tlsCertificate: Buffer | string;
  tlsPrivateKey: Buffer | string;
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
  validateOptions(options);
  const app = createMcpExpressApp({
    host: options.bindHost,
    allowedHosts: [...options.allowedHosts],
    allowedOrigins: [...options.allowedOrigins],
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

function validateOptions(options: HttpsMcpEdgeOptions): void {
  if (options.resourceServerUrl.protocol !== "https:") throw new Error("MCP resource server URL must use HTTPS");
  if (
    options.resourceServerUrl.username ||
    options.resourceServerUrl.password ||
    options.resourceServerUrl.hash ||
    options.resourceServerUrl.search
  ) {
    throw new Error("MCP resource server URL must not contain credentials, a query, or a fragment");
  }
  if (!options.resourceServerUrl.pathname.startsWith("/") || options.resourceServerUrl.pathname === "/") {
    throw new Error("MCP resource server URL must use a dedicated path");
  }
  if (options.allowedHosts.length === 0 || !options.allowedHosts.includes(options.resourceServerUrl.hostname)) {
    throw new Error("MCP Host allowlist must include the public resource hostname");
  }
  if (options.allowedOrigins.length === 0) throw new Error("MCP Origin allowlist must not be empty");
}
