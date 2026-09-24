import { subscribe, unsubscribe } from "node:diagnostics_channel";
import type { IncomingMessage, ServerResponse } from "node:http";

const paths = new Set([
  "/mcp", "/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp",
  "/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp",
  "/.well-known/openid-configuration", "/register", "/authorize", "/token", "/revoke",
  "/jwks", "/oauth/login", "/oauth/consent", "/oauth/status", "/approval", "/approval/login", "/approval/review", "/approval/decision"
]);

/** Only fixed categories are logged; no request-controlled strings or credentials. */
export function connectionDiagnostic(request: IncomingMessage, response: ServerResponse) {
  const originalUrl = (request as IncomingMessage & { originalUrl?: string }).originalUrl;
  const path = (originalUrl ?? request.url)?.split("?", 1)[0] ?? "";
  const method = request.method ?? "";
  const agent = request.headers["user-agent"] ?? "";
  const body = (request as IncomingMessage & { body?: { method?: unknown; params?: { protocolVersion?: unknown } } }).body;
  const methodName = body?.method;
  const revision = request.headers["mcp-protocol-version"] ?? body?.params?.protocolVersion;
  const rpc = path === "/mcp" ? {
    rpcMethod: typeof methodName === "string" && ["initialize", "server/discover", "tools/list", "tools/call", "notifications/initialized"].includes(methodName) ? methodName : "other",
    protocolVersion: typeof revision === "string" && ["2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25", "2026-07-28"].includes(revision) ? revision : "other"
  } : {};
  return {
    ...rpc,
    path: paths.has(path) ? path : "other",
    method: ["GET", "HEAD", "POST", "OPTIONS", "DELETE"].includes(method) ? method : "other",
    status: response.statusCode,
    client: /openai|chatgpt/iu.test(agent) ? "openai" : /curl/iu.test(agent) ? "curl" : /python|httpx/iu.test(agent) ? "python" : "other",
    authenticated: request.headers.authorization !== undefined
  };
}

export function enableConnectionDiagnostics(component: "auth" | "edge"): () => void {
  let count = 0; let windowStart = Date.now(); let sequence = 0;
  const pending = new Map<ServerResponse, () => void>();
  const started = new WeakMap<ServerResponse, { id: number; time: number; ray: string | undefined }>();
  const write = (record: object) => {
    if (Date.now() - windowStart >= 60_000) { count = 0; windowStart = Date.now(); }
    if (++count > 300) return;
    console.log(JSON.stringify({ event: "connection", time: new Date().toISOString(), component, ...record }));
  };
  const onStart = (message: unknown) => {
    const { request, response } = message as { request: IncomingMessage; response: ServerResponse };
    const header = request.headers["cf-ray"];
    const ray = typeof header === "string" && /^[a-f0-9]{16}(?:-[A-Z]{3})?$/u.test(header) ? header : undefined;
    const state = { id: ++sequence, time: performance.now(), ray };
    started.set(response, state);
    const { status: _status, ...fields } = connectionDiagnostic(request, response);
    write({ phase: "received", requestId: state.id, ray, ...fields });
    const close = () => {
      pending.delete(response);
      if (!response.writableFinished) write({ phase: "aborted", requestId: state.id, ray,
        durationMs: Math.round(performance.now() - state.time), ...fields });
    };
    pending.set(response, close);
    response.once("close", close);
  };
  const onFinish = (message: unknown) => {
    const { request, response } = message as { request: IncomingMessage; response: ServerResponse };
    const state = started.get(response);
    write({ phase: "completed", requestId: state?.id, ray: state?.ray,
      durationMs: state ? Math.round(performance.now() - state.time) : undefined,
      ...connectionDiagnostic(request, response) });
  };
  subscribe("http.server.request.start", onStart);
  subscribe("http.server.response.finish", onFinish);
  return () => {
    unsubscribe("http.server.request.start", onStart);
    unsubscribe("http.server.response.finish", onFinish);
    for (const [response, close] of pending) response.off("close", close);
    pending.clear();
  };
}
