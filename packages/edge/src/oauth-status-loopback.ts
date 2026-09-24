import { request as httpsRequest } from "node:https";
import { X509Certificate } from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";

const DEFAULT_TIMEOUT_MS = 3_000;
const MAX_RESPONSE_BYTES = 4 * 1024;

export interface LoopbackOAuthStatusFetchOptions {
  publicUrl: URL;
  loopbackUrl: URL;
  serverName: string;
  ca: Buffer;
  timeoutMs?: number;
}

/**
 * Keep the issuer-bound OAuth status URL as the logical request target while
 * sending the request to a fixed local HTTPS listener. The status key remains
 * the primary sibling-authentication boundary; TLS pins the local connection
 * to the owner-controlled CA and issuer hostname.
 */
export function createLoopbackOAuthStatusFetch(options: LoopbackOAuthStatusFetchOptions): typeof fetch {
  const validated = validateOptions(options);
  return async (input, init = {}) => {
    const requestedUrl = readRequestUrl(input);
    if (requestedUrl.href !== validated.publicUrl.href) throw new Error("OAuth status request URL is not issuer-bound");
    if (String(init.method ?? "GET").toUpperCase() !== "POST") throw new Error("OAuth status loopback requires POST");
    if (typeof init.body !== "string") throw new Error("OAuth status loopback requires a bounded string body");

    const headers = new Headers(init.headers);
    const authorization = headers.get("authorization");
    if (authorization === null || authorization.length === 0) throw new Error("OAuth status loopback requires authentication");
    const contentType = headers.get("content-type");
    if (contentType !== "application/json") throw new Error("OAuth status loopback requires JSON");
    const body = Buffer.from(init.body, "utf8");
    if (body.byteLength > MAX_RESPONSE_BYTES) throw new Error("OAuth status loopback request is too large");

    return await requestLoopback(validated, authorization, body, init.signal);
  };
}

interface ValidatedOptions {
  publicUrl: URL;
  loopbackUrl: URL;
  serverName: string;
  ca: Buffer;
  timeoutMs: number;
}

function validateOptions(options: LoopbackOAuthStatusFetchOptions): ValidatedOptions {
  if (!(options.publicUrl instanceof URL) || options.publicUrl.protocol !== "https:" ||
      options.publicUrl.pathname !== "/oauth/status" || options.publicUrl.search || options.publicUrl.hash ||
      options.publicUrl.username || options.publicUrl.password) {
    throw new Error("OAuth public status URL is invalid");
  }
  if (!(options.loopbackUrl instanceof URL) || options.loopbackUrl.protocol !== "https:" ||
      options.loopbackUrl.hostname !== "127.0.0.1" || options.loopbackUrl.pathname !== "/oauth/status" ||
      options.loopbackUrl.search || options.loopbackUrl.hash || options.loopbackUrl.username || options.loopbackUrl.password ||
      options.loopbackUrl.port.length === 0) {
    throw new Error("OAuth status loopback URL must be a fixed HTTPS IPv4 loopback endpoint");
  }
  if (typeof options.serverName !== "string" || options.serverName.length === 0 ||
      options.serverName !== options.serverName.toLowerCase() || !/^[a-z0-9.-]+$/u.test(options.serverName)) {
    throw new Error("OAuth status TLS server name is invalid");
  }
  if (options.ca.byteLength === 0 || options.ca.byteLength > 256 * 1024) throw new Error("OAuth status TLS CA is invalid");
  try {
    if (!new X509Certificate(options.ca).ca) throw new Error("OAuth status TLS CA is not a CA");
  } catch (error) {
    if (error instanceof Error && error.message === "OAuth status TLS CA is not a CA") throw error;
    throw new Error("OAuth status TLS CA is invalid");
  }
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 100 || timeoutMs > 10_000) throw new Error("OAuth status loopback timeout is invalid");
  return {
    publicUrl: new URL(options.publicUrl.href),
    loopbackUrl: new URL(options.loopbackUrl.href),
    serverName: options.serverName,
    ca: Buffer.from(options.ca),
    timeoutMs
  };
}

function readRequestUrl(input: RequestInfo | URL): URL {
  if (input instanceof URL) return new URL(input.href);
  if (typeof input === "string") return new URL(input);
  return new URL(input.url);
}

function requestLoopback(
  options: ValidatedOptions,
  authorization: string,
  body: Buffer,
  signal: AbortSignal | null | undefined
): Promise<Response> {
  return new Promise<Response>((resolve, reject) => {
    let settled = false;
    const finish = (error?: Error, response?: Response) => {
      if (settled) return;
      settled = true;
      signal?.removeEventListener("abort", onAbort);
      if (error) reject(error); else resolve(response!);
    };
    const onAbort = () => request.destroy(new Error("OAuth status loopback request was aborted"));
    const request = httpsRequest({
      hostname: options.loopbackUrl.hostname,
      port: Number(options.loopbackUrl.port),
      path: options.loopbackUrl.pathname,
      method: "POST",
      servername: options.serverName,
      ca: options.ca,
      rejectUnauthorized: true,
      headers: {
        host: options.serverName,
        authorization,
        "content-type": "application/json",
        "content-length": String(body.byteLength)
      },
      timeout: options.timeoutMs
    }, response => {
      const chunks: Buffer[] = [];
      let size = 0;
      response.on("data", chunk => {
        const value = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += value.byteLength;
        if (size > MAX_RESPONSE_BYTES) {
          response.destroy(new Error("OAuth status loopback response is too large"));
          return;
        }
        chunks.push(value);
      });
      response.once("error", error => finish(error));
      response.once("end", () => finish(undefined, new Response(Buffer.concat(chunks), {
        status: response.statusCode ?? 599,
        headers: responseHeaders(response.headers)
      })));
    });
    request.once("timeout", () => request.destroy(new Error("OAuth status loopback request timed out")));
    request.once("error", error => finish(error));
    if (signal?.aborted) {
      request.destroy(new Error("OAuth status loopback request was aborted"));
      return;
    }
    signal?.addEventListener("abort", onAbort, { once: true });
    request.end(body);
  });
}

function responseHeaders(headers: IncomingHttpHeaders): Headers {
  const result = new Headers();
  for (const [name, value] of Object.entries(headers)) {
    if (typeof value === "string") result.set(name, value);
    else if (Array.isArray(value)) result.set(name, value.join(", "));
  }
  return result;
}
