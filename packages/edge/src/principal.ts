import { SCOPES, type PrincipalContext, type Scope } from "@mac-operator/contracts";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { isPlainDataArray, isPlainDataRecord } from "./plain-record.js";

const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const KNOWN_SCOPES = new Set<string>(SCOPES);

export function projectPrincipal(
  auth: AuthInfo,
  options: { edgeId: string; brokerAudience: string; resourceServerUrl: URL }
): PrincipalContext {
  const extra = auth.extra;
  if (extra !== undefined && !isPlainDataRecord(extra)) {
    throw new Error("Verified access token identity metadata is malformed");
  }
  if (!isPlainDataArray(auth.scopes, SCOPES.length)) {
    throw new Error("Verified access token scopes are malformed");
  }
  const principalId = readId(extra, "principalId");
  const issuer = readId(extra, "issuer");
  const sessionId = readId(extra, "sessionId");
  const issuedAtMs = readInteger(extra, "issuedAtMs");
  if (auth.expiresAt === undefined || !Number.isSafeInteger(auth.expiresAt)) {
    throw new Error("Verified access token must include an integer expiration");
  }
  if (!auth.resource || normalizeResource(auth.resource) !== normalizeResource(options.resourceServerUrl)) {
    throw new Error("Verified access token resource does not match this MCP Edge");
  }
  const scopes = [...new Set(auth.scopes.filter((scope): scope is Scope => KNOWN_SCOPES.has(scope)))];
  return {
    principalId,
    sessionId,
    issuer,
    audience: options.brokerAudience,
    scopes,
    issuedAtMs,
    expiresAtMs: auth.expiresAt * 1_000,
    edgeId: options.edgeId
  };
}

function readId(extra: Record<string, unknown> | undefined, key: string): string {
  const value = extra?.[key];
  if (typeof value !== "string" || !ID_PATTERN.test(value)) {
    throw new Error(`Verified access token ${key} is missing or malformed`);
  }
  return value;
}

function readInteger(extra: Record<string, unknown> | undefined, key: string): number {
  const value = extra?.[key];
  if (!Number.isSafeInteger(value)) throw new Error(`Verified access token ${key} is missing or malformed`);
  return value as number;
}

function normalizeResource(url: URL): string {
  const normalized = new URL(url);
  normalized.hash = "";
  return normalized.href;
}
