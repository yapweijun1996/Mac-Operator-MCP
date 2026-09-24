import { SCOPES, type Scope } from "@mac-operator/contracts";
import type { JwtRevocationContext } from "@mac-operator/edge";
import type { GrantRevocationNotice } from "./store.js";

export const AUTH_REVOCATION_TYPE = "oauth-grant-revoked" as const;
export const MAX_PENDING_AUTH_REVOCATIONS = 32;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/u;
const AUTH_REVOCATION_KEYS = ["type", "grantId", "principalId", "scopes", "expiresAtMs"] as const;

export type AuthGrantRevocationMessage = GrantRevocationNotice & { type: typeof AUTH_REVOCATION_TYPE };

export function parseAuthGrantRevocation(value: unknown): AuthGrantRevocationMessage | undefined {
  if (!isPlainRecord(value) || !hasExactKeys(value, AUTH_REVOCATION_KEYS) || value.type !== AUTH_REVOCATION_TYPE ||
      typeof value.grantId !== "string" || !ID_PATTERN.test(value.grantId) ||
      typeof value.principalId !== "string" || !ID_PATTERN.test(value.principalId) ||
      typeof value.expiresAtMs !== "number" || !Number.isSafeInteger(value.expiresAtMs) || value.expiresAtMs < 0 ||
      !Array.isArray(value.scopes) || value.scopes.length === 0 || value.scopes.length > SCOPES.length ||
      value.scopes.some(scope => typeof scope !== "string" || !(SCOPES as readonly string[]).includes(scope)) ||
      new Set(value.scopes).size !== value.scopes.length) return undefined;
  const grantId = value.grantId as string;
  const principalId = value.principalId as string;
  const scopes = value.scopes as Scope[];
  const expiresAtMs = value.expiresAtMs as number;
  return Object.freeze({ type: AUTH_REVOCATION_TYPE, grantId, principalId,
    scopes: Object.freeze([...scopes]), expiresAtMs });
}

export function toJwtRevocationContext(message: AuthGrantRevocationMessage, issuerId: string): JwtRevocationContext {
  return Object.freeze({ issuerId, subject: message.principalId, sessionId: message.grantId,
    tokenId: `auth-grant:${message.grantId}`, expiresAt: Math.floor(message.expiresAtMs / 1_000),
    scopes: Object.freeze([...message.scopes]) });
}

/**
 * Forward durable AuthStore revocation notices to the Edge child in order.
 * A send failure is a supervisor-fatal boundary error; silently dropping an
 * authority event would let Edge keep an otherwise revoked session active.
 */
export function createAuthRevocationQueue(options: {
  isConnected: () => boolean;
  send: (message: AuthGrantRevocationMessage, callback: (error: Error | null) => void) => void;
  onSendFailure: (error: Error) => void;
  maxPending?: number;
}): {
  enqueue: (message: AuthGrantRevocationMessage) => void;
  flush: () => void;
  pendingCount: () => number;
} {
  const maxPending = options.maxPending ?? MAX_PENDING_AUTH_REVOCATIONS;
  if (!Number.isSafeInteger(maxPending) || maxPending < 1 || maxPending > MAX_PENDING_AUTH_REVOCATIONS) {
    throw new Error("Auth revocation queue limit is outside the supported range");
  }
  const pending: AuthGrantRevocationMessage[] = [];
  let sending = false;

  const flush = (): void => {
    if (sending || pending.length === 0 || !options.isConnected()) return;
    const message = pending[0];
    if (message === undefined) return;
    sending = true;
    try {
      options.send(message, error => {
        sending = false;
        if (error !== null) {
          options.onSendFailure(error);
          return;
        }
        if (pending[0] === message) pending.shift();
        flush();
      });
    } catch (error) {
      sending = false;
      options.onSendFailure(error instanceof Error ? error : new Error("Auth revocation send failed"));
    }
  };

  return {
    enqueue(message): void {
      if (pending.length >= maxPending) throw new Error("Auth revocation queue capacity exceeded");
      pending.push(message);
      flush();
    },
    flush,
    pendingCount: () => pending.length
  };
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  try {
    if (Object.getPrototypeOf(value) !== Object.prototype || Object.getOwnPropertySymbols(value).length !== 0) return false;
    return Object.keys(value).every(key => {
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      return descriptor !== undefined && "value" in descriptor;
    });
  } catch { return false; }
}

function hasExactKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}
