import { isAbsolute } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";
import { assertContentDoesNotContainSecrets } from "./secret-policy.js";

export type OwnerTerminalSessionRequest =
  | { action: "start"; cwd: string; idempotencyKey: string; rows: number; cols: number; lifetimeMs: number; idleTimeoutMs: number }
  | { action: "write"; sessionId: string; data: string }
  | { action: "read"; sessionId: string; cursor: number; maxBytes: number; waitMs: number }
  | { action: "stop"; sessionId: string };

const FIELDS: Record<OwnerTerminalSessionRequest["action"], readonly string[]> = {
  start: ["action", "cwd", "idempotency_key", "rows", "cols", "lifetime_ms", "idle_timeout_ms"],
  write: ["action", "session_id", "data"],
  read: ["action", "session_id", "cursor", "max_bytes", "wait_ms"],
  stop: ["action", "session_id"]
};

function invalid(): never {
  throw new BrokerError("PRECONDITION_FAILED", "Terminal session action or arguments are invalid");
}

function integer(value: unknown, min: number, max: number, fallback?: number): number {
  if (value === undefined && fallback !== undefined) return fallback;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < min || value > max) invalid();
  return value;
}

/** Validates the exact per-action argument set; unknown or foreign fields are rejected. */
export function parseOwnerTerminalSessionRequest(value: unknown): OwnerTerminalSessionRequest {
  if (!isPlainDataRecord(value) || typeof value.action !== "string" || !Object.hasOwn(FIELDS, value.action)) invalid();
  const action = value.action as OwnerTerminalSessionRequest["action"];
  const allowed = FIELDS[action];
  if (Object.keys(value).some(key => !allowed.includes(key))) invalid();
  if (action === "start") {
    if (typeof value.cwd !== "string" || value.cwd.length > 4096 || !isAbsolute(value.cwd) || value.cwd.includes("\0") ||
        typeof value.idempotency_key !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(value.idempotency_key)) invalid();
    const lifetimeMs = integer(value.lifetime_ms, 1_000, 600_000, 300_000);
    const idleTimeoutMs = integer(value.idle_timeout_ms, 1_000, 600_000, Math.min(120_000, lifetimeMs));
    if (idleTimeoutMs > lifetimeMs) invalid();
    return { action, cwd: value.cwd, idempotencyKey: value.idempotency_key, rows: integer(value.rows, 1, 200, 24),
      cols: integer(value.cols, 1, 500, 80), lifetimeMs, idleTimeoutMs };
  }
  if (typeof value.session_id !== "string" || !/^tsess_[0-9a-f]{24}$/u.test(value.session_id)) invalid();
  const sessionId = value.session_id;
  if (action === "write") {
    if (typeof value.data !== "string" || value.data.length === 0 || value.data.includes("\0") || Buffer.byteLength(value.data, "utf8") > 4_096) invalid();
    assertContentDoesNotContainSecrets(Buffer.from(value.data, "utf8"));
    return { action, sessionId, data: value.data };
  }
  if (action === "read") {
    return { action, sessionId, cursor: integer(value.cursor, 0, Number.MAX_SAFE_INTEGER), maxBytes: integer(value.max_bytes, 1, 65_536, 65_536),
      waitMs: integer(value.wait_ms, 0, 5_000, 0) };
  }
  return { action, sessionId };
}
