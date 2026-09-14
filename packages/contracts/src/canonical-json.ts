import { createHash } from "node:crypto";

/**
 * Versioned wire profile used for every request, response, and audit digest.
 * The implementation follows ECMAScript JSON string escaping and UTF-16
 * property-name ordering so native adapters can reproduce the exact bytes.
 */
export const CANONICAL_JSON_PROFILE = "jcs-utf8-v1" as const;

function canonicalizeValue(value: unknown): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new TypeError("Non-finite numbers are not canonical JSON");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeValue).join(",")}]`;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, item]) => item !== undefined)
      .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0);
    return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonicalizeValue(item)}`).join(",")}}`;
  }
  throw new TypeError(`Unsupported canonical JSON type: ${typeof value}`);
}

export function canonicalJson(value: unknown): string {
  return canonicalizeValue(value);
}

/** Return the exact UTF-8 bytes covered by a canonical digest or signature. */
export function canonicalJsonUtf8(value: unknown): Buffer {
  return Buffer.from(canonicalJson(value), "utf8");
}

/** Decode protocol bytes without silently replacing malformed UTF-8. */
export function decodeUtf8Strict(value: Uint8Array): string {
  if (!(value instanceof Uint8Array)) throw new TypeError("UTF-8 input must be bytes");
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(value);
  } catch {
    throw new TypeError("Input is not valid UTF-8");
  }
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
