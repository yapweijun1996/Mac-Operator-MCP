import { createHash } from "node:crypto";

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

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
