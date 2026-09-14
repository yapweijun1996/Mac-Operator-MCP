import { createHash } from "node:crypto";

/**
 * Versioned wire profile used for every request, response, and audit digest.
 * The implementation follows ECMAScript JSON string escaping and UTF-16
 * property-name ordering so native adapters can reproduce the exact bytes.
 */
export const CANONICAL_JSON_PROFILE = "jcs-utf8-v1" as const;

function canonicalizeValue(value: unknown): string {
  if (value === null || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "string") {
    assertNoUnpairedSurrogates(value);
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
    return `{${entries.map(([key, item]) => {
      assertNoUnpairedSurrogates(key);
      return `${JSON.stringify(key)}:${canonicalizeValue(item)}`;
    }).join(",")}}`;
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

/**
 * Parse JSON only after checking the wire grammar for duplicate object keys
 * and unpaired UTF-16 surrogates. JSON.parse alone loses duplicate keys and
 * accepts lone surrogate escapes that the native canonicalizer rejects.
 */
export function parseJsonUtf8Strict(value: Uint8Array): unknown {
  return parseJsonStrict(decodeUtf8Strict(value));
}

export function parseJsonStrict(value: string): unknown {
  if (typeof value !== "string") throw new TypeError("JSON input must be text");
  scanJson(value);
  return JSON.parse(value) as unknown;
}

interface JsonScanState {
  index: number;
}

function scanJson(value: string): void {
  const state: JsonScanState = { index: 0 };
  scanJsonValue(value, state, 0);
  skipJsonWhitespace(value, state);
  if (state.index !== value.length) throw new TypeError("JSON input contains trailing data");
}

function scanJsonValue(value: string, state: JsonScanState, depth: number): void {
  if (depth > 64) throw new TypeError("JSON input exceeds the supported depth");
  skipJsonWhitespace(value, state);
  const byte = value.charCodeAt(state.index);
  if (byte === 0x7b) {
    scanJsonObject(value, state, depth + 1);
    return;
  }
  if (byte === 0x5b) {
    scanJsonArray(value, state, depth + 1);
    return;
  }
  if (byte === 0x22) {
    scanJsonString(value, state);
    return;
  }
  const start = state.index;
  while (state.index < value.length) {
    const code = value.charCodeAt(state.index);
    if (isJsonWhitespace(code) || code === 0x2c || code === 0x5d || code === 0x7d) break;
    state.index += 1;
  }
  if (start === state.index) throw new TypeError("JSON value is missing");
  const token = value.slice(start, state.index);
  try { JSON.parse(token); }
  catch { throw new TypeError("JSON value is malformed"); }
}

function scanJsonObject(value: string, state: JsonScanState, depth: number): void {
  state.index += 1;
  skipJsonWhitespace(value, state);
  const keys = new Set<string>();
  if (value.charCodeAt(state.index) === 0x7d) {
    state.index += 1;
    return;
  }
  while (true) {
    skipJsonWhitespace(value, state);
    if (value.charCodeAt(state.index) !== 0x22) throw new TypeError("JSON object key is missing");
    const key = scanJsonString(value, state);
    if (keys.has(key)) throw new TypeError("JSON object contains a duplicate key");
    keys.add(key);
    skipJsonWhitespace(value, state);
    if (value.charCodeAt(state.index) !== 0x3a) throw new TypeError("JSON object separator is missing");
    state.index += 1;
    scanJsonValue(value, state, depth);
    skipJsonWhitespace(value, state);
    const separator = value.charCodeAt(state.index);
    if (separator === 0x7d) {
      state.index += 1;
      return;
    }
    if (separator !== 0x2c) throw new TypeError("JSON object separator is malformed");
    state.index += 1;
  }
}

function scanJsonArray(value: string, state: JsonScanState, depth: number): void {
  state.index += 1;
  skipJsonWhitespace(value, state);
  if (value.charCodeAt(state.index) === 0x5d) {
    state.index += 1;
    return;
  }
  while (true) {
    scanJsonValue(value, state, depth);
    skipJsonWhitespace(value, state);
    const separator = value.charCodeAt(state.index);
    if (separator === 0x5d) {
      state.index += 1;
      return;
    }
    if (separator !== 0x2c) throw new TypeError("JSON array separator is malformed");
    state.index += 1;
  }
}

function scanJsonString(value: string, state: JsonScanState): string {
  const start = state.index;
  state.index += 1;
  while (state.index < value.length) {
    const code = value.charCodeAt(state.index);
    if (code === 0x22) {
      state.index += 1;
      const raw = value.slice(start, state.index);
      let parsed: unknown;
      try { parsed = JSON.parse(raw); }
      catch { throw new TypeError("JSON string is malformed"); }
      if (typeof parsed !== "string") throw new TypeError("JSON string is malformed");
      assertNoUnpairedSurrogates(parsed);
      return parsed;
    }
    if (code < 0x20) throw new TypeError("JSON string contains a control character");
    if (code === 0x5c) {
      state.index += 1;
      const escape = value.charCodeAt(state.index);
      if (escape === 0x75) {
        if (!isHexQuad(value, state.index + 1)) throw new TypeError("JSON Unicode escape is malformed");
        state.index += 5;
      } else if (escape === 0x22 || escape === 0x2f || escape === 0x5c || escape === 0x62 ||
                 escape === 0x66 || escape === 0x6e || escape === 0x72 || escape === 0x74) {
        state.index += 1;
      } else {
        throw new TypeError("JSON string escape is malformed");
      }
      continue;
    }
    state.index += 1;
  }
  throw new TypeError("JSON string is unterminated");
}

function isHexQuad(value: string, start: number): boolean {
  if (start + 4 > value.length) return false;
  for (let index = start; index < start + 4; index += 1) {
    const code = value.charCodeAt(index);
    if (!((code >= 0x30 && code <= 0x39) || (code >= 0x41 && code <= 0x46) || (code >= 0x61 && code <= 0x66))) return false;
  }
  return true;
}

function assertNoUnpairedSurrogates(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) {
        throw new TypeError("JSON string contains an unpaired surrogate");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("JSON string contains an unpaired surrogate");
    }
  }
}

function skipJsonWhitespace(value: string, state: JsonScanState): void {
  while (state.index < value.length && isJsonWhitespace(value.charCodeAt(state.index))) state.index += 1;
}

function isJsonWhitespace(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d;
}

export function sha256(value: string | Buffer): string {
  return createHash("sha256").update(value).digest("hex");
}
