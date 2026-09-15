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
  let parsed: unknown;
  try { parsed = JSON.parse(token); }
  catch { throw new TypeError("JSON value is malformed"); }
  if (typeof parsed === "number") {
    const canonical = JSON.stringify(parsed);
    if (!Number.isFinite(parsed) || canonical !== canonicalizeJsonNumberToken(token)) {
      throw new TypeError("JSON number is not representable by the canonical wire profile");
    }
    assertSafePlainDecimalInteger(token, parsed);
  }
}

/**
 * Plain decimal integer wire values must remain exactly representable in
 * JavaScript so another runtime cannot preserve a different integer while
 * verifying a request or audit digest. Scientific notation remains governed
 * by the versioned ECMAScript JSON.stringify profile and is bounded by each
 * field's contract before authority decisions.
 */
function assertSafePlainDecimalInteger(token: string, value: number): void {
  if (/^-?\d+$/u.test(token) && Number.isInteger(value) && !Number.isSafeInteger(value)) {
    throw new TypeError("JSON integer is outside the safe integer range");
  }
}

/**
 * Normalize a syntactically valid JSON number without converting it through a
 * floating-point runtime. The scanner compares this spelling with Node's
 * ECMAScript JSON.stringify output so a native lexical canonicalizer observes
 * the same IEEE-754 value and cannot silently preserve discarded precision.
 */
function canonicalizeJsonNumberToken(token: string): string {
  let text = token;
  let negative = false;
  if (text.startsWith("-")) {
    negative = true;
    text = text.slice(1);
  }
  const exponentParts = text.split(/[eE]/u);
  if (exponentParts.length > 2) throw new TypeError("JSON number exponent is malformed");
  const mantissa = exponentParts[0] ?? "";
  const exponentText = exponentParts.length === 2 ? exponentParts[1] ?? "" : "";
  const exponent = exponentText.length === 0 ? 0 : Number(exponentText);
  if (!Number.isSafeInteger(exponent) || exponent < -10_000 || exponent > 10_000) {
    throw new TypeError("JSON number exponent is outside the supported range");
  }
  const mantissaParts = mantissa.split(".");
  if (mantissaParts.length > 2) throw new TypeError("JSON number fraction is malformed");
  const integerPart = mantissaParts[0] ?? "";
  const fractionalPart = mantissaParts.length === 2 ? mantissaParts[1] ?? "" : "";
  let digits = `${integerPart}${fractionalPart}`.split("");
  if (digits.length === 0 || digits.some((digit) => digit < "0" || digit > "9")) {
    throw new TypeError("JSON number digits are malformed");
  }
  let decimalPoint = integerPart.length + exponent;
  while (digits.length > 1 && digits[0] === "0") {
    digits = digits.slice(1);
    decimalPoint -= 1;
  }
  while (digits.length > 1 && digits[digits.length - 1] === "0") digits.pop();
  if (digits.every((digit) => digit === "0")) return "0";

  const scientificExponent = decimalPoint - 1;
  const useScientific = scientificExponent < -6 || scientificExponent >= 21;
  let body: string;
  if (useScientific) {
    body = digits[0] ?? "";
    if (digits.length > 1) body += `.${digits.slice(1).join("")}`;
    body += `e${scientificExponent >= 0 ? "+" : ""}${scientificExponent}`;
  } else if (decimalPoint <= 0) {
    body = `0.${"0".repeat(-decimalPoint)}${digits.join("")}`;
  } else if (decimalPoint >= digits.length) {
    body = `${digits.join("")}${"0".repeat(decimalPoint - digits.length)}`;
  } else {
    body = `${digits.slice(0, decimalPoint).join("")}.${digits.slice(decimalPoint).join("")}`;
  }
  return negative ? `-${body}` : body;
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
