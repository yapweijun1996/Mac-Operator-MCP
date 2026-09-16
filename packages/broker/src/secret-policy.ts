import { basename } from "node:path";
import { createPrivateKey } from "node:crypto";
import { BrokerError } from "@mac-operator/contracts";

const DENIED_BASENAMES = new Set([
  ".git-credentials", ".netrc", ".npmrc", ".pypirc", "application_default_credentials.json",
  "credentials", "credentials.json", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"
]);

/**
 * Private signing and credential containers are denied by name before any
 * content read. Some formats are encrypted or opaque binary values and cannot
 * be identified reliably by the bounded content scanner alone.
 */
const DENIED_NAME_SUFFIXES = [
  ".key", ".p8", ".p12", ".pfx", ".ppk", ".jks", ".keystore", ".mobileprovision", ".provisionprofile"
];

const DENIED_PATH_FRAGMENTS = [
  "/.ssh/", "/.gnupg/", "/.aws/", "/.azure/", "/.config/gcloud/", "/.config/gh/", "/.kube/", "/.docker/",
  "/private/var/root/", "/var/root/",
  "/library/keychains/", "/library/mail/", "/library/messages/", "/library/safari/",
  "/library/application support/google/chrome/", "/library/application support/bravesoftware/brave-browser/",
  "/library/application support/microsoft edge/", "/library/containers/com.apple.mail/",
  "/library/containers/com.apple.messages/", "/library/containers/com.apple.safari/",
  "/photos library.photoslibrary/"
];

const SECRET_CONTENT_PATTERNS = [
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\b(?:ASIA|AIDA|AROA|AGPA|ANPA|ANVA)[0-9A-Z]{16}\b/u,
  /\b(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9/+=]{20,}/iu,
  /\bAIza[0-9A-Za-z_-]{30,}\b/u,
  /\bya29\.[0-9A-Za-z_-]{20,}\b/u,
  /\bGOCSPX-[0-9A-Za-z_-]{16,}\b/u,
  /\bgh[pousr]_[0-9A-Za-z]{20,}\b/u,
  /\bgithub_pat_[0-9A-Za-z_]{20,}\b/u,
  /\bglpat-[0-9A-Za-z_-]{16,}\b/u,
  /\bnpm_[0-9A-Za-z]{16,}\b/u,
  /\bpypi-[0-9A-Za-z_-]{16,}\b/u,
  /\bsk-proj-[0-9A-Za-z_-]{16,}\b/u,
  /\bsk-(?!proj-)[0-9A-Za-z]{24,}\b/u,
  /\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b/u,
  /\bcfp_[0-9A-Za-z_-]{16,}\b/u,
  /\b(?:cf[_-](?:pat|token)|heroku[_-]?api[_-]?key)[=:_-]?[0-9A-Za-z._-]{16,}\b/iu,
  /\bBearer\s+[A-Za-z0-9._~+\/-]{16,}\b/iu,
  /\bBasic\s+[A-Za-z0-9+/=]{16,}\b/iu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u,
  /\bxox[baprs]-[0-9A-Za-z-]{16,}\b/u,
  /\b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token)\s*[:=]\s*["']?[^\s"']{8,}/iu
];

/**
 * Encoded credential values are accepted only when their decoded bytes match
 * an already-known signature. This avoids entropy heuristics and keeps the
 * additional scan bounded and explainable.
 */
const BASE64_CANDIDATE_PATTERN = /(?:^|[\s"'=,:;()[\]{}])([A-Za-z0-9+/]{24,}={0,2})(?=$|[\s"'=,:;()[\]{}])/gu;
const MAX_ENCODED_CANDIDATES = 512;
const MAX_BINARY_KEY_PARSE_BYTES = 128 * 1024;

/**
 * Command-line option names are observable through process listings. A task
 * cannot safely pass credentials in argv even when the value itself does not
 * match one of the known token formats, so sensitive option names are denied
 * before a child process is created.
 */
const SECRET_ARGUMENT_NAME_PATTERN = /(?:^|[-_])(?:api[_-]?key|auth(?:entication)?|client[_-]?secret|credential|password|passwd|passphrase|private[_-]?key|secret|token|bearer|cookie)(?:[-_]|$)/iu;

/**
 * Values can be split across argv entries (for example `Bearer`, then the
 * token). Treat protocol/credential labels as sensitive when a following
 * value exists, because the complete value is observable in the process
 * table even when no single entry matches a token signature.
 */
const SPLIT_SECRET_LABEL_PATTERN = /^(?:authorization|proxy-authorization|cookie|set-cookie|bearer|basic|token|password|passwd|passphrase|secret|api[_-]?key|client[_-]?secret|credential):?$/iu;
const HEADER_OPTION_PATTERN = /^(?:--header|-H)$/u;

const LOG_SECRET_REDACTION_PATTERNS: readonly RegExp[] = [
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/gu,
  /\bAKIA[0-9A-Z]{16}\b/gu,
  /\b(?:ASIA|AIDA|AROA|AGPA|ANPA|ANVA)[0-9A-Z]{16}\b/gu,
  /\b(?:aws[_-]?secret[_-]?access[_-]?key|secret[_-]?access[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9/+=]{20,}/giu,
  /\bAIza[0-9A-Za-z_-]{30,}\b/gu,
  /\bya29\.[0-9A-Za-z_-]{20,}\b/gu,
  /\bGOCSPX-[0-9A-Za-z_-]{16,}\b/gu,
  /\bgh[pousr]_[0-9A-Za-z]{20,}\b/gu,
  /\bgithub_pat_[0-9A-Za-z_]{20,}\b/gu,
  /\bglpat-[0-9A-Za-z_-]{16,}\b/gu,
  /\bnpm_[0-9A-Za-z]{16,}\b/gu,
  /\bpypi-[0-9A-Za-z_-]{16,}\b/gu,
  /\bsk-proj-[0-9A-Za-z_-]{16,}\b/gu,
  /\bsk-(?!proj-)[0-9A-Za-z]{24,}\b/gu,
  /\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b/gu,
  /\bcfp_[0-9A-Za-z_-]{16,}\b/gu,
  /\b(?:cf[_-](?:pat|token)|heroku[_-]?api[_-]?key)[=:_-]?[0-9A-Za-z._-]{16,}\b/giu,
  /\bBearer\s+[A-Za-z0-9._~+\/-]{16,}\b/giu,
  /\bBasic\s+[A-Za-z0-9+/=]{16,}\b/giu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gu,
  /\bxox[baprs]-[0-9A-Za-z-]{16,}\b/gu,
  /\b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token)\s*[:=]\s*["']?[^\s"']{8,}/giu,
  /(?:\/(?:[^\r\n,;)]{1,512})\.(?:key|p8|p12|pfx|ppk|jks|keystore|mobileprovision|provisionprofile))(?=$|[\s,;)'"])/giu,
  /(?:\/(?:private\/)?Users\/[^/\s]+|\/(?:private\/)?var\/root)\/(?:\.ssh|\.gnupg|\.aws|\.azure|\.config\/(?:gcloud|gh)|\.kube|\.docker|Library\/(?:Keychains|Mail|Messages|Safari|Application Support\/(?:Google\/Chrome|BraveSoftware\/Brave-Browser|Microsoft Edge)|Containers\/com\.apple\.(?:mail|messages|safari))|Photos Library\.photoslibrary)(?:[^\r\n,;)]*)/giu,
  /(?:\/(?:private\/)?var\/root)(?:[^\r\n,;)]*)/giu
];

export function assertContentPathAllowed(path: string): void {
  const normalized = path.normalize("NFKC").toLocaleLowerCase("en-US");
  const name = basename(normalized);
  if (name === ".env" || name.startsWith(".env.") || DENIED_BASENAMES.has(name) ||
      DENIED_NAME_SUFFIXES.some((suffix) => name.endsWith(suffix)) ||
      DENIED_PATH_FRAGMENTS.some((fragment) => `${normalized}/`.includes(fragment))) {
    throw new BrokerError("POLICY_DENIED", "Filesystem content is inside a protected secret zone");
  }
}

export function assertContentDoesNotContainSecrets(content: Buffer): void {
  const text = content.toString("utf8");
  if (containsEncodedSecretRepresentation(content, text)) {
    throw new BrokerError("POLICY_DENIED", "Filesystem content matched a protected secret signature");
  }
}

/**
 * Reject secret-bearing command-line options before they become visible to
 * other users through the host process table. This is intentionally a
 * conservative option-name gate; profile-owned argument patterns remain the
 * authority for all non-sensitive task arguments.
 */
export function assertArgumentsDoNotContainSecrets(argumentsValue: readonly string[]): void {
  if (!Array.isArray(argumentsValue)) {
    throw new BrokerError("PRECONDITION_FAILED", "Process arguments are malformed");
  }
  for (const argument of argumentsValue) {
    if (typeof argument !== "string") {
      throw new BrokerError("POLICY_DENIED", "Process arguments matched a protected secret signature");
    }
    const option = /^(?:--?)[A-Za-z][A-Za-z0-9_-]*(?:=|$)/u.test(argument)
      ? argument.replace(/^--?/u, "").split("=", 1)[0] ?? ""
      : "";
    if (option !== "" && SECRET_ARGUMENT_NAME_PATTERN.test(option)) {
      throw new BrokerError("POLICY_DENIED", "Process arguments matched a protected secret option");
    }
    if (containsSecretRepresentation(argument)) {
      throw new BrokerError("POLICY_DENIED", "Process arguments matched a protected secret signature");
    }
  }
  for (let index = 0; index < argumentsValue.length - 1; index += 1) {
    const argument = argumentsValue[index]!;
    const next = argumentsValue[index + 1]!;
    if (SPLIT_SECRET_LABEL_PATTERN.test(argument) ||
        (HEADER_OPTION_PATTERN.test(argument) && SPLIT_SECRET_LABEL_PATTERN.test(next.split(":", 1)[0] ?? ""))) {
      throw new BrokerError("POLICY_DENIED", "Process arguments matched a protected secret sequence");
    }
  }
}

/**
 * Reject known credential signatures before a child process receives an
 * explicitly allowlisted environment value. Key-name filtering remains the
 * primary boundary, while this value check catches opaque profiles that would
 * otherwise smuggle a token through a generic variable such as PROFILE_DATA.
 */
export function assertEnvironmentValuesDoNotContainSecrets(environment: Readonly<Record<string, string>>): void {
  if (!environment || typeof environment !== "object" || Array.isArray(environment)) {
    throw new BrokerError("PRECONDITION_FAILED", "Process environment is malformed");
  }
  for (const value of Object.values(environment)) {
    if (typeof value !== "string" || containsSecretRepresentation(value)) {
      throw new BrokerError("POLICY_DENIED", "Process environment value matched a protected secret signature");
    }
  }
}

/** Return whether a bounded value matches one of the known credential signatures. */
export function containsKnownSecretSignature(value: string): boolean {
  return typeof value === "string" && SECRET_CONTENT_PATTERNS.some((pattern) => pattern.test(value));
}

export function redactLogText(value: string): { text: string; redacted: boolean } {
  const result = redactBoundedText(value, 8_192);
  return { text: result.text, redacted: result.redacted || result.truncated };
}

export function redactBoundedText(value: string, maxBytes: number): { text: string; redacted: boolean; truncated: boolean } {
  let text = value;
  let redacted = false;
  for (const pattern of LOG_SECRET_REDACTION_PATTERNS) {
    const next = text.replace(pattern, "[REDACTED]");
    redacted ||= next !== text;
    text = next;
  }
  const encodedResult = redactEncodedSecretRepresentations(text);
  text = encodedResult.text;
  redacted ||= encodedResult.redacted;
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1) {
    throw new BrokerError("PRECONDITION_FAILED", "Redaction output budget is invalid");
  }
  const encoded = Buffer.from(text, "utf8");
  let truncated = false;
  if (encoded.byteLength > maxBytes) {
    const suffix = Buffer.from("…[TRUNCATED]", "utf8");
    if (maxBytes < suffix.byteLength) {
      text = utf8Prefix(encoded, maxBytes);
    } else {
      const prefixBytes = maxBytes - suffix.byteLength;
      text = `${utf8Prefix(encoded, prefixBytes)}${suffix.toString("utf8")}`;
    }
    redacted = true;
    truncated = true;
  }
  return { text, redacted, truncated };
}

function containsEncodedSecretRepresentation(content: Buffer, text: string): boolean {
  if (containsBinarySecretRepresentation(content)) return true;
  // UTF-16 is common in exported plist/credential material. Decode only when
  // the byte pattern strongly indicates text; arbitrary binary is not treated
  // as a secret merely because it contains NUL bytes.
  if (looksLikeUtf16Le(content)) {
    if (containsKnownSecretSignature(stripTrailingNuls(content.toString("utf16le")))) return true;
  }
  if (looksLikeUtf16Be(content)) {
    if (containsKnownSecretSignature(stripTrailingNuls(decodeUtf16Be(content)))) return true;
  }
  return containsSecretRepresentation(text);
}

export function containsSecretRepresentation(value: string): boolean {
  return containsKnownSecretSignature(value) || containsBase64EncodedSecret(value);
}

function containsBase64EncodedSecret(text: string): boolean {
  let inspected = 0;
  for (const match of text.matchAll(BASE64_CANDIDATE_PATTERN)) {
    if (inspected >= MAX_ENCODED_CANDIDATES) break;
    inspected += 1;
    const encoded = match[1];
    if (encoded === undefined || encoded.length % 4 === 1) continue;
    let decoded: Buffer;
    try { decoded = Buffer.from(encoded, "base64"); }
    catch { continue; }
    if (decoded.byteLength === 0) continue;
    if (containsKnownSecretSignature(decoded.toString("utf8")) || containsBinarySecretRepresentation(decoded)) return true;
  }
  return false;
}

function redactEncodedSecretRepresentations(text: string): { text: string; redacted: boolean } {
  let redacted = false;
  const next = text.replace(BASE64_CANDIDATE_PATTERN, (whole, encoded: string) => {
    if (encoded.length % 4 === 1) return whole;
    let decoded: Buffer;
    try { decoded = Buffer.from(encoded, "base64"); }
    catch { return whole; }
    if (!containsKnownSecretSignature(decoded.toString("utf8")) && !containsBinarySecretRepresentation(decoded)) return whole;
    redacted = true;
    return whole.replace(encoded, "[REDACTED]");
  });
  return { text: next, redacted };
}

/**
 * Detect private-key containers without treating arbitrary binary data as a
 * credential. Node's DER parser validates the private-key structure for the
 * supported PKCS#8, PKCS#1, and SEC1 encodings; public SPKI material is not
 * accepted by these type-specific parsers. OpenSSH's binary envelope has a
 * separate fixed magic prefix.
 */
function containsBinarySecretRepresentation(content: Buffer): boolean {
  const opensshMagic = Buffer.from("openssh-key-v1\0", "utf8");
  if (content.byteLength >= opensshMagic.byteLength && content.subarray(0, opensshMagic.byteLength).equals(opensshMagic)) return true;
  if (content.byteLength < 16 || content.byteLength > MAX_BINARY_KEY_PARSE_BYTES || content[0] !== 0x30) return false;
  // EncryptedPrivateKeyInfo cannot be parsed without a passphrase. PBES2 is
  // the standard encrypted PKCS#8 algorithm identifier, so treat the exact
  // DER OID as a private-key container rather than attempting decryption.
  if (content.indexOf(Buffer.from("06092a864886f70d01050d", "hex")) >= 0) return true;
  for (const type of ["pkcs8", "pkcs1", "sec1"] as const) {
    try {
      createPrivateKey({ key: content, format: "der", type });
      return true;
    } catch {
      // A non-private DER value or another binary format is not a match.
    }
  }
  return false;
}

function looksLikeUtf16Le(content: Buffer): boolean {
  if (content.byteLength < 16 || content.byteLength % 2 !== 0) return false;
  if (content[0] === 0xff && content[1] === 0xfe) return true;
  let zeroOdd = 0;
  let pairs = 0;
  for (let index = 1; index < content.byteLength; index += 2) {
    pairs += 1;
    if (content[index] === 0) zeroOdd += 1;
  }
  return pairs > 0 && zeroOdd / pairs >= 0.6;
}

function looksLikeUtf16Be(content: Buffer): boolean {
  if (content.byteLength < 16 || content.byteLength % 2 !== 0) return false;
  if (content[0] === 0xfe && content[1] === 0xff) return true;
  let zeroEven = 0;
  let pairs = 0;
  for (let index = 0; index < content.byteLength; index += 2) {
    pairs += 1;
    if (content[index] === 0) zeroEven += 1;
  }
  return pairs > 0 && zeroEven / pairs >= 0.6;
}

function decodeUtf16Be(content: Buffer): string {
  const start = content[0] === 0xfe && content[1] === 0xff ? 2 : 0;
  const swapped = Buffer.allocUnsafe(content.byteLength - start);
  for (let source = start, target = 0; source + 1 < content.byteLength; source += 2, target += 2) {
    swapped[target] = content[source + 1]!;
    swapped[target + 1] = content[source]!;
  }
  return swapped.toString("utf16le");
}

function stripTrailingNuls(value: string): string {
  return value.replace(/\u0000+$/gu, "");
}

function utf8Prefix(value: Buffer, maxBytes: number): string {
  let end = Math.min(value.byteLength, maxBytes);
  while (end > 0) {
    const prefix = value.subarray(0, end).toString("utf8");
    if (Buffer.byteLength(prefix, "utf8") <= maxBytes) return prefix;
    end -= 1;
  }
  return "";
}
