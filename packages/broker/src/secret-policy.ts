import { basename } from "node:path";
import { BrokerError } from "@mac-operator/contracts";

const DENIED_BASENAMES = new Set([
  ".git-credentials", ".netrc", ".npmrc", ".pypirc", "application_default_credentials.json",
  "credentials", "credentials.json", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"
]);

const DENIED_PATH_FRAGMENTS = [
  "/.ssh/", "/.gnupg/", "/.aws/", "/.azure/", "/.config/gcloud/", "/.config/gh/", "/.kube/", "/.docker/",
  "/library/keychains/", "/library/mail/", "/library/messages/", "/library/safari/",
  "/library/application support/google/chrome/", "/library/application support/bravesoftware/brave-browser/",
  "/library/application support/microsoft edge/", "/library/containers/com.apple.mail/",
  "/library/containers/com.apple.messages/", "/library/containers/com.apple.safari/",
  "/photos library.photoslibrary/"
];

const SECRET_CONTENT_PATTERNS = [
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\bAIza[0-9A-Za-z_-]{30,}\b/u,
  /\bgh[pousr]_[0-9A-Za-z]{20,}\b/u,
  /\bsk-proj-[0-9A-Za-z_-]{16,}\b/u,
  /\bBearer\s+[A-Za-z0-9._~+\/-]{16,}\b/iu,
  /\bBasic\s+[A-Za-z0-9+/=]{16,}\b/iu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/u,
  /\bxox[baprs]-[0-9A-Za-z-]{16,}\b/u,
  /\b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token)\s*[:=]\s*["']?[^\s"']{8,}/iu
];

/**
 * Command-line option names are observable through process listings. A task
 * cannot safely pass credentials in argv even when the value itself does not
 * match one of the known token formats, so sensitive option names are denied
 * before a child process is created.
 */
const SECRET_ARGUMENT_NAME_PATTERN = /(?:^|[-_])(?:api[_-]?key|auth(?:entication)?|client[_-]?secret|credential|password|passwd|passphrase|private[_-]?key|secret|token|bearer|cookie)(?:[-_]|$)/iu;

const LOG_SECRET_REDACTION_PATTERNS: readonly RegExp[] = [
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/gu,
  /\bAKIA[0-9A-Z]{16}\b/gu,
  /\bAIza[0-9A-Za-z_-]{30,}\b/gu,
  /\bgh[pousr]_[0-9A-Za-z]{20,}\b/gu,
  /\bsk-proj-[0-9A-Za-z_-]{16,}\b/gu,
  /\bBearer\s+[A-Za-z0-9._~+\/-]{16,}\b/giu,
  /\bBasic\s+[A-Za-z0-9+/=]{16,}\b/giu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gu,
  /\bxox[baprs]-[0-9A-Za-z-]{16,}\b/gu,
  /\b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token)\s*[:=]\s*["']?[^\s"']{8,}/giu,
  /(?:\/(?:private\/)?Users\/[^/\s]+|\/(?:private\/)?var\/root)\/(?:\.ssh|\.gnupg|\.aws|\.azure|\.config\/(?:gcloud|gh)|\.kube|\.docker|Library\/(?:Keychains|Mail|Messages|Safari|Application Support\/(?:Google\/Chrome|BraveSoftware\/Brave-Browser|Microsoft Edge)|Containers\/com\.apple\.(?:mail|messages|safari))|Photos Library\.photoslibrary)(?:[^\r\n,;)]*)/giu
];

export function assertContentPathAllowed(path: string): void {
  const normalized = path.normalize("NFKC").toLocaleLowerCase("en-US");
  const name = basename(normalized);
  if (name === ".env" || name.startsWith(".env.") || DENIED_BASENAMES.has(name) ||
      DENIED_PATH_FRAGMENTS.some((fragment) => `${normalized}/`.includes(fragment))) {
    throw new BrokerError("POLICY_DENIED", "Filesystem content is inside a protected secret zone");
  }
}

export function assertContentDoesNotContainSecrets(content: Buffer): void {
  const text = content.toString("utf8");
  if (SECRET_CONTENT_PATTERNS.some((pattern) => pattern.test(text))) {
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
    if (SECRET_CONTENT_PATTERNS.some((pattern) => pattern.test(argument))) {
      throw new BrokerError("POLICY_DENIED", "Process arguments matched a protected secret signature");
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
    if (typeof value !== "string" || containsKnownSecretSignature(value)) {
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

function utf8Prefix(value: Buffer, maxBytes: number): string {
  let end = Math.min(value.byteLength, maxBytes);
  while (end > 0) {
    const prefix = value.subarray(0, end).toString("utf8");
    if (Buffer.byteLength(prefix, "utf8") <= maxBytes) return prefix;
    end -= 1;
  }
  return "";
}
