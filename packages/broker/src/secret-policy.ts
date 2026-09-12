import { basename } from "node:path";
import { BrokerError } from "@mac-operator/contracts";

const DENIED_BASENAMES = new Set([
  ".git-credentials", ".netrc", ".npmrc", ".pypirc", "application_default_credentials.json",
  "credentials", "credentials.json", "id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"
]);

const DENIED_PATH_FRAGMENTS = [
  "/.ssh/", "/.gnupg/", "/.aws/", "/.azure/", "/.config/gcloud/", "/.kube/",
  "/library/keychains/", "/library/mail/", "/library/messages/", "/library/safari/",
  "/library/application support/google/chrome/", "/photos library.photoslibrary/"
];

const SECRET_CONTENT_PATTERNS = [
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /\bAIza[0-9A-Za-z_-]{30,}\b/u,
  /\bgh[pousr]_[0-9A-Za-z]{20,}\b/u,
  /\bsk-proj-[0-9A-Za-z_-]{16,}\b/u,
  /\bxox[baprs]-[0-9A-Za-z-]{16,}\b/u,
  /\b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token)\s*[:=]\s*["']?[^\s"']{8,}/iu
];

const LOG_SECRET_REDACTION_PATTERNS: readonly RegExp[] = [
  /-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----/gu,
  /\bAKIA[0-9A-Z]{16}\b/gu,
  /\bAIza[0-9A-Za-z_-]{30,}\b/gu,
  /\bgh[pousr]_[0-9A-Za-z]{20,}\b/gu,
  /\bsk-proj-[0-9A-Za-z_-]{16,}\b/gu,
  /\bxox[baprs]-[0-9A-Za-z-]{16,}\b/gu,
  /\b(?:api[_-]?key|client[_-]?secret|password|passwd|secret|token)\s*[:=]\s*["']?[^\s"']{8,}/giu,
  /(?:\/Users\/[^\s/]+|\/var\/root)\/(?:\.ssh|\.gnupg|\.aws|\.azure|\.kube|Library\/(?:Keychains|Mail|Messages|Safari|Application Support\/Google\/Chrome))[^\s]*/giu
];

export function assertContentPathAllowed(path: string): void {
  const normalized = path.normalize("NFKC").toLocaleLowerCase("en-US");
  const name = basename(normalized);
  if (name === ".env" || name.startsWith(".env.") || DENIED_BASENAMES.has(name) ||
      DENIED_PATH_FRAGMENTS.some((fragment) => `${normalized}/`.includes(fragment))) {
    throw new BrokerError("POLICY_DENIED", "Filesystem content is inside a protected secret zone");
  }
  if (normalized.endsWith("/.docker/config.json") || normalized.endsWith("/.kube/config")) {
    throw new BrokerError("POLICY_DENIED", "Filesystem content is inside a protected secret zone");
  }
}

export function assertContentDoesNotContainSecrets(content: Buffer): void {
  const text = content.toString("utf8");
  if (SECRET_CONTENT_PATTERNS.some((pattern) => pattern.test(text))) {
    throw new BrokerError("POLICY_DENIED", "Filesystem content matched a protected secret signature");
  }
}

export function redactLogText(value: string): { text: string; redacted: boolean } {
  let text = value;
  let redacted = false;
  for (const pattern of LOG_SECRET_REDACTION_PATTERNS) {
    const next = text.replace(pattern, "[REDACTED]");
    redacted ||= next !== text;
    text = next;
  }
  if (text.length > 8192) {
    text = `${text.slice(0, 8180)}…[TRUNCATED]`;
    redacted = true;
  }
  return { text, redacted };
}
