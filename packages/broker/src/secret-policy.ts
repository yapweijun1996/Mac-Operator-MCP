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
