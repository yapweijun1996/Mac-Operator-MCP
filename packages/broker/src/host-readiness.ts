import { isPlainDataRecord } from "./plain-record.js";

const MAX_EVIDENCE_AGE_MS = 10 * 60 * 1_000;
const HOST_PLATFORMS = new Set(["darwin"]);

export interface MacOsHostReadinessEvidence {
  schemaVersion: "0.1";
  mechanism: "macos-host-readiness-v1";
  status: "ready" | "blocked" | "unsupported-platform";
  failClosed: true;
  capturedAtMs: number;
  readyForRelease: boolean;
  readyForGui: boolean;
  persistentServiceVerified: boolean;
  host: {
    platform: "darwin";
    arch: string;
    ownerUid: number;
  };
  signing: {
    status: "read" | "unavailable";
    validIdentityCount: number;
    developerIdCount: number;
    ready: boolean;
  };
  gatekeeper: {
    status: "read" | "unavailable";
    enabled: boolean;
  };
  accessibility: {
    status: string;
    failClosed: true;
  };
  launchd: readonly {
    label: string;
    status: string;
    present: boolean;
  }[];
}

export interface HostReadinessRequirements {
  requireRelease?: boolean;
  requireGui?: boolean;
  nowMs?: number;
  ownerUid?: number;
  platform?: string;
  arch?: string;
}

/** Validate the owner-only host evidence consumed by production startup. */
export function validateMacOsHostReadinessEvidence(
  value: unknown,
  requirements: HostReadinessRequirements = {}
): MacOsHostReadinessEvidence {
  if (!isPlainDataRecord(value) ||
      !hasExactKeys(value, [
        "accessibility", "capturedAtMs", "failClosed", "gatekeeper", "host", "launchd", "mechanism",
        "persistentServiceVerified", "readyForGui", "readyForRelease", "schemaVersion", "signing", "status"
      ])) {
    throw new Error("Host readiness evidence is malformed");
  }
  if (value.schemaVersion !== "0.1" || value.mechanism !== "macos-host-readiness-v1" || value.failClosed !== true ||
      value.status !== "ready" && value.status !== "blocked" && value.status !== "unsupported-platform") {
    throw new Error("Host readiness evidence identity is invalid");
  }
  if (!isSafeNonNegativeInteger(value.capturedAtMs) ||
      typeof value.readyForRelease !== "boolean" || typeof value.readyForGui !== "boolean" ||
      typeof value.persistentServiceVerified !== "boolean") {
    throw new Error("Host readiness evidence state is invalid");
  }
  const host = value.host;
  if (!isPlainDataRecord(host) || !hasExactKeys(host, ["arch", "ownerUid", "platform"]) ||
      typeof host.platform !== "string" || !HOST_PLATFORMS.has(host.platform) ||
      typeof host.arch !== "string" || host.arch.length < 1 || host.arch.length > 32 ||
      !isSafeNonNegativeInteger(host.ownerUid)) {
    throw new Error("Host readiness evidence host identity is invalid");
  }
  const signing = value.signing;
  if (!isPlainDataRecord(signing) || !hasExactKeys(signing, ["developerIdCount", "ready", "status", "validIdentityCount"]) ||
      (signing.status !== "read" && signing.status !== "unavailable") ||
      !isSafeNonNegativeInteger(signing.validIdentityCount) || !isSafeNonNegativeInteger(signing.developerIdCount) ||
      typeof signing.ready !== "boolean") {
    throw new Error("Host readiness signing evidence is invalid");
  }
  const gatekeeper = value.gatekeeper;
  if (!isPlainDataRecord(gatekeeper) || !hasExactKeys(gatekeeper, ["enabled", "status"]) ||
      (gatekeeper.status !== "read" && gatekeeper.status !== "unavailable") || typeof gatekeeper.enabled !== "boolean") {
    throw new Error("Host readiness Gatekeeper evidence is invalid");
  }
  const accessibility = value.accessibility;
  if (!isPlainDataRecord(accessibility) || !hasExactKeys(accessibility, ["failClosed", "status"]) ||
      typeof accessibility.status !== "string" || accessibility.status.length < 1 || accessibility.status.length > 64 ||
      accessibility.failClosed !== true) {
    throw new Error("Host readiness Accessibility evidence is invalid");
  }
  if (!Array.isArray(value.launchd) || value.launchd.length > 16 || value.launchd.some((entry) => {
    if (!isPlainDataRecord(entry) || !hasExactKeys(entry, ["label", "present", "status"])) return true;
    return typeof entry.label !== "string" || entry.label.length < 1 || entry.label.length > 256 ||
      typeof entry.status !== "string" || entry.status.length < 1 || entry.status.length > 64 ||
      typeof entry.present !== "boolean";
  })) {
    throw new Error("Host readiness launchd evidence is invalid");
  }

  const nowMs = requirements.nowMs ?? Date.now();
  const ownerUid = requirements.ownerUid ?? process.getuid?.();
  const platform = requirements.platform ?? process.platform;
  const arch = requirements.arch ?? process.arch;
  if (!isSafeNonNegativeInteger(nowMs) || ownerUid === undefined || !isSafeNonNegativeInteger(ownerUid)) {
    throw new Error("Host readiness verification context is invalid");
  }
  if (host.platform !== platform || host.arch !== arch || host.ownerUid !== ownerUid) {
    throw new Error("Host readiness evidence belongs to another host");
  }
  if (value.capturedAtMs > nowMs || nowMs - value.capturedAtMs > MAX_EVIDENCE_AGE_MS) {
    throw new Error("Host readiness evidence is stale");
  }
  if (requirements.requireRelease === true && value.readyForRelease !== true) {
    throw new Error("Host readiness release evidence is not ready");
  }
  if (requirements.requireGui === true && value.readyForGui !== true) {
    throw new Error("Host readiness GUI evidence is not ready");
  }
  if (value.readyForRelease !== (signing.ready && gatekeeper.enabled && signing.developerIdCount > 0)) {
    throw new Error("Host readiness release state is inconsistent");
  }
  if (value.readyForGui !== (accessibility.status === "observed")) {
    throw new Error("Host readiness GUI state is inconsistent");
  }
  return freezeEvidence(value as unknown as MacOsHostReadinessEvidence);
}

function freezeEvidence(value: MacOsHostReadinessEvidence): MacOsHostReadinessEvidence {
  Object.freeze(value.host);
  Object.freeze(value.signing);
  Object.freeze(value.gatekeeper);
  Object.freeze(value.accessibility);
  for (const entry of value.launchd) Object.freeze(entry);
  Object.freeze(value.launchd);
  return Object.freeze(value);
}

function hasExactKeys(value: Record<string, unknown>, required: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  const expected = [...required].sort();
  return keys.length === expected.length && keys.every((key, index) => key === expected[index]);
}

function isSafeNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
