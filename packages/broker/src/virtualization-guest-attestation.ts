import { createPrivateKey, createPublicKey, verify, type KeyObject } from "node:crypto";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";

const EVIDENCE_REFERENCE_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;
const SANDBOX_PROFILE_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const RUNTIME_VERSION_PATTERN = /^[A-Za-z0-9._:+/-]{1,128}$/u;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const DEFAULT_ALLOWED_CLOCK_SKEW_MS = 5_000;
const DEFAULT_MAX_ATTESTATION_LIFETIME_MS = 24 * 60 * 60 * 1_000;

/** Host-owned identity of the immutable guest image and runtime. */
export interface VirtualizationGuestIdentity {
  imageSha256: string;
  runtimeVersion: string;
}

/** Unsigned attestation claims emitted by a guest adapter. */
export interface VirtualizationGuestAttestation {
  schemaVersion: "0.1";
  guestIdentity: VirtualizationGuestIdentity;
  sandboxProfile: string;
  filesystem: "guest-private";
  network: "profile-bound";
  credentials: "host-credentials-unavailable";
  processTree: "guest-owned";
  processTreePolicy: "single_process" | "owned_group";
  evidenceRef: string;
  attestationDigest: string;
}

export interface VirtualizationGuestAttestationVerificationKey {
  keyId: string;
  publicKeyPem: string | Buffer;
  notBeforeMs?: number;
  expiresAtMs?: number;
}

export interface SignedVirtualizationGuestAttestation {
  schemaVersion: "0.1";
  keyId: string;
  algorithm: "Ed25519";
  issuedAtMs: number;
  expiresAtMs: number;
  payloadDigest: string;
  payload: VirtualizationGuestAttestation;
  signature: string;
}

export type UnsignedVirtualizationGuestAttestation = Omit<SignedVirtualizationGuestAttestation, "signature">;

export interface VerifiedVirtualizationGuestAttestation {
  attestation: VirtualizationGuestAttestation;
  keyId: string;
  payloadDigest: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

/**
 * Returns the exact canonical bytes a guest attestation signer must sign.
 * The key, algorithm, freshness window, payload digest, and claims are all
 * covered; changing any envelope field invalidates the signature.
 */
export function virtualizationGuestAttestationSigningPayload(
  envelope: UnsignedVirtualizationGuestAttestation
): Buffer {
  return Buffer.from(canonicalJson(envelope), "utf8");
}

/**
 * Verifies short-lived, key-bound guest provenance before a task can run.
 * Trusted keys are supplied by startup configuration; MCP arguments never
 * select a key or alter the revocation/freshness policy.
 */
export class VirtualizationGuestAttestationVerifier {
  private constructor(
    private readonly trustedKeys: ReadonlyMap<string, { publicKey: KeyObject; notBeforeMs: number; expiresAtMs: number }>,
    private readonly revocationCheck: (keyId: string) => boolean,
    private readonly now: () => number,
    private readonly allowedClockSkewMs: number,
    private readonly maxAttestationLifetimeMs: number
  ) {}

  static create(options: {
    trustedKeys: readonly VirtualizationGuestAttestationVerificationKey[];
    revocationCheck?: (keyId: string) => boolean;
    now?: () => number;
    allowedClockSkewMs?: number;
    maxAttestationLifetimeMs?: number;
  }): VirtualizationGuestAttestationVerifier {
    if (!Array.isArray(options.trustedKeys) || options.trustedKeys.length < 1 || options.trustedKeys.length > 32) {
      throw new Error("At least one and no more than 32 guest attestation keys are required");
    }
    const allowedClockSkewMs = options.allowedClockSkewMs ?? DEFAULT_ALLOWED_CLOCK_SKEW_MS;
    const maxAttestationLifetimeMs = options.maxAttestationLifetimeMs ?? DEFAULT_MAX_ATTESTATION_LIFETIME_MS;
    if (!Number.isSafeInteger(allowedClockSkewMs) || allowedClockSkewMs < 0 || allowedClockSkewMs > 300_000 ||
        !Number.isSafeInteger(maxAttestationLifetimeMs) || maxAttestationLifetimeMs < 1 || maxAttestationLifetimeMs > 7 * 24 * 60 * 60 * 1_000) {
      throw new Error("Guest attestation verifier bounds are invalid");
    }
    const trustedKeys = new Map<string, { publicKey: KeyObject; notBeforeMs: number; expiresAtMs: number }>();
    for (const configured of options.trustedKeys) {
      if (configured === null || typeof configured !== "object" ||
          !KEY_ID_PATTERN.test(configured.keyId) || trustedKeys.has(configured.keyId)) {
        throw new Error("Guest attestation key identity is duplicated or malformed");
      }
      const notBeforeMs = configured.notBeforeMs ?? 0;
      const expiresAtMs = configured.expiresAtMs ?? Number.MAX_SAFE_INTEGER;
      if (!Number.isSafeInteger(notBeforeMs) || notBeforeMs < 0 ||
          !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= notBeforeMs) {
        throw new Error(`Guest attestation key validity window is invalid: ${configured.keyId}`);
      }
      assertPublicKeyMaterial(configured.publicKeyPem);
      const publicKey = createPublicKey(configured.publicKeyPem);
      if (publicKey.asymmetricKeyType !== "ed25519") {
        throw new Error("Guest attestation verification key must be Ed25519");
      }
      trustedKeys.set(configured.keyId, { publicKey, notBeforeMs, expiresAtMs });
    }
    return new VirtualizationGuestAttestationVerifier(
      trustedKeys,
      options.revocationCheck ?? (() => false),
      options.now ?? Date.now,
      allowedClockSkewMs,
      maxAttestationLifetimeMs
    );
  }

  verify(raw: unknown): VerifiedVirtualizationGuestAttestation {
    if (!isPlainDataRecord(raw)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation envelope is unavailable");
    }
    const envelope = raw as Partial<SignedVirtualizationGuestAttestation>;
    const allowedKeys = new Set([
      "algorithm", "expiresAtMs", "issuedAtMs", "keyId", "payload", "payloadDigest", "schemaVersion", "signature"
    ]);
    if (Object.keys(raw).some((key) => !allowedKeys.has(key)) ||
        envelope.schemaVersion !== "0.1" || envelope.algorithm !== "Ed25519" ||
        typeof envelope.keyId !== "string" || !KEY_ID_PATTERN.test(envelope.keyId) ||
        typeof envelope.issuedAtMs !== "number" || typeof envelope.expiresAtMs !== "number" ||
        typeof envelope.payloadDigest !== "string" || !SHA256_PATTERN.test(envelope.payloadDigest) ||
        typeof envelope.signature !== "string" || !BASE64_PATTERN.test(envelope.signature) || envelope.signature.length === 0) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation envelope is malformed");
    }
    const keyId = envelope.keyId;
    const issuedAtMs = envelope.issuedAtMs;
    const expiresAtMs = envelope.expiresAtMs;
    const payloadDigest = envelope.payloadDigest;
    const signatureText = envelope.signature;
    if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0 ||
        !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= issuedAtMs ||
        expiresAtMs - issuedAtMs > this.maxAttestationLifetimeMs ||
        signatureText.length % 4 !== 0) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation signature encoding is malformed");
    }
    const payload = validateVirtualizationGuestAttestation(envelope.payload);
    const payloadBytes = Buffer.from(canonicalJson(payload), "utf8");
    if (sha256(payloadBytes) !== payloadDigest) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation payload digest is invalid");
    }
    const key = this.trustedKeys.get(keyId);
    if (!key) throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation key is not trusted");
    if (this.revocationCheck(keyId)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation key is revoked");
    }
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0 ||
        nowMs + this.allowedClockSkewMs < key.notBeforeMs || nowMs >= key.expiresAtMs ||
        issuedAtMs < key.notBeforeMs || expiresAtMs > key.expiresAtMs ||
        issuedAtMs > nowMs + this.allowedClockSkewMs || nowMs >= expiresAtMs) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation is outside its validity window");
    }
    const unsigned: UnsignedVirtualizationGuestAttestation = {
      schemaVersion: "0.1",
      keyId,
      algorithm: "Ed25519",
      issuedAtMs,
      expiresAtMs,
      payloadDigest,
      payload
    };
    const signature = Buffer.from(signatureText, "base64");
    if (signature.length < 1 || !verify(null, virtualizationGuestAttestationSigningPayload(unsigned), key.publicKey, signature)) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation signature is invalid");
    }
    return {
      attestation: payload,
      keyId,
      payloadDigest,
      issuedAtMs,
      expiresAtMs
    };
  }
}

/** Refuse private key material even when Node could derive a public key from it. */
function assertPublicKeyMaterial(value: string | Buffer): void {
  try {
    createPrivateKey(value);
  } catch {
    return;
  }
  throw new Error("Guest attestation verification key must contain public material only");
}

export function isVirtualizationGuestIdentity(value: unknown): value is VirtualizationGuestIdentity {
  if (!isPlainDataRecord(value)) return false;
  const record = value as Record<string, unknown>;
  return Object.keys(record).every((key) => key === "imageSha256" || key === "runtimeVersion") &&
    typeof record.imageSha256 === "string" && SHA256_PATTERN.test(record.imageSha256) &&
    typeof record.runtimeVersion === "string" && RUNTIME_VERSION_PATTERN.test(record.runtimeVersion);
}

export function parseVirtualizationGuestIdentity(value: unknown): VirtualizationGuestIdentity {
  if (!isVirtualizationGuestIdentity(value)) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest identity is malformed");
  }
  return { imageSha256: value.imageSha256, runtimeVersion: value.runtimeVersion };
}

export function sameVirtualizationGuestIdentity(
  expected: VirtualizationGuestIdentity,
  actual: VirtualizationGuestIdentity | null
): boolean {
  return actual !== null &&
    isVirtualizationGuestIdentity(actual) &&
    actual.imageSha256 === expected.imageSha256 &&
    actual.runtimeVersion === expected.runtimeVersion;
}

export function validateVirtualizationGuestAttestation(value: unknown): VirtualizationGuestAttestation {
  if (!isPlainDataRecord(value)) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation is unavailable");
  }
  const attestation = value as Partial<VirtualizationGuestAttestation>;
  const allowedKeys = new Set([
    "attestationDigest", "credentials", "evidenceRef", "filesystem", "guestIdentity",
    "network", "processTree", "processTreePolicy", "sandboxProfile", "schemaVersion"
  ]);
  if (Object.keys(value).some((key) => !allowedKeys.has(key)) ||
      attestation.schemaVersion !== "0.1" ||
      !isVirtualizationGuestIdentity(attestation.guestIdentity) ||
      typeof attestation.sandboxProfile !== "string" ||
      !SANDBOX_PROFILE_PATTERN.test(attestation.sandboxProfile) ||
      attestation.filesystem !== "guest-private" ||
      attestation.network !== "profile-bound" ||
      attestation.credentials !== "host-credentials-unavailable" ||
      attestation.processTree !== "guest-owned" ||
      (attestation.processTreePolicy !== "single_process" && attestation.processTreePolicy !== "owned_group") ||
      typeof attestation.evidenceRef !== "string" ||
      !EVIDENCE_REFERENCE_PATTERN.test(attestation.evidenceRef) ||
      typeof attestation.attestationDigest !== "string" ||
      !SHA256_PATTERN.test(attestation.attestationDigest)) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation is malformed");
  }
  const unsigned = {
    schemaVersion: "0.1" as const,
    guestIdentity: parseVirtualizationGuestIdentity(attestation.guestIdentity),
    sandboxProfile: attestation.sandboxProfile,
    filesystem: "guest-private" as const,
    network: "profile-bound" as const,
    credentials: "host-credentials-unavailable" as const,
    processTree: "guest-owned" as const,
    processTreePolicy: attestation.processTreePolicy,
    evidenceRef: attestation.evidenceRef
  };
  if (sha256(canonicalJson(unsigned)) !== attestation.attestationDigest) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest attestation digest is invalid");
  }
  return { ...unsigned, attestationDigest: attestation.attestationDigest };
}
