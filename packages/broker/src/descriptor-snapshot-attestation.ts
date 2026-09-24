import { constants } from "node:fs";
import { createHash, createPrivateKey, createPublicKey, KeyObject, randomBytes, sign, verify } from "node:crypto";
import { lstat, open, realpath, type FileHandle } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";

const SNAPSHOT_AUDIENCE = "mac-operator-descriptor-helper-v0.1" as const;
const APP_SANDBOX_SNAPSHOT_AUDIENCE = "mac-operator-app-sandbox-helper-v0.1" as const;
const SNAPSHOT_AUDIENCES = new Set([SNAPSHOT_AUDIENCE, APP_SANDBOX_SNAPSHOT_AUDIENCE]);
const SNAPSHOT_SCHEMA_VERSION = "0.1" as const;
const SNAPSHOT_ALGORITHM = "Ed25519" as const;
const SNAPSHOT_REF_PATTERN = /^snapshot:[a-f0-9]{48}$/u;
const PROFILE_PATTERN = /^[A-Za-z0-9._:-]{1,128}$/u;
const KEY_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u;
const DEFAULT_MAX_LIFETIME_MS = 30_000;
const MAX_LIFETIME_MS = 60_000;
const DEFAULT_MAX_SNAPSHOTS = 64;
const MAX_SNAPSHOTS = 256;
const MAX_EXECUTABLE_DIGEST_BYTES = 64 * 1024 * 1024;
const MAX_SCRIPT_DIGEST_BYTES = 16 * 1024 * 1024;
const EXECUTABLE_DIGEST_READ_CHUNK_BYTES = 1024 * 1024;

export type DescriptorSnapshotNetworkPolicy = "none" | "allowlist";
export type DescriptorSnapshotProcessTreePolicy = "single_process" | "owned_group";

/**
 * Non-secret plan facts that may cross a future descriptor-helper boundary.
 * Paths, argv, environment values, filesystem roots, and network destinations
 * are represented only by Broker-owned digests.
 */
export type DescriptorSnapshotAudience = typeof SNAPSHOT_AUDIENCE | typeof APP_SANDBOX_SNAPSHOT_AUDIENCE;

export interface DescriptorSnapshotAttestation {
  schemaVersion: typeof SNAPSHOT_SCHEMA_VERSION;
  audience: DescriptorSnapshotAudience;
  snapshotRef: string;
  profile: string;
  taskDescriptorDigest: string;
  argsDigest: string;
  environmentDigest: string;
  filesystemRootsDigest: string;
  sandboxProfile: string;
  networkPolicy: DescriptorSnapshotNetworkPolicy;
  processTreePolicy: DescriptorSnapshotProcessTreePolicy;
  credentialPolicy: "none";
  /** The native handoff must still prove an immutable selection mechanism. */
  immutableSelection: "revalidation-only";
  executableContentSha256: string;
  executableIdentityDigest: string;
  cwdIdentityDigest: string;
}

export interface UnsignedDescriptorSnapshotAttestation {
  schemaVersion: typeof SNAPSHOT_SCHEMA_VERSION;
  keyId: string;
  algorithm: typeof SNAPSHOT_ALGORITHM;
  issuedAtMs: number;
  expiresAtMs: number;
  payloadDigest: string;
  payload: DescriptorSnapshotAttestation;
}

export interface SignedDescriptorSnapshotAttestation extends UnsignedDescriptorSnapshotAttestation {
  signature: string;
}

export interface VerifiedDescriptorSnapshotAttestation {
  attestation: DescriptorSnapshotAttestation;
  keyId: string;
  payloadDigest: string;
  issuedAtMs: number;
  expiresAtMs: number;
}

/** Stable identity fields that a native helper can recompute from an FD. */
export interface DescriptorFileIdentity {
  /** APFS inode/device values may exceed JavaScript's safe integer range. */
  device: number | string;
  inode: number | string;
  ownerUid: number;
  ownerGid: number;
  mode: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  contentSha256?: string;
}

export interface DescriptorSnapshotPreparationInput {
  audience?: DescriptorSnapshotAudience;
  profile: string;
  executablePath: string;
  cwdPath: string;
  /** Optional Broker-owned script source for the fixed App Sandbox interpreter path. */
  scriptPath?: string;
  taskDescriptorDigest: string;
  argsDigest: string;
  environmentDigest: string;
  filesystemRootsDigest: string;
  sandboxProfile: string;
  networkPolicy: DescriptorSnapshotNetworkPolicy;
  processTreePolicy: DescriptorSnapshotProcessTreePolicy;
}

export interface PreparedDescriptorSnapshot {
  snapshotRef: string;
  attestation: SignedDescriptorSnapshotAttestation;
}

/**
 * A borrowed handoff. The descriptor numbers are valid only while the
 * registry callback is running; the registry closes them before returning.
 * No pathname or command-line data is exposed to the callback.
 */
export interface DescriptorSnapshotHandoff {
  readonly executableFd: number;
  readonly cwdFd: number;
  readonly scriptFd?: number;
  readonly scriptContentSha256?: string;
  readonly attestation: SignedDescriptorSnapshotAttestation;
}

export interface DescriptorSnapshotSignerOptions {
  keyId: string;
  privateKey: string | Buffer | KeyObject;
  now?: () => number;
  maxLifetimeMs?: number;
}

/** Host-owned Ed25519 signer; private key material never enters an attestation. */
export class DescriptorSnapshotAttestationSigner {
  private readonly signerKeyId: string;
  private readonly privateKey: KeyObject;
  private readonly now: () => number;
  private readonly maxLifetimeMs: number;

  constructor(options: DescriptorSnapshotSignerOptions) {
    if (!KEY_ID_PATTERN.test(options.keyId)) throw new Error("Descriptor snapshot signer key ID is malformed");
    const maxLifetimeMs = options.maxLifetimeMs ?? DEFAULT_MAX_LIFETIME_MS;
    if (!Number.isSafeInteger(maxLifetimeMs) || maxLifetimeMs < 1 || maxLifetimeMs > MAX_LIFETIME_MS) {
      throw new Error("Descriptor snapshot signer lifetime is invalid");
    }
    const privateKey = options.privateKey instanceof KeyObject ? options.privateKey : createPrivateKey(options.privateKey);
    if (privateKey.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
      throw new Error("Descriptor snapshot signer key must be an Ed25519 private key");
    }
    this.signerKeyId = options.keyId;
    this.privateKey = privateKey;
    this.now = options.now ?? Date.now;
    this.maxLifetimeMs = maxLifetimeMs;
  }

  /** Host-owned identity used when provisioning the native helper verifier. */
  get keyId(): string {
    return this.signerKeyId;
  }

  /** Export only the Ed25519 public key; private key bytes never leave this signer. */
  exportPublicKey(): Buffer {
    return createPublicKey(this.privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  }

  sign(payload: DescriptorSnapshotAttestation, expiresAtMs?: number): SignedDescriptorSnapshotAttestation {
    validateDescriptorSnapshotAttestation(payload);
    const payloadSnapshot = { ...payload };
    const issuedAtMs = this.now();
    const effectiveExpiresAtMs = expiresAtMs ?? issuedAtMs + this.maxLifetimeMs;
    if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0 ||
        !Number.isSafeInteger(effectiveExpiresAtMs) || effectiveExpiresAtMs <= issuedAtMs ||
        effectiveExpiresAtMs - issuedAtMs > this.maxLifetimeMs) {
      throw new BrokerError("AUTH_EXPIRED", "Descriptor snapshot attestation lifetime is invalid");
    }
    const unsigned: UnsignedDescriptorSnapshotAttestation = {
      schemaVersion: SNAPSHOT_SCHEMA_VERSION,
      keyId: this.signerKeyId,
      algorithm: SNAPSHOT_ALGORITHM,
      issuedAtMs,
      expiresAtMs: effectiveExpiresAtMs,
      payloadDigest: sha256(canonicalJson(payloadSnapshot)),
      payload: payloadSnapshot
    };
    return freezeSnapshotAttestation({
      ...unsigned,
      signature: sign(null, descriptorSnapshotAttestationSigningPayload(unsigned), this.privateKey).toString("base64")
    });
  }
}

export interface DescriptorSnapshotVerificationKey {
  keyId: string;
  publicKey: string | Buffer | KeyObject;
  notBeforeMs?: number;
  expiresAtMs?: number;
}

/** Verifies helper-bound claims without trusting any path or caller argument. */
export class DescriptorSnapshotAttestationVerifier {
  private constructor(
    private readonly trustedKeys: ReadonlyMap<string, { publicKey: KeyObject; notBeforeMs: number; expiresAtMs: number }>,
    private readonly revocationCheck: (keyId: string) => boolean,
    private readonly now: () => number,
    private readonly allowedClockSkewMs: number,
    private readonly maxLifetimeMs: number
  ) {}

  static create(options: {
    trustedKeys: readonly DescriptorSnapshotVerificationKey[];
    revocationCheck?: (keyId: string) => boolean;
    now?: () => number;
    allowedClockSkewMs?: number;
    maxLifetimeMs?: number;
  }): DescriptorSnapshotAttestationVerifier {
    if (!Array.isArray(options.trustedKeys) || options.trustedKeys.length < 1 || options.trustedKeys.length > 32) {
      throw new Error("At least one descriptor snapshot verification key is required");
    }
    const allowedClockSkewMs = options.allowedClockSkewMs ?? 5_000;
    const maxLifetimeMs = options.maxLifetimeMs ?? DEFAULT_MAX_LIFETIME_MS;
    if (!Number.isSafeInteger(allowedClockSkewMs) || allowedClockSkewMs < 0 || allowedClockSkewMs > 300_000 ||
        !Number.isSafeInteger(maxLifetimeMs) || maxLifetimeMs < 1 || maxLifetimeMs > MAX_LIFETIME_MS) {
      throw new Error("Descriptor snapshot verifier bounds are invalid");
    }
    const trustedKeys = new Map<string, { publicKey: KeyObject; notBeforeMs: number; expiresAtMs: number }>();
    for (const configured of options.trustedKeys) {
      if (!KEY_ID_PATTERN.test(configured.keyId) || trustedKeys.has(configured.keyId)) {
        throw new Error("Descriptor snapshot verification key identity is duplicated or malformed");
      }
      const notBeforeMs = configured.notBeforeMs ?? 0;
      const expiresAtMs = configured.expiresAtMs ?? Number.MAX_SAFE_INTEGER;
      if (!Number.isSafeInteger(notBeforeMs) || notBeforeMs < 0 ||
          !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= notBeforeMs) {
        throw new Error("Descriptor snapshot verification key validity window is invalid");
      }
      assertPublicKey(configured.publicKey);
      const publicKey = configured.publicKey instanceof KeyObject ? configured.publicKey : createPublicKey(configured.publicKey);
      if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Descriptor snapshot verification key must be Ed25519");
      trustedKeys.set(configured.keyId, { publicKey, notBeforeMs, expiresAtMs });
    }
    return new DescriptorSnapshotAttestationVerifier(
      trustedKeys,
      options.revocationCheck ?? (() => false),
      options.now ?? Date.now,
      allowedClockSkewMs,
      maxLifetimeMs
    );
  }

  verify(raw: unknown): VerifiedDescriptorSnapshotAttestation {
    const envelope = snapshotSignedDescriptorSnapshotAttestation(raw);
    const key = this.trustedKeys.get(envelope.keyId);
    if (!key || this.revocationCheck(envelope.keyId)) {
      throw new BrokerError("POLICY_DENIED", "Descriptor snapshot attestation key is not trusted");
    }
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0 ||
        envelope.expiresAtMs - envelope.issuedAtMs > this.maxLifetimeMs ||
        nowMs + this.allowedClockSkewMs < key.notBeforeMs || nowMs >= key.expiresAtMs ||
        envelope.issuedAtMs < key.notBeforeMs || envelope.expiresAtMs > key.expiresAtMs ||
        envelope.issuedAtMs > nowMs + this.allowedClockSkewMs || nowMs >= envelope.expiresAtMs) {
      throw new BrokerError("POLICY_DENIED", "Descriptor snapshot attestation is outside its validity window");
    }
    if (sha256(canonicalJson(envelope.payload)) !== envelope.payloadDigest ||
        !verify(null, descriptorSnapshotAttestationSigningPayload({
          schemaVersion: envelope.schemaVersion,
          keyId: envelope.keyId,
          algorithm: envelope.algorithm,
          issuedAtMs: envelope.issuedAtMs,
          expiresAtMs: envelope.expiresAtMs,
          payloadDigest: envelope.payloadDigest,
          payload: envelope.payload
        }), key.publicKey, Buffer.from(envelope.signature, "base64"))) {
      throw new BrokerError("POLICY_DENIED", "Descriptor snapshot attestation signature is invalid");
    }
    return freezeSnapshotAttestation({
      attestation: envelope.payload,
      keyId: envelope.keyId,
      payloadDigest: envelope.payloadDigest,
      issuedAtMs: envelope.issuedAtMs,
      expiresAtMs: envelope.expiresAtMs
    });
  }
}

/** Exact bytes signed by the Broker and verified by the future helper. */
export function descriptorSnapshotAttestationSigningPayload(
  envelope: UnsignedDescriptorSnapshotAttestation
): Buffer {
  return Buffer.from(canonicalJson(envelope), "utf8");
}

export function validateDescriptorSnapshotAttestation(value: unknown): asserts value is DescriptorSnapshotAttestation {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, [
    "argsDigest", "audience", "credentialPolicy", "cwdIdentityDigest", "environmentDigest",
    "executableContentSha256", "executableIdentityDigest", "filesystemRootsDigest", "immutableSelection",
    "networkPolicy", "processTreePolicy", "profile", "sandboxProfile", "schemaVersion", "snapshotRef",
    "taskDescriptorDigest"
  ])) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot attestation payload is malformed");
  }
  const payload = value as Partial<DescriptorSnapshotAttestation>;
  if (payload.schemaVersion !== SNAPSHOT_SCHEMA_VERSION ||
      typeof payload.audience !== "string" || !SNAPSHOT_AUDIENCES.has(payload.audience as DescriptorSnapshotAudience) ||
      typeof payload.snapshotRef !== "string" || !SNAPSHOT_REF_PATTERN.test(payload.snapshotRef) ||
      typeof payload.profile !== "string" || !PROFILE_PATTERN.test(payload.profile) ||
      typeof payload.sandboxProfile !== "string" || !PROFILE_PATTERN.test(payload.sandboxProfile) ||
      !isSha256(payload.taskDescriptorDigest) || !isSha256(payload.argsDigest) ||
      !isSha256(payload.environmentDigest) || !isSha256(payload.filesystemRootsDigest) ||
      !isSha256(payload.executableContentSha256) || !isSha256(payload.executableIdentityDigest) ||
      !isSha256(payload.cwdIdentityDigest) ||
      (payload.networkPolicy !== "none" && payload.networkPolicy !== "allowlist") ||
      (payload.processTreePolicy !== "single_process" && payload.processTreePolicy !== "owned_group") ||
      payload.credentialPolicy !== "none" || payload.immutableSelection !== "revalidation-only") {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot attestation payload is malformed");
  }
}

export function snapshotSignedDescriptorSnapshotAttestation(value: unknown): SignedDescriptorSnapshotAttestation {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, [
    "algorithm", "expiresAtMs", "issuedAtMs", "keyId", "payload", "payloadDigest", "schemaVersion", "signature"
  ])) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot attestation envelope is malformed");
  }
  const envelope = value as Partial<SignedDescriptorSnapshotAttestation>;
  if (envelope.schemaVersion !== SNAPSHOT_SCHEMA_VERSION || envelope.algorithm !== SNAPSHOT_ALGORITHM ||
      typeof envelope.keyId !== "string" || !KEY_ID_PATTERN.test(envelope.keyId) ||
      !Number.isSafeInteger(envelope.issuedAtMs) || (envelope.issuedAtMs as number) < 0 ||
      !Number.isSafeInteger(envelope.expiresAtMs) || (envelope.expiresAtMs as number) <= (envelope.issuedAtMs as number) ||
      !isSha256(envelope.payloadDigest) || typeof envelope.signature !== "string" ||
      !BASE64_PATTERN.test(envelope.signature) || envelope.signature.length === 0 ||
      envelope.signature.length % 4 !== 0) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot attestation envelope is malformed");
  }
  const signatureBytes = Buffer.from(envelope.signature, "base64");
  if (signatureBytes.length !== 64) throw new BrokerError("POLICY_DENIED", "Descriptor snapshot attestation signature is malformed");
  if (envelope.payload === undefined) throw new BrokerError("POLICY_DENIED", "Descriptor snapshot attestation payload is unavailable");
  validateDescriptorSnapshotAttestation(envelope.payload);
  return freezeSnapshotAttestation({
    schemaVersion: SNAPSHOT_SCHEMA_VERSION,
    keyId: envelope.keyId,
    algorithm: SNAPSHOT_ALGORITHM,
    issuedAtMs: envelope.issuedAtMs as number,
    expiresAtMs: envelope.expiresAtMs as number,
    payloadDigest: envelope.payloadDigest,
    payload: envelope.payload,
    signature: envelope.signature
  });
}

export function descriptorFileIdentityDigest(identity: DescriptorFileIdentity): string {
  validateDescriptorFileIdentity(identity);
  return sha256(canonicalJson(identity));
}

/**
 * Native helper-side check: compare only FD-derived identity facts to the
 * signed attestation. It deliberately has no pathname or argv parameter.
 */
export function assertDescriptorSnapshotIdentity(
  attestation: DescriptorSnapshotAttestation,
  observed: { executable: DescriptorFileIdentity; cwd: DescriptorFileIdentity }
): void {
  validateDescriptorSnapshotAttestation(attestation);
  validateDescriptorFileIdentity(observed.executable, true);
  validateDescriptorFileIdentity(observed.cwd);
  if (observed.executable.contentSha256 !== attestation.executableContentSha256 ||
      descriptorFileIdentityDigest(observed.executable) !== attestation.executableIdentityDigest ||
      descriptorFileIdentityDigest(observed.cwd) !== attestation.cwdIdentityDigest) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot FD identity does not match the attestation");
  }
}

export interface DescriptorSnapshotRegistryOptions {
  /** Explicit opt-in; production construction must remain disabled by default. */
  enabled?: boolean;
  signer?: DescriptorSnapshotAttestationSigner;
  verifier?: DescriptorSnapshotAttestationVerifier;
  now?: () => number;
  lifetimeMs?: number;
  maxSnapshots?: number;
}

interface SnapshotEntry {
  snapshot: PreparedDescriptorSnapshot;
  executableHandle: FileHandle;
  cwdHandle: FileHandle;
  scriptHandle?: FileHandle;
  executable: DescriptorFileIdentity;
  cwd: DescriptorFileIdentity;
  script?: DescriptorFileIdentity;
  expiresAtMs: number;
  claimed: boolean;
}

/**
 * Holds Broker-opened descriptors behind an opaque, one-shot reference. This
 * is a preparation seam for a future native helper and does not prove kernel
 * immutable selection or close-on-exec by itself.
 */
export class DescriptorSnapshotRegistry {
  private readonly enabled: boolean;
  private readonly signer: DescriptorSnapshotAttestationSigner | undefined;
  private readonly verifier: DescriptorSnapshotAttestationVerifier | undefined;
  private readonly now: () => number;
  private readonly lifetimeMs: number;
  private readonly maxSnapshots: number;
  private readonly entries = new Map<string, SnapshotEntry>();
  private closed = false;

  constructor(options: DescriptorSnapshotRegistryOptions = {}) {
    this.enabled = options.enabled ?? false;
    this.signer = options.signer;
    this.verifier = options.verifier;
    this.now = options.now ?? Date.now;
    this.lifetimeMs = options.lifetimeMs ?? DEFAULT_MAX_LIFETIME_MS;
    this.maxSnapshots = options.maxSnapshots ?? DEFAULT_MAX_SNAPSHOTS;
    if (typeof this.enabled !== "boolean" || !Number.isSafeInteger(this.lifetimeMs) ||
        this.lifetimeMs < 1 || this.lifetimeMs > MAX_LIFETIME_MS ||
        !Number.isSafeInteger(this.maxSnapshots) || this.maxSnapshots < 1 || this.maxSnapshots > MAX_SNAPSHOTS ||
        (this.enabled && (this.signer === undefined || this.verifier === undefined))) {
      throw new Error("Descriptor snapshot registry options are invalid");
    }
  }

  get available(): boolean {
    return this.enabled && !this.closed;
  }

  async prepare(input: DescriptorSnapshotPreparationInput): Promise<PreparedDescriptorSnapshot> {
    if (!this.available) throw new BrokerError("UNSUPPORTED_CAPABILITY", "Descriptor snapshot registry is not enabled");
    validatePreparationInput(input);
    await this.pruneExpired();
    if (this.entries.size >= this.maxSnapshots) {
      throw new BrokerError("AUDIT_UNAVAILABLE", "Descriptor snapshot registry is at capacity", true);
    }
    const issuedAtMs = this.now();
    if (!Number.isSafeInteger(issuedAtMs) || issuedAtMs < 0) throw new BrokerError("PRECONDITION_FAILED", "Descriptor snapshot clock is invalid");

    let executableHandle: FileHandle | undefined;
    let cwdHandle: FileHandle | undefined;
    let scriptHandle: FileHandle | undefined;
    try {
      const pathExecutable = await capturePathDescriptorIdentity(input.executablePath, true);
      const pathCwd = await capturePathDescriptorIdentity(input.cwdPath, false);
      const pathScript = input.scriptPath === undefined ? undefined : await captureRegularFileMetadata(input.scriptPath);
      executableHandle = await open(input.executablePath, constants.O_RDONLY | constants.O_NOFOLLOW);
      cwdHandle = await open(input.cwdPath, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
      if (input.scriptPath !== undefined) {
        scriptHandle = await open(input.scriptPath, constants.O_RDONLY | constants.O_NOFOLLOW);
      }
      const executable = await readDescriptorFileIdentity(executableHandle, true);
      const cwd = await readDescriptorFileIdentity(cwdHandle, false);
      const script = scriptHandle === undefined ? undefined : await readDescriptorFileIdentity(scriptHandle, true, MAX_SCRIPT_DIGEST_BYTES);
      if (!sameDescriptorFileIdentity(pathExecutable, executable) || !sameDescriptorFileIdentity(pathCwd, cwd)) {
        throw new BrokerError("POLICY_DENIED", "Descriptor snapshot target changed while opening");
      }
      if (pathScript !== undefined && (script === undefined || !sameDescriptorMetadata(pathScript, script))) {
        throw new BrokerError("POLICY_DENIED", "Descriptor snapshot script changed while opening");
      }
      const snapshotRef = `snapshot:${randomBytes(24).toString("hex")}`;
      const payload: DescriptorSnapshotAttestation = {
        schemaVersion: SNAPSHOT_SCHEMA_VERSION,
        audience: input.audience ?? SNAPSHOT_AUDIENCE,
        snapshotRef,
        profile: input.profile,
        taskDescriptorDigest: input.taskDescriptorDigest,
        argsDigest: input.argsDigest,
        environmentDigest: input.environmentDigest,
        filesystemRootsDigest: input.filesystemRootsDigest,
        sandboxProfile: input.sandboxProfile,
        networkPolicy: input.networkPolicy,
        processTreePolicy: input.processTreePolicy,
        credentialPolicy: "none",
        immutableSelection: "revalidation-only",
        executableContentSha256: executable.contentSha256!,
        executableIdentityDigest: descriptorFileIdentityDigest(executable),
        cwdIdentityDigest: descriptorFileIdentityDigest(cwd)
      };
      const attestation = this.signer!.sign(payload, issuedAtMs + this.lifetimeMs);
      const snapshot = freezeSnapshotAttestation({ snapshotRef, attestation });
      this.entries.set(snapshotRef, {
        snapshot,
        executableHandle,
        cwdHandle,
        ...(scriptHandle === undefined || script === undefined ? {} : { scriptHandle, script }),
        executable,
        cwd,
        ...(script === undefined ? {} : { script }),
        expiresAtMs: attestation.expiresAtMs,
        claimed: false
      });
      executableHandle = undefined;
      cwdHandle = undefined;
      scriptHandle = undefined;
      return snapshot;
    } finally {
      await executableHandle?.close().catch(() => undefined);
      await cwdHandle?.close().catch(() => undefined);
      await scriptHandle?.close().catch(() => undefined);
    }
  }

  async withSnapshot<T>(
    snapshot: PreparedDescriptorSnapshot,
    callback: (handoff: DescriptorSnapshotHandoff) => Promise<T> | T
  ): Promise<T> {
    if (!this.available) throw new BrokerError("UNSUPPORTED_CAPABILITY", "Descriptor snapshot registry is not enabled");
    if (typeof callback !== "function" || !isPlainDataRecord(snapshot) || !hasExactKeys(snapshot, ["attestation", "snapshotRef"]) ||
        typeof snapshot.snapshotRef !== "string" || !SNAPSHOT_REF_PATTERN.test(snapshot.snapshotRef)) {
      throw new BrokerError("PRECONDITION_FAILED", "Descriptor snapshot handoff is malformed");
    }
    const entry = this.entries.get(snapshot.snapshotRef);
    if (!entry || entry.claimed) throw new BrokerError("REPLAY_DENIED", "Descriptor snapshot was already consumed or is unavailable");
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new BrokerError("PRECONDITION_FAILED", "Descriptor snapshot clock is invalid");
    if (nowMs >= entry.expiresAtMs) {
      await this.disposeEntry(snapshot.snapshotRef, entry);
      throw new BrokerError("AUTH_EXPIRED", "Descriptor snapshot has expired");
    }
    const verified = this.verifier!.verify(snapshot.attestation);
    if (verified.attestation.snapshotRef !== snapshot.snapshotRef ||
        canonicalJson(snapshot.attestation) !== canonicalJson(entry.snapshot.attestation)) {
      throw new BrokerError("POLICY_DENIED", "Descriptor snapshot attestation is not bound to the registry entry");
    }
    entry.claimed = true;
    try {
      const executable = await readDescriptorFileIdentity(entry.executableHandle, true);
      const cwd = await readDescriptorFileIdentity(entry.cwdHandle, false);
      assertDescriptorSnapshotIdentity(verified.attestation, { executable, cwd });
      const script = entry.scriptHandle === undefined || entry.script === undefined
        ? undefined
        : await readDescriptorFileIdentity(entry.scriptHandle, true, MAX_SCRIPT_DIGEST_BYTES);
      if (script !== undefined && !sameDescriptorFileIdentity(entry.script!, script)) {
        throw new BrokerError("POLICY_DENIED", "Descriptor snapshot script changed before handoff");
      }
      const handoff: DescriptorSnapshotHandoff = Object.freeze({
        executableFd: entry.executableHandle.fd,
        cwdFd: entry.cwdHandle.fd,
        ...(entry.scriptHandle === undefined || entry.script === undefined ? {} : {
          scriptFd: entry.scriptHandle.fd,
          scriptContentSha256: entry.script.contentSha256!
        }),
        attestation: entry.snapshot.attestation
      });
      return await callback(handoff);
    } finally {
      await this.disposeEntry(snapshot.snapshotRef, entry);
    }
  }

  async release(snapshotRef: string): Promise<void> {
    const entry = this.entries.get(snapshotRef);
    if (entry !== undefined) await this.disposeEntry(snapshotRef, entry);
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    const entries = [...this.entries.entries()];
    for (const [snapshotRef, entry] of entries) await this.disposeEntry(snapshotRef, entry);
  }

  private async pruneExpired(): Promise<void> {
    const nowMs = this.now();
    if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new BrokerError("PRECONDITION_FAILED", "Descriptor snapshot clock is invalid");
    for (const [snapshotRef, entry] of this.entries) {
      if (nowMs >= entry.expiresAtMs) await this.disposeEntry(snapshotRef, entry);
    }
  }

  private async disposeEntry(snapshotRef: string, entry: SnapshotEntry): Promise<void> {
    if (this.entries.get(snapshotRef) !== entry) return;
    this.entries.delete(snapshotRef);
    await Promise.all([
      entry.executableHandle.close().catch(() => undefined),
      entry.cwdHandle.close().catch(() => undefined),
      entry.scriptHandle?.close().catch(() => undefined) ?? Promise.resolve()
    ]);
  }
}

function validatePreparationInput(value: unknown): asserts value is DescriptorSnapshotPreparationInput {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, [
    "argsDigest", "cwdPath", "environmentDigest", "executablePath", "filesystemRootsDigest", "networkPolicy",
    "processTreePolicy", "profile", "sandboxProfile", "taskDescriptorDigest"
  ], ["audience", "scriptPath"])) {
    throw new BrokerError("PRECONDITION_FAILED", "Descriptor snapshot preparation input is malformed");
  }
  const input = value as Partial<DescriptorSnapshotPreparationInput>;
  if ((input.audience !== undefined &&
       (typeof input.audience !== "string" || !SNAPSHOT_AUDIENCES.has(input.audience as DescriptorSnapshotAudience))) ||
      typeof input.executablePath !== "string" || !isCanonicalAbsolutePath(input.executablePath) ||
      typeof input.cwdPath !== "string" || !isCanonicalAbsolutePath(input.cwdPath) ||
      (input.scriptPath !== undefined && (typeof input.scriptPath !== "string" || !isCanonicalAbsolutePath(input.scriptPath))) ||
      typeof input.profile !== "string" || !PROFILE_PATTERN.test(input.profile) ||
      typeof input.sandboxProfile !== "string" || !PROFILE_PATTERN.test(input.sandboxProfile) ||
      !isSha256(input.taskDescriptorDigest) || !isSha256(input.argsDigest) ||
      !isSha256(input.environmentDigest) || !isSha256(input.filesystemRootsDigest) ||
      (input.networkPolicy !== "none" && input.networkPolicy !== "allowlist") ||
      (input.processTreePolicy !== "single_process" && input.processTreePolicy !== "owned_group")) {
    throw new BrokerError("PRECONDITION_FAILED", "Descriptor snapshot preparation input is malformed");
  }
}

async function readDescriptorFileIdentity(
  handle: FileHandle,
  includeContent: boolean,
  maxContentBytes = MAX_EXECUTABLE_DIGEST_BYTES
): Promise<DescriptorFileIdentity> {
  const before = await handle.stat({ bigint: true });
  if (!before.isFile() && !(before.isDirectory() && !includeContent)) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot FD kind is invalid");
  }
  const identity: DescriptorFileIdentity = {
    device: normalizeIdentityNumber(before.dev, "device"),
    inode: normalizeIdentityNumber(before.ino, "inode"),
    ownerUid: normalizeSafeNumber(before.uid, "owner UID"),
    ownerGid: normalizeSafeNumber(before.gid, "owner GID"),
    mode: normalizeSafeNumber(before.mode, "mode") & 0o7777,
    size: normalizeSafeNumber(before.size, "size"),
    mtimeMs: normalizeTimestamp(before.mtimeMs, "mtime"),
    ctimeMs: normalizeTimestamp(before.ctimeMs, "ctime")
  };
  if (includeContent) {
    if (identity.size > maxContentBytes) throw new BrokerError("OUTPUT_LIMIT", "Descriptor snapshot content is too large");
    identity.contentSha256 = await digestFileHandle(handle, identity.size);
  }
  const after = await handle.stat({ bigint: true });
  const afterIdentity: DescriptorFileIdentity = {
    device: normalizeIdentityNumber(after.dev, "device"),
    inode: normalizeIdentityNumber(after.ino, "inode"),
    ownerUid: normalizeSafeNumber(after.uid, "owner UID"),
    ownerGid: normalizeSafeNumber(after.gid, "owner GID"),
    mode: normalizeSafeNumber(after.mode, "mode") & 0o7777,
    size: normalizeSafeNumber(after.size, "size"),
    mtimeMs: normalizeTimestamp(after.mtimeMs, "mtime"),
    ctimeMs: normalizeTimestamp(after.ctimeMs, "ctime"),
    ...(identity.contentSha256 === undefined ? {} : { contentSha256: identity.contentSha256 })
  };
  if (!sameDescriptorFileIdentity(identity, afterIdentity)) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot FD changed while reading");
  }
  return identity;
}

async function digestFileHandle(handle: FileHandle, expectedSize: number): Promise<string> {
  const digest = createHash("sha256");
  const buffer = Buffer.allocUnsafe(EXECUTABLE_DIGEST_READ_CHUNK_BYTES);
  let remaining = expectedSize;
  let position = 0;
  while (remaining > 0) {
    const { bytesRead } = await handle.read(buffer, 0, Math.min(buffer.byteLength, remaining), position);
    if (bytesRead < 1) throw new BrokerError("POLICY_DENIED", "Descriptor snapshot executable changed while reading");
    digest.update(buffer.subarray(0, bytesRead));
    remaining -= bytesRead;
    position += bytesRead;
  }
  const { bytesRead } = await handle.read(buffer, 0, 1, position);
  if (bytesRead !== 0) throw new BrokerError("POLICY_DENIED", "Descriptor snapshot executable changed while reading");
  return digest.digest("hex");
}

function validateDescriptorFileIdentity(value: unknown, requireContent = false): asserts value is DescriptorFileIdentity {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, [
    "ctimeMs", "device", "inode", "mode", "mtimeMs", "ownerGid", "ownerUid", "size"
  ], ["contentSha256"])) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot FD identity is malformed");
  }
  const identity = value as Partial<DescriptorFileIdentity>;
  const identityFields = ["device", "inode"] as const;
  const integerFields = ["ownerUid", "ownerGid", "mode", "size"] as const;
  const timeFields = ["mtimeMs", "ctimeMs"] as const;
  if (!identityFields.every((key) => isIdentityNumber(identity[key])) || !integerFields.every((key) => {
    const candidate = identity[key];
    return typeof candidate === "number" && Number.isSafeInteger(candidate) && candidate >= 0;
  }) || !timeFields.every((key) => {
    const candidate = identity[key];
    return typeof candidate === "number" && Number.isFinite(candidate) && candidate >= 0 && candidate <= Number.MAX_SAFE_INTEGER;
  }) || (identity.contentSha256 !== undefined && !isSha256(identity.contentSha256)) ||
      (requireContent && identity.contentSha256 === undefined)) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot FD identity is malformed");
  }
}

function sameDescriptorFileIdentity(left: DescriptorFileIdentity, right: DescriptorFileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode && left.ownerUid === right.ownerUid &&
    left.ownerGid === right.ownerGid && left.mode === right.mode && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs &&
    left.contentSha256 === right.contentSha256;
}

function sameDescriptorMetadata(left: DescriptorFileIdentity, right: DescriptorFileIdentity): boolean {
  return left.device === right.device && left.inode === right.inode && left.ownerUid === right.ownerUid &&
    left.ownerGid === right.ownerGid && left.mode === right.mode && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}

async function captureRegularFileMetadata(path: string): Promise<DescriptorFileIdentity> {
  try {
    return await capturePathDescriptorIdentity(path, false);
  } catch (error) {
    if (error instanceof BrokerError) throw error;
    throw new BrokerError("TARGET_NOT_FOUND", "Descriptor snapshot script was not found");
  }
}

async function capturePathDescriptorIdentity(path: string, includeContent: boolean): Promise<DescriptorFileIdentity> {
  const before = await lstat(path, { bigint: true });
  if (before.isSymbolicLink() || (includeContent ? !before.isFile() : !before.isFile() && !before.isDirectory())) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot path kind is invalid");
  }
  if ((normalizeSafeNumber(before.mode, "mode") & 0o022) !== 0) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot path permissions are not owner-only");
  }
  const canonical = await realpath(path);
  if (canonical !== path) throw new BrokerError("POLICY_DENIED", "Descriptor snapshot path must be canonical");
  const handle = await open(path, constants.O_RDONLY | (before.isDirectory() ? constants.O_DIRECTORY : 0) | constants.O_NOFOLLOW);
  try {
    const identity = await readDescriptorFileIdentity(handle, includeContent);
    const pathIdentity: DescriptorFileIdentity = {
      device: normalizeIdentityNumber(before.dev, "device"),
      inode: normalizeIdentityNumber(before.ino, "inode"),
      ownerUid: normalizeSafeNumber(before.uid, "owner UID"),
      ownerGid: normalizeSafeNumber(before.gid, "owner GID"),
      mode: normalizeSafeNumber(before.mode, "mode") & 0o7777,
      size: normalizeSafeNumber(before.size, "size"),
      mtimeMs: normalizeTimestamp(before.mtimeMs, "mtime"),
      ctimeMs: normalizeTimestamp(before.ctimeMs, "ctime"),
      ...(identity.contentSha256 === undefined ? {} : { contentSha256: identity.contentSha256 })
    };
    if (!sameDescriptorFileIdentity(pathIdentity, identity)) {
      throw new BrokerError("POLICY_DENIED", "Descriptor snapshot path changed while opening");
    }
    return identity;
  } finally {
    await handle.close();
  }
}

function normalizeIdentityNumber(value: number | bigint, label: string): number | string {
  if (typeof value === "bigint") {
    return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString(10);
  }
  if (!Number.isSafeInteger(value) || value < 0) throw new BrokerError("POLICY_DENIED", `Descriptor snapshot ${label} is unsafe`);
  return value;
}

function normalizeSafeNumber(value: number | bigint, label: string): number {
  const normalized = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isSafeInteger(normalized) || normalized < 0) throw new BrokerError("POLICY_DENIED", `Descriptor snapshot ${label} is unsafe`);
  return normalized;
}

function normalizeTimestamp(value: number | bigint, label: string): number {
  const normalized = typeof value === "bigint" ? Number(value) : value;
  if (!Number.isFinite(normalized) || normalized < 0 || normalized > Number.MAX_SAFE_INTEGER) {
    throw new BrokerError("POLICY_DENIED", `Descriptor snapshot ${label} is unsafe`);
  }
  return normalized;
}

function isIdentityNumber(value: unknown): value is number | string {
  return (typeof value === "number" && Number.isSafeInteger(value) && value >= 0) ||
    (typeof value === "string" && /^\d{1,32}$/u.test(value));
}

function isCanonicalAbsolutePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096 &&
    isAbsolute(value) && resolve(value) === value && !value.includes("\0") && !value.includes("\n");
}

function isSha256(value: unknown): value is string {
  return typeof value === "string" && SHA256_PATTERN.test(value);
}

function hasExactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const allowed = new Set([...required, ...optional]);
  const keys = Object.keys(value);
  return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) && keys.every((key) => allowed.has(key));
}

function assertPublicKey(value: string | Buffer | KeyObject): void {
  if (value instanceof KeyObject) {
    if (value.type !== "public") throw new Error("Descriptor snapshot verification key must contain public material only");
    return;
  }
  try {
    createPrivateKey(value);
  } catch {
    return;
  }
  throw new Error("Descriptor snapshot verification key must contain public material only");
}

function freezeSnapshotAttestation<T>(value: T): T {
  const seen = new Set<object>();
  const freeze = (candidate: unknown): void => {
    if (candidate === null || typeof candidate !== "object" || seen.has(candidate)) return;
    seen.add(candidate);
    if (Array.isArray(candidate)) {
      for (const item of candidate) freeze(item);
    } else {
      for (const child of Object.values(candidate)) freeze(child);
    }
    Object.freeze(candidate);
  };
  freeze(value);
  return value;
}
