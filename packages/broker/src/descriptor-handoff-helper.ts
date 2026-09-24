import { createHash } from "node:crypto";
import { fstatSync, readSync } from "node:fs";
import { BrokerError, parseJsonUtf8Strict } from "@mac-operator/contracts";
import {
  receiveAuthenticatedDescriptorHandoff,
  type DescriptorHandoffFrame
} from "./descriptor-handoff-receiver.js";
import { loadNativePeerAdapter, type PeerCredentialPolicy, type PeerCredentials } from "./peer-credentials.js";
import {
  assertDescriptorSnapshotIdentity,
  snapshotSignedDescriptorSnapshotAttestation,
  type DescriptorFileIdentity,
  type DescriptorSnapshotAttestationVerifier,
  type VerifiedDescriptorSnapshotAttestation
} from "./descriptor-snapshot-attestation.js";

export interface DescriptorHandoffHelperReceiverOptions {
  socketDescriptor: number;
  peerPolicy: PeerCredentialPolicy;
  expectedDescriptorCount: number;
  maxPayloadBytes?: number;
  snapshotVerifier?: DescriptorSnapshotAttestationVerifier;
}

export interface DescriptorHandoffHelperHandoff {
  credentials: PeerCredentials;
  frame: DescriptorHandoffFrame;
}

export interface DescriptorHandoffHelperVerifiedSnapshot extends DescriptorHandoffHelperHandoff {
  attestation: VerifiedDescriptorSnapshotAttestation;
}

/**
 * One-shot receiver boundary for a future unprivileged helper process.
 *
 * This class owns only peer authentication, bounded frame receive, and
 * deterministic descriptor cleanup. It never launches a child, interprets a
 * path/argv/environment value, or changes task admission.
 */
export class DescriptorHandoffHelperReceiver {
  private readonly native: { closeUnixDescriptor(descriptor: number): void };
  private consumed = false;
  private closed = false;

  constructor(private readonly options: DescriptorHandoffHelperReceiverOptions) {
    if (!Number.isSafeInteger(options.socketDescriptor) || options.socketDescriptor < 0) {
      throw new BrokerError("POLICY_DENIED", "Descriptor handoff helper socket descriptor is invalid");
    }
    this.native = loadNativePeerAdapter();
  }

  /** Receive one authenticated frame. A second call is a durable local replay denial. */
  receiveOnce(): DescriptorHandoffHelperHandoff {
    if (this.closed) throw new BrokerError("POLICY_DENIED", "Descriptor handoff helper receiver is closed");
    if (this.consumed) throw new BrokerError("REPLAY_DENIED", "Descriptor handoff helper frame was already consumed");
    this.consumed = true;
    try {
      return receiveAuthenticatedDescriptorHandoff(this.options.socketDescriptor, this.options.peerPolicy, {
        ...(this.options.maxPayloadBytes === undefined ? {} : { maxPayloadBytes: this.options.maxPayloadBytes }),
        expectedDescriptorCount: this.options.expectedDescriptorCount
      });
    } catch (error) {
      this.close();
      throw error;
    }
  }

  /** Verify one signed snapshot and revalidate both received descriptors by FD identity. */
  receiveVerifiedSnapshotOnce(): DescriptorHandoffHelperVerifiedSnapshot {
    const verifier = this.options.snapshotVerifier;
    if (verifier === undefined) {
      throw new BrokerError("UNSUPPORTED_CAPABILITY", "Descriptor snapshot verification is not configured");
    }
    const handoff = this.receiveOnce();
    try {
      const attestation = verifyDescriptorSnapshotHandoff(handoff, verifier);
      return { ...handoff, attestation };
    } catch (error) {
      closeDescriptorList(handoff.frame.descriptors, this.native);
      this.close();
      if (error instanceof BrokerError) throw error;
      throw new BrokerError("POLICY_DENIED", "Descriptor snapshot handoff verification failed");
    }
  }

  /** Run one callback while received descriptors are valid, then close everything. */
  async withHandoff<T>(callback: (handoff: DescriptorHandoffHelperHandoff) => Promise<T> | T): Promise<T> {
    if (typeof callback !== "function") throw new BrokerError("PRECONDITION_FAILED", "Descriptor handoff helper callback is invalid");
    const handoff = this.receiveOnce();
    try {
      return await callback(handoff);
    } finally {
      closeDescriptorList(handoff.frame.descriptors, this.native);
      this.close();
    }
  }

  /** Run one verified snapshot callback while both received descriptors are valid. */
  async withVerifiedSnapshot<T>(callback: (handoff: DescriptorHandoffHelperVerifiedSnapshot) => Promise<T> | T): Promise<T> {
    if (typeof callback !== "function") throw new BrokerError("PRECONDITION_FAILED", "Descriptor snapshot helper callback is invalid");
    const handoff = this.receiveVerifiedSnapshotOnce();
    try {
      return await callback(handoff);
    } finally {
      closeDescriptorList(handoff.frame.descriptors, this.native);
      this.close();
    }
  }

  /** Close the one-shot transport. Repeated close is harmless. */
  close(): void {
    if (this.closed) return;
    this.closed = true;
    try { this.native.closeUnixDescriptor(this.options.socketDescriptor); } catch { /* fail-closed cleanup */ }
  }
}

/**
 * Verify a received descriptor pair without taking ownership of its socket or
 * descriptors. Callers must close the descriptors after this function returns.
 * This is shared by the native root-helper transport and the one-shot test
 * receiver so both paths use the same FD identity proof.
 */
export function verifyDescriptorSnapshotHandoff(
  handoff: DescriptorHandoffHelperHandoff,
  verifier: DescriptorSnapshotAttestationVerifier
): VerifiedDescriptorSnapshotAttestation {
  if (handoff === null || typeof handoff !== "object" || handoff.frame.descriptors.length !== 2) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot requires executable and cwd descriptors");
  }
  const signed = snapshotSignedDescriptorSnapshotAttestation(parseJsonUtf8Strict(handoff.frame.payload));
  const attestation = verifier.verify(signed);
  const executable = readDescriptorFileIdentity(handoff.frame.descriptors[0]!, true);
  const cwd = readDescriptorFileIdentity(handoff.frame.descriptors[1]!, false);
  assertDescriptorSnapshotIdentity(attestation.attestation, { executable, cwd });
  return attestation;
}

function closeDescriptorList(descriptors: readonly number[], native: { closeUnixDescriptor(descriptor: number): void }): void {
  const closed = new Set<number>();
  for (const descriptor of descriptors) {
    if (closed.has(descriptor)) continue;
    closed.add(descriptor);
    try { native.closeUnixDescriptor(descriptor); } catch { /* fail-closed cleanup */ }
  }
}

const MAX_EXECUTABLE_DIGEST_BYTES = 64 * 1024 * 1024;
const DIGEST_READ_CHUNK_BYTES = 1024 * 1024;

function readDescriptorFileIdentity(descriptor: number, includeContent: boolean): DescriptorFileIdentity {
  const before = fstatSync(descriptor, { bigint: true });
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
    if (identity.size > MAX_EXECUTABLE_DIGEST_BYTES) {
      throw new BrokerError("OUTPUT_LIMIT", "Descriptor snapshot executable is too large");
    }
    identity.contentSha256 = digestDescriptor(descriptor, identity.size);
  }
  const after = fstatSync(descriptor, { bigint: true });
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
  if (afterIdentity.device !== identity.device || afterIdentity.inode !== identity.inode ||
      afterIdentity.ownerUid !== identity.ownerUid || afterIdentity.ownerGid !== identity.ownerGid ||
      afterIdentity.mode !== identity.mode || afterIdentity.size !== identity.size ||
      afterIdentity.mtimeMs !== identity.mtimeMs || afterIdentity.ctimeMs !== identity.ctimeMs) {
    throw new BrokerError("POLICY_DENIED", "Descriptor snapshot FD changed while reading");
  }
  return identity;
}

function normalizeIdentityNumber(value: number | bigint, label: string): number | string {
  if (typeof value === "bigint") return value <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(value) : value.toString(10);
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

function digestDescriptor(descriptor: number, expectedSize: number): string {
  const digest = createHash("sha256");
  const buffer = Buffer.allocUnsafe(DIGEST_READ_CHUNK_BYTES);
  let position = 0;
  while (position < expectedSize) {
    const requested = Math.min(buffer.byteLength, expectedSize - position);
    const bytesRead = readSync(descriptor, buffer, 0, requested, position);
    if (bytesRead < 1) throw new BrokerError("POLICY_DENIED", "Descriptor snapshot executable changed while reading");
    digest.update(buffer.subarray(0, bytesRead));
    position += bytesRead;
  }
  const trailing = readSync(descriptor, buffer, 0, 1, expectedSize);
  if (trailing !== 0) throw new BrokerError("POLICY_DENIED", "Descriptor snapshot executable changed while reading");
  return digest.digest("hex");
}
