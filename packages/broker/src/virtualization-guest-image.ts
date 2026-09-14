import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { createHash } from "node:crypto";
import { basename, dirname, isAbsolute, join, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import type { VirtualizationGuestIdentity } from "./task-runner.js";

const SHA256_PATTERN = /^[a-f0-9]{64}$/u;
const RUNTIME_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const DEFAULT_MAX_IMAGE_BYTES = 512 * 1024 * 1024 * 1024;
const IMAGE_CHUNK_BYTES = 1024 * 1024;

export interface VirtualizationGuestImageConfig {
  path: string;
  expectedSha256: string;
  runtimeVersion: string;
  maxBytes?: number;
}

export interface LoadedVirtualizationGuestImage {
  path: string;
  guestIdentity: VirtualizationGuestIdentity;
  device: string;
  inode: string;
  sizeBytes: number;
}

/** Re-reads the startup-bound image before a VM dispatch or status recovery. */
export async function verifyVirtualizationGuestImage(
  loaded: LoadedVirtualizationGuestImage
): Promise<LoadedVirtualizationGuestImage> {
  if (loaded === null || typeof loaded !== "object" ||
      typeof loaded.path !== "string" ||
      loaded.guestIdentity === null || typeof loaded.guestIdentity !== "object" ||
      typeof loaded.guestIdentity.imageSha256 !== "string" ||
      typeof loaded.guestIdentity.runtimeVersion !== "string" ||
      typeof loaded.sizeBytes !== "number" || !Number.isSafeInteger(loaded.sizeBytes) || loaded.sizeBytes < 1 ||
      typeof loaded.device !== "string" || typeof loaded.inode !== "string") {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest image binding is malformed");
  }
  const verified = await loadVirtualizationGuestImage({
    path: loaded.path,
    expectedSha256: loaded.guestIdentity.imageSha256,
    runtimeVersion: loaded.guestIdentity.runtimeVersion,
    maxBytes: loaded.sizeBytes
  });
  if (verified.device !== loaded.device || verified.inode !== loaded.inode || verified.sizeBytes !== loaded.sizeBytes) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest image identity changed after preflight");
  }
  return verified;
}

/**
 * Reads a host-owned guest image through one protected descriptor and binds
 * the bytes to the immutable identity supplied by startup configuration.
 * Caller-controlled MCP arguments never select this path or digest.
 */
export async function loadVirtualizationGuestImage(
  config: VirtualizationGuestImageConfig
): Promise<LoadedVirtualizationGuestImage> {
  validateConfig(config);
  const maxBytes = config.maxBytes ?? DEFAULT_MAX_IMAGE_BYTES;
  const canonicalParent = await realpath(dirname(config.path)).catch(() => undefined);
  const canonicalPath = canonicalParent === undefined ? undefined : join(canonicalParent, basename(config.path));
  const pathStat = canonicalPath === undefined ? undefined : await lstat(canonicalPath).catch(() => undefined);
  const currentUid = process.getuid?.();
  if (!pathStat || !pathStat.isFile() || pathStat.isSymbolicLink() ||
      currentUid === undefined || pathStat.uid !== currentUid ||
      (pathStat.mode & 0o077) !== 0 || pathStat.size < 1 || pathStat.size > maxBytes) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest image is not a protected owner-only regular file");
  }
  await assertProtectedDirectory(canonicalParent!, currentUid);

  const handle = await open(canonicalPath!, constants.O_RDONLY | constants.O_NOFOLLOW).catch(() => undefined);
  if (!handle) throw new BrokerError("POLICY_DENIED", "Virtualization guest image could not be opened safely");
  try {
    const opened = await handle.stat();
    if (!sameIdentity(opened, pathStat) || opened.size < 1 || opened.size > maxBytes) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest image target changed while opening");
    }
    const digest = await hashDescriptor(handle, opened.size, maxBytes);
    const after = await handle.stat();
    if (!sameIdentity(after, pathStat) || after.size !== opened.size || digest !== config.expectedSha256) {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest image digest or identity precondition failed");
    }
    return {
      path: canonicalPath!,
      guestIdentity: { imageSha256: digest, runtimeVersion: config.runtimeVersion },
      device: String(after.dev),
      inode: String(after.ino),
      sizeBytes: after.size
    };
  } finally {
    await handle.close();
  }
}

function validateConfig(config: VirtualizationGuestImageConfig): void {
  if (config === null || typeof config !== "object" || Array.isArray(config) ||
      typeof config.path !== "string" || !isAbsolute(config.path) || resolve(config.path) !== config.path || config.path.includes("\0") || config.path.length > 4_096 ||
      typeof config.expectedSha256 !== "string" || !SHA256_PATTERN.test(config.expectedSha256) ||
      typeof config.runtimeVersion !== "string" || !RUNTIME_VERSION_PATTERN.test(config.runtimeVersion) ||
      (config.maxBytes !== undefined && (!Number.isSafeInteger(config.maxBytes) || config.maxBytes < 1 || config.maxBytes > DEFAULT_MAX_IMAGE_BYTES))) {
    throw new BrokerError("PRECONDITION_FAILED", "Virtualization guest image configuration is malformed");
  }
}

async function assertProtectedDirectory(path: string, currentUid: number): Promise<void> {
  const directory = await lstat(path).catch(() => undefined);
  if (!directory || !directory.isDirectory() || directory.isSymbolicLink() || directory.uid !== currentUid || (directory.mode & 0o077) !== 0) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest image directory is not protected");
  }
}

function sameIdentity(left: { dev: number | bigint; ino: number | bigint; size: number }, right: { dev: number | bigint; ino: number | bigint; size: number }): boolean {
  return String(left.dev) === String(right.dev) && String(left.ino) === String(right.ino) && left.size === right.size;
}

async function hashDescriptor(handle: Awaited<ReturnType<typeof open>>, size: number, maxBytes: number): Promise<string> {
  if (!Number.isSafeInteger(size) || size < 1 || size > maxBytes) {
    throw new BrokerError("OUTPUT_LIMIT", "Virtualization guest image exceeds its configured size budget");
  }
  const digest = createHash("sha256");
  const buffer = Buffer.allocUnsafe(IMAGE_CHUNK_BYTES);
  let offset = 0;
  while (offset < size) {
    const length = Math.min(buffer.byteLength, size - offset);
    const result = await handle.read(buffer, 0, length, offset);
    if (result.bytesRead < 1) throw new BrokerError("POLICY_DENIED", "Virtualization guest image ended during hashing");
    digest.update(buffer.subarray(0, result.bytesRead));
    offset += result.bytesRead;
  }
  return digest.digest("hex");
}
