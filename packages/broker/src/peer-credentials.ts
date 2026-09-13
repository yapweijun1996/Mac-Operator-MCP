import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import type { Socket } from "node:net";

export interface PeerCredentials {
  uid: number;
  gid: number;
  pid: number;
}

export interface PeerCredentialVerifier {
  verify(socket: Socket): PeerCredentials;
}

interface NativePeerCredentials {
  getPeerCredentials(descriptor: number): unknown;
  createUnixListener(path: string, backlog: number): number;
  acceptUnixClient(descriptor: number): unknown;
  closeUnixDescriptor(descriptor: number): void;
}

interface SocketWithHandle extends Socket {
  _handle?: { fd?: unknown };
}

const require = createRequire(import.meta.url);
const MAX_NATIVE_ADAPTER_BYTES = 16 * 1024 * 1024;
const REQUIRED_NATIVE_EXPORTS = [
  "getPeerCredentials", "createUnixListener", "acceptUnixClient", "closeUnixDescriptor",
  "inspectNetwork", "statPathWithinRoot", "statStorageVolumeWithinRoot", "listDirectoryWithinRoot",
  "readFileWithinRoot", "hashFileWithinRoot", "writeFileAtomicWithinRoot", "unlinkFileWithinRoot",
  "listProcesses", "inspectProcess", "listDescendantProcesses", "isProcessIdentityAlive", "getProcessIdentity"
] as const;

interface NativeAdapterArtifact {
  device: number;
  inode: number;
  size: number;
  digest: string;
}

let loadedNativeArtifact: NativeAdapterArtifact | undefined;

export class MacOsPeerCredentialVerifier implements PeerCredentialVerifier {
  private readonly native: NativePeerCredentials;

  constructor(private readonly policy: {
    expectedUid: number;
    expectedGid?: number;
    allowedProcessIds?: ReadonlySet<number>;
  }) {
    if (!Number.isSafeInteger(policy.expectedUid) || policy.expectedUid < 0) {
      throw new Error("Expected Edge user ID is invalid");
    }
    this.native = loadNativePeerAdapter();
  }

  verify(socket: Socket): PeerCredentials {
    const descriptor = (socket as SocketWithHandle)._handle?.fd;
    if (!Number.isSafeInteger(descriptor) || (descriptor as number) < 0) {
      throw new Error("Accepted IPC socket descriptor is unavailable");
    }
    const credentials = parsePeerCredentials(this.native.getPeerCredentials(descriptor as number));
    authorizePeerCredentials(credentials, this.policy);
    return credentials;
  }
}

export function loadNativePeerAdapter(): NativePeerCredentials {
  if (process.platform !== "darwin") throw new Error("Peer credential verification requires macOS");
  try {
    const nativePath = require.resolve("./peer_credentials.node");
    const before = readNativeAdapterArtifact(nativePath);
    if (loadedNativeArtifact !== undefined && !sameNativeAdapterArtifact(loadedNativeArtifact, before)) {
      throw new Error("Native peer adapter changed after initial load");
    }
    const native = require(nativePath) as Partial<NativePeerCredentials>;
    const after = readNativeAdapterArtifact(nativePath);
    if (!sameNativeAdapterArtifact(before, after)) {
      throw new Error("Native peer adapter changed while loading");
    }
    if (REQUIRED_NATIVE_EXPORTS.some((name) => typeof (native as Record<string, unknown>)[name] !== "function")) {
      throw new Error("Native peer adapter exports are incomplete");
    }
    loadedNativeArtifact = after;
    return native as NativePeerCredentials;
  } catch {
    throw new Error("Peer credential native adapter is unavailable");
  }
}

function readNativeAdapterArtifact(nativePath: string): NativeAdapterArtifact {
  validateNativeAdapterPath(nativePath);
  const stat = statSync(nativePath);
  return {
    device: stat.dev,
    inode: stat.ino,
    size: stat.size,
    digest: createHash("sha256").update(readFileSync(nativePath)).digest("hex")
  };
}

function sameNativeAdapterArtifact(left: NativeAdapterArtifact, right: NativeAdapterArtifact): boolean {
  return left.device === right.device && left.inode === right.inode && left.size === right.size && left.digest === right.digest;
}

export function validateNativeAdapterPath(nativePath: string): void {
  if (!isAbsolute(nativePath) || resolve(nativePath) !== nativePath || realpathSync(nativePath) !== nativePath) {
    throw new Error("Native peer adapter path is not canonical");
  }
  const linkStat = lstatSync(nativePath);
  if (!linkStat.isFile() || linkStat.isSymbolicLink() || linkStat.size < 1 || linkStat.size > MAX_NATIVE_ADAPTER_BYTES ||
      (linkStat.mode & 0o022) !== 0) {
    throw new Error("Native peer adapter file is not protected");
  }
  const uid = process.getuid?.();
  if (uid !== undefined && linkStat.uid !== uid) throw new Error("Native peer adapter owner is not current user");
}

export function parsePeerCredentials(value: unknown): PeerCredentials {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Peer credential result is malformed");
  }
  const record = value as Record<string, unknown>;
  if (
    !Number.isSafeInteger(record.uid) || (record.uid as number) < 0 ||
    !Number.isSafeInteger(record.gid) || (record.gid as number) < 0 ||
    !Number.isSafeInteger(record.pid) || (record.pid as number) <= 0
  ) {
    throw new Error("Peer credential result is malformed");
  }
  return { uid: record.uid as number, gid: record.gid as number, pid: record.pid as number };
}

export function authorizePeerCredentials(
  credentials: PeerCredentials,
  policy: { expectedUid: number; expectedGid?: number; allowedProcessIds?: ReadonlySet<number> }
): void {
  if (credentials.uid !== policy.expectedUid) throw new Error("IPC peer user is not authorized");
  if (policy.expectedGid !== undefined && credentials.gid !== policy.expectedGid) {
    throw new Error("IPC peer group is not authorized");
  }
  if (policy.allowedProcessIds && !policy.allowedProcessIds.has(credentials.pid)) {
    throw new Error("IPC peer process is not authorized");
  }
}
