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

export interface PeerProcessIdentity {
  pid: number;
  startTimeMicros: number;
}

export interface PeerCredentialPolicy {
  expectedUid: number;
  expectedGid?: number;
  allowedProcessIds?: ReadonlySet<number>;
  /** Optional PID plus start-time binding that resists PID reuse. */
  allowedProcessIdentity?: PeerProcessIdentity;
}

interface NativePeerCredentials {
  nativeNapiVersion: number;
  getPeerCredentials(descriptor: number): unknown;
  getProcessIdentity(pid: number): unknown;
  readKeychainGenericPassword(service: string, account: string): unknown;
  writeKeychainGenericPassword(service: string, account: string, key: Buffer): unknown;
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
  "listProcesses", "inspectProcess", "listDescendantProcesses", "isProcessIdentityAlive", "getProcessIdentity",
  "readKeychainGenericPassword", "writeKeychainGenericPassword"
] as const;
const MIN_SUPPORTED_NAPI_VERSION = 8;

interface NativeAdapterArtifact {
  device: number;
  inode: number;
  size: number;
  digest: string;
}

let loadedNativeArtifact: NativeAdapterArtifact | undefined;

export class MacOsPeerCredentialVerifier implements PeerCredentialVerifier {
  private readonly native: NativePeerCredentials;

  constructor(private readonly policy: PeerCredentialPolicy) {
    if (!Number.isSafeInteger(policy.expectedUid) || policy.expectedUid < 0) {
      throw new Error("Expected Edge user ID is invalid");
    }
    validateAllowedProcessIdentity(policy.allowedProcessIdentity);
    this.native = loadNativePeerAdapter();
  }

  verify(socket: Socket): PeerCredentials {
    const descriptor = (socket as SocketWithHandle)._handle?.fd;
    if (!Number.isSafeInteger(descriptor) || (descriptor as number) < 0) {
      throw new Error("Accepted IPC socket descriptor is unavailable");
    }
    const credentials = parsePeerCredentials(this.native.getPeerCredentials(descriptor as number));
    authorizePeerCredentials(credentials, this.policy, (pid) => this.native.getProcessIdentity(pid));
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
    const runtimeNapiVersion = Number.parseInt(process.versions.napi ?? "", 10);
    const nativeNapiVersion = native.nativeNapiVersion;
    if (!Number.isSafeInteger(runtimeNapiVersion) || runtimeNapiVersion < MIN_SUPPORTED_NAPI_VERSION ||
        typeof nativeNapiVersion !== "number" || !Number.isSafeInteger(nativeNapiVersion) || nativeNapiVersion < MIN_SUPPORTED_NAPI_VERSION ||
        nativeNapiVersion > runtimeNapiVersion) {
      throw new Error("Native peer adapter N-API version is incompatible");
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

export function parsePeerProcessIdentity(value: unknown): PeerProcessIdentity {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Peer process identity is malformed");
  }
  const record = value as Record<string, unknown>;
  if (
    !Number.isSafeInteger(record.pid) || (record.pid as number) < 1 || (record.pid as number) > 99_999_999 ||
    !Number.isSafeInteger(record.parentPid) || (record.parentPid as number) < 1 || (record.parentPid as number) > 99_999_999 ||
    !Number.isSafeInteger(record.startTimeMicros) || (record.startTimeMicros as number) < 1
  ) {
    throw new Error("Peer process identity is malformed");
  }
  return { pid: record.pid as number, startTimeMicros: record.startTimeMicros as number };
}

export function capturePeerProcessIdentity(pid: number): PeerProcessIdentity {
  if (!Number.isSafeInteger(pid) || pid < 1 || pid > 99_999_999) {
    throw new Error("Peer process ID is invalid");
  }
  const native = loadNativePeerAdapter();
  return parsePeerProcessIdentity(native.getProcessIdentity(pid));
}

/**
 * Reads one exact Broker-owned generic-password item. The native adapter
 * returns only a bounded raw key; callers must validate the service/account
 * namespace and never log or persist the returned bytes.
 */
export function readKeychainGenericPassword(service: string, account: string): Buffer {
  if (!/^com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(service) ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(account)) {
    throw new Error("Keychain service or account is invalid");
  }
  const value = loadNativePeerAdapter().readKeychainGenericPassword(service, account);
  if (!Buffer.isBuffer(value) || value.byteLength !== 32) {
    throw new Error("Keychain generic password has an invalid length");
  }
  return Buffer.from(value);
}

/**
 * Provisions one exact 32-byte generic-password item with a device-bound
 * after-first-unlock accessibility class. Provisioning is explicit startup or
 * operator configuration work; MCP request arguments never select it.
 */
export function writeKeychainGenericPassword(service: string, account: string, key: Buffer): void {
  if (!/^com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(service) ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(account)) {
    throw new Error("Keychain service or account is invalid");
  }
  if (!Buffer.isBuffer(key) || key.byteLength !== 32) {
    throw new Error("Keychain generic password must contain exactly 32 bytes");
  }
  loadNativePeerAdapter().writeKeychainGenericPassword(service, account, Buffer.from(key));
}

export function authorizePeerCredentials(
  credentials: PeerCredentials,
  policy: PeerCredentialPolicy,
  readProcessIdentity?: (pid: number) => unknown
): void {
  if (credentials.uid !== policy.expectedUid) throw new Error("IPC peer user is not authorized");
  if (policy.expectedGid !== undefined && credentials.gid !== policy.expectedGid) {
    throw new Error("IPC peer group is not authorized");
  }
  if (policy.allowedProcessIds && !policy.allowedProcessIds.has(credentials.pid)) {
    throw new Error("IPC peer process is not authorized");
  }
  const expectedIdentity = policy.allowedProcessIdentity;
  if (expectedIdentity !== undefined) {
    if (credentials.pid !== expectedIdentity.pid || readProcessIdentity === undefined) {
      throw new Error("IPC peer process identity is not authorized");
    }
    let observed: PeerProcessIdentity;
    try {
      observed = parsePeerProcessIdentity(readProcessIdentity(credentials.pid));
    } catch {
      throw new Error("IPC peer process identity is unavailable");
    }
    if (observed.pid !== expectedIdentity.pid || observed.startTimeMicros !== expectedIdentity.startTimeMicros) {
      throw new Error("IPC peer process identity is not authorized");
    }
  }
}

function validateAllowedProcessIdentity(identity: PeerProcessIdentity | undefined): void {
  if (identity === undefined) return;
  if (!Number.isSafeInteger(identity.pid) || identity.pid < 1 || identity.pid > 99_999_999 ||
      !Number.isSafeInteger(identity.startTimeMicros) || identity.startTimeMicros < 1) {
    throw new Error("Allowed peer process identity is invalid");
  }
}
