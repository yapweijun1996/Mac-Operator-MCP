import { createRequire } from "node:module";
import { createHash } from "node:crypto";
import { lstatSync, readFileSync, realpathSync, statSync } from "node:fs";
import { resolve } from "node:path";
import { assertNativeNodeRuntimeVersion, validateNativeAdapterPath } from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";

const require = createRequire(import.meta.url);
const MAX_NATIVE_ADAPTER_BYTES = 16 * 1024 * 1024;
const MIN_SUPPORTED_NAPI_VERSION = 8;

export interface VirtualizationGuestConfigurationReadback {
  path: string;
  device: string;
  inode: string;
  sha256: string;
  sizeBytes: number;
  readOnlyAttachment: boolean;
  configurationValid: boolean;
  vmBootAttempted: boolean;
  hostNetworkAttached: boolean;
  hostDirectorySharingAttached: boolean;
}

interface NativeVirtualizationGuestAdapter {
  nativeNapiVersion: number;
  nativeNodeVersion: string;
  inspectGuestConfiguration(
    path: string,
    device: string,
    inode: string,
    sha256: string
  ): unknown;
}

interface NativeAdapterArtifact {
  device: number;
  inode: number;
  size: number;
  digest: string;
}

let loadedArtifact: NativeAdapterArtifact | undefined;

/**
 * Loads the protected Virtualization.framework N-API artifact. This is a
 * startup/evidence boundary; MCP arguments never select the native module.
 */
export function loadNativeVirtualizationGuestAdapter(): NativeVirtualizationGuestAdapter {
  if (process.platform !== "darwin") throw new Error("Virtualization guest adapter requires macOS");
  try {
    const nativePath = require.resolve("./virtualization_guest.node");
    const before = readArtifact(nativePath);
    if (loadedArtifact !== undefined && !sameArtifact(loadedArtifact, before)) {
      throw new Error("Virtualization guest adapter changed after initial load");
    }
    const native = require(nativePath) as Partial<NativeVirtualizationGuestAdapter>;
    const after = readArtifact(nativePath);
    if (!sameArtifact(before, after)) throw new Error("Virtualization guest adapter changed while loading");
    const runtimeNapiVersion = Number.parseInt(process.versions.napi ?? "", 10);
    if (typeof native.inspectGuestConfiguration !== "function" ||
        !Number.isSafeInteger(runtimeNapiVersion) || runtimeNapiVersion < MIN_SUPPORTED_NAPI_VERSION ||
        typeof native.nativeNapiVersion !== "number" || !Number.isSafeInteger(native.nativeNapiVersion) ||
        native.nativeNapiVersion < MIN_SUPPORTED_NAPI_VERSION || native.nativeNapiVersion > runtimeNapiVersion) {
      throw new Error("Virtualization guest adapter exports are incompatible");
    }
    assertNativeNodeRuntimeVersion(native.nativeNodeVersion);
    loadedArtifact = after;
    return native as NativeVirtualizationGuestAdapter;
  } catch {
    throw new Error("Virtualization guest native adapter is unavailable");
  }
}

/**
 * Revalidates a startup-bound image through the native Virtualization.framework
 * artifact. The result contains only bounded identity/configuration metadata.
 */
export function inspectVirtualizationGuestConfiguration(
  imagePath: string,
  device: string,
  inode: string,
  sha256: string
): VirtualizationGuestConfigurationReadback {
  if (typeof imagePath !== "string" || typeof device !== "string" ||
      typeof inode !== "string" || typeof sha256 !== "string") {
    throw new Error("Virtualization guest image identity is malformed");
  }
  const result = loadNativeVirtualizationGuestAdapter().inspectGuestConfiguration(imagePath, device, inode, sha256);
  return parseVirtualizationGuestConfigurationResult(result);
}

export function parseVirtualizationGuestConfigurationResult(result: unknown): VirtualizationGuestConfigurationReadback {
  if (!isPlainDataRecord(result) || !hasExactFields(result, [
    "configurationValid", "device", "hostDirectorySharingAttached", "hostNetworkAttached", "inode",
    "path", "readOnlyAttachment", "sha256", "sizeBytes", "vmBootAttempted"
  ])) {
    throw new Error("Virtualization guest native readback is malformed");
  }
  const value = result as Record<string, unknown>;
  if (typeof value.path !== "string" || typeof value.device !== "string" || typeof value.inode !== "string" ||
      typeof value.sha256 !== "string" || typeof value.sizeBytes !== "number" ||
      !Number.isSafeInteger(value.sizeBytes) || value.sizeBytes < 1 ||
      typeof value.readOnlyAttachment !== "boolean" || typeof value.configurationValid !== "boolean" ||
      typeof value.vmBootAttempted !== "boolean" || typeof value.hostNetworkAttached !== "boolean" ||
      typeof value.hostDirectorySharingAttached !== "boolean") {
    throw new Error("Virtualization guest native readback is malformed");
  }
  return {
    path: value.path,
    device: value.device,
    inode: value.inode,
    sha256: value.sha256,
    sizeBytes: value.sizeBytes,
    readOnlyAttachment: value.readOnlyAttachment,
    configurationValid: value.configurationValid,
    vmBootAttempted: value.vmBootAttempted,
    hostNetworkAttached: value.hostNetworkAttached,
    hostDirectorySharingAttached: value.hostDirectorySharingAttached
  };
}

function hasExactFields(value: Record<string, unknown>, required: readonly string[]): boolean {
  const keys = Object.keys(value);
  return keys.length === required.length && required.every((key) => Object.prototype.hasOwnProperty.call(value, key));
}

function readArtifact(nativePath: string): NativeAdapterArtifact {
  validateNativeAdapterPath(nativePath);
  const stat = statSync(nativePath);
  if (stat.size > MAX_NATIVE_ADAPTER_BYTES) throw new Error("Virtualization guest adapter is oversized");
  return {
    device: stat.dev,
    inode: stat.ino,
    size: stat.size,
    digest: createHash("sha256").update(readFileSync(nativePath)).digest("hex")
  };
}

function sameArtifact(left: NativeAdapterArtifact, right: NativeAdapterArtifact): boolean {
  return left.device === right.device && left.inode === right.inode &&
    left.size === right.size && left.digest === right.digest;
}

/** Exposed for focused tests that assert canonical artifact loading. */
export function validateNativeVirtualizationGuestAdapterPath(nativePath: string): void {
  if (resolve(nativePath) !== nativePath || realpathSync(nativePath) !== nativePath) {
    throw new Error("Virtualization guest adapter path is not canonical");
  }
  const stat = lstatSync(nativePath);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 1 || stat.size > MAX_NATIVE_ADAPTER_BYTES ||
      (stat.mode & 0o022) !== 0 || (process.getuid !== undefined && stat.uid !== process.getuid())) {
    throw new Error("Virtualization guest adapter file is not protected");
  }
}
