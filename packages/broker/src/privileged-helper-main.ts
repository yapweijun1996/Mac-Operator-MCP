import { createRequire } from "node:module";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { CONTRACT_VERSION, parseJsonUtf8Strict } from "@mac-operator/contracts";
import { createPrivilegedHelperAdapter } from "./privileged-helper-adapters.js";
import type { ApprovedPackageArtifact } from "./privileged-package-install.js";
import {
  createPrivilegedHelperRuntimeFromKeyMaterialForLaunchdBroker,
  type PrivilegedHelperRuntime
} from "./privileged-helper-runtime.js";
import { FailClosedPrivilegedHelper, type PrivilegedHelperStatusReadback } from "./privileged-helper.js";

const RUNTIME_ASSET_NAME = "privileged-helper-runtime.json";
const SOURCE_REVISION_PATTERN = /^[a-f0-9]{40}$/u;
const VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,120}$/u;
const CAPABILITY_ORDER = ["mac_priv_service_control", "mac_priv_package_install", "mac_priv_power"] as const;

export interface PrivilegedHelperRuntimeDescriptor {
  schemaVersion: "0.1";
  helperRoot: string;
  helperKeyConfigPath: string;
  helperSocketPath: string;
  brokerSocketPath: string;
  helperAuthoritySocketPath: string;
  brokerPeer: { uid: number; gid: number };
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  capabilities: {
    serviceControl: { enabled: boolean; systemPublishedExecutablePathAccepted: boolean };
    packageInstall: {
      enabled: boolean;
      systemPublishedExecutablePathAccepted: boolean;
      catalog: readonly ApprovedPackageArtifact[];
    };
    power: { enabled: boolean; systemPublishedExecutablePathAccepted: boolean };
  };
}

export type PrivilegedHelperRuntimeLaunchOptions = Parameters<typeof createPrivilegedHelperRuntimeFromKeyMaterialForLaunchdBroker>[0];

export interface PrivilegedHelperRuntimeHost {
  platform: string;
  effectiveUid: number;
  executablePath: string;
  onPeerIdentityLost?: () => void;
  createRuntime?: (options: PrivilegedHelperRuntimeLaunchOptions) => Promise<PrivilegedHelperRuntime>;
}

/**
 * Parse the immutable runtime descriptor embedded into the signed helper app.
 * Unknown fields are rejected so the artifact cannot gain behavior through a
 * configuration field that this runtime does not understand.
 */
export function validatePrivilegedHelperRuntimeDescriptor(value: unknown): PrivilegedHelperRuntimeDescriptor {
  const record = requireRecord(value, "runtime descriptor");
  requireExactKeys(record, [
    "schemaVersion", "helperRoot", "helperKeyConfigPath", "helperSocketPath", "brokerSocketPath",
    "helperAuthoritySocketPath", "brokerPeer", "sourceRevision", "contractVersion", "policyVersion", "capabilities"
  ], "runtime descriptor");
  if (record.schemaVersion !== "0.1") throw new Error("runtime descriptor schema version is unsupported");

  const helperRoot = requireCanonicalPath(record.helperRoot, "helperRoot");
  const helperKeyConfigPath = requireCanonicalPath(record.helperKeyConfigPath, "helperKeyConfigPath");
  const helperSocketPath = requireCanonicalPath(record.helperSocketPath, "helperSocketPath");
  const brokerSocketPath = requireCanonicalPath(record.brokerSocketPath, "brokerSocketPath");
  const helperAuthoritySocketPath = requireCanonicalPath(record.helperAuthoritySocketPath, "helperAuthoritySocketPath");
  if (helperRoot === "/" || !isDescendant(helperRoot, helperKeyConfigPath) || !isDescendant(helperRoot, helperSocketPath)) {
    throw new Error("helper key config and command socket must remain inside the helper root");
  }
  if (isDescendant(helperRoot, brokerSocketPath) || isDescendant(helperRoot, helperAuthoritySocketPath)) {
    throw new Error("Broker-owned sockets must remain outside the root-owned helper package");
  }
  if (new Set([helperSocketPath, brokerSocketPath, helperAuthoritySocketPath]).size !== 3) {
    throw new Error("helper, Broker, and authority sockets must be distinct");
  }
  for (const [label, path] of [["helperSocketPath", helperSocketPath], ["brokerSocketPath", brokerSocketPath], ["helperAuthoritySocketPath", helperAuthoritySocketPath]] as const) {
    if (Buffer.byteLength(path, "utf8") >= 104) throw new Error(`${label} exceeds the macOS Unix socket path limit`);
  }

  const brokerPeerRecord = requireRecord(record.brokerPeer, "brokerPeer");
  requireExactKeys(brokerPeerRecord, ["uid", "gid"], "brokerPeer");
  const brokerPeer = {
    uid: requireInteger(brokerPeerRecord.uid, 1, 2_147_483_647, "brokerPeer.uid"),
    gid: requireInteger(brokerPeerRecord.gid, 0, 2_147_483_647, "brokerPeer.gid")
  };
  const sourceRevision = requireString(record.sourceRevision, SOURCE_REVISION_PATTERN, "sourceRevision");
  const contractVersion = requireString(record.contractVersion, VERSION_PATTERN, "contractVersion");
  if (contractVersion !== CONTRACT_VERSION) throw new Error("runtime descriptor contract version does not match this helper");
  const policyVersion = requireString(record.policyVersion, VERSION_PATTERN, "policyVersion");

  const capabilitiesRecord = requireRecord(record.capabilities, "capabilities");
  requireExactKeys(capabilitiesRecord, ["serviceControl", "packageInstall", "power"], "capabilities");
  const serviceControl = parseBoundaryCapability(capabilitiesRecord.serviceControl, "serviceControl");
  const packageInstallRecord = requireRecord(capabilitiesRecord.packageInstall, "capabilities.packageInstall");
  requireExactKeys(packageInstallRecord, ["enabled", "systemPublishedExecutablePathAccepted", "catalog"], "capabilities.packageInstall");
  const packageInstallBoundary = parseBoundaryCapability({
    enabled: packageInstallRecord.enabled,
    systemPublishedExecutablePathAccepted: packageInstallRecord.systemPublishedExecutablePathAccepted
  }, "packageInstall");
  if (!Array.isArray(packageInstallRecord.catalog) || packageInstallRecord.catalog.length > 256) {
    throw new Error("packageInstall catalog is malformed");
  }
  const catalog = packageInstallRecord.catalog.map((entry, index) => parsePackageArtifact(entry, index));
  if (packageInstallBoundary.enabled && catalog.length === 0) throw new Error("enabled packageInstall requires a non-empty approved catalog");
  if (!packageInstallBoundary.enabled && catalog.length !== 0) throw new Error("disabled packageInstall cannot carry an inactive artifact catalog");
  const power = parseBoundaryCapability(capabilitiesRecord.power, "power");

  return Object.freeze({
    schemaVersion: "0.1",
    helperRoot,
    helperKeyConfigPath,
    helperSocketPath,
    brokerSocketPath,
    helperAuthoritySocketPath,
    brokerPeer: Object.freeze(brokerPeer),
    sourceRevision,
    contractVersion,
    policyVersion,
    capabilities: Object.freeze({
      serviceControl: Object.freeze(serviceControl),
      packageInstall: Object.freeze({ ...packageInstallBoundary, catalog: Object.freeze(catalog) }),
      power: Object.freeze(power)
    })
  });
}

/** Parse descriptor bytes without accepting duplicate keys or malformed UTF-8. */
export function parsePrivilegedHelperRuntimeDescriptor(bytes: Uint8Array): PrivilegedHelperRuntimeDescriptor {
  return validatePrivilegedHelperRuntimeDescriptor(parseJsonUtf8Strict(bytes));
}

/**
 * Bind an embedded descriptor to the root process and the exact Broker
 * LaunchAgent. The async authority poller remains the final Broker-owned gate;
 * this process-local callback never grants capability on its own.
 */
export async function createPrivilegedHelperRuntimeFromDescriptor(
  descriptorInput: unknown,
  host: PrivilegedHelperRuntimeHost = {
    platform: process.platform,
    effectiveUid: process.geteuid?.() ?? -1,
    executablePath: process.execPath
  }
): Promise<PrivilegedHelperRuntime> {
  const descriptor = validatePrivilegedHelperRuntimeDescriptor(descriptorInput);
  if (host.platform !== "darwin") throw new Error("privileged helper runtime requires macOS");
  if (host.effectiveUid !== 0) throw new Error("privileged helper runtime requires the root service identity");
  const executablePath = requireCanonicalPath(host.executablePath, "helper executable path");

  const expectedCapabilities = enabledCapabilities(descriptor);
  const adapter = expectedCapabilities.length === 0
    ? new FailClosedPrivilegedHelper()
    : createPrivilegedHelperAdapter({
      serviceControl: {
        enabled: descriptor.capabilities.serviceControl.enabled,
        systemPublishedExecutablePathAccepted: descriptor.capabilities.serviceControl.systemPublishedExecutablePathAccepted
      },
      packageInstall: {
        enabled: descriptor.capabilities.packageInstall.enabled,
        systemPublishedExecutablePathAccepted: descriptor.capabilities.packageInstall.systemPublishedExecutablePathAccepted,
        catalog: descriptor.capabilities.packageInstall.catalog
      },
      power: {
        enabled: descriptor.capabilities.power.enabled,
        systemPublishedExecutablePathAccepted: descriptor.capabilities.power.systemPublishedExecutablePathAccepted
      }
    });
  if (!sameStrings(adapter.enabledCapabilities, expectedCapabilities) || adapter.available !== (expectedCapabilities.length > 0)) {
    throw new Error("signed helper capability projection does not match host readiness");
  }

  const createRuntime = host.createRuntime ?? createPrivilegedHelperRuntimeFromKeyMaterialForLaunchdBroker;
  return createRuntime({
    helperRoot: descriptor.helperRoot,
    helperKeyConfigPath: descriptor.helperKeyConfigPath,
    keychainTrustedExecutablePath: executablePath,
    socketPath: descriptor.helperSocketPath,
    brokerSocketPath: descriptor.brokerSocketPath,
    authoritySocketPath: descriptor.helperAuthoritySocketPath,
    brokerServiceId: `gui/${descriptor.brokerPeer.uid}/com.mac-operator.broker`,
    expectedBrokerUid: descriptor.brokerPeer.uid,
    expectedBrokerGid: descriptor.brokerPeer.gid,
    adapter,
    authorizeCommand: () => undefined,
    authorizeStatus: () => undefined,
    ...(host.onPeerIdentityLost === undefined ? {} : { serverOptions: { onPeerIdentityLost: host.onPeerIdentityLost } }),
    readStatus: (): PrivilegedHelperStatusReadback => ({
      component: "mac-operator-privileged-helper",
      state: "running",
      runtimeState: "running",
      nativeTransportRequired: true,
      adapterAvailable: adapter.available,
      helperSocketPath: descriptor.helperSocketPath,
      brokerSocketPath: descriptor.brokerSocketPath,
      helperAuthoritySocketPath: descriptor.helperAuthoritySocketPath,
      brokerPeerUid: descriptor.brokerPeer.uid,
      brokerPeerGid: descriptor.brokerPeer.gid,
      sourceRevision: descriptor.sourceRevision,
      contractVersion: descriptor.contractVersion,
      policyVersion: descriptor.policyVersion,
      enabledCapabilities: [...adapter.enabledCapabilities]
    })
  });
}

/** Entry called by the small CommonJS SEA bootstrap stored inside the app. */
export async function runEmbeddedPrivilegedHelper(): Promise<void> {
  const sea = createRequire(import.meta.url)("node:sea") as {
    isSea(): boolean;
    getAsset(name: string): Buffer;
  };
  if (!sea.isSea()) throw new Error("privileged helper must run as a signed single-executable app");
  const descriptor = parsePrivilegedHelperRuntimeDescriptor(sea.getAsset(RUNTIME_ASSET_NAME));
  let closing = false;
  let identityLostBeforeRuntime = false;
  let runtime: PrivilegedHelperRuntime | undefined;
  const close = (fatal: boolean): void => {
    if (closing) return;
    closing = true;
    if (fatal) process.exitCode = 1;
    if (runtime !== undefined) void runtime.close().catch(() => { process.exitCode = 1; });
  };
  const handleSigterm = (): void => close(false);
  const handleSigint = (): void => close(false);
  process.once("SIGTERM", handleSigterm);
  process.once("SIGINT", handleSigint);
  runtime = await createPrivilegedHelperRuntimeFromDescriptor(descriptor, {
    platform: process.platform,
    effectiveUid: process.geteuid?.() ?? -1,
    executablePath: process.execPath,
    onPeerIdentityLost: () => {
      if (runtime === undefined) identityLostBeforeRuntime = true;
      close(true);
    }
  });
  if (identityLostBeforeRuntime) {
    await runtime.close().catch(() => undefined);
    throw new Error("bound Broker process identity was lost during helper startup");
  }
  if (closing) {
    await runtime.close();
    return;
  }
  try {
    await runtime.start();
  } catch (error) {
    process.removeListener("SIGTERM", handleSigterm);
    process.removeListener("SIGINT", handleSigint);
    throw error;
  }
}

function enabledCapabilities(descriptor: PrivilegedHelperRuntimeDescriptor): string[] {
  const enabled = new Set<string>();
  if (descriptor.capabilities.serviceControl.enabled) enabled.add("mac_priv_service_control");
  if (descriptor.capabilities.packageInstall.enabled) enabled.add("mac_priv_package_install");
  if (descriptor.capabilities.power.enabled) enabled.add("mac_priv_power");
  return CAPABILITY_ORDER.filter((capability) => enabled.has(capability));
}

function parseBoundaryCapability(value: unknown, label: string): { enabled: boolean; systemPublishedExecutablePathAccepted: boolean } {
  const record = requireRecord(value, `capabilities.${label}`);
  requireExactKeys(record, ["enabled", "systemPublishedExecutablePathAccepted"], `capabilities.${label}`);
  if (typeof record.enabled !== "boolean" || typeof record.systemPublishedExecutablePathAccepted !== "boolean") {
    throw new Error(`capabilities.${label} boundary flags are invalid`);
  }
  if (record.enabled !== record.systemPublishedExecutablePathAccepted) {
    throw new Error(`capabilities.${label} requires explicit acceptance of its fixed system executable boundary`);
  }
  return { enabled: record.enabled, systemPublishedExecutablePathAccepted: record.systemPublishedExecutablePathAccepted };
}

function parsePackageArtifact(value: unknown, index: number): ApprovedPackageArtifact {
  const record = requireRecord(value, `packageInstall.catalog[${index}]`);
  requireExactKeys(record, ["packageId", "version", "artifactId", "artifactPath", "artifactSha256", "sourceProfile"], `packageInstall.catalog[${index}]`);
  const packageId = requireString(record.packageId, /^[A-Za-z0-9][A-Za-z0-9._:@+-]{0,254}$/u, "packageId");
  const version = requireString(record.version, /^[A-Za-z0-9._:+-]{1,128}$/u, "package version");
  const artifactId = requireString(record.artifactId, /^[A-Za-z0-9._:@/+-]{1,255}$/u, "artifactId");
  const artifactPath = requireCanonicalPath(record.artifactPath, "artifactPath");
  const artifactSha256 = requireString(record.artifactSha256, /^[a-f0-9]{64}$/u, "artifactSha256");
  const sourceProfile = requireString(record.sourceProfile, /^[A-Za-z0-9._:-]{1,128}$/u, "sourceProfile");
  return Object.freeze({ packageId, version, artifactId, artifactPath, artifactSha256, sourceProfile });
}

function requireRecord(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value) || Object.getPrototypeOf(value) !== Object.prototype) {
    throw new Error(`${label} must be a plain object`);
  }
  return value as Record<string, unknown>;
}

function requireExactKeys(value: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  const actual = Object.keys(value);
  if (actual.length !== keys.length || actual.some((key) => !allowed.has(key))) {
    throw new Error(`${label} contains unsupported or missing fields`);
  }
}

function requireCanonicalPath(value: unknown, label: string): string {
  if (typeof value !== "string" || !isAbsolute(value) || value === "/" || value.endsWith("/") ||
      value.includes("\0") || value.includes("\r") || value.includes("\n") || resolve(value) !== value) {
    throw new Error(`${label} must be a canonical absolute path`);
  }
  return value;
}

function isDescendant(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path !== "" && path !== ".." && !path.startsWith(`..${sep}`) && !isAbsolute(path);
}

function requireInteger(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${label} is outside its supported range`);
  }
  return value as number;
}

function requireString(value: unknown, pattern: RegExp, label: string): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`${label} is malformed`);
  return value;
}

function sameStrings(left: readonly string[], right: readonly string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}
