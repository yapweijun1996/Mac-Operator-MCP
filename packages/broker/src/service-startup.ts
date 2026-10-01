import type { DevelopmentGateway } from "./development-gateway.js";
import { DEVELOPMENT_EXECUTION_TOOLS } from "./development-policy.js";
import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Broker } from "./broker.js";
import { BrokerStore } from "./persistence.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { PolicyBundleVerifier, PolicyManager } from "./policy-loader.js";
import {
  captureLaunchdAuthorityProcessIdentity,
  createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig,
  createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfigAndAuthority,
  createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfigAndRootHelperSnapshotAuthority,
  type LaunchdIdentityCommandExecutor
} from "./native-runtime-startup.js";
import { BrokerServiceEntrypoint, type BrokerServiceMetadata } from "./service-entrypoint.js";
import { assertSocketNotActive } from "./ipc-server.js";
import { BrokerServiceInstanceLock } from "./service-instance-lock.js";
import { BrokerStatusIpcServer, BrokerStoreBrokerStatusReplayGuard } from "./broker-status-ipc.js";
import { createKeychainAuditAnchorKeySource, loadAuthenticationKey } from "./credentials.js";
import { BrokerError, parseJsonUtf8Strict, sha256 } from "@mac-operator/contracts";
import { VirtualizationGuestAttestationKeyManager } from "./virtualization-guest-attestation-keyring.js";
import {
  createVirtualizationGuestRuntime,
  type VirtualizationGuestRuntime,
  type VirtualizationGuestRuntimeStartupOptions
} from "./virtualization-guest-startup.js";
import { BrokerStoreVirtualizationGuestReplayGuard } from "./virtualization-guest-transport.js";
import {
  AppSandboxTaskRunner,
  RootHelperSnapshotTaskRunner,
  SandboxExecTaskRunner,
  assertTaskRunnerPublicEnablement,
  type SandboxExecTaskRunnerOptions
} from "./task-runner.js";
import { validateTaskProfileRegistry, type TaskProfileRegistry } from "./task-profile.js";
import type { RootHelperSnapshotRequestAuthority } from "./root-helper-snapshot-authority.js";
import {
  createRootHelperSnapshotTaskRunnerFromActiveKeyConfig,
  type RootHelperSnapshotTaskRunnerStartupOptions
} from "./root-helper-snapshot-task-startup.js";
import {
  createAppSandboxTaskRunnerFromStartup,
  type AppSandboxTaskRunnerStartupOptions
} from "./app-sandbox-task-startup.js";
import {
  ACCESSIBILITY_BOUND_GUI_TOOLS,
  assertGuiPublicEnablement,
  type GuiPublicEnablement
} from "./gui-readiness.js";
import {
  DEVELOPER_MUTATION_TOOLS,
  assertDeveloperPublicEnablement,
  type DeveloperPublicEnablement
} from "./developer-readiness.js";
import { validateMacOsHostReadinessEvidence } from "./host-readiness.js";
import { isPlainDataRecord } from "./plain-record.js";
import {
  UserServiceControlAdapter,
  type UserServiceBinding,
  type UserServiceSourceRevisionReader
} from "./user-service-control.js";
import type { DescriptorProcessSpawnAdapter } from "./process-supervisor.js";
import { UserServiceControlJobExecutor } from "./user-service-control-executor.js";
import {
  createApprovalIssuerRuntime,
  type ApprovalIssuerRuntimeAssembly,
  type ApprovalIssuerStartupOptions
} from "./approval-issuer-startup.js";

const MAX_CONFIG_BYTES = 64 * 1024;
const CONFIG_KEYS = new Set([
  "schemaVersion", "packageRoot", "dataRoot", "runtimeRoot", "brokerDatabasePath", "brokerSocketPath",
  "statusSocketPath", "statusKeyPath", "statusKeyDigest",
  "auditAnchorPath", "auditAnchorKeyService", "auditAnchorKeyAccount", "auditAnchorKeyId",
  "auditArchiveKeyService", "auditArchiveKeyAccount", "auditArchiveKeyId",
  "edgeId", "edgeServiceId", "expectedEdgeUid", "expectedEdgeGid", "edgeKeyConfigPath",
  "policyBundlePath", "policySchemaDirectory", "policyVerificationKeyId", "policyVerificationKeyPath", "guestAttestationKeyConfigPath",
  "approvalIssuerKeyConfigPath", "approvalIssuerSocketPath",
  "authorityControlKeyConfigPath", "authorityControlSocketPath", "authorityOperatorSocketPath", "authorityControlServiceId",
  "rootHelperSnapshotKeyConfigPath", "rootHelperSnapshotSocketPath", "rootHelperSnapshotAuthoritySocketPath", "rootHelperSnapshotServiceId",
  "guiPublicEnablement", "developerPublicEnablement", "hostReadinessEvidencePath",
  "sourceRevision", "contractVersion"
]);
const REVISION_PATTERN = /^[0-9a-f]{7,64}$/u;
const VERSION_PATTERN = /^v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u;
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;

export interface BrokerServiceStartupConfig {
  schemaVersion: "0.1";
  packageRoot: string;
  dataRoot: string;
  runtimeRoot: string;
  brokerDatabasePath: string;
  brokerSocketPath: string;
  statusSocketPath: string;
  statusKeyPath: string;
  statusKeyDigest: string;
  auditAnchorPath: string;
  auditAnchorKeyService: string;
  auditAnchorKeyAccount: string;
  auditAnchorKeyId: string;
  /** Optional separate Keychain item used only for encrypted audit exports. */
  auditArchiveKeyService?: string;
  auditArchiveKeyAccount?: string;
  auditArchiveKeyId?: string;
  edgeId: string;
  edgeServiceId: string;
  expectedEdgeUid: number;
  expectedEdgeGid?: number;
  edgeKeyConfigPath: string;
  policyBundlePath: string;
  policySchemaDirectory: string;
  policyVerificationKeyId: string;
  policyVerificationKeyPath: string;
  /** Optional startup-only trust set for signed guest provenance. */
  guestAttestationKeyConfigPath?: string;
  /** Optional protected owner approval issuer metadata and local socket. */
  approvalIssuerKeyConfigPath?: string;
  approvalIssuerSocketPath?: string;
  /** Optional protected owner Authority Control key and stable operator service. */
  authorityControlKeyConfigPath?: string;
  authorityControlSocketPath?: string;
  authorityOperatorSocketPath?: string;
  authorityControlServiceId?: `gui/${number}/com.mac-operator.authority`;
  /** Optional explicit root-helper authority channel configuration. */
  rootHelperSnapshotKeyConfigPath?: string;
  rootHelperSnapshotSocketPath?: string;
  rootHelperSnapshotAuthoritySocketPath?: string;
  rootHelperSnapshotServiceId?: "system/com.mac-operator.root-helper-snapshot";
  /** Owner-only startup gate for Accessibility-dependent GUI tools. */
  guiPublicEnablement?: GuiPublicEnablement;
  /** Owner-only startup gate for D1 developer mutation tools. */
  developerPublicEnablement?: DeveloperPublicEnablement;
  /** Owner-only, time-bounded evidence consumed by production exposure gates. */
  hostReadinessEvidencePath?: string;
  sourceRevision: string;
  contractVersion: string;
}

export interface BrokerServiceAssembly {
  readonly service: BrokerServiceEntrypoint;
  readonly store: BrokerStore;
  readonly edgeKeyring: EdgeKeyring;
  /** Restored startup trust set, when signed guest provenance is configured. */
  readonly guestAttestationKeyManager?: VirtualizationGuestAttestationKeyManager;
  /** Optional startup-owned VM/channel runtime; absent when virtualization is disabled. */
  readonly virtualizationGuestRuntime?: VirtualizationGuestRuntime;
  /** Optional startup-owned experimental sandbox runner; absent by default. */
  readonly sandboxTaskRunner?: SandboxExecTaskRunner;
  /** Optional startup-owned App Sandbox runner; absent by default. */
  readonly appSandboxTaskRunner?: AppSandboxTaskRunner;
  /** Optional startup-owned root-helper snapshot runner; absent by default. */
  readonly rootHelperSnapshotTaskRunner?: RootHelperSnapshotTaskRunner;
  /** Optional startup-owned user-service control adapter; absent by default. */
  readonly userServiceControlAdapter?: UserServiceControlAdapter;
  /** Optional startup-owned user-service Job executor; absent by default. */
  readonly userServiceControlExecutor?: UserServiceControlJobExecutor;
  /** Optional startup-owned owner approval issuer; absent by default. */
  readonly approvalIssuerRuntime?: ApprovalIssuerRuntimeAssembly;
  close(): Promise<void>;
}

/**
 * Explicit host-owned inputs for the bounded user-domain LaunchAgent path.
 * Startup never derives bindings, source revisions, or principal authority
 * from MCP arguments or ambient environment state.
 */
export interface UserServiceControlStartupOptions {
  enabled?: boolean;
  uid?: number;
  bindings: readonly UserServiceBinding[];
  authorizedPrincipalIds: readonly string[];
  sourceRevisionReader: UserServiceSourceRevisionReader;
  descriptorSpawnAdapter?: DescriptorProcessSpawnAdapter;
  systemPublishedExecutablePathAccepted?: boolean;
  leaseDurationMs?: number;
}

export interface UserServiceControlRuntimeAssembly {
  adapter: UserServiceControlAdapter;
  executor: UserServiceControlJobExecutor;
}

/**
 * Assemble the bounded user-service runtime from explicit owner startup
 * inputs. The default is disabled; enabled assembly requires the adapter's
 * native host boundary to be independently available.
 */
export function createUserServiceControlRuntime(options: {
  store: BrokerStore;
  startup: UserServiceControlStartupOptions;
  now?: () => number;
}): UserServiceControlRuntimeAssembly {
  if (!options || typeof options !== "object" || !options.store || !options.startup || typeof options.startup !== "object") {
    throw new Error("User service-control startup options are malformed");
  }
  const startup = options.startup;
  if (!Array.isArray(startup.bindings) || !Array.isArray(startup.authorizedPrincipalIds) ||
      !startup.sourceRevisionReader || typeof startup.sourceRevisionReader.read !== "function") {
    throw new Error("User service-control startup inputs are incomplete");
  }
  if (startup.enabled !== undefined && typeof startup.enabled !== "boolean") {
    throw new Error("User service-control startup enablement is invalid");
  }
  const enabled = startup.enabled ?? false;
  const adapter = new UserServiceControlAdapter({
    enabled,
    ...(startup.uid === undefined ? {} : { uid: startup.uid }),
    bindings: startup.bindings,
    sourceRevisionReader: startup.sourceRevisionReader,
    ...(startup.descriptorSpawnAdapter === undefined ? {} : { descriptorSpawnAdapter: startup.descriptorSpawnAdapter }),
    ...(startup.systemPublishedExecutablePathAccepted === undefined ? {} : { systemPublishedExecutablePathAccepted: startup.systemPublishedExecutablePathAccepted }),
    ...(options.now === undefined ? {} : { now: options.now })
  });
  const executor = new UserServiceControlJobExecutor({
    store: options.store,
    adapter,
    enabled,
    ...(startup.leaseDurationMs === undefined ? {} : { leaseDurationMs: startup.leaseDurationMs }),
    ...(options.now === undefined ? {} : { now: options.now })
  });
  return { adapter, executor };
}

export function brokerServiceInstanceLockPath(runtimeRoot: string): string {
  validateCanonicalPath(runtimeRoot, "runtime root");
  return join(runtimeRoot, "broker.instance.lock");
}

/** Fixed owner-only destination for host audit exports; MCP paths cannot select it. */
export function brokerAuditArchiveDirectoryPath(config: BrokerServiceStartupConfig): string {
  const validated = validateBrokerServiceStartupConfig(config);
  return join(validated.dataRoot, "audit-exports");
}

/** Canonical Broker-owned roots that an experimental host task must never read or write. */
export function brokerSandboxProtectedFilesystemRoots(config: BrokerServiceStartupConfig): readonly string[] {
  const validated = validateBrokerServiceStartupConfig(config);
  return [validated.packageRoot, validated.dataRoot, validated.runtimeRoot];
}

/**
 * Loads the fixed, non-secret startup document used by a packaged Broker
 * entrypoint. Secret bytes are deliberately absent; key and policy loaders
 * apply their own owner-only, digest, and activation checks later.
 */
export async function loadBrokerServiceStartupConfig(path: string): Promise<BrokerServiceStartupConfig> {
  const content = await readProtectedConfig(path);
  let value: unknown;
  try {
    value = parseJsonUtf8Strict(content);
  } catch {
    throw new Error("Broker service startup config is not valid JSON");
  }
  return validateBrokerServiceStartupConfig(value);
}

export function validateBrokerServiceStartupConfig(value: unknown): BrokerServiceStartupConfig {
  if (!isPlainDataRecord(value)) {
    throw new Error("Broker service startup config is malformed");
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!CONFIG_KEYS.has(key)) throw new Error(`Broker service startup config has an unknown field: ${key}`);
  }
  if (record.schemaVersion !== "0.1") throw new Error("Broker service startup config schema version is unsupported");
  const pathValues = [
    "packageRoot", "dataRoot", "runtimeRoot", "brokerDatabasePath", "brokerSocketPath", "statusSocketPath", "statusKeyPath", "auditAnchorPath", "edgeKeyConfigPath",
    "policyBundlePath", "policySchemaDirectory", "policyVerificationKeyPath"
  ].map((key) => [key, record[key]] as const);
  for (const [key, pathValue] of pathValues) validateCanonicalPath(pathValue, key);
  if (record.guestAttestationKeyConfigPath !== undefined) {
    validateCanonicalPath(record.guestAttestationKeyConfigPath, "guestAttestationKeyConfigPath");
  }
  if (record.hostReadinessEvidencePath !== undefined) {
    validateCanonicalPath(record.hostReadinessEvidencePath, "hostReadinessEvidencePath");
  }
  const auditArchiveKeyFields = [record.auditArchiveKeyService, record.auditArchiveKeyAccount, record.auditArchiveKeyId];
  const auditArchiveKeyFieldCount = auditArchiveKeyFields.filter((value) => value !== undefined).length;
  if (auditArchiveKeyFieldCount !== 0 && auditArchiveKeyFieldCount !== auditArchiveKeyFields.length) {
    throw new Error("Audit archive Keychain configuration must be complete");
  }
  const approvalIssuerFields = [record.approvalIssuerKeyConfigPath, record.approvalIssuerSocketPath];
  const approvalIssuerFieldCount = approvalIssuerFields.filter((value) => value !== undefined).length;
  if (approvalIssuerFieldCount !== 0 && approvalIssuerFieldCount !== approvalIssuerFields.length) {
    throw new Error("Approval issuer startup configuration must be complete");
  }
  if (approvalIssuerFieldCount === approvalIssuerFields.length) {
    validateCanonicalPath(record.approvalIssuerKeyConfigPath, "approvalIssuerKeyConfigPath");
    validateCanonicalPath(record.approvalIssuerSocketPath, "approvalIssuerSocketPath");
  }
  const authorityControlFields = [
    record.authorityControlKeyConfigPath,
    record.authorityControlSocketPath,
    record.authorityOperatorSocketPath,
    record.authorityControlServiceId
  ];
  const authorityControlFieldCount = authorityControlFields.filter((value) => value !== undefined).length;
  if (authorityControlFieldCount !== 0 && authorityControlFieldCount !== authorityControlFields.length) {
    throw new Error("Authority Control startup configuration must be complete");
  }
  if (authorityControlFieldCount === authorityControlFields.length) {
    validateCanonicalPath(record.authorityControlKeyConfigPath, "authorityControlKeyConfigPath");
    validateCanonicalPath(record.authorityControlSocketPath, "authorityControlSocketPath");
    validateCanonicalPath(record.authorityOperatorSocketPath, "authorityOperatorSocketPath");
  }
  const rootHelperFields = [
    record.rootHelperSnapshotKeyConfigPath,
    record.rootHelperSnapshotSocketPath,
    record.rootHelperSnapshotAuthoritySocketPath,
    record.rootHelperSnapshotServiceId
  ];
  const rootHelperFieldCount = rootHelperFields.filter((value) => value !== undefined).length;
  if (rootHelperFieldCount !== 0 && rootHelperFieldCount !== rootHelperFields.length) {
    throw new Error("Root-helper snapshot startup configuration must be complete");
  }
  if (rootHelperFieldCount === rootHelperFields.length) {
    validateCanonicalPath(record.rootHelperSnapshotKeyConfigPath, "rootHelperSnapshotKeyConfigPath");
    validateCanonicalPath(record.rootHelperSnapshotSocketPath, "rootHelperSnapshotSocketPath");
    validateCanonicalPath(record.rootHelperSnapshotAuthoritySocketPath, "rootHelperSnapshotAuthoritySocketPath");
  }
  const packageRoot = record.packageRoot as string;
  const dataRoot = record.dataRoot as string;
  const runtimeRoot = record.runtimeRoot as string;
  if (packageRoot === "/" || dataRoot === "/" || runtimeRoot === "/" || packageRoot === dataRoot || packageRoot === runtimeRoot || dataRoot === runtimeRoot) {
    throw new Error("Broker service startup roots must be distinct non-root paths");
  }
  const brokerDatabasePath = record.brokerDatabasePath as string;
  const brokerSocketPath = record.brokerSocketPath as string;
  const statusSocketPath = record.statusSocketPath as string;
  const statusKeyPath = record.statusKeyPath as string;
  const auditAnchorPath = record.auditAnchorPath as string;
  if (!isDescendant(dataRoot, brokerDatabasePath) || !isDescendant(runtimeRoot, brokerSocketPath) ||
      !isDescendant(runtimeRoot, statusSocketPath) || !isDescendant(dataRoot, statusKeyPath) ||
      !isDescendant(dataRoot, auditAnchorPath) || auditAnchorPath === brokerDatabasePath ||
      brokerSocketPath === statusSocketPath || !statusSocketPath.endsWith(".sock") ||
      Buffer.byteLength(statusSocketPath, "utf8") >= 104 ||
      typeof record.statusKeyDigest !== "string" || !/^[a-f0-9]{64}$/u.test(record.statusKeyDigest) ||
      typeof record.auditAnchorKeyService !== "string" || !/^com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(record.auditAnchorKeyService) ||
      typeof record.auditAnchorKeyAccount !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(record.auditAnchorKeyAccount) ||
      !ID_PATTERN.test(String(record.auditAnchorKeyId))) {
    throw new Error("Broker service state paths must remain inside their configured roots");
  }
  if (auditArchiveKeyFieldCount === auditArchiveKeyFields.length &&
      (typeof record.auditArchiveKeyService !== "string" || !/^com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(record.auditArchiveKeyService) ||
       typeof record.auditArchiveKeyAccount !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(record.auditArchiveKeyAccount) ||
       !ID_PATTERN.test(String(record.auditArchiveKeyId)) ||
       (record.auditArchiveKeyService === record.auditAnchorKeyService && record.auditArchiveKeyAccount === record.auditAnchorKeyAccount))) {
    throw new Error("Audit archive Keychain configuration is invalid or reuses the audit anchor item");
  }
  if (!isDescendant(dataRoot, record.edgeKeyConfigPath as string) || !isDescendant(dataRoot, record.policyBundlePath as string) ||
      !isDescendant(dataRoot, record.policyVerificationKeyPath as string) || !isDescendant(packageRoot, record.policySchemaDirectory as string) ||
      (record.guestAttestationKeyConfigPath !== undefined && !isDescendant(dataRoot, record.guestAttestationKeyConfigPath as string)) ||
      (approvalIssuerFieldCount === approvalIssuerFields.length &&
        (!isDescendant(dataRoot, record.approvalIssuerKeyConfigPath as string) ||
         !isDescendant(runtimeRoot, record.approvalIssuerSocketPath as string))) ||
      (authorityControlFieldCount === authorityControlFields.length &&
        (!isDescendant(dataRoot, record.authorityControlKeyConfigPath as string) ||
         !isDescendant(runtimeRoot, record.authorityControlSocketPath as string) ||
         !isDescendant(runtimeRoot, record.authorityOperatorSocketPath as string))) ||
      (record.hostReadinessEvidencePath !== undefined &&
        !isDescendant(dataRoot, record.hostReadinessEvidencePath as string))) {
    throw new Error("Broker service configuration paths must remain inside their configured roots");
  }
  if (approvalIssuerFieldCount === approvalIssuerFields.length &&
      (!String(record.approvalIssuerSocketPath).endsWith(".sock") ||
       String(record.approvalIssuerSocketPath) === brokerSocketPath ||
       String(record.approvalIssuerSocketPath) === statusSocketPath ||
       Buffer.byteLength(String(record.approvalIssuerSocketPath), "utf8") >= 104)) {
    throw new Error("Approval issuer startup socket is invalid");
  }
  if (authorityControlFieldCount === authorityControlFields.length &&
      (!String(record.authorityControlSocketPath).endsWith(".sock") ||
       String(record.authorityControlSocketPath) === brokerSocketPath ||
       String(record.authorityControlSocketPath) === statusSocketPath ||
       (approvalIssuerFieldCount === approvalIssuerFields.length && String(record.authorityControlSocketPath) === String(record.approvalIssuerSocketPath)) ||
       String(record.authorityOperatorSocketPath) === brokerSocketPath ||
       String(record.authorityOperatorSocketPath) === statusSocketPath ||
       String(record.authorityOperatorSocketPath) === String(record.authorityControlSocketPath) ||
       (approvalIssuerFieldCount === approvalIssuerFields.length && String(record.authorityOperatorSocketPath) === String(record.approvalIssuerSocketPath)) ||
       !String(record.authorityOperatorSocketPath).endsWith(".sock") ||
       Buffer.byteLength(String(record.authorityControlSocketPath), "utf8") >= 104 ||
       Buffer.byteLength(String(record.authorityOperatorSocketPath), "utf8") >= 104 ||
       !/^gui\/[1-9][0-9]{0,9}\/com\.mac-operator\.authority$/u.test(String(record.authorityControlServiceId)))) {
    throw new Error("Authority Control startup socket or service identity is invalid");
  }
  if (rootHelperFieldCount === rootHelperFields.length &&
      (!isDescendant(dataRoot, record.rootHelperSnapshotKeyConfigPath as string) ||
       !isDescendant(runtimeRoot, record.rootHelperSnapshotSocketPath as string) ||
       !isDescendant(runtimeRoot, record.rootHelperSnapshotAuthoritySocketPath as string))) {
    throw new Error("Root-helper snapshot startup paths escaped the configured roots");
  }
  if (rootHelperFieldCount === rootHelperFields.length &&
      (!String(record.rootHelperSnapshotSocketPath).endsWith(".sock") ||
       !String(record.rootHelperSnapshotAuthoritySocketPath).endsWith(".sock") ||
       String(record.rootHelperSnapshotSocketPath) === brokerSocketPath ||
       String(record.rootHelperSnapshotSocketPath) === String(record.rootHelperSnapshotAuthoritySocketPath) ||
       !/^system\/com\.mac-operator\.root-helper-snapshot$/u.test(String(record.rootHelperSnapshotServiceId)))) {
    throw new Error("Root-helper snapshot startup paths or service identity are invalid");
  }
  const guiPublicEnablement = parsePublicEnablement(record.guiPublicEnablement, "guiPublicEnablement");
  const developerPublicEnablement = parsePublicEnablement(record.developerPublicEnablement, "developerPublicEnablement");
  if (!brokerSocketPath.endsWith(".sock")) throw new Error("Broker service socket path must end in .sock");
  if (!ID_PATTERN.test(String(record.edgeId))) throw new Error("Broker service Edge identity is invalid");
  const expectedEdgeUid = parseUid(record.expectedEdgeUid, "expectedEdgeUid");
  const expectedEdgeGid = record.expectedEdgeGid === undefined ? undefined : parseUid(record.expectedEdgeGid, "expectedEdgeGid");
  if (!/^gui\/[1-9][0-9]{0,9}\/com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(String(record.edgeServiceId)) ||
      !String(record.edgeServiceId).startsWith(`gui/${expectedEdgeUid}/`)) {
    throw new Error("Broker service Edge launchd identity is invalid");
  }
  if (authorityControlFieldCount === authorityControlFields.length &&
      !String(record.authorityControlServiceId).startsWith(`gui/${expectedEdgeUid}/`)) {
    throw new Error("Authority Control service user does not match the Broker user");
  }
  if (!ID_PATTERN.test(String(record.policyVerificationKeyId))) throw new Error("Broker policy verification key identity is invalid");
  if (!REVISION_PATTERN.test(String(record.sourceRevision))) throw new Error("Broker service source revision is invalid");
  if (!VERSION_PATTERN.test(String(record.contractVersion))) throw new Error("Broker service contract version is invalid");
  return {
    schemaVersion: "0.1",
    packageRoot,
    dataRoot,
    runtimeRoot,
    brokerDatabasePath,
    brokerSocketPath,
    statusSocketPath,
    statusKeyPath,
    statusKeyDigest: record.statusKeyDigest as string,
    auditAnchorPath,
    auditAnchorKeyService: record.auditAnchorKeyService as string,
    auditAnchorKeyAccount: record.auditAnchorKeyAccount as string,
    auditAnchorKeyId: record.auditAnchorKeyId as string,
    ...(record.auditArchiveKeyService === undefined ? {} : { auditArchiveKeyService: record.auditArchiveKeyService as string }),
    ...(record.auditArchiveKeyAccount === undefined ? {} : { auditArchiveKeyAccount: record.auditArchiveKeyAccount as string }),
    ...(record.auditArchiveKeyId === undefined ? {} : { auditArchiveKeyId: record.auditArchiveKeyId as string }),
    edgeId: record.edgeId as string,
    edgeServiceId: record.edgeServiceId as string,
    expectedEdgeUid,
    ...(expectedEdgeGid === undefined ? {} : { expectedEdgeGid }),
    edgeKeyConfigPath: record.edgeKeyConfigPath as string,
    policyBundlePath: record.policyBundlePath as string,
    policySchemaDirectory: record.policySchemaDirectory as string,
    policyVerificationKeyId: record.policyVerificationKeyId as string,
    policyVerificationKeyPath: record.policyVerificationKeyPath as string,
    ...(record.guestAttestationKeyConfigPath === undefined ? {} : { guestAttestationKeyConfigPath: record.guestAttestationKeyConfigPath as string }),
    ...(record.approvalIssuerKeyConfigPath === undefined ? {} : { approvalIssuerKeyConfigPath: record.approvalIssuerKeyConfigPath as string }),
    ...(record.approvalIssuerSocketPath === undefined ? {} : { approvalIssuerSocketPath: record.approvalIssuerSocketPath as string }),
    ...(record.authorityControlKeyConfigPath === undefined ? {} : { authorityControlKeyConfigPath: record.authorityControlKeyConfigPath as string }),
    ...(record.authorityControlSocketPath === undefined ? {} : { authorityControlSocketPath: record.authorityControlSocketPath as string }),
    ...(record.authorityOperatorSocketPath === undefined ? {} : { authorityOperatorSocketPath: record.authorityOperatorSocketPath as string }),
    ...(record.authorityControlServiceId === undefined ? {} : { authorityControlServiceId: record.authorityControlServiceId as `gui/${number}/com.mac-operator.authority` }),
    ...(record.rootHelperSnapshotKeyConfigPath === undefined ? {} : { rootHelperSnapshotKeyConfigPath: record.rootHelperSnapshotKeyConfigPath as string }),
    ...(record.rootHelperSnapshotSocketPath === undefined ? {} : { rootHelperSnapshotSocketPath: record.rootHelperSnapshotSocketPath as string }),
    ...(record.rootHelperSnapshotAuthoritySocketPath === undefined ? {} : { rootHelperSnapshotAuthoritySocketPath: record.rootHelperSnapshotAuthoritySocketPath as string }),
    ...(record.rootHelperSnapshotServiceId === undefined ? {} : { rootHelperSnapshotServiceId: record.rootHelperSnapshotServiceId as "system/com.mac-operator.root-helper-snapshot" }),
    ...(guiPublicEnablement === undefined ? {} : { guiPublicEnablement }),
    ...(developerPublicEnablement === undefined ? {} : { developerPublicEnablement }),
    ...(record.hostReadinessEvidencePath === undefined ? {} : { hostReadinessEvidencePath: record.hostReadinessEvidencePath as string }),
    sourceRevision: record.sourceRevision as string,
    contractVersion: record.contractVersion as string
  };
}

/**
 * Assembles the production Broker service without accepting MCP or ambient
 * environment authority. The persisted Edge-key and policy activations must
 * already exist; startup never silently activates new authority.
 */
export async function createBrokerServiceFromStartupConfig(options: {
  config: BrokerServiceStartupConfig;
  commandExecutor?: LaunchdIdentityCommandExecutor;
  now?: () => number;
  /** Explicit host startup seam; MCP request arguments never reach this object. */
  virtualizationGuest?: VirtualizationGuestRuntimeStartupOptions;
  /** Explicit host startup seam; production defaults remain fail-closed. */
  sandboxTaskRunner?: SandboxExecTaskRunnerOptions;
  /** Explicit host startup seam; production defaults remain fail-closed. */
  appSandboxTaskRunner?: AppSandboxTaskRunnerStartupOptions;
  /** Explicit host startup seam; default root-helper assembly is disabled. */
  rootHelperSnapshotTaskRunner?: RootHelperSnapshotTaskRunnerStartupOptions;
  /** Explicit host-owned task profiles paired with an isolated runner. */
  developmentGateway?: DevelopmentGateway;
  taskProfileRegistry?: TaskProfileRegistry;
  /** Host-owned gate for active root-helper snapshot request digests. */
  authorizeRootHelperSnapshotRequest?: (requestDigest: string) => void;
  /** The same Broker-owned registry must be propagated to the task runner. */
  rootHelperSnapshotRequestAuthority?: RootHelperSnapshotRequestAuthority;
  /** Explicit owner startup seam for the bounded user-service runtime. */
  userServiceControl?: UserServiceControlStartupOptions;
  /** Explicit owner startup seam; default approval issuance remains disabled. */
  approvalIssuer?: ApprovalIssuerStartupOptions;
  /** Host-owned Accessibility readiness; production defaults to unavailable. */
  guiPublicEnablement?: GuiPublicEnablement;
  /** Host-owned D1 mutation readiness; production defaults to unavailable. */
  developerPublicEnablement?: DeveloperPublicEnablement;
}): Promise<BrokerServiceAssembly> {
  const config = validateBrokerServiceStartupConfig(options.config);
  if ((options.sandboxTaskRunner !== undefined || options.appSandboxTaskRunner !== undefined) && options.virtualizationGuest !== undefined) {
    throw new Error("Broker startup cannot configure sandbox and virtualization task runners together");
  }
  if ((options.rootHelperSnapshotTaskRunner !== undefined && (options.sandboxTaskRunner !== undefined || options.appSandboxTaskRunner !== undefined)) ||
      (options.rootHelperSnapshotTaskRunner !== undefined && options.virtualizationGuest !== undefined)) {
    throw new Error("Broker startup cannot configure competing task runners together");
  }
  if (options.sandboxTaskRunner !== undefined && options.appSandboxTaskRunner !== undefined) {
    throw new Error("Broker startup cannot configure competing sandbox task runners together");
  }
  if (options.rootHelperSnapshotTaskRunner?.enabled === true &&
      options.rootHelperSnapshotRequestAuthority === undefined) {
    throw new Error("Enabled root-helper snapshot tasks require the Broker-owned active-request registry");
  }
  if (options.taskProfileRegistry !== undefined &&
      options.sandboxTaskRunner === undefined && options.appSandboxTaskRunner === undefined && options.virtualizationGuest === undefined &&
      options.rootHelperSnapshotTaskRunner === undefined) {
    throw new Error("Broker startup cannot configure task profiles without an isolated task runner");
  }
  if (options.taskProfileRegistry !== undefined) validateTaskProfileRegistry(options.taskProfileRegistry);
    const now = options.now ?? Date.now;
    const guiPublicEnablement = options.guiPublicEnablement ?? config.guiPublicEnablement ?? "unavailable";
    const developerPublicEnablement = options.developerPublicEnablement ?? config.developerPublicEnablement ?? "unavailable";
    const requiresReleaseReadiness = guiPublicEnablement === "production" || developerPublicEnablement === "production";
    if (requiresReleaseReadiness && config.hostReadinessEvidencePath === undefined) {
      throw new Error("Production public exposure requires host readiness evidence");
    }
  await assertStartupDirectories(config);
    if (requiresReleaseReadiness) {
      let readiness: unknown;
      try {
        readiness = parseJsonUtf8Strict(await readProtectedConfig(config.hostReadinessEvidencePath!));
      } catch {
        throw new Error("Host readiness evidence cannot be read");
      }
      validateMacOsHostReadinessEvidence(readiness, {
        requireRelease: true,
        requireGui: guiPublicEnablement === "production",
        nowMs: now(),
        ...(process.getuid === undefined ? {} : { ownerUid: process.getuid() }),
        platform: process.platform,
        arch: process.arch
      });
    }
  const instanceLockPath = brokerServiceInstanceLockPath(config.runtimeRoot);
  let instanceLock: BrokerServiceInstanceLock | undefined;
  let store: BrokerStore | undefined;
  let edgeKeyring: EdgeKeyring | undefined;
  let guestAttestationKeyManager: VirtualizationGuestAttestationKeyManager | undefined;
  let virtualizationGuestRuntime: VirtualizationGuestRuntime | undefined;
  let sandboxTaskRunner: SandboxExecTaskRunner | undefined;
  let appSandboxTaskRunner: AppSandboxTaskRunner | undefined;
  let rootHelperSnapshotTaskRunner: RootHelperSnapshotTaskRunner | undefined;
  let userServiceControlAdapter: UserServiceControlAdapter | undefined;
  let userServiceControlExecutor: UserServiceControlJobExecutor | undefined;
  let approvalIssuerRuntime: ApprovalIssuerRuntimeAssembly | undefined;
  let broker: Broker | undefined;
  let service: BrokerServiceEntrypoint | undefined;
  let statusChannel: BrokerStatusIpcServer | undefined;
  let rootHelperAuthorityChannel: import("./root-helper-snapshot-authority.js").RootHelperSnapshotAuthorityIpcServer | undefined;
  try {
    // Acquire the per-runtime owner lock before checking the Broker socket or
    // touching the Job Ledger. This closes the pre-listener recovery race
    // between two concurrent service starts.
    instanceLock = await BrokerServiceInstanceLock.acquire(instanceLockPath);
    // Do not reconcile a shared Job Ledger until the configured Broker socket
    // proves that no prior Broker instance is still serving requests.
    await assertSocketNotActive(config.brokerSocketPath);
    const activeStore = new BrokerStore(config.brokerDatabasePath, {
      runtimeFence: true,
      auditAnchor: {
        path: config.auditAnchorPath,
        keySource: createKeychainAuditAnchorKeySource(
          config.auditAnchorKeyService,
          config.auditAnchorKeyAccount,
          config.auditAnchorKeyId
        )
      }
    });
    store = activeStore;
    if (config.guestAttestationKeyConfigPath !== undefined) {
      guestAttestationKeyManager = new VirtualizationGuestAttestationKeyManager(
        config.guestAttestationKeyConfigPath,
        activeStore,
        now,
        5_000,
        24 * 60 * 60 * 1_000,
        config.dataRoot
      );
      // Startup never silently activates a new trust set. An exact persisted
      // revision/digest must already exist before listeners or recovery run.
      await guestAttestationKeyManager.restore();
    }
    const verifier = await PolicyBundleVerifier.createFromKeyFile({
      schemaDirectory: config.policySchemaDirectory,
      expectedKeyId: config.policyVerificationKeyId,
      publicKeyPath: config.policyVerificationKeyPath,
      now
    });
    const verifiedPolicy = await verifier.verifyFile(config.policyBundlePath);
    if (!verifiedPolicy.policy.trustedEdgeIds.has(config.edgeId)) {
      throw new Error("Active policy does not trust the configured Edge identity");
    }
    const policyManager = new PolicyManager(verifiedPolicy.policy, activeStore, now);
    policyManager.restore(verifiedPolicy);
    if (options.sandboxTaskRunner !== undefined) {
      const protectedFilesystemRoots = [...new Set([
        ...brokerSandboxProtectedFilesystemRoots(config),
        ...(options.sandboxTaskRunner.protectedFilesystemRoots ?? [])
      ])].sort();
      sandboxTaskRunner = new SandboxExecTaskRunner({
        ...options.sandboxTaskRunner,
        protectedFilesystemRoots
      });
    }
    if (options.appSandboxTaskRunner !== undefined) {
      const appSandboxTaskAssembly = createAppSandboxTaskRunnerFromStartup(options.appSandboxTaskRunner);
      appSandboxTaskRunner = appSandboxTaskAssembly.taskRunner;
    }
    if (options.rootHelperSnapshotTaskRunner !== undefined) {
      const rootHelperStartup = options.rootHelperSnapshotTaskRunner;
      const rootHelperTaskAssembly = await createRootHelperSnapshotTaskRunnerFromActiveKeyConfig({
        store: activeStore,
        startup: {
          ...rootHelperStartup,
          ...(rootHelperStartup.socketPath === undefined && config.rootHelperSnapshotSocketPath === undefined
            ? {}
            : { socketPath: rootHelperStartup.socketPath ?? config.rootHelperSnapshotSocketPath }),
          ...(rootHelperStartup.brokerSocketPath === undefined ? { brokerSocketPath: config.brokerSocketPath } : {}),
          ...(rootHelperStartup.helperKeyConfigPath === undefined && config.rootHelperSnapshotKeyConfigPath === undefined
            ? {}
            : { helperKeyConfigPath: rootHelperStartup.helperKeyConfigPath ?? config.rootHelperSnapshotKeyConfigPath }),
          ...(rootHelperStartup.rootHelperServiceId === undefined && config.rootHelperSnapshotServiceId === undefined
            ? {}
            : { rootHelperServiceId: rootHelperStartup.rootHelperServiceId ?? config.rootHelperSnapshotServiceId })
        }
      });
      rootHelperSnapshotTaskRunner = rootHelperTaskAssembly.taskRunner;
    }
    if (options.virtualizationGuest !== undefined) {
      const guestOptions = options.virtualizationGuest;
      virtualizationGuestRuntime = await createVirtualizationGuestRuntime({
        ...guestOptions,
        replayGuard: guestOptions.replayGuard ?? new BrokerStoreVirtualizationGuestReplayGuard(activeStore, { now }),
        ...(guestOptions.enabled === true && guestOptions.hostEvidenceAccepted === true &&
        guestOptions.attestationVerifier === undefined && guestAttestationKeyManager !== undefined
          ? { attestationVerifier: guestAttestationKeyManager.createVerifier() }
          : {})
      });
    }
    if (options.userServiceControl !== undefined) {
      const userServiceControl = createUserServiceControlRuntime({
        store: activeStore,
        startup: options.userServiceControl,
        now
      });
      userServiceControlAdapter = userServiceControl.adapter;
      userServiceControlExecutor = userServiceControl.executor;
    }
    if (options.approvalIssuer !== undefined) {
      const configuredKeyPath = config.approvalIssuerKeyConfigPath;
      const configuredSocketPath = config.approvalIssuerSocketPath;
      approvalIssuerRuntime = await createApprovalIssuerRuntime({
        store: activeStore,
        startup: {
          ...options.approvalIssuer,
          ...(options.approvalIssuer.keyConfigPath === undefined && configuredKeyPath === undefined
            ? {} : { keyConfigPath: options.approvalIssuer.keyConfigPath ?? configuredKeyPath }),
          ...(options.approvalIssuer.socketPath === undefined && configuredSocketPath === undefined
            ? {} : { socketPath: options.approvalIssuer.socketPath ?? configuredSocketPath }),
          ...(options.approvalIssuer.peerPolicy === undefined && options.approvalIssuer.peerCredentialVerifier === undefined
            ? {
              peerPolicy: {
                expectedUid: config.expectedEdgeUid,
                ...(config.expectedEdgeGid === undefined ? {} : { expectedGid: config.expectedEdgeGid })
              }
            } : {})
        },
        now
      });
    }
    const statusKey = await loadAuthenticationKey(config.statusKeyPath);
    try {
      if (sha256(statusKey) !== config.statusKeyDigest) {
        throw new Error("Broker status key digest precondition failed");
      }
      statusChannel = new BrokerStatusIpcServer({
        socketPath: config.statusSocketPath,
        authenticationKey: statusKey,
        replayGuard: new BrokerStoreBrokerStatusReplayGuard(activeStore),
        peerPolicy: {
          expectedUid: config.expectedEdgeUid,
          ...(config.expectedEdgeGid === undefined ? {} : { expectedGid: config.expectedEdgeGid })
        },
        readStatus: () => {
          if (!service) throw new BrokerError("PRECONDITION_FAILED", "Broker service status is unavailable");
          return service.readback();
        },
        authorizeStatus: () => {
          if (!service || service.state !== "running") {
            throw new BrokerError("PRECONDITION_FAILED", "Broker service status is not ready");
          }
        }
      });
    } finally {
      statusKey.fill(0);
    }
    const runtimeOptions = {
      socketPath: config.brokerSocketPath,
      edgeId: config.edgeId,
      edgeServiceId: config.edgeServiceId,
      expectedEdgeUid: config.expectedEdgeUid,
      ...(config.expectedEdgeGid === undefined ? {} : { expectedEdgeGid: config.expectedEdgeGid }),
      ...(options.commandExecutor === undefined ? {} : { commandExecutor: options.commandExecutor }),
      edgeKeyConfigPath: config.edgeKeyConfigPath,
      edgeKeyStore: activeStore,
      operatorChannels: [
        ...(virtualizationGuestRuntime?.available ? [virtualizationGuestRuntime.runtimeChannel] : []),
        statusChannel,
        ...(approvalIssuerRuntime === undefined ? [] : [approvalIssuerRuntime.channel])
      ],
      createBroker: (edgeAuthenticationKeys: EdgeKeyring) => {
        edgeKeyring = edgeAuthenticationKeys;
        broker = new Broker({
          store: activeStore,
          policy: policyManager,
          edgeAuthenticationKeys,
          now,
          ...(options.taskProfileRegistry === undefined ? {} : { taskProfileRegistry: options.taskProfileRegistry }),
          ...(options.developmentGateway === undefined ? {} : { developmentGateway: options.developmentGateway }),
                  ...(options.rootHelperSnapshotRequestAuthority === undefined ? {} : { rootHelperSnapshotRequestAuthority: options.rootHelperSnapshotRequestAuthority }),
                  guiPublicEnablement,
                  developerPublicEnablement,
          ...(userServiceControlAdapter === undefined || userServiceControlExecutor === undefined || options.userServiceControl === undefined
            ? {}
            : {
              userServiceControlCandidate: {
                adapter: userServiceControlAdapter,
                executor: userServiceControlExecutor,
                authorizedPrincipalIds: options.userServiceControl.authorizedPrincipalIds,
                ...(options.userServiceControl.enabled === undefined ? {} : { enabled: options.userServiceControl.enabled }),
                now
              }
            }),
          ...(virtualizationGuestRuntime === undefined
            ? (rootHelperSnapshotTaskRunner === undefined
              ? (appSandboxTaskRunner === undefined
                ? (sandboxTaskRunner === undefined ? {} : { taskRunner: sandboxTaskRunner })
                : { taskRunner: appSandboxTaskRunner })
              : { taskRunner: rootHelperSnapshotTaskRunner })
          : { taskRunner: virtualizationGuestRuntime.taskRunner })
        });
        return broker;
      }
    };
    const rootHelperConfigured = config.rootHelperSnapshotKeyConfigPath !== undefined &&
      config.rootHelperSnapshotSocketPath !== undefined &&
      config.rootHelperSnapshotAuthoritySocketPath !== undefined &&
      config.rootHelperSnapshotServiceId !== undefined;
    const authorityControlConfigured = config.authorityControlKeyConfigPath !== undefined &&
      config.authorityControlSocketPath !== undefined &&
      config.authorityOperatorSocketPath !== undefined &&
      config.authorityControlServiceId !== undefined;
    if (authorityControlConfigured && rootHelperConfigured) {
      throw new Error("Authority Control and root-helper authority startup channels require an explicit combined assembly");
    }
    let assembled: Awaited<ReturnType<typeof createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig>>;
    if (authorityControlConfigured) {
      const authorityKeyConfigPath = config.authorityControlKeyConfigPath;
      const authoritySocketPath = config.authorityControlSocketPath;
      const authorityServiceId = config.authorityControlServiceId;
      if (authorityKeyConfigPath === undefined || authoritySocketPath === undefined || config.authorityOperatorSocketPath === undefined || authorityServiceId === undefined) {
        throw new Error("Authority Control startup configuration is incomplete");
      }
      const authorityIdentity = await captureLaunchdAuthorityProcessIdentity({
        authorityServiceId,
        expectedUid: config.expectedEdgeUid,
        ...(options.commandExecutor === undefined ? {} : { commandExecutor: options.commandExecutor })
      });
      assembled = await createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfigAndAuthority({
        ...runtimeOptions,
        authorityKeyConfigPath,
        authoritySocketPath,
        authorityPeerPolicy: {
          expectedUid: config.expectedEdgeUid,
          ...(config.expectedEdgeGid === undefined ? {} : { expectedGid: config.expectedEdgeGid }),
          allowedProcessIdentity: authorityIdentity
        }
      });
    } else if (rootHelperConfigured) {
      const authorizeRootHelperSnapshotRequest = options.authorizeRootHelperSnapshotRequest;
      if (authorizeRootHelperSnapshotRequest === undefined) {
        throw new Error("Root-helper snapshot startup requires a Broker-owned active-request gate");
      }
      if (options.rootHelperSnapshotRequestAuthority === undefined) {
        throw new Error("Root-helper snapshot startup requires the active-request registry used by the task runner");
      }
      const rootHelperKeyConfigPath = config.rootHelperSnapshotKeyConfigPath;
      const rootHelperAuthoritySocketPath = config.rootHelperSnapshotAuthoritySocketPath;
      const rootHelperServiceId = config.rootHelperSnapshotServiceId;
      if (rootHelperKeyConfigPath === undefined || rootHelperAuthoritySocketPath === undefined || rootHelperServiceId === undefined) {
        throw new Error("Root-helper snapshot startup configuration is incomplete");
      }
      const rootAssembled = await createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfigAndRootHelperSnapshotAuthority({
        ...runtimeOptions,
        rootHelperKeyConfigPath,
        rootHelperAuthoritySocketPath,
        rootHelperServiceId,
        ...(options.commandExecutor === undefined ? {} : { rootHelperCommandExecutor: options.commandExecutor }),
        rootHelperSnapshotRequestAuthority: options.rootHelperSnapshotRequestAuthority,
        ...(authorizeRootHelperSnapshotRequest === undefined ? {} : { authorizeRootHelperSnapshotRequest }),
      });
      rootHelperAuthorityChannel = rootAssembled.rootHelperAuthorityChannel;
      assembled = rootAssembled;
    } else {
      assembled = await createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig(runtimeOptions);
    }
    if (!store) throw new Error("Broker service startup did not construct a BrokerStore");
    if (!edgeKeyring) throw new Error("Broker service startup did not construct an Edge keyring");
    if (!broker) throw new Error("Broker service startup did not construct a Broker");

    const selectedTaskRunner = virtualizationGuestRuntime?.taskRunner ??
      rootHelperSnapshotTaskRunner ?? appSandboxTaskRunner ?? sandboxTaskRunner;
    assertTaskRunnerPublicEnablement(
      ["mac_task_run", ...DEVELOPMENT_EXECUTION_TOOLS].some((tool) => verifiedPolicy.policy.tools.get(tool)?.enabled === true),
      selectedTaskRunner
    );
    for (const toolName of ACCESSIBILITY_BOUND_GUI_TOOLS) {
      assertGuiPublicEnablement(
        verifiedPolicy.policy.tools.get(toolName)?.enabled === true,
        guiPublicEnablement
      );
    }
    for (const toolName of DEVELOPER_MUTATION_TOOLS) {
      assertDeveloperPublicEnablement(
        verifiedPolicy.policy.tools.get(toolName)?.enabled === true,
        developerPublicEnablement
      );
    }

    // Bring an explicitly enabled guest to a known running state before Job
    // Ledger recovery. Otherwise a persisted UNKNOWN guest task could be
    // queried against a VM that has not yet booted. The runtime channel repeats
    // this idempotently when the service listener starts.
    if (virtualizationGuestRuntime?.available) {
      await virtualizationGuestRuntime.start();
    }

    // Reconcile interrupted work before the service can expose any IPC
    // listener. Recovery is bounded and conservative: unresolved process
    // identities and write artifacts remain UNKNOWN rather than being
    // promoted to success.
    let recoveryError: unknown;
    try {
      await broker.reconcileRestartedGuestTasks();
    } catch (error) {
      recoveryError = error;
    }
    try {
      await broker.reconcileRestartedTaskProcesses();
    } catch (error) {
      recoveryError = error;
    }
    try {
      broker.reconcileRestartedWriteArtifacts();
    } catch (error) {
      recoveryError ??= error;
    }
    try {
      await broker.reconcileRestartedUserServiceJobs();
    } catch (error) {
      recoveryError ??= error;
    }
    if (recoveryError !== undefined) throw recoveryError;

    const metadata: BrokerServiceMetadata = {
      component: "mac-operator-broker",
      sourceRevision: config.sourceRevision,
      contractVersion: config.contractVersion,
      policyVersion: verifiedPolicy.policy.version
    };
    const enabledCapabilities = broker.enabledRuntimeCapabilityNames();
    service = new BrokerServiceEntrypoint(assembled.runtime, metadata, enabledCapabilities, () => activeStore.auditIntegrityReadback());
    return {
      service,
      store: activeStore,
      edgeKeyring,
      ...(guestAttestationKeyManager === undefined ? {} : { guestAttestationKeyManager }),
      ...(virtualizationGuestRuntime === undefined ? {} : { virtualizationGuestRuntime }),
      ...(sandboxTaskRunner === undefined ? {} : { sandboxTaskRunner }),
      ...(appSandboxTaskRunner === undefined ? {} : { appSandboxTaskRunner }),
      ...(rootHelperSnapshotTaskRunner === undefined ? {} : { rootHelperSnapshotTaskRunner }),
      ...(userServiceControlAdapter === undefined ? {} : { userServiceControlAdapter }),
      ...(userServiceControlExecutor === undefined ? {} : { userServiceControlExecutor }),
      ...(approvalIssuerRuntime === undefined ? {} : { approvalIssuerRuntime }),
      async close() {
        let firstError: unknown;
        try {
          await service?.stop();
        } catch (error) {
          firstError = error;
        }
        try {
          await rootHelperAuthorityChannel?.close();
        } catch (error) {
          firstError ??= error;
        }
        try {
          await approvalIssuerRuntime?.close();
        } catch (error) {
          firstError ??= error;
        }
        try {
          await virtualizationGuestRuntime?.close();
        } catch (error) {
          firstError ??= error;
        }
        try {
          await rootHelperSnapshotTaskRunner?.close();
        } catch (error) {
          firstError ??= error;
        }
        try {
          await appSandboxTaskRunner?.close();
        } catch (error) {
          firstError ??= error;
        }
        try {
          // LocalBrokerRuntime closes Broker resources after a running
          // transport stops. This explicit close also covers an assembled
          // service that is disposed before its first start.
          await broker?.close();
        } catch (error) {
          firstError ??= error;
        }
        try {
          edgeKeyring?.dispose();
        } catch (error) {
          firstError ??= error;
        }
        try {
          activeStore.close();
        } catch (error) {
          firstError ??= error;
        }
        try {
          await instanceLock?.close();
        } catch (error) {
          firstError ??= error;
        }
        if (firstError !== undefined) throw firstError;
      }
    };
  } catch (error) {
    await statusChannel?.close().catch(() => undefined);
    await rootHelperAuthorityChannel?.close().catch(() => undefined);
    await approvalIssuerRuntime?.close().catch(() => undefined);
    await virtualizationGuestRuntime?.close().catch(() => undefined);
    await rootHelperSnapshotTaskRunner?.close().catch(() => undefined);
    await appSandboxTaskRunner?.close().catch(() => undefined);
    await sandboxTaskRunner?.close().catch(() => undefined);
    await broker?.close().catch(() => undefined);
    try { edgeKeyring?.dispose(); } catch { /* preserve the startup error */ }
    try { store?.close(); } catch { /* preserve the startup error */ }
    await instanceLock?.close().catch(() => undefined);
    throw error;
  }
}

/**
 * Fixed-argv LaunchAgent entrypoint. The default config is adjacent to the
 * packaged entrypoint; callers cannot select a socket, key, policy, or
 * capability through process arguments or environment variables.
 */
export async function runBrokerServiceMain(options: {
  configPath?: string;
  commandExecutor?: LaunchdIdentityCommandExecutor;
  now?: () => number;
  signals?: import("./service-entrypoint.js").ServiceSignalSource;
  sandboxTaskRunner?: SandboxExecTaskRunnerOptions;
  appSandboxTaskRunner?: AppSandboxTaskRunnerStartupOptions;
  rootHelperSnapshotTaskRunner?: RootHelperSnapshotTaskRunnerStartupOptions;
  developmentGateway?: DevelopmentGateway;
  taskProfileRegistry?: TaskProfileRegistry;
  authorizeRootHelperSnapshotRequest?: (requestDigest: string) => void;
  rootHelperSnapshotRequestAuthority?: RootHelperSnapshotRequestAuthority;
  approvalIssuer?: ApprovalIssuerStartupOptions;
} = {}): Promise<void> {
  const configPath = options.configPath ?? defaultBrokerServiceConfigPath();
  const config = await loadBrokerServiceStartupConfig(configPath);
  const assembly = await createBrokerServiceFromStartupConfig({
    config,
    ...(options.commandExecutor === undefined ? {} : { commandExecutor: options.commandExecutor }),
    ...(options.now === undefined ? {} : { now: options.now }),
    ...(options.sandboxTaskRunner === undefined ? {} : { sandboxTaskRunner: options.sandboxTaskRunner }),
    ...(options.appSandboxTaskRunner === undefined ? {} : { appSandboxTaskRunner: options.appSandboxTaskRunner }),
    ...(options.rootHelperSnapshotTaskRunner === undefined ? {} : { rootHelperSnapshotTaskRunner: options.rootHelperSnapshotTaskRunner }),
    ...(options.taskProfileRegistry === undefined ? {} : { taskProfileRegistry: options.taskProfileRegistry }),
    ...(options.developmentGateway === undefined ? {} : { developmentGateway: options.developmentGateway }),
    ...(options.authorizeRootHelperSnapshotRequest === undefined ? {} : { authorizeRootHelperSnapshotRequest: options.authorizeRootHelperSnapshotRequest }),
    ...(options.rootHelperSnapshotRequestAuthority === undefined ? {} : { rootHelperSnapshotRequestAuthority: options.rootHelperSnapshotRequestAuthority }),
    ...(options.approvalIssuer === undefined ? {} : { approvalIssuer: options.approvalIssuer })
  });
  try {
    await assembly.service.runUntilSignal(options.signals ?? process);
  } finally {
    await assembly.close();
  }
}

export function defaultBrokerServiceConfigPath(moduleUrl = import.meta.url): string {
  return join(dirname(fileURLToPath(moduleUrl)), "broker-service.json");
}

async function assertStartupDirectories(config: BrokerServiceStartupConfig): Promise<void> {
  await assertDirectory(config.packageRoot, false);
  await assertDirectory(config.dataRoot, true);
  await assertDirectory(config.runtimeRoot, true);
  await assertDirectory(config.policySchemaDirectory, false);
  await assertStartupTarget(config.dataRoot, config.brokerDatabasePath);
  await assertStartupTarget(config.runtimeRoot, config.brokerSocketPath);
  await assertStartupTarget(config.runtimeRoot, config.statusSocketPath);
  await assertStartupTarget(config.dataRoot, config.statusKeyPath);
  await assertStartupTarget(config.dataRoot, config.auditAnchorPath);
  await assertStartupTarget(config.runtimeRoot, brokerServiceInstanceLockPath(config.runtimeRoot));
  await assertStartupTarget(config.dataRoot, config.edgeKeyConfigPath);
  await assertStartupTarget(config.dataRoot, config.policyBundlePath);
  await assertStartupTarget(config.dataRoot, config.policyVerificationKeyPath);
  if (config.hostReadinessEvidencePath !== undefined) {
    await assertStartupTarget(config.dataRoot, config.hostReadinessEvidencePath);
  }
  if (config.guestAttestationKeyConfigPath !== undefined) {
    await assertStartupTarget(config.dataRoot, config.guestAttestationKeyConfigPath);
  }
  if (config.approvalIssuerKeyConfigPath !== undefined && config.approvalIssuerSocketPath !== undefined) {
    await assertStartupTarget(config.dataRoot, config.approvalIssuerKeyConfigPath);
    await assertStartupTarget(config.runtimeRoot, config.approvalIssuerSocketPath);
  }
  if (config.authorityControlKeyConfigPath !== undefined && config.authorityControlSocketPath !== undefined && config.authorityOperatorSocketPath !== undefined) {
    await assertStartupTarget(config.dataRoot, config.authorityControlKeyConfigPath);
    await assertStartupTarget(config.runtimeRoot, config.authorityControlSocketPath);
    await assertStartupTarget(config.runtimeRoot, config.authorityOperatorSocketPath);
  }
  if (config.rootHelperSnapshotKeyConfigPath !== undefined &&
      config.rootHelperSnapshotSocketPath !== undefined && config.rootHelperSnapshotAuthoritySocketPath !== undefined) {
    await assertStartupTarget(config.dataRoot, config.rootHelperSnapshotKeyConfigPath);
    await assertStartupTarget(config.runtimeRoot, config.rootHelperSnapshotSocketPath);
    await assertStartupTarget(config.runtimeRoot, config.rootHelperSnapshotAuthoritySocketPath);
  }
}

async function assertStartupTarget(root: string, target: string): Promise<void> {
  const parent = await realpath(dirname(target));
  if (!isDescendant(root, parent) && parent !== root) {
    throw new Error("Broker service startup target parent escaped its configured root");
  }
  try {
    const value = await lstat(target);
    if (value.isSymbolicLink()) throw new Error("Broker service startup target must not be a symlink");
    if (await realpath(target) !== target) throw new Error("Broker service startup target is not canonical");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function readProtectedConfig(path: string): Promise<Buffer> {
  validateCanonicalPath(path, "config path");
  const pathStat = await lstat(path);
  const uid = process.getuid?.();
  if (!pathStat.isFile() || pathStat.isSymbolicLink() || uid === undefined || pathStat.uid !== uid || (pathStat.mode & 0o077) !== 0) {
    throw new Error("Broker service startup config must be an owner-only regular file");
  }
  if (pathStat.size < 2 || pathStat.size > MAX_CONFIG_BYTES) throw new Error("Broker service startup config size is invalid");
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.dev !== pathStat.dev || opened.ino !== pathStat.ino) {
      throw new Error("Broker service startup config target changed while opening");
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}

async function assertDirectory(path: string, privateDirectory: boolean): Promise<void> {
  const value = await lstat(path);
  const uid = process.getuid?.();
  if (!value.isDirectory() || value.isSymbolicLink() || uid === undefined || value.uid !== uid ||
      (privateDirectory ? (value.mode & 0o077) !== 0 : (value.mode & 0o022) !== 0)) {
    throw new Error("Broker service startup directory failed ownership or permission checks");
  }
  if (await realpath(path) !== path) throw new Error("Broker service startup directory is not canonical");
}

function validateCanonicalPath(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new Error(`Broker service ${label} must be a canonical absolute path`);
  }
}

function isDescendant(root: string, target: string): boolean {
  const child = relative(root, target);
  return child.length > 0 && child !== ".." && !child.startsWith("..") && !isAbsolute(child);
}

function parseUid(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 1 || (value as number) > 2_147_483_647) {
    throw new Error(`Broker service ${label} must be a positive non-root uid`);
  }
  return value as number;
}

function parsePublicEnablement(value: unknown, field: string): GuiPublicEnablement | DeveloperPublicEnablement | undefined {
  if (value === undefined) return undefined;
  if (value !== "unavailable" && value !== "staging-only" && value !== "production") {
    throw new Error(`Broker service ${field} is invalid`);
  }
  return value;
}
