import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { Broker } from "./broker.js";
import { BrokerStore } from "./persistence.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { PolicyBundleVerifier, PolicyManager } from "./policy-loader.js";
import { runtimeToolStates } from "./policy.js";
import {
  createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig,
  type LaunchdIdentityCommandExecutor
} from "./native-runtime-startup.js";
import { BrokerServiceEntrypoint, type BrokerServiceMetadata } from "./service-entrypoint.js";
import { assertSocketNotActive } from "./ipc-server.js";

const MAX_CONFIG_BYTES = 64 * 1024;
const CONFIG_KEYS = new Set([
  "schemaVersion", "packageRoot", "dataRoot", "runtimeRoot", "brokerDatabasePath", "brokerSocketPath",
  "edgeId", "edgeServiceId", "expectedEdgeUid", "expectedEdgeGid", "edgeKeyConfigPath",
  "policyBundlePath", "policySchemaDirectory", "policyVerificationKeyId", "policyVerificationKeyPath",
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
  edgeId: string;
  edgeServiceId: string;
  expectedEdgeUid: number;
  expectedEdgeGid?: number;
  edgeKeyConfigPath: string;
  policyBundlePath: string;
  policySchemaDirectory: string;
  policyVerificationKeyId: string;
  policyVerificationKeyPath: string;
  sourceRevision: string;
  contractVersion: string;
}

export interface BrokerServiceAssembly {
  readonly service: BrokerServiceEntrypoint;
  readonly store: BrokerStore;
  readonly edgeKeyring: EdgeKeyring;
  close(): Promise<void>;
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
    value = JSON.parse(content.toString("utf8")) as unknown;
  } catch {
    throw new Error("Broker service startup config is not valid JSON");
  }
  return validateBrokerServiceStartupConfig(value);
}

export function validateBrokerServiceStartupConfig(value: unknown): BrokerServiceStartupConfig {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Broker service startup config is malformed");
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!CONFIG_KEYS.has(key)) throw new Error(`Broker service startup config has an unknown field: ${key}`);
  }
  if (record.schemaVersion !== "0.1") throw new Error("Broker service startup config schema version is unsupported");
  const pathValues = [
    "packageRoot", "dataRoot", "runtimeRoot", "brokerDatabasePath", "brokerSocketPath", "edgeKeyConfigPath",
    "policyBundlePath", "policySchemaDirectory", "policyVerificationKeyPath"
  ].map((key) => [key, record[key]] as const);
  for (const [key, pathValue] of pathValues) validateCanonicalPath(pathValue, key);
  const packageRoot = record.packageRoot as string;
  const dataRoot = record.dataRoot as string;
  const runtimeRoot = record.runtimeRoot as string;
  if (packageRoot === "/" || dataRoot === "/" || runtimeRoot === "/" || packageRoot === dataRoot || packageRoot === runtimeRoot || dataRoot === runtimeRoot) {
    throw new Error("Broker service startup roots must be distinct non-root paths");
  }
  const brokerDatabasePath = record.brokerDatabasePath as string;
  const brokerSocketPath = record.brokerSocketPath as string;
  if (!isDescendant(dataRoot, brokerDatabasePath) || !isDescendant(runtimeRoot, brokerSocketPath)) {
    throw new Error("Broker service state paths must remain inside their configured roots");
  }
  if (!isDescendant(dataRoot, record.edgeKeyConfigPath as string) || !isDescendant(dataRoot, record.policyBundlePath as string) ||
      !isDescendant(dataRoot, record.policyVerificationKeyPath as string) || !isDescendant(packageRoot, record.policySchemaDirectory as string)) {
    throw new Error("Broker service configuration paths must remain inside their configured roots");
  }
  if (!brokerSocketPath.endsWith(".sock")) throw new Error("Broker service socket path must end in .sock");
  if (!ID_PATTERN.test(String(record.edgeId))) throw new Error("Broker service Edge identity is invalid");
  const expectedEdgeUid = parseUid(record.expectedEdgeUid, "expectedEdgeUid");
  const expectedEdgeGid = record.expectedEdgeGid === undefined ? undefined : parseUid(record.expectedEdgeGid, "expectedEdgeGid");
  if (!/^gui\/[1-9][0-9]{0,9}\/com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(String(record.edgeServiceId)) ||
      !String(record.edgeServiceId).startsWith(`gui/${expectedEdgeUid}/`)) {
    throw new Error("Broker service Edge launchd identity is invalid");
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
    edgeId: record.edgeId as string,
    edgeServiceId: record.edgeServiceId as string,
    expectedEdgeUid,
    ...(expectedEdgeGid === undefined ? {} : { expectedEdgeGid }),
    edgeKeyConfigPath: record.edgeKeyConfigPath as string,
    policyBundlePath: record.policyBundlePath as string,
    policySchemaDirectory: record.policySchemaDirectory as string,
    policyVerificationKeyId: record.policyVerificationKeyId as string,
    policyVerificationKeyPath: record.policyVerificationKeyPath as string,
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
}): Promise<BrokerServiceAssembly> {
  const config = validateBrokerServiceStartupConfig(options.config);
  await assertStartupDirectories(config);
  // Do not reconcile a shared Job Ledger until the configured Broker socket
  // proves that no prior Broker instance is still serving requests.
  await assertSocketNotActive(config.brokerSocketPath);
  const now = options.now ?? Date.now;
  const store = new BrokerStore(config.brokerDatabasePath);
  let edgeKeyring: EdgeKeyring | undefined;
  let broker: Broker | undefined;
  let service: BrokerServiceEntrypoint | undefined;
  try {
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
    const policyManager = new PolicyManager(verifiedPolicy.policy, store, now);
    policyManager.restore(verifiedPolicy);
    const assembled = await createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig({
      socketPath: config.brokerSocketPath,
      edgeId: config.edgeId,
      edgeServiceId: config.edgeServiceId,
      expectedEdgeUid: config.expectedEdgeUid,
      ...(config.expectedEdgeGid === undefined ? {} : { expectedEdgeGid: config.expectedEdgeGid }),
      ...(options.commandExecutor === undefined ? {} : { commandExecutor: options.commandExecutor }),
      edgeKeyConfigPath: config.edgeKeyConfigPath,
      edgeKeyStore: store,
      createBroker: (edgeAuthenticationKeys) => {
        edgeKeyring = edgeAuthenticationKeys;
        broker = new Broker({ store, policy: policyManager, edgeAuthenticationKeys, now });
        return broker;
      }
    });
    if (!edgeKeyring) throw new Error("Broker service startup did not construct an Edge keyring");
    if (!broker) throw new Error("Broker service startup did not construct a Broker");

    // Reconcile interrupted work before the service can expose any IPC
    // listener. Recovery is bounded and conservative: unresolved process
    // identities and write artifacts remain UNKNOWN rather than being
    // promoted to success.
    let recoveryError: unknown;
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
    if (recoveryError !== undefined) throw recoveryError;

    const metadata: BrokerServiceMetadata = {
      component: "mac-operator-broker",
      sourceRevision: config.sourceRevision,
      contractVersion: config.contractVersion,
      policyVersion: verifiedPolicy.policy.version
    };
    const enabledCapabilities = runtimeToolStates(policyManager.current())
      .filter((capability) => capability.enabled)
      .map((capability) => capability.tool);
    service = new BrokerServiceEntrypoint(assembled.runtime, metadata, enabledCapabilities);
    return {
      service,
      store,
      edgeKeyring,
      async close() {
        let firstError: unknown;
        try {
          await service?.stop();
        } catch (error) {
          firstError = error;
        }
        try {
          // LocalBrokerRuntime closes Broker resources after a running
          // transport stops. This explicit close also covers an assembled
          // service that is disposed before its first start.
          await broker?.close();
        } catch (error) {
          firstError ??= error;
        }
        edgeKeyring?.dispose();
        store.close();
        if (firstError !== undefined) throw firstError;
      }
    };
  } catch (error) {
    await broker?.close().catch(() => undefined);
    edgeKeyring?.dispose();
    store.close();
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
} = {}): Promise<void> {
  const configPath = options.configPath ?? defaultBrokerServiceConfigPath();
  const config = await loadBrokerServiceStartupConfig(configPath);
  const assembly = await createBrokerServiceFromStartupConfig({
    config,
    ...(options.commandExecutor === undefined ? {} : { commandExecutor: options.commandExecutor }),
    ...(options.now === undefined ? {} : { now: options.now })
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
  await assertStartupTarget(config.dataRoot, config.edgeKeyConfigPath);
  await assertStartupTarget(config.dataRoot, config.policyBundlePath);
  await assertStartupTarget(config.dataRoot, config.policyVerificationKeyPath);
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
