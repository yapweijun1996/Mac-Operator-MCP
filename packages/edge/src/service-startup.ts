import { constants } from "node:fs";
import { lstat, open, realpath } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { parseJsonUtf8Strict } from "@mac-operator/contracts";
import { dirname, join, relative, resolve, isAbsolute } from "node:path";
import type { OAuthMetadata, OAuthTokenVerifier } from "@modelcontextprotocol/server";
import { BrokerIpcClient } from "./ipc-client.js";
import { AuthenticatedIpcBrokerGateway } from "./gateway.js";
import { EdgeRequestFactory } from "./request-factory.js";
import { ToolContractRegistry } from "./contract-registry.js";
import { createHttpsMcpEdge, type HttpsMcpEdge } from "./https-edge.js";
import { createJwtAccessTokenVerifier } from "./jwt-verifier.js";
import { loadProtectedTlsMaterial } from "./tls-material.js";
import { isPlainDataArray, isPlainDataRecord } from "./plain-record.js";
import { readProtectedFileAfterIdentity, sameProtectedFileMetadata } from "./protected-file.js";

const MAX_CONFIG_BYTES = 64 * 1024;
const CONFIG_KEYS = new Set([
  "schemaVersion", "packageRoot", "dataRoot", "runtimeRoot", "edgeId", "brokerAudience", "brokerSocketPath",
  "authenticationKeyPath", "authenticationKeyId", "authenticationKeyDigest", "contractsDirectory",
  "tlsCertificatePath", "tlsPrivateKeyPath", "bindHost", "bindPort", "resourceServerUrl", "oauthIssuer",
  "issuerId", "authorizationEndpoint", "tokenEndpoint", "jwksUri", "allowedHosts", "allowedOrigins",
  "policyVersion", "sourceRevision", "contractVersion", "ipcTimeoutMs", "maxIpcResponseBytes",
  "rateLimitWindowMs", "rateLimitMaxRequests", "rateLimitMaxKeys"
]);
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u;
const REVISION_PATTERN = /^[0-9a-f]{7,64}$/u;
const VERSION_PATTERN = /^v?\d+\.\d+(?:\.\d+)?(?:[-+].*)?$/u;
const POLICY_VERSION_PATTERN = /^(?:policy-[1-9][0-9]*|\d+\.\d+(?:\.\d+)?(?:[-+].*)?)$/u;
const DIGEST_PATTERN = /^[a-f0-9]{64}$/u;

export interface EdgeServiceStartupConfig {
  schemaVersion: "0.1";
  packageRoot: string;
  dataRoot: string;
  runtimeRoot: string;
  edgeId: string;
  brokerAudience: string;
  brokerSocketPath: string;
  authenticationKeyPath: string;
  authenticationKeyId: string;
  authenticationKeyDigest: string;
  contractsDirectory: string;
  tlsCertificatePath: string;
  tlsPrivateKeyPath: string;
  bindHost: string;
  bindPort: number;
  resourceServerUrl: string;
  oauthIssuer: string;
  issuerId: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  allowedHosts: string[];
  allowedOrigins: string[];
  policyVersion: string;
  sourceRevision: string;
  contractVersion: string;
  ipcTimeoutMs: number;
  maxIpcResponseBytes: number;
  rateLimitWindowMs: number;
  rateLimitMaxRequests: number;
  rateLimitMaxKeys: number;
}

export type EdgeServiceState = "stopped" | "starting" | "running" | "stopping" | "failed";

export interface EdgeServiceReadback {
  component: "mac-operator-edge";
  state: EdgeServiceState;
  sourceRevision: string;
  contractVersion: string;
  policyVersion: string;
  bindHost: string;
  bindPort: number;
  listening: boolean;
}

export interface EdgeServiceAssembly {
  readonly service: EdgeServiceEntrypoint;
  readonly edge: HttpsMcpEdge;
  close(): Promise<void>;
}

export interface EdgeServiceSignalSource {
  on(event: "SIGINT" | "SIGTERM", listener: () => void): unknown;
  removeListener(event: "SIGINT" | "SIGTERM", listener: () => void): unknown;
}

/** Owns the process-facing HTTPS Edge lifecycle and never changes authority at runtime. */
export class EdgeServiceEntrypoint {
  private stateValue: EdgeServiceState = "stopped";
  /** Serialize lifecycle transitions so stop cannot race a still-pending start. */
  private lifecycleQueue: Promise<void> = Promise.resolve();

  constructor(
    private readonly edge: HttpsMcpEdge,
    private readonly config: Pick<EdgeServiceStartupConfig, "bindHost" | "bindPort" | "sourceRevision" | "contractVersion" | "policyVersion">
  ) {
    if (!REVISION_PATTERN.test(config.sourceRevision)) throw new Error("Edge service source revision is invalid");
    if (!VERSION_PATTERN.test(config.contractVersion)) throw new Error("Edge service contract version is invalid");
    if (!POLICY_VERSION_PATTERN.test(config.policyVersion)) throw new Error("Edge service policy version is invalid");
  }

  get state(): EdgeServiceState {
    return this.stateValue;
  }

  start(): Promise<void> {
    return this.enqueueLifecycle(() => this.startInternal());
  }

  stop(): Promise<void> {
    return this.enqueueLifecycle(() => this.stopInternal());
  }

  private enqueueLifecycle(operation: () => Promise<void>): Promise<void> {
    const next = this.lifecycleQueue.then(operation, operation);
    this.lifecycleQueue = next.catch(() => undefined);
    return next;
  }

  private async startInternal(): Promise<void> {
    if (this.stateValue !== "stopped") throw new Error(`Edge service cannot start from ${this.stateValue}`);
    this.stateValue = "starting";
    try {
      await new Promise<void>((resolveListen, rejectListen) => {
        let settled = false;
        const onError = (error: Error) => {
          if (settled) return;
          settled = true;
          this.edge.server.removeListener("listening", onListening);
          rejectListen(error);
        };
        const onListening = () => {
          if (settled) return;
          settled = true;
          this.edge.server.removeListener("error", onError);
          const address = this.edge.server.address();
          if (address === null || typeof address === "string" || address.port !== this.config.bindPort) {
            rejectListen(new Error("Edge HTTPS listener readback did not match startup configuration"));
            return;
          }
          resolveListen();
        };
        this.edge.server.once("error", onError);
        this.edge.server.once("listening", onListening);
        this.edge.server.listen(this.config.bindPort, this.config.bindHost);
      });
      this.stateValue = "running";
    } catch (error) {
      this.stateValue = "failed";
      await this.edge.close().catch(() => undefined);
      throw error;
    }
  }

  private async stopInternal(): Promise<void> {
    if (this.stateValue === "stopped") return;
    this.stateValue = "stopping";
    try {
      await this.edge.close();
      this.stateValue = "stopped";
    } catch (error) {
      this.stateValue = "failed";
      throw error;
    }
  }

  readback(): EdgeServiceReadback {
    const address = this.edge.server.address();
    return {
      component: "mac-operator-edge",
      state: this.stateValue,
      sourceRevision: this.config.sourceRevision,
      contractVersion: this.config.contractVersion,
      policyVersion: this.config.policyVersion,
      bindHost: this.config.bindHost,
      bindPort: this.config.bindPort,
      listening: this.edge.server.listening && address !== null
    };
  }

  async runUntilSignal(signals: EdgeServiceSignalSource): Promise<void> {
    await this.start();
    await new Promise<void>((resolveSignal, rejectSignal) => {
      let settled = false;
      const handleSignal = () => {
        if (settled) return;
        settled = true;
        signals.removeListener("SIGINT", handleSignal);
        signals.removeListener("SIGTERM", handleSignal);
        void this.stop().then(resolveSignal, rejectSignal);
      };
      signals.on("SIGINT", handleSignal);
      signals.on("SIGTERM", handleSignal);
    });
  }
}

/** Loads the fixed, non-secret startup document used by the packaged Edge. */
export async function loadEdgeServiceStartupConfig(path: string): Promise<EdgeServiceStartupConfig> {
  const content = await readProtectedConfig(path);
  try {
    let value: unknown;
    try {
      value = parseJsonUtf8Strict(content);
    } catch {
      throw new Error("Edge service startup config is not valid JSON");
    }
    return validateEdgeServiceStartupConfig(value);
  } finally {
    content.fill(0);
  }
}

export function validateEdgeServiceStartupConfig(value: unknown): EdgeServiceStartupConfig {
  if (!isPlainDataRecord(value)) {
    throw new Error("Edge service startup config is malformed");
  }
  const record = value;
  for (const key of Object.keys(record)) {
    if (!CONFIG_KEYS.has(key)) throw new Error(`Edge service startup config has an unknown field: ${key}`);
  }
  if (record.schemaVersion !== "0.1") throw new Error("Edge service startup config schema version is unsupported");
  const pathKeys = [
    "packageRoot", "dataRoot", "runtimeRoot", "brokerSocketPath", "authenticationKeyPath", "contractsDirectory",
    "tlsCertificatePath", "tlsPrivateKeyPath"
  ];
  for (const key of pathKeys) validateCanonicalPath(record[key], key);
  const packageRoot = record.packageRoot as string;
  const dataRoot = record.dataRoot as string;
  const runtimeRoot = record.runtimeRoot as string;
  if ([packageRoot, dataRoot, runtimeRoot].some((path) => path === "/") || new Set([packageRoot, dataRoot, runtimeRoot]).size !== 3) {
    throw new Error("Edge service startup roots must be distinct non-root paths");
  }
  const brokerSocketPath = record.brokerSocketPath as string;
  const authenticationKeyPath = record.authenticationKeyPath as string;
  const contractsDirectory = record.contractsDirectory as string;
  const tlsCertificatePath = record.tlsCertificatePath as string;
  const tlsPrivateKeyPath = record.tlsPrivateKeyPath as string;
  if (!isDescendant(runtimeRoot, brokerSocketPath) || !brokerSocketPath.endsWith(".sock") ||
      !isDescendant(dataRoot, authenticationKeyPath) || !isDescendant(packageRoot, contractsDirectory) ||
      !isDescendant(dataRoot, tlsCertificatePath) || !isDescendant(dataRoot, tlsPrivateKeyPath)) {
    throw new Error("Edge service startup paths escaped their configured roots");
  }
  const edgeId = readId(record.edgeId, "edge identity");
  const brokerAudience = readId(record.brokerAudience, "Broker audience");
  const authenticationKeyId = readId(record.authenticationKeyId, "authentication key identity");
  const issuerId = readId(record.issuerId, "OAuth issuer identity");
  const authenticationKeyDigest = readDigest(record.authenticationKeyDigest);
  const bindHost = readHost(record.bindHost);
  const bindPort = boundedInteger(record.bindPort, 1, 65_535, "Edge bind port");
  const resourceServerUrl = readHttpsUrl(record.resourceServerUrl, "resource server URL", true);
  const oauthIssuer = readHttpsUrl(record.oauthIssuer, "OAuth issuer URL", false);
  const authorizationEndpoint = readHttpsUrl(record.authorizationEndpoint, "OAuth authorization endpoint", false);
  const tokenEndpoint = readHttpsUrl(record.tokenEndpoint, "OAuth token endpoint", false);
  const jwksUri = readHttpsUrl(record.jwksUri, "OAuth JWKS URL", false);
  const allowedHosts = readHostList(record.allowedHosts, "Host");
  const allowedOrigins = readHostList(record.allowedOrigins, "Origin");
  if (!allowedHosts.includes(new URL(resourceServerUrl).hostname.toLowerCase())) {
    throw new Error("Edge Host allowlist must include the resource server hostname");
  }
  const policyVersion = readPattern(record.policyVersion, POLICY_VERSION_PATTERN, "policy version");
  const sourceRevision = readPattern(record.sourceRevision, REVISION_PATTERN, "source revision");
  const contractVersion = readPattern(record.contractVersion, VERSION_PATTERN, "contract version");
  return {
    schemaVersion: "0.1", packageRoot, dataRoot, runtimeRoot, edgeId, brokerAudience, brokerSocketPath,
    authenticationKeyPath, authenticationKeyId, authenticationKeyDigest, contractsDirectory,
    tlsCertificatePath, tlsPrivateKeyPath, bindHost, bindPort, resourceServerUrl, oauthIssuer, issuerId,
    authorizationEndpoint, tokenEndpoint, jwksUri, allowedHosts, allowedOrigins, policyVersion,
    sourceRevision, contractVersion,
    ipcTimeoutMs: boundedInteger(record.ipcTimeoutMs, 100, 30_000, "Edge IPC timeout"),
    maxIpcResponseBytes: boundedInteger(record.maxIpcResponseBytes, 1_024, 8 * 1024 * 1024, "Edge IPC response limit"),
    rateLimitWindowMs: boundedInteger(record.rateLimitWindowMs, 1_000, 86_400_000, "Edge rate-limit window"),
    rateLimitMaxRequests: boundedInteger(record.rateLimitMaxRequests, 1, 100_000, "Edge rate-limit request limit"),
    rateLimitMaxKeys: boundedInteger(record.rateLimitMaxKeys, 1, 1_000_000, "Edge rate-limit key limit")
  };
}

export async function createEdgeServiceFromStartupConfig(options: {
  config: EdgeServiceStartupConfig;
}): Promise<EdgeServiceAssembly> {
  const config = validateEdgeServiceStartupConfig(options.config);
  await assertStartupDirectories(config);
  const contracts = await ToolContractRegistry.load(config.contractsDirectory);
  const tls = await loadProtectedTlsMaterial({
    certificatePath: config.tlsCertificatePath,
    privateKeyPath: config.tlsPrivateKeyPath
  });
  let requestFactory: EdgeRequestFactory | undefined;
  try {
    requestFactory = await EdgeRequestFactory.fromProtectedKeyFile({
      authenticationKeyPath: config.authenticationKeyPath,
      expectedAuthenticationKeyDigest: config.authenticationKeyDigest,
      authenticationKeyId: config.authenticationKeyId,
      brokerAudience: config.brokerAudience,
      policyVersion: () => config.policyVersion
    });
    const client = new BrokerIpcClient(
      config.brokerSocketPath,
      (request, response) => requestFactory?.verifyResponse(request, response) ?? false,
      { timeoutMs: config.ipcTimeoutMs, maxResponseBytes: config.maxIpcResponseBytes }
    );
    const gateway = new AuthenticatedIpcBrokerGateway(requestFactory, client);
    const resourceServerUrl = new URL(config.resourceServerUrl);
    const issuer = new URL(config.oauthIssuer);
    const tokenVerifier: OAuthTokenVerifier = createJwtAccessTokenVerifier({
      issuer,
      issuerId: config.issuerId,
      resourceServerUrl,
      jwksUri: new URL(config.jwksUri)
    });
    const oauthMetadata: OAuthMetadata = {
      issuer: issuer.href,
      authorization_endpoint: config.authorizationEndpoint,
      token_endpoint: config.tokenEndpoint,
      response_types_supported: ["code"]
    };
    const edge = createHttpsMcpEdge({
      edgeId: config.edgeId,
      brokerAudience: config.brokerAudience,
      resourceServerUrl,
      contracts,
      gateway,
      bindHost: config.bindHost,
      allowedHosts: config.allowedHosts,
      allowedOrigins: config.allowedOrigins,
      tlsCertificate: tls.certificate,
      tlsPrivateKey: tls.privateKey,
      oauthIssuer: issuer,
      tokenVerifier,
      oauthMetadata,
      rateLimit: {
        windowMs: config.rateLimitWindowMs,
        maxRequests: config.rateLimitMaxRequests,
        maxKeys: config.rateLimitMaxKeys
      }
    });
    const service = new EdgeServiceEntrypoint(edge, config);
    return {
      service,
      edge,
      async close() {
        try {
          await service.stop();
        } finally {
          requestFactory?.dispose();
          tls.certificate.fill(0);
          tls.privateKey.fill(0);
        }
      }
    };
  } catch (error) {
    requestFactory?.dispose();
    tls.certificate.fill(0);
    tls.privateKey.fill(0);
    throw error;
  }
}

export async function runEdgeServiceMain(options: {
  configPath?: string;
  signals?: EdgeServiceSignalSource;
} = {}): Promise<void> {
  const config = await loadEdgeServiceStartupConfig(options.configPath ?? defaultEdgeServiceConfigPath());
  const assembly = await createEdgeServiceFromStartupConfig({ config });
  try {
    await assembly.service.runUntilSignal(options.signals ?? process);
  } finally {
    await assembly.close();
  }
}

export function defaultEdgeServiceConfigPath(moduleUrl = import.meta.url): string {
  return join(dirname(fileURLToPath(moduleUrl)), "edge-service.json");
}

async function assertStartupDirectories(config: EdgeServiceStartupConfig): Promise<void> {
  await assertDirectory(config.packageRoot, false);
  await assertDirectory(config.dataRoot, true);
  await assertDirectory(config.runtimeRoot, true);
  await assertDirectory(config.contractsDirectory, false);
  for (const [root, target] of [
    [config.runtimeRoot, config.brokerSocketPath],
    [config.dataRoot, config.authenticationKeyPath],
    [config.dataRoot, config.tlsCertificatePath],
    [config.dataRoot, config.tlsPrivateKeyPath]
  ] as const) {
    await assertStartupTarget(root, target);
  }
}

async function assertStartupTarget(root: string, target: string): Promise<void> {
  const parentPath = dirname(target);
  const parent = await realpath(parentPath);
  if (parent !== parentPath) throw new Error("Edge service startup target parent must not contain symlinks");
  if (parent !== root && !isDescendant(root, parent)) throw new Error("Edge service startup target parent escaped its configured root");
  try {
    const value = await lstat(target);
    if (value.isSymbolicLink() || await realpath(target) !== target) throw new Error("Edge service startup target must be canonical and non-symlink");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
}

async function assertDirectory(path: string, privateDirectory: boolean): Promise<void> {
  const value = await lstat(path);
  const uid = process.getuid?.();
  if (!value.isDirectory() || value.isSymbolicLink() || uid === undefined || value.uid !== uid ||
      (privateDirectory ? (value.mode & 0o077) !== 0 : (value.mode & 0o022) !== 0)) {
    throw new Error("Edge service startup directory failed ownership or permission checks");
  }
  if (await realpath(path) !== path) throw new Error("Edge service startup directory is not canonical");
}

async function readProtectedConfig(path: string): Promise<Buffer> {
  validateCanonicalPath(path, "config path");
  const before = await lstat(path);
  const uid = process.getuid?.();
  if (!before.isFile() || before.isSymbolicLink() || uid === undefined || before.uid !== uid || (before.mode & 0o077) !== 0) {
    throw new Error("Edge service startup config must be an owner-only regular file");
  }
  if (before.size < 2 || before.size > MAX_CONFIG_BYTES) throw new Error("Edge service startup config size is invalid");
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameProtectedFileMetadata(before, opened)) {
      throw new Error("Edge service startup config target changed while opening");
    }
    return await readProtectedFileAfterIdentity(handle, opened, MAX_CONFIG_BYTES, "Edge service startup config");
  } finally {
    await handle.close();
  }
}

function validateCanonicalPath(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || value.includes("\0") || value.includes("\n") || value.includes("\r")) {
    throw new Error(`Edge service ${label} must be a canonical absolute path`);
  }
}

function isDescendant(root: string, target: string): boolean {
  const child = relative(root, target);
  return child.length > 0 && child !== ".." && !child.startsWith("..") && !isAbsolute(child);
}

function readId(value: unknown, label: string): string {
  if (typeof value !== "string" || !ID_PATTERN.test(value)) throw new Error(`Edge service ${label} is malformed`);
  return value;
}

function readDigest(value: unknown): string {
  if (typeof value !== "string" || !DIGEST_PATTERN.test(value)) throw new Error("Edge authentication key digest is malformed");
  return value;
}

function readHost(value: unknown): string {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim() || /[\0\r\n]/u.test(value)) {
    throw new Error("Edge bind host is malformed");
  }
  return value;
}

function readHttpsUrl(value: unknown, label: string, requirePath: boolean): string {
  if (typeof value !== "string") throw new Error(`${label} is malformed`);
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`${label} is malformed`);
  }
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.hostname.length === 0) {
    throw new Error(`${label} must be an HTTPS URL without credentials, query, or fragment`);
  }
  if (requirePath && (!parsed.pathname.startsWith("/") || parsed.pathname === "/")) {
    throw new Error(`${label} must use a dedicated path`);
  }
  return parsed.href;
}

function readHostList(value: unknown, label: string): string[] {
  if (!isPlainDataArray(value, 64) || value.length === 0) throw new Error(`Edge ${label} allowlist must not be empty`);
  const normalized = value.map((entry) => {
    if (typeof entry !== "string" || entry.length === 0 || entry !== entry.trim() || /[\0\r\n]/u.test(entry)) {
      throw new Error(`Edge ${label} allowlist contains an invalid hostname`);
    }
    let parsed: URL;
    try {
      parsed = new URL(`https://${entry}`);
    } catch {
      throw new Error(`Edge ${label} allowlist contains an invalid hostname`);
    }
    if (parsed.hostname !== entry.toLowerCase() || parsed.username || parsed.password || parsed.port || parsed.pathname !== "/" || parsed.search || parsed.hash) {
      throw new Error(`Edge ${label} allowlist contains an invalid hostname`);
    }
    return parsed.hostname;
  });
  return [...new Set(normalized)].sort();
}

function readPattern(value: unknown, pattern: RegExp, label: string): string {
  if (typeof value !== "string" || !pattern.test(value)) throw new Error(`Edge service ${label} is malformed`);
  return value;
}

function boundedInteger(value: unknown, minimum: number, maximum: number, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) throw new Error(`${label} is out of bounds`);
  return value as number;
}
