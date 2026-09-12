import { constants } from "node:fs";
import { lstat, open, readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { isAbsolute, join, resolve } from "node:path";
import { createPublicKey, verify, type KeyObject } from "node:crypto";
import {
  PLANNED_TOOL_NAMES,
  SCOPES,
  canonicalJson,
  sha256,
  type Scope
} from "@mac-operator/contracts";
import { createDefaultPolicy } from "./default-policy.js";
import type { BrokerStore } from "./persistence.js";
import type { BrokerPolicy, NormalizedTarget, PrincipalGrant, TargetRule } from "./policy.js";
import type { FilesystemRootPolicy } from "./filesystem-inspector.js";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default as new (options: Record<string, unknown>) => {
  addSchema(schema: object): void;
  compile(schema: object): ((value: unknown) => boolean) & { errors?: unknown };
  errorsText(errors: unknown): string;
};
const addFormats = require("ajv-formats").default as (ajv: InstanceType<typeof Ajv2020>) => void;

export interface PolicyDocument {
  schema_version: "0.1";
  revision: number;
  audience: string;
  issued_at_ms: number;
  trusted_edge_keys: Array<{ edge_id: string; key_id: string; not_before_ms: number; expires_at_ms: number }>;
  principal_grants: Array<{ principal_id: string; issuer: string; scopes: Scope[]; enabled: boolean }>;
  target_rules: Array<{
    rule_id: string;
    effect: "allow" | "deny";
    principal_id: string;
    scope: Scope;
    target: NormalizedTarget;
  }>;
  filesystem_roots: Array<{
    root_id: string;
    path: string;
    metadata: boolean;
    content_read: boolean;
    write?: boolean;
    deny_relative_paths: string[];
  }>;
  tool_enablement: Array<{ tool: string; enabled: boolean }>;
  kill_switches: Record<"global" | "mutations" | "process" | "network" | "gui" | "destructive" | "privileged", boolean>;
}

export interface SignedPolicyBundle {
  bundle_version: "0.1";
  key_id: string;
  algorithm: "Ed25519";
  payload_digest: string;
  payload: PolicyDocument;
  signature: string;
}

export interface PolicyVerificationKey {
  keyId: string;
  publicKeyPem: string | Buffer;
  notBeforeMs?: number;
  expiresAtMs?: number;
}

export interface VerifiedPolicy {
  policy: BrokerPolicy;
  payloadDigest: string;
  keyId: string;
}

export class PolicyBundleVerifier {
  private constructor(
    private readonly validateBundle: ((value: unknown) => boolean) & { errors?: unknown },
    private readonly ajv: InstanceType<typeof Ajv2020>,
    private readonly trustedKeys: ReadonlyMap<string, { publicKey: KeyObject; notBeforeMs: number; expiresAtMs: number }>,
    private readonly revocationCheck: (keyId: string) => boolean,
    private readonly now: () => number,
    private readonly allowedClockSkewMs: number
  ) {}

  static async create(options: {
    schemaDirectory: string;
    expectedKeyId?: string;
    publicKeyPem?: string | Buffer;
    trustedKeys?: readonly PolicyVerificationKey[];
    revocationCheck?: (keyId: string) => boolean;
    now?: () => number;
    allowedClockSkewMs?: number;
  }): Promise<PolicyBundleVerifier> {
    if (!isAbsolute(options.schemaDirectory)) throw new Error("Policy schema directory must be absolute");
    const documentSchema = JSON.parse(await readFile(join(options.schemaDirectory, "policy-document.schema.json"), "utf8")) as object;
    const bundleSchema = JSON.parse(await readFile(join(options.schemaDirectory, "signed-policy-bundle.schema.json"), "utf8")) as object;
    const ajv = new Ajv2020({ allErrors: true, strict: true });
    addFormats(ajv);
    ajv.addSchema(documentSchema);
    const validateBundle = ajv.compile(bundleSchema);
    const configuredKeys = options.trustedKeys ?? (options.expectedKeyId !== undefined && options.publicKeyPem !== undefined
      ? [{ keyId: options.expectedKeyId, publicKeyPem: options.publicKeyPem }]
      : []);
    if (configuredKeys.length < 1 || configuredKeys.length > 32) {
      throw new Error("At least one and no more than 32 policy verification keys are required");
    }
    const trustedKeys = new Map<string, { publicKey: KeyObject; notBeforeMs: number; expiresAtMs: number }>();
    for (const key of configuredKeys) {
      if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(key.keyId) || trustedKeys.has(key.keyId)) {
        throw new Error("Policy verification key identity is duplicated or malformed");
      }
      const notBeforeMs = key.notBeforeMs ?? 0;
      const expiresAtMs = key.expiresAtMs ?? Number.MAX_SAFE_INTEGER;
      if (!Number.isSafeInteger(notBeforeMs) || notBeforeMs < 0 ||
          !Number.isSafeInteger(expiresAtMs) || expiresAtMs <= notBeforeMs) {
        throw new Error(`Policy verification key validity window is invalid: ${key.keyId}`);
      }
      const publicKey = createPublicKey(key.publicKeyPem);
      if (publicKey.asymmetricKeyType !== "ed25519") throw new Error("Policy verification key must be Ed25519");
      trustedKeys.set(key.keyId, { publicKey, notBeforeMs, expiresAtMs });
    }
    return new PolicyBundleVerifier(
      validateBundle,
      ajv,
      trustedKeys,
      options.revocationCheck ?? (() => false),
      options.now ?? Date.now,
      options.allowedClockSkewMs ?? 5_000
    );
  }

  static async createFromKeyFile(options: {
    schemaDirectory: string;
    expectedKeyId: string;
    publicKeyPath: string;
    now?: () => number;
    allowedClockSkewMs?: number;
  }): Promise<PolicyBundleVerifier> {
    const publicKeyPem = await readProtectedRegularFile(options.publicKeyPath, 64 * 1024, "Policy verification key");
    return PolicyBundleVerifier.create({
      schemaDirectory: options.schemaDirectory,
      expectedKeyId: options.expectedKeyId,
      publicKeyPem,
      ...(options.now ? { now: options.now } : {}),
      ...(options.allowedClockSkewMs !== undefined ? { allowedClockSkewMs: options.allowedClockSkewMs } : {})
    });
  }

  static async createFromKeyFiles(options: {
    schemaDirectory: string;
    keys: readonly (Omit<PolicyVerificationKey, "publicKeyPem"> & { publicKeyPath: string })[];
    revocationCheck?: (keyId: string) => boolean;
    now?: () => number;
    allowedClockSkewMs?: number;
  }): Promise<PolicyBundleVerifier> {
    const trustedKeys: PolicyVerificationKey[] = [];
    for (const key of options.keys) {
      const publicKeyPem = await readProtectedRegularFile(key.publicKeyPath, 64 * 1024, "Policy verification key");
      trustedKeys.push({
        keyId: key.keyId,
        publicKeyPem,
        ...(key.notBeforeMs !== undefined ? { notBeforeMs: key.notBeforeMs } : {}),
        ...(key.expiresAtMs !== undefined ? { expiresAtMs: key.expiresAtMs } : {})
      });
    }
    return PolicyBundleVerifier.create({
      schemaDirectory: options.schemaDirectory,
      trustedKeys,
      ...(options.revocationCheck ? { revocationCheck: options.revocationCheck } : {}),
      ...(options.now ? { now: options.now } : {}),
      ...(options.allowedClockSkewMs !== undefined ? { allowedClockSkewMs: options.allowedClockSkewMs } : {})
    });
  }

  verify(rawBundle: unknown): VerifiedPolicy {
    if (!this.validateBundle(rawBundle)) {
      throw new Error(`Policy bundle schema validation failed: ${this.ajv.errorsText(this.validateBundle.errors)}`);
    }
    const bundle = rawBundle as SignedPolicyBundle;
    const key = this.trustedKeys.get(bundle.key_id);
    if (!key) throw new Error("Policy signing key ID is not trusted");
    if (this.revocationCheck(bundle.key_id)) throw new Error("Policy signing key is revoked");
    const nowMs = this.now();
    if (nowMs + this.allowedClockSkewMs < key.notBeforeMs || nowMs >= key.expiresAtMs) {
      throw new Error("Policy signing key is outside its validity window");
    }
    const payloadBytes = Buffer.from(canonicalJson(bundle.payload), "utf8");
    const digest = sha256(payloadBytes);
    if (digest !== bundle.payload_digest) throw new Error("Policy payload digest does not match");
    const signature = Buffer.from(bundle.signature, "base64");
    if (!verify(null, payloadBytes, key.publicKey, signature)) throw new Error("Policy signature is invalid");
    if (bundle.payload.issued_at_ms > nowMs + this.allowedClockSkewMs) {
      throw new Error("Policy issue time is in the future");
    }
    return {
      policy: buildBrokerPolicy(bundle.payload),
      payloadDigest: digest,
      keyId: bundle.key_id
    };
  }

  async verifyFile(path: string): Promise<VerifiedPolicy> {
    const content = await readProtectedPolicyFile(path);
    let parsed: unknown;
    try {
      parsed = JSON.parse(content.toString("utf8")) as unknown;
    } catch {
      throw new Error("Policy bundle is not valid JSON");
    }
    return this.verify(parsed);
  }
}

export class PolicyManager {
  private activePolicy: BrokerPolicy;

  constructor(
    initialPolicy: BrokerPolicy,
    private readonly store?: BrokerStore,
    private readonly now: () => number = Date.now
  ) {
    this.activePolicy = initialPolicy;
  }

  current(): BrokerPolicy {
    return this.activePolicy;
  }

  activate(verified: VerifiedPolicy): void {
    const currentRevision = this.activePolicy.revision;
    if (verified.policy.revision <= currentRevision) {
      throw new Error("Policy revision must increase");
    }
    this.store?.activatePolicy({
      revision: verified.policy.revision,
      version: verified.policy.version,
      payloadDigest: verified.payloadDigest,
      keyId: verified.keyId,
      activatedAtMs: this.now()
    }, currentRevision);
    this.activePolicy = verified.policy;
  }

  restore(verified: VerifiedPolicy): void {
    if (!this.store) throw new Error("Policy restore requires a persistence store");
    const persisted = this.store.activePolicyIdentity();
    if (
      !persisted ||
      persisted.revision !== verified.policy.revision ||
      persisted.version !== verified.policy.version ||
      persisted.payloadDigest !== verified.payloadDigest ||
      persisted.keyId !== verified.keyId
    ) {
      throw new Error("Verified policy does not match persisted active policy identity");
    }
    this.activePolicy = verified.policy;
  }

  rollback(verified: VerifiedPolicy, precondition: { expectedCurrentRevision: number; reasonCode: string }): void {
    if (!this.store) throw new Error("Policy rollback requires a persistence store");
    if (this.activePolicy.revision !== precondition.expectedCurrentRevision) {
      throw new Error("In-memory active policy does not match rollback precondition");
    }
    this.store.rollbackPolicy({
      revision: verified.policy.revision,
      version: verified.policy.version,
      payloadDigest: verified.payloadDigest,
      keyId: verified.keyId
    }, precondition.expectedCurrentRevision, precondition.reasonCode, this.now());
    this.activePolicy = verified.policy;
  }
}

function buildBrokerPolicy(document: PolicyDocument): BrokerPolicy {
  const knownScopes = new Set<string>(SCOPES);
  const plannedTools = new Set<string>(PLANNED_TOOL_NAMES);
  const principalGrants = new Map<string, PrincipalGrant>();
  for (const grant of document.principal_grants) {
    if (principalGrants.has(grant.principal_id)) throw new Error(`Duplicate principal grant: ${grant.principal_id}`);
    if (grant.scopes.some((scope) => !knownScopes.has(scope))) throw new Error(`Principal ${grant.principal_id} has an unknown scope`);
    principalGrants.set(grant.principal_id, {
      principalId: grant.principal_id,
      issuer: grant.issuer,
      scopes: [...grant.scopes],
      enabled: grant.enabled
    });
  }

  const ruleIds = new Set<string>();
  const targetRules: TargetRule[] = document.target_rules.map((rule) => {
    if (ruleIds.has(rule.rule_id)) throw new Error(`Duplicate target rule: ${rule.rule_id}`);
    ruleIds.add(rule.rule_id);
    const grant = principalGrants.get(rule.principal_id);
    if (!grant) throw new Error(`Target rule references an unknown principal: ${rule.principal_id}`);
    if (!knownScopes.has(rule.scope) || !grant.scopes.includes(rule.scope)) {
      throw new Error(`Target rule scope is outside the principal grant: ${rule.rule_id}`);
    }
    if (rule.target.reference.includes("\0") || rule.target.reference.includes("*")) {
      throw new Error(`Target rule uses an unsupported reference: ${rule.rule_id}`);
    }
    return {
      ruleId: rule.rule_id,
      effect: rule.effect,
      principalId: rule.principal_id,
      scope: rule.scope,
      target: { ...rule.target }
    };
  });

  const trustedEdgeIds = new Set<string>();
  const trustedEdgeKeys = new Map<string, { notBeforeMs: number; expiresAtMs: number }>();
  for (const edgeKey of document.trusted_edge_keys) {
    const identity = `${edgeKey.edge_id}:${edgeKey.key_id}`;
    if (trustedEdgeKeys.has(identity)) throw new Error(`Duplicate trusted Edge key: ${identity}`);
    if (edgeKey.expires_at_ms <= edgeKey.not_before_ms) throw new Error(`Trusted Edge key validity window is invalid: ${identity}`);
    trustedEdgeIds.add(edgeKey.edge_id);
    trustedEdgeKeys.set(identity, { notBeforeMs: edgeKey.not_before_ms, expiresAtMs: edgeKey.expires_at_ms });
  }
  const filesystemRootIds = new Set<string>();
  const filesystemRoots: FilesystemRootPolicy[] = document.filesystem_roots.map((root) => {
    if (filesystemRootIds.has(root.root_id)) throw new Error(`Duplicate filesystem root: ${root.root_id}`);
    if (!isAbsolute(root.path) || resolve(root.path) !== root.path || root.path.includes("\0")) {
      throw new Error(`Filesystem root path is not lexically normalized: ${root.root_id}`);
    }
    for (const denied of root.deny_relative_paths) {
      if (isAbsolute(denied) || denied.includes("\0") || resolve("/", denied) !== `/${denied}`) {
        throw new Error(`Filesystem deny path is not a normalized relative path: ${root.root_id}`);
      }
    }
    filesystemRootIds.add(root.root_id);
    return {
      rootId: root.root_id,
      path: root.path,
      metadata: root.metadata,
      contentRead: root.content_read,
      write: root.write ?? false,
      denyRelativePaths: [...root.deny_relative_paths]
    };
  });
  for (const rule of targetRules) {
    if (rule.target.kind === "path" && !filesystemRootIds.has(rule.target.reference)) {
      throw new Error(`Path target rule references an unknown filesystem root: ${rule.ruleId}`);
    }
    if (rule.target.kind === "project" &&
        (!isAbsolute(rule.target.reference) || resolve(rule.target.reference) !== rule.target.reference || rule.target.reference.includes("\n"))) {
      throw new Error(`Project target rule is not a canonical absolute path: ${rule.ruleId}`);
    }
  }
  const base = createDefaultPolicy([...trustedEdgeIds][0] ?? "invalid-edge");
  const tools = new Map([...base.tools].map(([name, tool]) => [name, { ...tool, enabled: false }]));
  const configuredTools = new Set<string>();
  for (const setting of document.tool_enablement) {
    if (configuredTools.has(setting.tool)) throw new Error(`Duplicate tool enablement: ${setting.tool}`);
    configuredTools.add(setting.tool);
    if (!plannedTools.has(setting.tool)) throw new Error(`Policy references an unknown tool: ${setting.tool}`);
    const tool = tools.get(setting.tool);
    if (setting.enabled && !tool?.implemented) throw new Error(`Policy cannot enable an unimplemented tool: ${setting.tool}`);
    if (tool) tools.set(setting.tool, { ...tool, enabled: setting.enabled });
  }

  return {
    revision: document.revision,
    version: `policy-${document.revision}`,
    audience: document.audience,
    trustedEdgeIds,
    trustedEdgeKeys,
    principalGrants,
    targetRules,
    filesystemRoots,
    killSwitches: { ...document.kill_switches },
    tools
  };
}

async function readProtectedPolicyFile(path: string): Promise<Buffer> {
  return readProtectedRegularFile(path, 1_048_576, "Policy");
}

async function readProtectedRegularFile(path: string, maxBytes: number, label: string): Promise<Buffer> {
  if (!isAbsolute(path)) throw new Error(`${label} path must be absolute`);
  const pathStat = await lstat(path);
  const currentUid = process.getuid?.();
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) throw new Error(`${label} must be a regular non-symlink file`);
  if (currentUid === undefined || pathStat.uid !== currentUid) throw new Error(`${label} must be owned by the Broker user`);
  if ((pathStat.mode & 0o022) !== 0) throw new Error(`${label} must not be writable by group or other users`);
  if (pathStat.size < 2 || pathStat.size > maxBytes) throw new Error(`${label} file size is outside the allowed range`);
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const openedStat = await handle.stat();
    if (!openedStat.isFile() || openedStat.dev !== pathStat.dev || openedStat.ino !== pathStat.ino) {
      throw new Error(`${label} target changed while opening`);
    }
    return await handle.readFile();
  } finally {
    await handle.close();
  }
}
