import { spawn, type ChildProcess } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { realpath, chmod } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { Broker, BrokerStore, BrokerServiceInstanceLock, EdgeKeyring, MacOsNativeBrokerIpcServer,
  capturePeerProcessIdentity, PolicyBundleVerifier, PolicyManager, createDefaultPolicy,
  ApprovalIssuerKeyManager, provisionAuthenticationKey, writeApprovalIssuerKeyConfig,
  type SignedPolicyBundle, type PolicyDocument } from "@mac-operator/broker";
import { runEdgeServiceMain, validateEdgeServiceStartupConfig, type JwtRevocationContext } from "@mac-operator/edge";
import { assertPrivateDirectory } from "./store.js";
import { readAuthFile, runAuthCli } from "./cli.js";
import { configSchema, READ_SCOPES, READ_TOOLS, W1_SCOPES, W1_TOOLS } from "./contracts.js";
import { configureIssuerNetwork } from "./issuer-network.js";
import { enableConnectionDiagnostics } from "./connection-diagnostics.js";
import { buildR1TargetRules, r1FilesystemRoots } from "./r1-policy.js";
import { assertW1Policy, buildW1TargetRules, w1FilesystemRoots, w1ProjectRoot } from "./w1-policy.js";
import { createPersonalApprovalIssuerRuntime } from "./personal-approval-issuer.js";
import { createProcessApprovalBrowserBridge, parseApprovalBrowserRequest } from "./approval-browser-bridge.js";
import { createPersonalApprovalBrowserController } from "./personal-approval-browser-controller.js";
import type { ApprovalIssuerRuntimeAssembly } from "@mac-operator/broker";
import { AUTH_REVOCATION_TYPE, createAuthRevocationQueue, MAX_PENDING_AUTH_REVOCATIONS, parseAuthGrantRevocation, toJwtRevocationContext } from "./personal-revocation.js";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const entrypoint = fileURLToPath(import.meta.url);
const digest = (bytes: Buffer) => createHash("sha256").update(bytes).digest("hex");
const save = (path: string, value: string | Buffer) => writeFileSync(path, value, { mode: 0o600, flag: "wx" });
const json = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

/** Personal installation: signed policy for one owner and one selected profile. */
async function provision(root: string, revision: string) {
  assertPrivateDirectory(root);
  const auth = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
  if (auth.grantProfile === "d1") throw new Error("Personal service accepts only r1 or w1 OAuth grants");
  const writeProfile = auth.grantProfile === "w1";
  const data = join(root, "personal"); const runtime = join(data, "run");
  if (Buffer.byteLength(join(runtime, "broker.sock")) >= 104) throw new Error("Runtime socket path is too long");
  mkdirSync(data, { mode: 0o700 }); mkdirSync(runtime, { mode: 0o700 });
  const edgeKey = randomBytes(32); const anchorKey = randomBytes(32);
  const statusKey = readAuthFile(join(root, "auth/status.key"));
  const keys = generateKeyPairSync("ed25519");
  const now = Date.now();
  const projectRoot = realpathSync(process.env.MAC_OPERATOR_PROJECT_ROOT ?? packageRoot);
  const filesystemRoots = writeProfile ? w1FilesystemRoots(w1ProjectRoot(projectRoot)) : r1FilesystemRoots();
  const scopes = writeProfile ? W1_SCOPES : READ_SCOPES;
  const enabledTools = writeProfile ? W1_TOOLS : READ_TOOLS;
  const policy: PolicyDocument = { schema_version: "0.1", revision: 1, audience: "mac-operator-broker", issued_at_ms: now,
    trusted_edge_keys: [{ edge_id: "personal-edge", key_id: "personal-edge-1", not_before_ms: now - 5000, expires_at_ms: now + 365 * 86400000 }],
    principal_grants: [{ principal_id: auth.principalId, issuer: auth.issuerId, scopes: [...scopes], enabled: true }],
    target_rules: writeProfile
      ? buildW1TargetRules(auth.principalId, filesystemRoots, projectRoot)
      : buildR1TargetRules(auth.principalId, filesystemRoots, projectRoot),
    filesystem_roots: filesystemRoots, tool_enablement: enabledTools.map(tool => ({ tool, enabled: true })),
    kill_switches: { global: false, mutations: !writeProfile, process: false, network: false, gui: true, destructive: true, privileged: true } };
  const payload = Buffer.from(canonicalJson(policy));
  const bundle: SignedPolicyBundle = { bundle_version: "0.1", key_id: "personal-policy-1", algorithm: "Ed25519", payload_digest: sha256(payload), payload: policy,
    signature: sign(null, payload, keys.privateKey).toString("base64") };
  try {
    save(join(data, "edge.key"), edgeKey); save(join(data, "audit.key"), anchorKey); save(join(data, "status.key"), statusKey);
    save(join(data, "policy-public.pem"), keys.publicKey.export({ type: "spki", format: "pem" }));
    save(join(root, "personal-policy-private.key"), keys.privateKey.export({ type: "pkcs8", format: "pem" }));
    save(join(data, "policy.json"), json(bundle));
    save(join(data, "auth-status-ca.crt"), readAuthFile(join(root, "tls/origin-ca.crt")));
    save(join(data, "edge.crt"), readAuthFile(join(root, "tls/edge.crt")));
    save(join(data, "edge-tls.key"), readAuthFile(join(root, "tls/edge.key")));
    const edge = validateEdgeServiceStartupConfig({ schemaVersion: "0.1", packageRoot, dataRoot: data, runtimeRoot: runtime,
      edgeId: "personal-edge", brokerAudience: "mac-operator-broker", brokerSocketPath: join(runtime, "broker.sock"),
      authenticationKeyPath: join(data, "edge.key"), authenticationKeyId: "personal-edge-1", authenticationKeyDigest: digest(edgeKey),
      contractsDirectory: join(packageRoot, "tool-contracts"), tlsCertificatePath: join(data, "edge.crt"), tlsPrivateKeyPath: join(data, "edge-tls.key"),
      bindHost: "127.0.0.1", bindPort: 3443, resourceServerUrl: auth.resource, oauthIssuer: auth.issuer, issuerId: auth.issuerId,
      authorizationEndpoint: new URL("/authorize", auth.issuer).href, tokenEndpoint: new URL("/token", auth.issuer).href, jwksUri: new URL("/jwks", auth.issuer).href,
      oauthStatusUrl: new URL("/oauth/status", auth.issuer).href, oauthStatusKeyPath: join(data, "status.key"), oauthStatusKeyDigest: digest(statusKey),
      oauthStatusLocalUrl: `https://127.0.0.1:${auth.port}/oauth/status`, oauthStatusLocalServerName: new URL(auth.issuer).hostname,
      oauthStatusLocalCaPath: join(data, "auth-status-ca.crt"),
      allowedHosts: [new URL(auth.issuer).hostname], allowedOrigins: ["chatgpt.com", new URL(auth.issuer).hostname],
      requiredScopes: [...scopes],
      policyVersion: "policy-1", sourceRevision: revision, contractVersion: "0.1", ipcTimeoutMs: 5000, maxIpcResponseBytes: 1048576,
      rateLimitWindowMs: 60000, rateLimitMaxRequests: 100, rateLimitMaxKeys: 100 });
    save(join(data, "edge-service.json"), json(edge));
    if (writeProfile) {
      const approvalKeyPath = join(data, "approval.key");
      await provisionAuthenticationKey(approvalKeyPath);
      await writeApprovalIssuerKeyConfig(join(data, "approval-keys.json"), {
        schemaVersion: "0.1",
        revision: 1,
        keys: [{ issuerId: auth.principalId, keyId: "personal-approval-1", path: approvalKeyPath,
          notBeforeMs: now - 5_000, expiresAtMs: now + 365 * 86_400_000, allowUnattended: false }]
      });
    }
    save(join(data, "approval-issuer.json"), json({ schemaVersion: "0.1", enabled: writeProfile,
      keyConfigPath: join(data, "approval-keys.json"), socketPath: join(runtime, "approval.sock") }));
    const store = openStore(data);
    try {
      const verifier = await policyVerifier(data);
      new PolicyManager(createDefaultPolicy("personal-edge"), store).activate(verifier.verify(bundle));
      if (writeProfile) {
        const manager = new ApprovalIssuerKeyManager(join(data, "approval-keys.json"), store);
        try { await manager.activate(); } finally { manager.dispose(); }
      }
    } finally { store.close(); }
    console.log("Personal service state provisioned; no listener started.");
  } finally { edgeKey.fill(0); anchorKey.fill(0); statusKey.fill(0); }
}

function openStore(data: string) {
  return new BrokerStore(join(data, "broker.sqlite"), { runtimeFence: true,
    auditAnchor: { path: join(data, "audit.anchor"), keySource: { keyId: "personal-audit-1", loadKey: () => readAuthFile(join(data, "audit.key"), 32) } } });
}
async function policyVerifier(data: string) {
  return PolicyBundleVerifier.createFromKeyFile({ schemaDirectory: join(packageRoot, "schemas"), expectedKeyId: "personal-policy-1", publicKeyPath: join(data, "policy-public.pem") });
}

async function start(root: string) {
  assertPrivateDirectory(root);
  const data = join(root, "personal"); const runtime = join(data, "run");
  assertPrivateDirectory(data); assertPrivateDirectory(runtime);
  const lock = await BrokerServiceInstanceLock.acquire(join(runtime, "service.lock"));
  const children: ChildProcess[] = [];
  let store: BrokerStore | undefined; let broker: Broker | undefined; let server: MacOsNativeBrokerIpcServer | undefined;
  let approvalIssuerRuntime: ApprovalIssuerRuntimeAssembly | undefined;
  let stopping = false; let failed = false;
  let edge: ChildProcess | undefined;
  let wake: () => void = () => {};
  const stopped = new Promise<void>(r => { wake = r; });
  const stop = () => { stopping = true; wake(); };
  process.once("SIGTERM", stop); process.once("SIGINT", stop);
  const key = readAuthFile(join(data, "edge.key"), 32);
  try {
    const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
    if (config.grantProfile === "d1") throw new Error("Personal service accepts only r1 or w1 OAuth grants");
    const writeProfile = config.grantProfile === "w1";
    store = openStore(data);
    const verified = await (await policyVerifier(data)).verifyFile(join(data, "policy.json"));
    new PolicyManager(verified.policy, store).restore(verified);
    const granted = [...verified.policy.principalGrants.values()];
    if (granted.length !== 1 || granted[0]?.principalId !== config.principalId || granted[0]?.issuer !== config.issuerId ||
        JSON.stringify([...granted[0].scopes].sort()) !== JSON.stringify([...(writeProfile ? W1_SCOPES : READ_SCOPES)].sort())) throw new Error("Owner policy mismatch");
    const enabled = [...verified.policy.tools.values()].filter(t => t.enabled).map(t => t.tool).sort();
    const roots = verified.policy.filesystemRoots;
    if (writeProfile) {
      assertW1Policy(verified.policy, config.principalId, config.issuerId);
    } else {
      if (JSON.stringify(enabled) !== JSON.stringify([...READ_TOOLS].sort()) ||
          roots.length !== 2 || roots.some(root => root.write === true || root.denyRelativePaths.length !== 0) ||
          !roots.some(root => root.rootId === "owner-home" && root.contentRead === true) ||
          !roots.some(root => root.rootId === "system-metadata" && root.path === "/" && root.contentRead === false) ||
          verified.policy.killSwitches.mutations !== true || verified.policy.killSwitches.process !== false ||
          verified.policy.killSwitches.network !== false || verified.policy.killSwitches.gui !== true ||
          verified.policy.killSwitches.destructive !== true || verified.policy.killSwitches.privileged !== true) {
        throw new Error("Read-only boundary mismatch");
      }
    }
    const bundle = JSON.parse(readAuthFile(join(data, "policy.json")).toString()) as SignedPolicyBundle;
    const validity = bundle.payload.trusted_edge_keys[0]!;
    broker = new Broker({ store, policy: verified.policy, edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "personal-edge", keyId: "personal-edge-1", key,
      notBeforeMs: validity.not_before_ms, expiresAtMs: validity.expires_at_ms }]) });
    const expectedTools = writeProfile ? W1_TOOLS : READ_TOOLS;
    if (JSON.stringify([...broker.enabledRuntimeCapabilityNames()].sort()) !== JSON.stringify([...expectedTools].sort())) throw new Error("Unexpected runtime capability");
    approvalIssuerRuntime = await createPersonalApprovalIssuerRuntime({
      configPath: join(data, "approval-issuer.json"), dataRoot: data, runtimeRoot: runtime, store,
      uid: process.getuid!(), ...(process.getgid === undefined ? {} : { gid: process.getgid() })
    });
    if (writeProfile !== (approvalIssuerRuntime !== undefined)) throw new Error("Personal approval boundary mismatch");
    const browserApprovalController = approvalIssuerRuntime === undefined ? undefined : createPersonalApprovalBrowserController({
      store, approvalIssuerRuntime, socketPath: join(runtime, "approval.sock")
    });
    const authRevocationQueue = createAuthRevocationQueue({
      isConnected: () => edge?.connected === true,
      send: (message, callback) => {
        if (edge?.connected !== true) { callback(new Error("Edge revocation channel is unavailable")); return; }
        edge.send(message, callback);
      },
      onSendFailure: () => {
        if (!stopping) { failed = true; stop(); }
      }
    });
    const launch = (mode: string) => {
      const childArgs = [entrypoint, mode, root];
      if (mode === "auth" && approvalIssuerRuntime) childArgs.push("approval-browser");
      const child = spawn(process.execPath, childArgs, {
        cwd: packageRoot,
        env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" },
        shell: false,
        stdio: ["ignore", "inherit", "inherit", "ipc"]
      });
      children.push(child);
      if (mode === "auth") {
        child.on("message", (raw: unknown) => {
          const revocation = parseAuthGrantRevocation(raw);
          if (revocation !== undefined) {
            try { authRevocationQueue.enqueue(revocation); }
            catch { failed = true; stop(); }
            return;
          }
          const request = parseApprovalBrowserRequest(raw);
          if (!request) return;
          const operation = request.operation === "preview"
            ? Promise.resolve(browserApprovalController?.preview(request.requestId)).then(preview => preview === undefined ? undefined : { preview })
            : (browserApprovalController === undefined ? Promise.reject(new Error("Owner approval channel is unavailable")) : browserApprovalController.issue(request.requestId));
          void operation.then(value => {
            if (!child.connected) return;
            const response = { type: "approval-browser-response", id: request.id, ok: value !== undefined, ...value };
            child.send(response, () => undefined);
          }).catch(() => {
            if (child.connected) child.send({ type: "approval-browser-response", id: request.id, ok: false }, () => undefined);
          });
        });
      }
      child.once("exit", () => { if (!stopping) { failed = true; stop(); } });
      child.once("error", () => { failed = true; stop(); });
      return child;
    };
    launch("auth");
    edge = launch("edge");
    authRevocationQueue.flush();
    let identity: ReturnType<typeof capturePeerProcessIdentity> | undefined;
    for (let i = 0; i < 50 && !stopping; i++) {
      try { identity = capturePeerProcessIdentity(edge.pid!); break; } catch { await delay(100); }
    }
    if (!identity || stopping || edge === undefined) throw new Error("Edge process unavailable");
    server = new MacOsNativeBrokerIpcServer({ socketPath: join(runtime, "broker.sock"), broker,
      peerPolicy: { expectedUid: process.getuid!(), expectedGid: process.getgid!(), allowedProcessIdentity: identity } });
    await server.listen();
    await approvalIssuerRuntime?.channel.listen();
    await chmod(join(data, "broker.sqlite"), 0o600);
    console.log(`Personal ${config.grantProfile} supervisor running; capabilities: ${expectedTools.join(", ")}.`);
    await stopped;
  } finally {
    stopping = true;
    for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
    for (let i = 0; i < 50 && children.some(c => c.exitCode === null && c.signalCode === null); i++) await delay(100);
    for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await approvalIssuerRuntime?.close(); await server?.close(); await broker?.close(); store?.close(); key.fill(0); await lock.close();
    process.off("SIGTERM", stop); process.off("SIGINT", stop);
  }
  if (failed) throw new Error("Child stopped unexpectedly");
}

async function main() {
  const [mode, rootArg, revision, feature] = process.argv.slice(2);
  if (!rootArg || process.getuid?.() === 0) throw new Error("Unprivileged owner and root path required");
  const root = await realpath(rootArg);
  if (mode === "init") { if (!revision || !/^[a-f0-9]{7,64}$/u.test(revision)) throw new Error("Snapshot identity required"); await provision(root, revision); }
  else if (mode === "start") await start(root);
  else if (mode === "edge" || mode === "auth") {
    if (!process.send) throw new Error("Supervisor IPC required");
    enableConnectionDiagnostics(mode);
    process.once("disconnect", () => process.emit("SIGTERM"));
    if (mode === "edge") {
      const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
      const network = configureIssuerNetwork(new URL(config.issuer).hostname);
      let notifyOAuthGrantRevoked: ((context: JwtRevocationContext) => Promise<void>) | undefined;
      const pendingRevocations = [] as Array<Parameters<typeof toJwtRevocationContext>[0]>;
      let revocationBridgeFailed = false;
      const failRevocationBridge = (): void => {
        if (revocationBridgeFailed) return;
        revocationBridgeFailed = true;
        queueMicrotask(() => { throw new Error("Edge OAuth revocation propagation failed"); });
      };
      const handleParentMessage = (raw: unknown) => {
        const revocation = parseAuthGrantRevocation(raw);
        if (revocation === undefined) return;
        if (notifyOAuthGrantRevoked === undefined) {
          if (pendingRevocations.length >= MAX_PENDING_AUTH_REVOCATIONS) throw new Error("Edge OAuth revocation queue capacity exceeded");
          pendingRevocations.push(revocation);
          return;
        }
        void notifyOAuthGrantRevoked(toJwtRevocationContext(revocation, config.issuerId)).catch(() => failRevocationBridge());
      };
      process.on("message", handleParentMessage);
      try {
        await runEdgeServiceMain({
          configPath: join(root, "personal/edge-service.json"),
          onReady: notify => {
            notifyOAuthGrantRevoked = notify;
            for (const revocation of pendingRevocations.splice(0)) {
              void notify(toJwtRevocationContext(revocation, config.issuerId)).catch(() => failRevocationBridge());
            }
          }
        });
      } finally {
        process.off("message", handleParentMessage);
        await network.close();
      }
    }
    else {
      const approvalBridge = feature === "approval-browser" ? createProcessApprovalBrowserBridge() : undefined;
      try {
        await runAuthCli(["serve", "--dir", join(root, "auth"), "--tls-cert", join(root, "tls/auth.crt"), "--tls-key", join(root, "tls/auth.key")], {
          ...(approvalBridge === undefined ? {} : { approvalBridge }),
          onGrantRevoked: notice => {
            if (!process.send || !process.connected) return;
            process.send({ type: AUTH_REVOCATION_TYPE, ...notice }, () => undefined);
          }
        });
      } finally { approvalBridge?.close(); }
    }
  } else throw new Error("Unknown mode");
}
// IPC channels used by the supervisor/PM2 otherwise keep a stopped process
// alive after all listeners close, preventing the manager from recovering it.
main().then(() => process.exit(0)).catch(() => {
  console.error("Personal service failed closed; check protected configuration and service prerequisites.");
  process.exit(1);
});
