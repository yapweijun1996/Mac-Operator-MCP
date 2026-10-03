import { loadPersonalDevelopmentRuntimeConfig, createPersonalDevelopmentRuntime, developmentPolicyConfiguration } from "./personal-development-runtime.js";
import { assertV2Policy } from "./v2-policy.js";
import { createPersonalDevelopmentApprover } from "./personal-development-approval.js";
import { GuiSessionApprovals } from "./gui-session-approval.js";
import { AuthStore } from "./store.js";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdirSync, realpathSync, writeFileSync } from "node:fs";
import { realpath, chmod } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { Broker, BrokerStore, BrokerServiceInstanceLock, EdgeKeyring, MacOsNativeBrokerIpcServer,
  capturePeerProcessIdentity, PolicyBundleVerifier, PolicyManager, createDefaultPolicy,
  ApprovalIssuerKeyManager, PersonalOwnerTerminalExecutor, OwnerTerminalSessionManager, provisionAuthenticationKey, writeApprovalIssuerKeyConfig,
  type SignedPolicyBundle, type PolicyDocument } from "@mac-operator/broker";
import { runEdgeServiceMain, validateEdgeServiceStartupConfig, type JwtRevocationContext } from "@mac-operator/edge";
import { assertPrivateDirectory } from "./store.js";
import { readAuthFile, runAuthCli } from "./cli.js";
import { configSchema, V2_SCOPES, V2_TOOLS, O1_SCOPES, O1_TOOLS, G1_SCOPES, G1_TOOLS, READ_SCOPES, READ_TOOLS, W1_READ_SCOPES, W1_SCOPES, W1_TOOLS } from "./contracts.js";
import { configureIssuerNetwork } from "./issuer-network.js";
import { enableConnectionDiagnostics } from "./connection-diagnostics.js";
import { buildR1TargetRules, r1FilesystemRoots } from "./r1-policy.js";
import { assertO1Policy, assertG1Policy, assertW1Policy, buildO1TargetRules, buildG1TargetRules, buildW1TargetRules, w1FilesystemRoots, w1ProjectRoot } from "./w1-policy.js";
import { upgradePersonalDevelopment } from "./personal-development-upgrade.js";
import { enablePersonalTerminalConnection } from "./personal-terminal-connection.js";
import { upgradePersonalOwnerTerminal } from "./personal-owner-upgrade.js";
import { upgradePersonalTerminalSessions } from "./personal-terminal-session-upgrade.js";
import { createPersonalTerminalApprover } from "./personal-terminal-approval.js";
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
  if (auth.grantProfile === "d1") throw new Error("Personal service accepts only r1, w1, g1, or o1 OAuth grants");
  if (auth.grantProfile === "v2") throw new Error("V2 requires an evidence-verified upgrade of an existing personal installation");
  const terminalProfile = auth.grantProfile === "o1";
  const guiProfile = auth.grantProfile === "g1" || terminalProfile;
  const writeProfile = auth.grantProfile === "w1" || guiProfile;
  const data = join(root, "personal"); const runtime = join(data, "run");
  if (Buffer.byteLength(join(runtime, "broker.sock")) >= 104) throw new Error("Runtime socket path is too long");
  mkdirSync(data, { mode: 0o700 }); mkdirSync(runtime, { mode: 0o700 });
  const edgeKey = randomBytes(32); const anchorKey = randomBytes(32);
  const statusKey = readAuthFile(join(root, "auth/status.key"));
  const keys = generateKeyPairSync("ed25519");
  const now = Date.now();
  const projectRoot = realpathSync(process.env.MAC_OPERATOR_PROJECT_ROOT ?? packageRoot);
  const filesystemRoots = writeProfile ? w1FilesystemRoots(w1ProjectRoot(projectRoot)) : r1FilesystemRoots();
  const scopes = terminalProfile ? O1_SCOPES : guiProfile ? G1_SCOPES : writeProfile ? W1_SCOPES : READ_SCOPES;
  const enabledTools = terminalProfile ? O1_TOOLS : guiProfile ? G1_TOOLS : writeProfile ? W1_TOOLS : READ_TOOLS;
  const policy: PolicyDocument = { schema_version: "0.1", revision: 1, audience: "mac-operator-broker", issued_at_ms: now,
    trusted_edge_keys: [{ edge_id: "personal-edge", key_id: "personal-edge-1", not_before_ms: now - 5000, expires_at_ms: now + 365 * 86400000 }],
    principal_grants: [{ principal_id: auth.principalId, issuer: auth.issuerId, scopes: [...scopes], enabled: true }],
    target_rules: writeProfile
      ? terminalProfile ? buildO1TargetRules(auth.principalId, filesystemRoots, projectRoot) : guiProfile ? buildG1TargetRules(auth.principalId, filesystemRoots, projectRoot) : buildW1TargetRules(auth.principalId, filesystemRoots, projectRoot)
      : buildR1TargetRules(auth.principalId, filesystemRoots, projectRoot),
    filesystem_roots: filesystemRoots, tool_enablement: enabledTools.map(tool => ({ tool, enabled: true })),
    kill_switches: { global: false, mutations: !writeProfile, process: false, network: false, gui: !guiProfile, destructive: true, privileged: true } };
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
      oauthScopes: [...scopes], requiredScopes: [...(writeProfile ? W1_READ_SCOPES : READ_SCOPES)],
      policyVersion: "policy-1", sourceRevision: revision, contractVersion: "0.1", ipcTimeoutMs: terminalProfile ? 180_000 : guiProfile ? 30_000 : 5000, maxIpcResponseBytes: 1048576,
      rateLimitWindowMs: 60000, rateLimitMaxRequests: 100, rateLimitMaxKeys: 100 });
    save(join(data, "edge-service.json"), json(edge));
    if (writeProfile) {
      const approvalKeyPath = join(data, "approval.key");
      await provisionAuthenticationKey(approvalKeyPath);
      if (terminalProfile) await provisionAuthenticationKey(join(data, "terminal-approval.key"));
      await writeApprovalIssuerKeyConfig(join(data, "approval-keys.json"), {
        schemaVersion: "0.1",
        revision: 1,
        // Browser consent is a separate authority from the MCP requesting principal.
        keys: [{ issuerId: `browser-approver-${sha256(auth.principalId).slice(0, 32)}`, keyId: "personal-approval-1", path: approvalKeyPath,
          notBeforeMs: now - 5_000, expiresAtMs: now + 365 * 86_400_000, allowUnattended: false },
          ...(terminalProfile ? [{ issuerId: `terminal-approver-${sha256(auth.principalId).slice(0, 32)}`, keyId: "personal-terminal-1",
            path: join(data, "terminal-approval.key"), notBeforeMs: now - 5_000, expiresAtMs: now + 365 * 86_400_000, allowUnattended: true }] : [])]
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
  let developmentRuntime: Awaited<ReturnType<typeof createPersonalDevelopmentRuntime>> | undefined;
  let browserAuthStore: AuthStore | undefined;
  let browserApprovalController: ReturnType<typeof createPersonalApprovalBrowserController> | undefined;
  let stopping = false; let failed = false;
  let edge: ChildProcess | undefined;
  let wake: () => void = () => {};
  const stopped = new Promise<void>(r => { wake = r; });
  const stop = () => { stopping = true; wake(); };
  process.once("SIGTERM", stop); process.once("SIGINT", stop);
  const key = readAuthFile(join(data, "edge.key"), 32);
  try {
    const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
    if (config.grantProfile === "d1") throw new Error("Personal service accepts only r1, w1, g1, or o1 OAuth grants");
    const edgeConfig = validateEdgeServiceStartupConfig(JSON.parse(readAuthFile(join(data, "edge-service.json")).toString()));
    if ((config.ownerTerminalConnection === true) !== (edgeConfig.ownerTerminalConnection === true) ||
        config.issuer !== edgeConfig.oauthIssuer || config.resource !== edgeConfig.resourceServerUrl ||
        new URL(config.issuer).pathname !== "/") throw new Error("Personal Auth/Edge connection configuration mismatch");
    const developmentProfile = config.grantProfile === "v2";
    const terminalProfile = config.grantProfile === "o1" || developmentProfile;
    const developmentConfig = developmentProfile ? loadPersonalDevelopmentRuntimeConfig(join(data, "development-runtime.json")) : undefined;
    const guiProfile = config.grantProfile === "g1" || terminalProfile;
    const writeProfile = config.grantProfile === "w1" || guiProfile;
    store = openStore(data);
    const verified = await (await policyVerifier(data)).verifyFile(join(data, "policy.json"));
    new PolicyManager(verified.policy, store).restore(verified);
    const granted = [...verified.policy.principalGrants.values()];
    if (granted.length !== 1 || granted[0]?.principalId !== config.principalId || granted[0]?.issuer !== config.issuerId ||
        JSON.stringify([...granted[0].scopes].sort()) !== JSON.stringify([...(developmentProfile ? V2_SCOPES : terminalProfile ? O1_SCOPES : guiProfile ? G1_SCOPES : writeProfile ? W1_SCOPES : READ_SCOPES)].sort())) throw new Error("Owner policy mismatch");
    const enabled = [...verified.policy.tools.values()].filter(t => t.enabled).map(t => t.tool).sort();
    const roots = verified.policy.filesystemRoots;
    if (writeProfile) {
      if (developmentConfig) {
        if (verified.policy.filesystemRoots.find(root => root.rootId === "owner-project")?.path !== developmentConfig.ownerProjectRoot) throw new Error("Development owner project binding changed");
        assertV2Policy(verified.policy, config.principalId, config.issuerId, developmentPolicyConfiguration(developmentConfig));
      } else if (terminalProfile) assertO1Policy(verified.policy, config.principalId, config.issuerId);
      else if (guiProfile) assertG1Policy(verified.policy, config.principalId, config.issuerId);
      else assertW1Policy(verified.policy, config.principalId, config.issuerId);
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
    if (guiProfile) {
      try {
        // Deployment retains an existing validated app to preserve its TCC identity.
        await promisify(execFile)(process.execPath, [join(packageRoot, "packages/broker/scripts/install-gui-app.mjs")], {
          cwd: packageRoot, timeout: 30000, maxBuffer: 16384, env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin" }, shell: false
        });
      } catch {
        // GUI readiness fails closed independently; keep health and terminal available.
        console.warn("GUI_HELPER_UNAVAILABLE: GUI installation/readiness requires owner attention");
      }
    }
    const bundle = JSON.parse(readAuthFile(join(data, "policy.json")).toString()) as SignedPolicyBundle;
    const validity = bundle.payload.trusted_edge_keys[0]!;
    if (developmentConfig) developmentRuntime = await createPersonalDevelopmentRuntime(developmentConfig, config.principalId);
    broker = new Broker({ store, policy: verified.policy,
      ...(developmentRuntime ? { developmentGateway: developmentRuntime.gateway, taskProfileRegistry: developmentRuntime.profiles,
        taskRunner: developmentRuntime.runner, authorizeDevelopment: operation => approvalIssuerRuntime === undefined ? Promise.resolve(false) :
          createPersonalDevelopmentApprover({ principalId: config.principalId, runtime: approvalIssuerRuntime, socketPath: join(runtime, "approval.sock"),
            worktrees: developmentRuntime!.gateway.worktrees, developmentProjects: developmentConfig!.developmentProjects,
            taskProfiles: developmentConfig!.taskProfiles })(operation) } : {}),
      ...(terminalProfile ? { ownerTerminalExecutor: new PersonalOwnerTerminalExecutor({ enabled: true }),
        ownerTerminalSessions: new OwnerTerminalSessionManager({ enabled: true }),
        authorizeOwnerTerminal: operation => approvalIssuerRuntime === undefined ? Promise.resolve(false) :
          createPersonalTerminalApprover({ principalId: config.principalId, runtime: approvalIssuerRuntime, socketPath: join(runtime, "approval.sock") })(operation) } : {}),
      ...(guiProfile ? { authorizeGuiSession: operation => browserApprovalController?.authorizeGuiSession(operation) ?? Promise.resolve(false) } : {}), edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "personal-edge", keyId: "personal-edge-1", key,
      notBeforeMs: validity.not_before_ms, expiresAtMs: validity.expires_at_ms }]) });
    const expectedTools = developmentProfile ? V2_TOOLS : terminalProfile ? O1_TOOLS : guiProfile ? G1_TOOLS : writeProfile ? W1_TOOLS : READ_TOOLS;
    if (JSON.stringify([...broker.enabledRuntimeCapabilityNames()].sort()) !== JSON.stringify([...expectedTools].sort())) throw new Error("Unexpected runtime capability");
    if (guiProfile) console.log(JSON.stringify({ component: "gui_helper", ...(await broker.guiHelperStatus()) }));
    approvalIssuerRuntime = await createPersonalApprovalIssuerRuntime({
      configPath: join(data, "approval-issuer.json"), dataRoot: data, runtimeRoot: runtime, store,
      uid: process.getuid!(), ...(process.getgid === undefined ? {} : { gid: process.getgid() })
    });
    if (writeProfile !== (approvalIssuerRuntime !== undefined)) throw new Error("Personal approval boundary mismatch");
    if (approvalIssuerRuntime && !terminalProfile && approvalIssuerRuntime.keyManager.current().keys.some(key => key.allowUnattended)) throw new Error("Unexpected terminal delegation");
    if (terminalProfile) {
      const delegated = approvalIssuerRuntime?.keyManager.current().keys.filter(key => key.allowUnattended) ?? [];
      const expected = developmentProfile ? ["personal-development-1", "personal-terminal-1"] : ["personal-terminal-1"];
      if (JSON.stringify(delegated.map(key => key.keyId).sort()) !== JSON.stringify(expected)) throw new Error("Explicit owner delegation keys do not match the selected profile");
    }
    if (developmentRuntime) await broker.reconcileRestartedContainerTasks();
    if (terminalProfile) await broker.reconcileRestartedTaskProcesses();
    if (guiProfile) browserAuthStore = new AuthStore(join(root, "auth"));
    browserApprovalController = approvalIssuerRuntime === undefined ? undefined : createPersonalApprovalBrowserController({
      store, ...(browserAuthStore ? { authStore: browserAuthStore } : {}), approvalIssuerRuntime, socketPath: join(runtime, "approval.sock")
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
          const operation = (async () => {
            const controller = browserApprovalController;
            if (!controller) throw new Error("Owner approval channel is unavailable");
            switch (request.operation) {
              case "preview": { const preview = controller.preview(request.requestId); return preview ? { preview } : undefined; }
              case "issue": return controller.issue(request.requestId);
              case "session-start": return { session: controller.sessions.start(request.requestId) };
              case "session-persistent-start": return { session: controller.sessions.start(request.requestId, true) };
              case "session-list": return { sessions: controller.sessions.list(config.principalId) };
              case "session-status": return { session: controller.sessions.status(request.requestId) };
              case "session-revoke": controller.sessions.revoke(request.requestId); return {};
            }
          })();
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
    try { browserApprovalController?.sessions.close(); } catch { failed = true; }
    stopping = true;
    for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGTERM");
    for (let i = 0; i < 50 && children.some(c => c.exitCode === null && c.signalCode === null); i++) await delay(100);
    for (const child of children) if (child.exitCode === null && child.signalCode === null) child.kill("SIGKILL");
    await approvalIssuerRuntime?.close(); await server?.close(); await broker?.close(); if (!broker && developmentRuntime) { await developmentRuntime.runner.close(); await developmentRuntime.gateway.close(); } store?.close(); browserAuthStore?.close(); key.fill(0); await lock.close();
    process.off("SIGTERM", stop); process.off("SIGINT", stop);
  }
  if (failed) throw new Error("Child stopped unexpectedly");
}

/** Explicit local-owner setup; uses the same preview, persistence and audit path as browser consent. */
async function grantPersistentBrowserAccess(root: string, requestId: string): Promise<void> {
  assertPrivateDirectory(root);
  const data = join(root, "personal");
  const lock = await BrokerServiceInstanceLock.acquire(join(data, "run/service.lock"));
  let store: BrokerStore | undefined;
  let authStore: AuthStore | undefined;
  try {
    const config = configSchema.parse(JSON.parse(readAuthFile(join(root, "auth/auth-config.json")).toString()));
    if (config.grantProfile !== "g1" && config.grantProfile !== "o1" && config.grantProfile !== "v2") throw new Error("Persistent browser access requires G1, O1 or V2");
    store = openStore(data);
    const verified = await (await policyVerifier(data)).verifyFile(join(data, "policy.json"));
    new PolicyManager(verified.policy, store).restore(verified);
    if (config.grantProfile === "v2") assertV2Policy(verified.policy, config.principalId, config.issuerId,
      developmentPolicyConfiguration(loadPersonalDevelopmentRuntimeConfig(join(data, "development-runtime.json"))));
    else (config.grantProfile === "o1" ? assertO1Policy : assertG1Policy)(verified.policy, config.principalId, config.issuerId);
    if (store.requestRecord(requestId)?.principalId !== config.principalId) throw new Error("Owner preview required");
    authStore = new AuthStore(join(root, "auth"));
    const sessions = new GuiSessionApprovals(store, async () => { throw new Error("Setup cannot issue operations"); }, Date.now, authStore);
    const grant = sessions.start(requestId, true);
    console.log(JSON.stringify({ status: "granted", appId: grant.appId, id: grant.id, duration: "until-revoked" }));
  } finally { authStore?.close(); store?.close(); await lock.close(); }
}

async function main() {
  const [mode, rootArg, detail] = process.argv.slice(2);
  if (!rootArg || process.getuid?.() === 0) throw new Error("Unprivileged owner and root path required");
  const root = await realpath(rootArg);
  if (mode === "init") { if (!detail || !/^[a-f0-9]{7,64}$/u.test(detail)) throw new Error("Snapshot identity required"); await provision(root, detail); }
  else if (mode === "start") await start(root);
  else if (mode === "owner-terminal") {
    if (!detail || !/^[a-f0-9]{7,64}$/u.test(detail) || process.argv[5] !== "--enable") throw new Error("Snapshot identity and explicit --enable required");
    await upgradePersonalOwnerTerminal(root, packageRoot, detail);
    console.log("Personal owner terminal enabled in offline state; reconnect OAuth to grant mac.terminal.exec.");
  }
  else if (mode === "terminal-sessions") {
    if (!detail || process.argv[5] !== "--enable") throw new Error("Source revision and explicit --enable required");
    await upgradePersonalTerminalSessions(root, packageRoot, detail);
    console.log("Owner terminal sessions enabled in offline state; existing OAuth grants keep their scopes and need no reconnect.");
  }
  else if (mode === "terminal-connection") {
    if (!detail || process.argv[5] !== "--enable") throw new Error("Source revision and explicit --enable required");
    await enablePersonalTerminalConnection(root, packageRoot, detail);
    console.log("Independent owner terminal connection enabled at /terminal/mcp; default V2 consent unchanged.");
  }
  else if (mode === "development") {
    if (!detail || !/^[a-f0-9]{7,64}$/u.test(detail) || !process.argv[5] || process.argv[6] !== "--enable") throw new Error("Source revision, private runtime config and explicit --enable required");
    await upgradePersonalDevelopment(root, packageRoot, detail, process.argv[5]);
    console.log("Evidence-verified development gateway enabled; existing OAuth grants retain their original scopes.");
  }
  else if (mode === "browser-access") {
    if (!detail || !/^[A-Za-z0-9._:-]{1,128}$/u.test(detail) || process.argv[5] !== "--until-revoked") {
      throw new Error("Explicit preview ID and --until-revoked required");
    }
    await grantPersistentBrowserAccess(root, detail);
  }
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
      const approvalBridge = detail === "approval-browser" ? createProcessApprovalBrowserBridge() : undefined;
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
