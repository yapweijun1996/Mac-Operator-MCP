#!/usr/bin/env node
import { createPrivateKey, generateKeyPairSync, randomBytes, createHash } from "node:crypto";
import { constants, closeSync, fstatSync, fsyncSync, mkdirSync, openSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { resolve, join, dirname } from "node:path";
import { pathToFileURL } from "node:url";
import { createServer } from "node:https";
import { parseEnv } from "node:util";
import { configSchema, G1_TOOLS, O1_TOOLS, READ_TOOLS, W1_TOOLS, scopesForGrantProfile, type AuthConfig, type GrantProfile } from "./contracts.js";
import { assertPrivateDirectory, assertPrivateFile, AuthStore, type GrantRevocationListener } from "./store.js";
import { createPassword } from "./password.js";
import { createAuthApp } from "./app.js";
import type { ApprovalBrowserBridge } from "./approval-browser-bridge.js";
import { buildR1TargetRules, r1FilesystemRoots } from "./r1-policy.js";
import { buildO1TargetRules, buildG1TargetRules, buildW1TargetRules, w1FilesystemRoots, w1ProjectRoot } from "./w1-policy.js";

export const usage = `mac-operator-auth init --dir PATH --username NAME --redirect-uri HTTPS_URL [--issuer HTTPS_ORIGIN] [--port 3444] [--grant-profile r1|w1|g1|o1|d1]
mac-operator-auth init --dir PATH --env-file PATH --redirect-uri HTTPS_URL [--issuer HTTPS_ORIGIN] [--port 3444] [--grant-profile r1|w1|g1|o1|d1]
mac-operator-auth serve --dir PATH --tls-cert PATH --tls-key PATH
mac-operator-auth reset-password --dir PATH
mac-operator-auth revoke-all --dir PATH

init requires a new directory under an existing owner-controlled parent.
Passwords are read from a hidden terminal prompt or an explicit owner-only .env file.
The .env file must define MAC_OPERATOR_USERNAME and MAC_OPERATOR_PASSWORD.
TLS files must be owner-only files outside the repository. No tunnel is created.`;

function saveExclusive(path: string, value: string | Buffer): void {
  const fd = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeFileSync(fd, value); fsyncSync(fd); } finally { closeSync(fd); }
  const parent = openSync(dirname(path), constants.O_RDONLY);
  try { fsyncSync(parent); } finally { closeSync(parent); }
}

export function readAuthFile(path: string, maxBytes = 65536, requirePrivateParent = true): Buffer {
  if (requirePrivateParent) assertPrivateDirectory(dirname(path));
  assertPrivateFile(path);
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.nlink !== 1 || before.uid !== process.getuid?.() || (before.mode & 0o077) !== 0 || before.size > maxBytes) throw new Error("Invalid protected file");
    const bytes = readFileSync(fd);
    const after = fstatSync(fd);
    if (bytes.length !== after.size || bytes.length > maxBytes || before.ino !== after.ino || before.dev !== after.dev ||
        before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) { bytes.fill(0); throw new Error("Protected file changed"); }
    return bytes;
  } finally { closeSync(fd); }
}

async function passwordPrompt(label: string): Promise<string> {
  if (!process.stdin.isTTY || !process.stdout.isTTY) throw new Error("Interactive terminal required");
  process.stdout.write(label);
  const wasRaw = process.stdin.isRaw;
  process.stdin.setRawMode(true);
  process.stdin.resume();
  return new Promise((resolvePassword, reject) => {
    const bytes: number[] = [];
    const finish = (error?: Error) => {
      process.stdin.removeListener("data", onData);
      process.stdin.setRawMode(wasRaw);
      process.stdin.pause();
      process.stdout.write("\n");
      const buffer = Buffer.from(bytes);
      bytes.fill(0);
      if (error) reject(error); else resolvePassword(buffer.toString("utf8"));
      buffer.fill(0);
    };
    const onData = (chunk: Buffer) => {
      for (const byte of chunk) {
        if (byte === 3 || byte === 4) { finish(new Error("Cancelled")); return; }
        if (byte === 13 || byte === 10) { finish(); return; }
        if (byte === 127 || byte === 8) { bytes.pop(); continue; }
        if (byte < 32) continue;
        bytes.push(byte);
        if (bytes.length > 1024) { finish(new Error("Password too long")); return; }
      }
    };
    process.stdin.on("data", onData);
  });
}

async function newPassword() {
  const password = await passwordPrompt("Password (14+ characters): ");
  const confirmation = await passwordPrompt("Repeat password: ");
  if (password !== confirmation) throw new Error("Passwords do not match");
  return createPassword(password);
}

export async function runAuthCli(args: string[], runtime: { approvalBridge?: ApprovalBrowserBridge; onGrantRevoked?: GrantRevocationListener } = {}): Promise<void> {
  const command = args[0];
  if (command === "--help" || args.length === 0) { process.stdout.write(`${usage}\n`); return; }
  if (!["init", "serve", "reset-password", "revoke-all"].includes(command!)) throw new Error("Unknown command");
  const options = new Map<string, string>();
  const allowed = command === "init" ? ["--dir", "--username", "--env-file", "--redirect-uri", "--issuer", "--port", "--grant-profile"] :
    command === "serve" ? ["--dir", "--tls-cert", "--tls-key"] : ["--dir"];
  for (let i = 1; i < args.length; i += 2) {
    if (!allowed.includes(args[i]!) || options.has(args[i]!) || !args[i + 1] || args[i + 1]!.startsWith("--")) throw new Error("Invalid command options");
    options.set(args[i]!, args[i + 1]!);
  }
  if (!options.get("--dir")) throw new Error("Directory required");
  const directory = resolve(options.get("--dir")!);
  if (command === "init") {
    let envCredentials: Record<string, string | undefined> | undefined;
    if (options.has("--env-file")) {
      if (options.has("--username")) throw new Error("Choose either env-file or interactive credentials");
      // Parse data without shell evaluation or exporting secrets to child processes.
      const bytes = readAuthFile(resolve(options.get("--env-file")!), 8192, false);
      try { envCredentials = parseEnv(bytes.toString("utf8")); } finally { bytes.fill(0); }
    }
    const username = envCredentials?.MAC_OPERATOR_USERNAME ?? options.get("--username") ?? "";
    if (!/^[A-Za-z0-9._-]{1,64}$/u.test(username)) throw new Error("Valid username required");
    const grantProfileValue = options.get("--grant-profile") ?? "r1";
    if (grantProfileValue !== "r1" && grantProfileValue !== "w1" && grantProfileValue !== "g1" && grantProfileValue !== "d1" && grantProfileValue !== "o1") throw new Error("Grant profile must be r1, w1, g1, o1, or d1");
    const grantProfile = grantProfileValue as GrantProfile;
    const issuer = new URL(options.get("--issuer") ?? "https://mac.yapweijun1996.com/").href;
    const config: AuthConfig = configSchema.parse({ version: 1, issuer, resource: new URL("/mcp", issuer).href,
      issuerId: "mac-operator-auth", principalId: `owner-${randomBytes(16).toString("hex")}`, keyId: `signing-${randomBytes(8).toString("hex")}`,
      port: Number(options.get("--port") ?? 3444), allowedRedirectUris: [options.get("--redirect-uri")], grantProfile });
    let password: Awaited<ReturnType<typeof createPassword>>;
    try { password = envCredentials ? await createPassword(envCredentials.MAC_OPERATOR_PASSWORD ?? "") : await newPassword(); }
    finally { if (envCredentials) { for (const key of Object.keys(envCredentials)) delete envCredentials[key]; } }
    const projectRoot = realpathSync(process.env.MAC_OPERATOR_PROJECT_ROOT ?? process.cwd());
    const filesystemRoots = grantProfile === "w1" || grantProfile === "g1" || grantProfile === "o1" ? w1FilesystemRoots(w1ProjectRoot(projectRoot)) : r1FilesystemRoots();
    // mkdir without recursive/exist-ok prevents accidental account replacement.
    mkdirSync(directory, { mode: 0o700 });
    assertPrivateDirectory(directory);
    const keys = generateKeyPairSync("ec", { namedCurve: "P-256" });
    saveExclusive(join(directory, "signing.key"), keys.privateKey.export({ type: "pkcs8", format: "pem" }));
    const statusKey = randomBytes(32);
    try {
      saveExclusive(join(directory, "status.key"), statusKey);
      saveExclusive(join(directory, "auth-config.json"), JSON.stringify(config, null, 2) + "\n");
      const store = new AuthStore(directory, true);
      try { store.put("account", "owner", { username, ...password, principalId: config.principalId }); }
      finally { store.close(); }
      saveExclusive(join(directory, "edge-auth-settings.json"), JSON.stringify({
        oauthIssuer: issuer, issuerId: config.issuerId, resourceServerUrl: config.resource, grantProfile: config.grantProfile,
        oauthScopes: scopesForGrantProfile(config.grantProfile),
        authorizationEndpoint: new URL("/authorize", issuer).href, tokenEndpoint: new URL("/token", issuer).href,
        jwksUri: new URL("/jwks", issuer).href, oauthStatusUrl: new URL("/oauth/status", issuer).href,
        oauthStatusKeyPath: "REPLACE_WITH_PROTECTED_EDGE_DATA_ROOT/status.key",
        oauthStatusKeyDigest: createHash("sha256").update(statusKey).digest("hex")
      }, null, 2) + "\n");
      saveExclusive(join(directory, "broker-policy-input.json"), JSON.stringify({
        principal: { principal_id: config.principalId, issuer: config.issuerId, scopes: scopesForGrantProfile(config.grantProfile), enabled: true },
        target_rules: grantProfile === "w1" || grantProfile === "g1" || grantProfile === "o1"
          ? grantProfile === "o1" ? buildO1TargetRules(config.principalId, filesystemRoots, projectRoot) : grantProfile === "g1" ? buildG1TargetRules(config.principalId, filesystemRoots, projectRoot) : buildW1TargetRules(config.principalId, filesystemRoots, projectRoot)
          : buildR1TargetRules(config.principalId, filesystemRoots, projectRoot),
        enabled_tools: grantProfile === "o1" ? O1_TOOLS : grantProfile === "g1" ? G1_TOOLS : grantProfile === "w1" ? W1_TOOLS : READ_TOOLS,
        filesystem_roots: filesystemRoots
      }, null, 2) + "\n");
    } finally { statusKey.fill(0); }
    process.stdout.write("Owner account provisioned. Review generated settings before assembling signed Broker policy and Edge configuration. No service was started.\n");
    return;
  }
  const configBytes = readAuthFile(join(directory, "auth-config.json"));
  let config: AuthConfig;
  try { config = configSchema.parse(JSON.parse(configBytes.toString("utf8"))); } finally { configBytes.fill(0); }
  const store = new AuthStore(directory);
  if (command !== "serve") {
    try {
      if (command === "reset-password") {
        const password = await newPassword();
        const owner = store.get("account", "owner");
        if (!owner) throw new Error("Owner unavailable");
        store.transaction(() => { store.put("account", "owner", { ...owner, ...password }); store.revokeAll(); });
      } else store.transaction(() => store.revokeAll());
      process.stdout.write("All browser sessions and OAuth grants revoked.\n");
    } finally { store.close(); }
    return;
  }
  const buffers: Buffer[] = [];
  try {
    const load = (path: string, maxBytes?: number) => { const bytes = readAuthFile(path, maxBytes); buffers.push(bytes); return bytes; };
    if (!options.get("--tls-cert") || !options.get("--tls-key")) throw new Error("Protected TLS certificate and key required");
    const signingKey = createPrivateKey(load(join(directory, "signing.key")));
    if (signingKey.asymmetricKeyType !== "ec" || signingKey.asymmetricKeyDetails?.namedCurve !== "prime256v1") throw new Error("ES256 key required");
    const statusKey = load(join(directory, "status.key"), 32);
    const { app } = await createAuthApp({ config, store, signingKey, statusKey, ...runtime });
    const server = createServer({ cert: load(resolve(options.get("--tls-cert")!)), key: load(resolve(options.get("--tls-key")!)), minVersion: "TLSv1.3" }, app);
    server.requestTimeout = 15000; server.headersTimeout = 10000; server.keepAliveTimeout = 5000; server.maxRequestsPerSocket = 100;
    await new Promise<void>((resolveListen, reject) => { server.once("error", reject); server.listen(config.port, "127.0.0.1", resolveListen); });
    process.stdout.write(`Auth listener ready on loopback port ${config.port}. Public routing remains operator-managed.\n`);
    await new Promise<void>(resolveStop => {
      const stop = () => {
        process.off("SIGINT", stop); process.off("SIGTERM", stop);
        server.close(() => resolveStop()); server.closeAllConnections();
      };
      process.on("SIGINT", stop); process.on("SIGTERM", stop);
    });
  } finally { for (const buffer of buffers) buffer.fill(0); store.close(); }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  runAuthCli(process.argv.slice(2)).catch(() => {
    // Do not print exception payloads: parsers can include submitted secrets.
    process.stderr.write("Auth command failed. Check options, protected files, and runtime prerequisites; no credentials were printed.\n");
    process.exitCode = 1;
  });
}
