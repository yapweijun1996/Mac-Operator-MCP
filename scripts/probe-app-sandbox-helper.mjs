import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { constants, openSync, closeSync, existsSync } from "node:fs";
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { connect } from "node:net";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { sendDescriptorHandoff } from "@mac-operator/broker";
import { canonicalJson, sha256 } from "@mac-operator/contracts";

assert.equal(process.platform, "darwin", "This probe requires macOS");

const nativePath = join(process.cwd(), "packages/broker/dist/AppSandboxHelper.app/Contents/MacOS/app_sandbox_helper");
const bundleIdentifier = "com.macoperator.mopappsandboxhelper";
const containerRoot = join(homedir(), "Library/Containers", bundleIdentifier, "Data");
const probeRoot = join(containerRoot, "Probe");
const outsideTarget = join(tmpdir(), `mop-app-sandbox-helper-outside-${process.pid}.txt`);
const requestDomain = "mac-operator-app-sandbox-helper-v0.1\0";
const responseDomain = "mac-operator-app-sandbox-helper-response-v0.1\0";
const MAX_CHILD_OUTPUT_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const CHILD_TIMEOUT_MS = 15_000;

await mkdir(probeRoot, { recursive: true, mode: 0o700 });
await rm(outsideTarget, { force: true });

async function connectWithRetry(socketPath, child, readStderr) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`App Sandbox helper exited before connect: ${child.exitCode}; ${readStderr()}`);
    try {
      return await new Promise((resolve, reject) => {
        const socket = connect(socketPath);
        const onError = (error) => { socket.destroy(); reject(error); };
        socket.once("error", onError);
        socket.once("connect", () => {
          socket.removeListener("error", onError);
          resolve(socket);
        });
      });
    } catch (error) {
      if (!(error?.code === "ENOENT" || error?.code === "ECONNREFUSED")) throw error;
      await delay(10);
    }
  }
  throw new Error("App Sandbox helper socket did not become available");
}

async function runCase(label, args, expectedClass) {
  const key = randomBytes(32);
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const now = Date.now();
  const socketPath = join(probeRoot, `${label}.sock`);
  const keyPath = join(probeRoot, `${label}.key`);
  const configPath = join(probeRoot, `${label}-config.json`);
  const attestationKeyPath = join(probeRoot, `${label}-attestation.pub`);
  const attestationConfigPath = join(probeRoot, `${label}-attestation-config.json`);
  const scriptPath = join(probeRoot, `${label}.sh`);
  const script = "#!/bin/sh\nset -eu\n: > \"$1\"\n";
  await writeFile(scriptPath, script, { mode: 0o700 });
  const executablePath = "/bin/sh";
  const executableDigest = createHash("sha256").update(await readFile(executablePath)).digest("hex");
  const scriptDigest = createHash("sha256").update(script).digest("hex");
  const environment = { LANG: "C" };
  const payload = {
    schemaVersion: "0.1",
    audience: "mac-operator-app-sandbox-helper-v0.1",
    snapshotRef: `snapshot:${"b".repeat(48)}`,
    profile: "probe.app-sandbox",
    taskDescriptorDigest: "0".repeat(64),
    argsDigest: sha256(canonicalJson(args)),
    environmentDigest: sha256(canonicalJson(environment)),
    filesystemRootsDigest: "0".repeat(64),
    sandboxProfile: "app-sandbox-deny-default-v0.1",
    networkPolicy: "none",
    processTreePolicy: "single_process",
    credentialPolicy: "none",
    immutableSelection: "revalidation-only",
    executableContentSha256: executableDigest,
    executableIdentityDigest: "0".repeat(64),
    cwdIdentityDigest: "0".repeat(64)
  };
  const unsignedAttestation = {
    schemaVersion: "0.1",
    keyId: "app-sandbox-helper-probe",
    algorithm: "Ed25519",
    issuedAtMs: now,
    expiresAtMs: now + 30_000,
    payloadDigest: sha256(canonicalJson(payload)),
    payload
  };
  const signedAttestation = {
    ...unsignedAttestation,
    signature: sign(null, Buffer.from(canonicalJson(unsignedAttestation), "utf8"), privateKey).toString("base64")
  };
  const unsigned = {
    schemaVersion: "0.1",
    mechanism: "darwin-app-sandbox-helper-v1",
    requestId: `snapshot-request:app-sandbox-${label}-1234567890`,
    timestampMs: now,
    expiresAtMs: now + 30_000,
    signedAttestation,
    executionKind: "posix-sh-script",
    scriptContentSha256: scriptDigest,
    args,
    environment,
    timeoutMs: 1_000,
    outputCapBytes: 1_024
  };
  const authenticationProof = createHmac("sha256", key)
    .update(requestDomain, "utf8")
    .update(sha256(canonicalJson(unsigned)), "utf8")
    .digest("hex");
  const signed = { ...unsigned, authenticationProof };
  const attestationPublicKey = publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  await writeFile(keyPath, key, { mode: 0o600 });
  await writeFile(attestationKeyPath, attestationPublicKey, { mode: 0o600 });
  await writeFile(configPath, `${canonicalJson({
    schemaVersion: "0.1",
    revision: 1,
    keys: [{
      keyId: "app-sandbox-helper-probe",
      keySource: "file",
      path: keyPath,
      keyDigest: sha256(key),
      notBeforeMs: now - 1_000,
      expiresAtMs: now + 30_000
    }]
  })}\n`, { mode: 0o600 });
  await writeFile(attestationConfigPath, `${canonicalJson({
    schemaVersion: "0.1",
    revision: 1,
    keys: [{
      keyId: "app-sandbox-helper-probe",
      path: attestationKeyPath,
      publicKeyDigest: sha256(attestationPublicKey),
      notBeforeMs: now - 1_000,
      expiresAtMs: now + 30_000
    }]
  })}\n`, { mode: 0o600 });

  const child = spawn(nativePath, ["--probe-app-sandbox-config", socketPath, configPath, attestationConfigPath, probeRoot], {
    cwd: process.cwd(),
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C", HOME: homedir() },
    shell: false,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stderr = "";
  let stdout = "";
  let outputOverflow = false;
  const append = (current, chunk) => {
    const next = `${current}${chunk.toString("utf8")}`;
    if (Buffer.byteLength(next, "utf8") > MAX_CHILD_OUTPUT_BYTES) {
      outputOverflow = true;
      try { child.kill("SIGKILL"); } catch { /* child may already be closed */ }
      return next.slice(0, MAX_CHILD_OUTPUT_BYTES);
    }
    return next;
  };
  child.stderr.on("data", (chunk) => { stderr = append(stderr, chunk); });
  child.stdout.on("data", (chunk) => { stdout = append(stdout, chunk); });
  const socket = await connectWithRetry(socketPath, child, () => stderr);
  const descriptor = socket._handle?.fd;
  assert.equal(Number.isSafeInteger(descriptor), true, "Helper socket descriptor must be available");
  const executableFd = openSync(executablePath, constants.O_RDONLY | constants.O_CLOEXEC);
  const cwdFd = openSync(probeRoot, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_CLOEXEC);
  const scriptFd = openSync(scriptPath, constants.O_RDONLY | constants.O_CLOEXEC);
  try {
    sendDescriptorHandoff(descriptor, Buffer.from(JSON.stringify(signed), "utf8"), [executableFd, cwdFd, scriptFd]);
  } finally {
    closeSync(executableFd);
    closeSync(cwdFd);
    closeSync(scriptFd);
  }
  let responseBytes = Buffer.alloc(0);
  let responseOverflow = false;
  socket.on("data", (chunk) => {
    if (responseBytes.byteLength + chunk.byteLength > MAX_RESPONSE_BYTES) {
      responseOverflow = true;
      socket.destroy();
      try { child.kill("SIGKILL"); } catch { /* child may already be closed */ }
      return;
    }
    responseBytes = Buffer.concat([responseBytes, chunk]);
  });
  await new Promise((resolve, reject) => {
    socket.once("end", resolve);
    socket.once("error", reject);
  });
  const exitResult = await new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      try { child.kill("SIGKILL"); } catch { /* child may already be closed */ }
      resolve({ code: null, timedOut: true });
    }, CHILD_TIMEOUT_MS);
    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, timedOut: false });
    });
  });
  if (outputOverflow || responseOverflow || exitResult.timedOut) {
    throw new Error("App Sandbox helper probe exceeded its bounded process limits");
  }
  const exitCode = exitResult.code;
  assert.equal(exitCode, 0, stderr);
  const nativeSummary = JSON.parse(stdout);
  const frames = responseBytes.toString("utf8").trim().split("\n").map((line) => JSON.parse(line));
  assert.equal(frames.length >= 2, true, "Native helper must emit a process event before the response");
  const processEvent = frames[0];
  assert.equal(processEvent.kind, "process_started");
  assert.equal(processEvent.requestId, unsigned.requestId);
  assert.equal(Number.isSafeInteger(processEvent.snapshot?.identity?.pid), true);
  assert.equal(processEvent.snapshot.identity.processGroupId, processEvent.snapshot.identity.pid);
  assert.deepEqual(processEvent.snapshot.descendants, []);
  const eventBody = { kind: processEvent.kind, requestId: processEvent.requestId, snapshot: processEvent.snapshot };
  const expectedEventProof = createHmac("sha256", key)
    .update(responseDomain, "utf8")
    .update(sha256(canonicalJson(unsigned)), "utf8")
    .update(canonicalJson(eventBody), "utf8")
    .digest("hex");
  assert.equal(processEvent.eventProof, expectedEventProof);
  const response = frames.at(-1);
  const body = { ...response };
  delete body.responseProof;
  const expectedResponseProof = createHmac("sha256", key)
    .update(responseDomain, "utf8")
    .update(sha256(canonicalJson(unsigned)), "utf8")
    .update(canonicalJson(body), "utf8")
    .digest("hex");
  assert.equal(response.responseProof, expectedResponseProof);
  assert.equal(nativeSummary.snapshotMaterialization, "verified");
  assert.equal(response.requestId, unsigned.requestId);
  assert.equal(response.result.resultClass, expectedClass, JSON.stringify({ response, stderr }));
  key.fill(0);
  await Promise.allSettled([
    rm(keyPath, { force: true }),
    rm(configPath, { force: true }),
    rm(attestationKeyPath, { force: true }),
    rm(attestationConfigPath, { force: true }),
    rm(socketPath, { force: true }),
    rm(scriptPath, { force: true })
  ]);
  return { nativeSummary, response };
}

try {
  const allowed = await runCase("allowed", ["allowed-by-app-sandbox.txt"], "SUCCEEDED");
  assert.equal(existsSync(join(probeRoot, "allowed-by-app-sandbox.txt")), true);
  await rm(join(probeRoot, "allowed-by-app-sandbox.txt"), { force: true });
  const denied = await runCase("denied", [outsideTarget], "EXECUTION_FAILED");
  assert.equal(existsSync(outsideTarget), false, "App Sandbox child must not write outside its container");
  console.log(JSON.stringify({
    schema_version: "0.1",
    probe: "macos-app-sandbox-helper-roundtrip",
    app_sandbox_entitlement: true,
    descriptor_handoff: "verified",
    attestation_audience: "verified",
    request_hmac: "verified",
    response_hmac: "verified",
    container_materialization: "verified",
    fixed_interpreter: "/bin/sh",
    script_descriptor: "verified",
    allowed_container_write: allowed.response.result.resultClass === "SUCCEEDED",
    outside_container_write_blocked: denied.response.result.resultClass === "EXECUTION_FAILED" && !existsSync(outsideTarget),
    production_enablement: "disabled"
  }, null, 2));
} finally {
  await rm(outsideTarget, { force: true });
  await rm(probeRoot, { recursive: true, force: true });
}
