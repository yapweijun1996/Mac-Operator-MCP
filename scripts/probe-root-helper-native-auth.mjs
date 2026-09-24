import assert from "node:assert/strict";
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { constants, closeSync, openSync } from "node:fs";
import { mkdtemp, mkdir, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { spawn } from "node:child_process";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import {
  createRootHelperSnapshotResponseProof,
  InMemoryRootHelperSnapshotAuthorityReplayGuard,
  RootHelperSnapshotAuthorityIpcServer,
  sendDescriptorHandoff
} from "@mac-operator/broker";
import { canonicalJson, sha256 } from "@mac-operator/contracts";

assert.equal(process.platform, "darwin", "This probe requires macOS");

const nativePath = join(process.cwd(), "packages/broker/dist/root_helper_snapshot");
const requestDomain = "mac-operator-root-helper-snapshot-v0.1\0";
const MAX_CHILD_OUTPUT_BYTES = 64 * 1024;
const MAX_RESPONSE_BYTES = 256 * 1024;
const CHILD_TIMEOUT_MS = 15_000;
const directory = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-auth-"));
const canonicalDirectory = await realpath(directory);
const canonicalTmpdir = await realpath(tmpdir());

function signedEnvelope(key, forged, executableDigest, args, { stale = false, tamperedDigest = false, malformedRequestId = false, forgedAttestation = false } = {}) {
  const now = Date.now();
  const issuedAtMs = stale ? now - 31_000 : now;
  const expiresAtMs = stale ? now - 1_000 : now + 30_000;
  const environment = { LANG: "C" };
  const payload = {
    schemaVersion: "0.1",
    audience: "mac-operator-descriptor-helper-v0.1",
    snapshotRef: `snapshot:${"a".repeat(48)}`,
    profile: "probe.echo",
    taskDescriptorDigest: "0".repeat(64),
    argsDigest: sha256(canonicalJson(args)),
    environmentDigest: sha256(canonicalJson(environment)),
    filesystemRootsDigest: "0".repeat(64),
    sandboxProfile: "task-deny-default-v0.1",
    networkPolicy: "none",
    processTreePolicy: "single_process",
    credentialPolicy: "none",
    immutableSelection: "revalidation-only",
    executableContentSha256: executableDigest,
    executableIdentityDigest: "0".repeat(64),
    cwdIdentityDigest: "0".repeat(64)
  };
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const signaturePrivateKey = forgedAttestation ? generateKeyPairSync("ed25519").privateKey : privateKey;
  const unsignedAttestation = {
    schemaVersion: "0.1",
    keyId: "native-auth-probe",
    algorithm: "Ed25519",
    issuedAtMs,
    expiresAtMs,
    payloadDigest: tamperedDigest ? "f".repeat(64) : sha256(canonicalJson(payload)),
    payload
  };
  const unsigned = {
    schemaVersion: "0.1",
    mechanism: "darwin-root-helper-snapshot-v1",
    requestId: malformedRequestId ? "snapshot-request:bad" : "snapshot-request:native-auth-probe-1234567890",
    timestampMs: issuedAtMs,
    expiresAtMs,
    signedAttestation: {
      ...unsignedAttestation,
      signature: sign(null, Buffer.from(canonicalJson(unsignedAttestation), "utf8"), signaturePrivateKey).toString("base64")
    },
    args,
    environment,
    timeoutMs: 1_000,
    outputCapBytes: 1_024
  };
  const proof = createHmac("sha256", key)
    .update(requestDomain, "utf8")
    .update(sha256(canonicalJson(unsigned)), "utf8")
    .digest("hex");
  const authenticationProof = forged ? `${proof.slice(0, -1)}${proof.endsWith("0") ? "1" : "0"}` : proof;
  return {
    unsigned,
    signed: { ...unsigned, authenticationProof },
    attestationPublicKey: publicKey.export({ format: "der", type: "spki" }).subarray(-32)
  };
}

async function connectWithRetry(socketPath, child, readStderr) {
  for (let attempt = 0; attempt < 200; attempt += 1) {
    if (child.exitCode !== null) throw new Error(`Native auth probe exited before connect: ${child.exitCode}; ${readStderr()}`);
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
      if (!(["ENOENT", "ECONNREFUSED"].includes(error?.code))) throw error;
      await delay(10);
    }
  }
  throw new Error("Native auth probe socket did not become available");
}

async function runCase({ forged = false, stale = false, tamperedDigest = false, malformedRequestId = false, forgedAttestation = false, execute = false, authority = false, authorityDenyAfter, executablePath = "/usr/bin/true", args = ["--native-auth-probe"], label }) {
  const key = randomBytes(32);
  const socketPath = join(canonicalTmpdir, `mop-auth-${process.pid}-${label}.sock`);
  const authoritySocketPath = join(canonicalTmpdir, `mop-authority-${process.pid}-${label}.sock`);
  const keyPath = join(canonicalDirectory, `${label}.key`);
  const configPath = join(canonicalDirectory, `${label}-config.json`);
  const authorityKey = authority ? randomBytes(32) : undefined;
  const authorityKeyPath = join(canonicalDirectory, `${label}-authority.key`);
  const authorityConfigPath = join(canonicalDirectory, `${label}-authority-config.json`);
  const attestationKeyPath = join(canonicalDirectory, `${label}-attestation.pub`);
  const attestationConfigPath = join(canonicalDirectory, `${label}-attestation-config.json`);
  const snapshotRoot = join(canonicalDirectory, `${label}-snapshots`);
  const now = Date.now();
  const executableDigest = createHash("sha256").update(await readFile(executablePath)).digest("hex");
  await writeFile(keyPath, key, { mode: 0o600 });
  await mkdir(snapshotRoot, { mode: 0o700 });
  await writeFile(configPath, `${canonicalJson({
    schemaVersion: "0.1",
    revision: 1,
    keys: [{
      keyId: "native-auth-probe",
      keySource: "file",
      path: keyPath,
      keyDigest: sha256(key),
      notBeforeMs: now - 1_000,
      expiresAtMs: now + 30_000
    }]
  })}\n`, { mode: 0o600 });
  if (authorityKey !== undefined) {
    await writeFile(authorityKeyPath, authorityKey, { mode: 0o600 });
    await writeFile(authorityConfigPath, `${canonicalJson({
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        keyId: "native-authority-probe",
        keySource: "file",
        path: authorityKeyPath,
        keyDigest: sha256(authorityKey),
        notBeforeMs: now - 1_000,
        expiresAtMs: now + 30_000
      }]
    })}\n`, { mode: 0o600 });
  }
  const { unsigned, signed, attestationPublicKey } = signedEnvelope(key, forged, executableDigest, args, { stale, tamperedDigest, malformedRequestId, forgedAttestation });
  await writeFile(attestationKeyPath, attestationPublicKey, { mode: 0o600 });
  await writeFile(attestationConfigPath, `${canonicalJson({
    schemaVersion: "0.1",
    revision: 1,
    keys: [{
      keyId: "native-auth-probe",
      path: attestationKeyPath,
      publicKeyDigest: sha256(attestationPublicKey),
      notBeforeMs: now - 1_000,
      expiresAtMs: now + 30_000
    }]
  })}\n`, { mode: 0o600 });
  let authorityServer;
  if (authorityKey !== undefined) {
    const expectedRequestDigest = sha256(canonicalJson(signed));
    let authorityPollCount = 0;
    authorityServer = new RootHelperSnapshotAuthorityIpcServer({
      socketPath: authoritySocketPath,
      authenticationKey: authorityKey,
      replayGuard: new InMemoryRootHelperSnapshotAuthorityReplayGuard(),
      authorizeRequest: (requestDigest) => {
        authorityPollCount += 1;
        if (requestDigest !== expectedRequestDigest) throw new Error("unexpected native authority request digest");
        if (authorityDenyAfter !== undefined && authorityPollCount > authorityDenyAfter) throw new Error("probe authority revoked");
      },
      peerPolicy: {
        expectedUid: process.getuid?.() ?? 1,
        ...(process.getgid === undefined ? {} : { expectedGid: process.getgid() })
      }
    });
    await authorityServer.listen();
  }
  const mode = authority ? "--probe-execute-authority-config" : execute ? "--probe-execute-config" : "--probe-server-config";
  const childArgs = authority
    ? [mode, socketPath, configPath, attestationConfigPath, snapshotRoot, authoritySocketPath, authorityConfigPath]
    : [mode, socketPath, configPath, attestationConfigPath, snapshotRoot];
  const child = spawn(nativePath, childArgs, {
    cwd: canonicalDirectory,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" },
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
  assert.equal(Number.isSafeInteger(descriptor), true, "Probe socket descriptor must be available");
  const executableFd = openSync(executablePath, constants.O_RDONLY | constants.O_CLOEXEC);
  const cwdFd = openSync(snapshotRoot, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_CLOEXEC);
  try {
    sendDescriptorHandoff(descriptor, Buffer.from(JSON.stringify(signed), "utf8"), [executableFd, cwdFd]);
  } finally {
    closeSync(executableFd);
    closeSync(cwdFd);
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
    throw new Error("Root-helper native auth probe exceeded its bounded process limits");
  }
  const exitCode = exitResult.code;
  if (authorityServer !== undefined) await authorityServer.close();
  authorityKey?.fill(0);
  if (forged || stale || tamperedDigest || malformedRequestId || forgedAttestation) {
    assert.equal(exitCode, 1);
    assert.equal(responseBytes.byteLength, 0);
    if (forged) return "forged_request_rejected";
    if (stale) return "stale_request_rejected";
    if (tamperedDigest) return "attestation_digest_rejected";
    if (forgedAttestation) return "attestation_signature_rejected";
    return "malformed_request_id_rejected";
  }
  assert.equal(exitCode, 0, stderr);
  const nativeSummary = JSON.parse(stdout);
  assert.equal(nativeSummary.snapshotMaterialization, "verified");
  const response = JSON.parse(responseBytes.toString("utf8"));
  assert.equal(response.requestId, unsigned.requestId);
  const body = { ...response };
  delete body.responseProof;
  assert.equal(response.responseProof, createRootHelperSnapshotResponseProof(unsigned, body, key));
  if (execute) {
    if (authorityDenyAfter !== undefined) {
      assert.equal(nativeSummary.execution, "authority_denied_or_lost");
      assert.equal(response.ok, false);
      assert.equal(response.resultClass, "UNKNOWN_OUTCOME");
      return { authority: "revocation_fail_closed_verified" };
    }
    assert.equal(nativeSummary.execution, authority ? "verified_with_authority_poll" : "verified");
    assert.equal(response.ok, true);
    assert.equal(response.result.state, "completed", JSON.stringify({ response, nativeSummary, stderr }));
    assert.equal(response.result.resultClass, "SUCCEEDED");
    assert.equal(response.result.exitCode, 0);
    assert.equal(response.result.signal, null);
    assert.match(response.result.stdout, /root-helper-native-roundtrip/);
    assert.equal(response.result.stderr, "");
    assert.equal(response.result.processGroupId, response.result.processId);
    assert.equal(response.result.terminationObserved, true);
    return {
      execution: "bounded_sandbox_child_verified",
      authority: authority ? "native_peer_hmac_poll_verified" : "not_attempted",
      snapshotMaterialization: nativeSummary.snapshotMaterialization
    };
  }
  assert.equal(response.ok, false);
  assert.equal(response.resultClass, "POLICY_DENIED");
  return {
    requestHmac: "authenticated_failure_response_verified",
    snapshotMaterialization: nativeSummary.snapshotMaterialization
  };
}

try {
  const valid = await runCase({ label: "valid" });
  const execution = await runCase({
    execute: true,
    authority: true,
    executablePath: nativePath,
    args: ["--self-test"],
    label: "execution"
  });
  const authorityLoss = await runCase({
    execute: true,
    authority: true,
    authorityDenyAfter: 1,
    executablePath: nativePath,
    args: ["--self-test"],
    label: "authority-loss"
  });
  const stale = await runCase({ stale: true, label: "stale" });
  const tamperedDigest = await runCase({ tamperedDigest: true, label: "tampered-digest" });
  const malformedRequestId = await runCase({ malformedRequestId: true, label: "malformed-request-id" });
  const forgedAttestation = await runCase({ forgedAttestation: true, label: "forged-attestation" });
  const forged = await runCase({ forged: true, label: "forged" });
  console.log(JSON.stringify({
    probe: "root-helper-native-auth-roundtrip",
    request_hmac: valid.requestHmac,
    snapshot_materialization: valid.snapshotMaterialization,
    native_execution: execution.execution,
    authority_poll: execution.authority,
    authority_revocation: authorityLoss.authority,
    freshness: stale,
    attestation_digest: tamperedDigest,
    attestation_signature: forgedAttestation,
    request_id: malformedRequestId,
    forged_hmac: forged,
    production_execution: "disabled"
  }, null, 2));
} finally {
  await rm(directory, { recursive: true, force: true });
}
