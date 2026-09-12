import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { connect } from "node:net";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { sha256 } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";
import {
  PolicySignerKeyManager,
  writePolicySignerKeyConfig,
  type PolicySignerKeyConfig
} from "./policy-signer-keyring.js";
import {
  PolicySignerIpcServer,
  signPolicySignerCommand,
  type PolicySignerIpcResponse,
  type UnsignedPolicySignerCommand
} from "./policy-signer-ipc.js";

const NOW = 1_700_000_000_000;
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function publicKeyDigest(publicKey: ReturnType<typeof generateKeyPairSync>["publicKey"]): string {
  return sha256(Buffer.from(publicKey.export({ type: "spki", format: "pem" })));
}

function configEntry(keyId: string, path: string, digest: string, notBeforeMs = NOW - 1_000, expiresAtMs = NOW + 60_000) {
  return { keyId, path, publicKeyDigest: digest, notBeforeMs, expiresAtMs } as const;
}

function command(
  operation: UnsignedPolicySignerCommand["operation"],
  sequence: number,
  fields: Omit<UnsignedPolicySignerCommand, "protocolVersion" | "requestId" | "nonce" | "nonceExpiresAtMs" | "timestampMs" | "operation"> = {}
): UnsignedPolicySignerCommand {
  return {
    protocolVersion: "0.1",
    requestId: `operator-command-${sequence}`,
    nonce: `operator-nonce-${String(sequence).padStart(16, "0")}`,
    nonceExpiresAtMs: NOW + 30_000,
    timestampMs: NOW,
    operation,
    ...fields
  };
}

async function sendCommand(socketPath: string, payload: unknown): Promise<PolicySignerIpcResponse> {
  return new Promise((resolvePromise, reject) => {
    const socket = connect(socketPath);
    let chunks: Buffer[] = [];
    socket.once("error", reject);
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      socket.destroy();
      try {
        resolvePromise(JSON.parse(combined.subarray(0, newline).toString("utf8")) as PolicySignerIpcResponse);
      } catch (error) {
        reject(error);
      }
    });
    socket.on("close", () => {
      if (chunks.length === 0) reject(new Error("Policy signer IPC closed without a response"));
    });
    socket.on("connect", () => socket.write(`${JSON.stringify(payload)}\n`));
  });
}

test("policy signer IPC authenticates, rejects replay, and performs audited operator lifecycle", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mopsi-"));
  const configPath = join(directory, "policy-signers.json");
  const socketPath = join(directory, "policy-signer.sock");
  const firstPath = join(directory, "policy-key-1.pem");
  const secondPath = join(directory, "policy-key-2.pem");
  const first = generateKeyPairSync("ed25519");
  const second = generateKeyPairSync("ed25519");
  const authenticationKey = randomBytes(32);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const manager = new PolicySignerKeyManager(configPath, join(repositoryRoot, "schemas"), store, () => NOW);
  const server = new PolicySignerIpcServer({
    socketPath,
    manager,
    store,
    authenticationKey,
    peerCredentialVerifier: { verify() { return { uid: 1, gid: 1, pid: 1 }; } },
    now: () => NOW
  });
  try {
    await writeFile(firstPath, first.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    await writeFile(secondPath, second.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    const firstConfig: PolicySignerKeyConfig = {
      schemaVersion: "0.1", revision: 1,
      keys: [configEntry("policy-key-1", firstPath, publicKeyDigest(first.publicKey))]
    };
    const secondConfig: PolicySignerKeyConfig = {
      schemaVersion: "0.1", revision: 2,
      keys: [
        configEntry("policy-key-1", firstPath, publicKeyDigest(first.publicKey)),
        configEntry("policy-key-2", secondPath, publicKeyDigest(second.publicKey), NOW, NOW + 120_000)
      ]
    };
    await writePolicySignerKeyConfig(configPath, firstConfig);
    await manager.activate();
    await server.listen();

    await writePolicySignerKeyConfig(configPath, secondConfig);
    const reload = command("reload", 1, { expectedPreviousRevision: 1 });
    const reloadResponse = await sendCommand(socketPath, signPolicySignerCommand(reload, authenticationKey));
    assert.deepEqual(reloadResponse, { ok: true, operation: "reload", revision: 2 });
    const replayResponse = await sendCommand(socketPath, signPolicySignerCommand(reload, authenticationKey));
    assert.equal(replayResponse.ok, false);
    if (!replayResponse.ok) assert.equal(replayResponse.result_class, "REPLAY_DENIED");

    const wrongProof = signPolicySignerCommand(command("revoke", 2, { keyId: "policy-key-1", reason: "COMPROMISED" }), randomBytes(32));
    const wrongResponse = await sendCommand(socketPath, wrongProof);
    assert.equal(wrongResponse.ok, false);
    if (!wrongResponse.ok) assert.equal(wrongResponse.result_class, "AUTH_INVALID");

    const revoke = command("revoke", 3, { keyId: "policy-key-1", reason: "COMPROMISED" });
    const revokeResponse = await sendCommand(socketPath, signPolicySignerCommand(revoke, authenticationKey));
    assert.deepEqual(revokeResponse, { ok: true, operation: "revoke", revision: 2, key_id: "policy-key-1" });

    await writePolicySignerKeyConfig(configPath, firstConfig);
    const rollback = command("rollback", 4, { expectedCurrentRevision: 2, reasonCode: "OPERATOR_RECOVERY" });
    const rollbackResponse = await sendCommand(socketPath, signPolicySignerCommand(rollback, authenticationKey));
    assert.deepEqual(rollbackResponse, { ok: true, operation: "rollback", revision: 1 });
    assert.equal(store.activePolicySignerConfigIdentity()?.revision, 1);
    assert.equal(store.isRevoked("policy_signer", "policy-key-1"), true);
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy signer IPC drops a denied peer before parsing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mopsi-deny-"));
  const socketPath = join(directory, "policy-signer.sock");
  const configPath = join(directory, "policy-signers.json");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const server = new PolicySignerIpcServer({
    socketPath,
    manager: new PolicySignerKeyManager(configPath, join(repositoryRoot, "schemas"), store, () => NOW),
    store,
    authenticationKey: randomBytes(32),
    peerCredentialVerifier: { verify() { throw new Error("denied"); } },
    now: () => NOW
  });
  try {
    await server.listen();
    await new Promise<void>((resolvePromise, reject) => {
      const socket = connect(socketPath);
      socket.once("error", (error: NodeJS.ErrnoException) => {
        if (error.code === "EPIPE" || error.code === "ECONNRESET") resolvePromise();
        else reject(error);
      });
      socket.once("close", () => resolvePromise());
      socket.on("connect", () => socket.write("not-json\n"));
    });
    assert.deepEqual(store.auditRows(), []);
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
