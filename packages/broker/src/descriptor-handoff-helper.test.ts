import assert from "node:assert/strict";
import { createHash, generateKeyPairSync } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { fstatSync, openSync } from "node:fs";
import { chmod, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { createDescriptorHandoffSocketPair, sendDescriptorHandoff } from "./descriptor-handoff-receiver.js";
import { DescriptorHandoffHelperReceiver } from "./descriptor-handoff-helper.js";
import {
  DescriptorSnapshotAttestationSigner,
  DescriptorSnapshotAttestationVerifier,
  DescriptorSnapshotRegistry,
  type DescriptorSnapshotPreparationInput
} from "./descriptor-snapshot-attestation.js";
import { capturePeerProcessIdentity, loadNativePeerAdapter } from "./peer-credentials.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const NOW = 1_800_000_000_000;

test("helper receiver verifies the signed snapshot and identities reconstructed from received FDs", { skip: process.platform !== "darwin" }, async () => {
  const native = loadNativePeerAdapter();
  const root = await realpath(await mkdtemp(join(tmpdir(), "mac-operator-handoff-snapshot-")));
  const executablePath = join(root, "runner");
  await writeFile(executablePath, "#!/bin/sh\nprintf '%s\\n' safe\n", { mode: 0o700 });
  await chmod(executablePath, 0o700);
  const keyPair = generateKeyPairSync("ed25519");
  const signer = new DescriptorSnapshotAttestationSigner({ keyId: "helper-test-key", privateKey: keyPair.privateKey, now: () => NOW, maxLifetimeMs: 30_000 });
  const verifier = DescriptorSnapshotAttestationVerifier.create({
    trustedKeys: [{ keyId: "helper-test-key", publicKey: keyPair.publicKey, notBeforeMs: NOW - 60_000, expiresAtMs: NOW + 60_000 }],
    now: () => NOW,
    maxLifetimeMs: 60_000
  });
  const registry = new DescriptorSnapshotRegistry({
    enabled: true,
    signer,
    verifier,
    now: () => NOW,
    lifetimeMs: 30_000
  });
  const input: DescriptorSnapshotPreparationInput = {
    profile: "tests.echo",
    executablePath,
    cwdPath: root,
    taskDescriptorDigest: "a".repeat(64),
    argsDigest: sha256(canonicalJson(["hello"])),
    environmentDigest: sha256(canonicalJson({ LANG: "C" })),
    filesystemRootsDigest: "b".repeat(64),
    sandboxProfile: "task-deny-default-v0.1",
    networkPolicy: "none",
    processTreePolicy: "single_process"
  };
  let pair: readonly [number, number] | undefined;
  try {
    const prepared = await registry.prepare(input);
    pair = createDescriptorHandoffSocketPair();
    const [sender, receiverSocket] = pair;
    await registry.withSnapshot(prepared, async (snapshot) => {
      sendDescriptorHandoff(sender, Buffer.from(JSON.stringify(snapshot.attestation), "utf8"), [snapshot.executableFd, snapshot.cwdFd]);
      const receiver = new DescriptorHandoffHelperReceiver({
        socketDescriptor: receiverSocket,
        peerPolicy: {
          expectedUid: process.getuid?.() ?? -1,
          expectedGid: process.getgid?.() ?? -1,
          allowedProcessIdentity: capturePeerProcessIdentity(process.pid)
        },
        expectedDescriptorCount: 2,
        maxPayloadBytes: 16 * 1024,
        snapshotVerifier: verifier
      });
      await receiver.withVerifiedSnapshot(({ attestation, frame }) => {
        assert.equal(attestation.attestation.snapshotRef, prepared.snapshotRef);
        assert.equal(attestation.attestation.immutableSelection, "revalidation-only");
        assert.equal(frame.descriptors.length, 2);
      });
    });
  } finally {
    if (pair) {
      native.closeUnixDescriptor(pair[0]);
      native.closeUnixDescriptor(pair[1]);
    }
    await registry.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("one-shot helper receiver authenticates before handing out descriptors and closes them", { skip: process.platform !== "darwin" }, async () => {
  const native = loadNativePeerAdapter();
  const [sender, receiverSocket] = createDescriptorHandoffSocketPair();
  const source = openSync("/dev/null", "r");
  const receiver = new DescriptorHandoffHelperReceiver({
    socketDescriptor: receiverSocket,
    peerPolicy: {
      expectedUid: process.getuid?.() ?? -1,
      expectedGid: process.getgid?.() ?? -1,
      allowedProcessIdentity: capturePeerProcessIdentity(process.pid)
    },
    expectedDescriptorCount: 1,
    maxPayloadBytes: 1024
  });
  let received: number | undefined;
  try {
    const payload = Buffer.from("helper-receiver-v1", "utf8");
    sendDescriptorHandoff(sender, payload, [source]);
    const result = receiver.receiveOnce();
    received = result.frame.descriptors[0];
    assert.ok(received !== undefined);
    assert.equal(result.credentials.pid, process.pid);
    assert.deepEqual(result.frame.payload, payload);
    assert.equal(fstatSync(received).ino, fstatSync(source).ino);
    native.closeUnixDescriptor(received);
    received = undefined;
    assert.throws(
      () => receiver.receiveOnce(),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
    );
  } finally {
    if (received !== undefined) native.closeUnixDescriptor(received);
    native.closeUnixDescriptor(source);
    native.closeUnixDescriptor(sender);
    receiver.close();
  }
});

test("helper receiver rejects a peer identity mismatch before frame consumption", { skip: process.platform !== "darwin" }, () => {
  const native = loadNativePeerAdapter();
  const [sender, receiverSocket] = createDescriptorHandoffSocketPair();
  const source = openSync("/dev/null", "r");
  const receiver = new DescriptorHandoffHelperReceiver({
    socketDescriptor: receiverSocket,
    peerPolicy: {
      expectedUid: process.getuid?.() ?? -1,
      expectedGid: process.getgid?.() ?? -1,
      allowedProcessIdentity: {
        pid: process.pid,
        startTimeMicros: capturePeerProcessIdentity(process.pid).startTimeMicros + 1
      }
    },
    expectedDescriptorCount: 1,
    maxPayloadBytes: 1024
  });
  try {
    sendDescriptorHandoff(sender, Buffer.from("must-not-be-read", "utf8"), [source]);
    assert.throws(
      () => receiver.receiveOnce(),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    native.closeUnixDescriptor(source);
    native.closeUnixDescriptor(sender);
    receiver.close();
  }
});

test("spawned helper receiver consumes one real cross-process descriptor handoff", { skip: process.platform !== "darwin" }, async () => {
  const native = loadNativePeerAdapter();
  const [sender, childSocket] = createDescriptorHandoffSocketPair();
  const source = openSync("/dev/null", "r");
  const sourceStat = fstatSync(source);
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-handoff-helper-"));
  const helperModule = pathToFileURL(join(repositoryRoot, "packages/broker/dist/descriptor-handoff-helper.js")).href;
  const receiverModule = pathToFileURL(join(repositoryRoot, "packages/broker/dist/descriptor-handoff-receiver.js")).href;
  const peerModule = pathToFileURL(join(repositoryRoot, "packages/broker/dist/peer-credentials.js")).href;
  const contractsModule = pathToFileURL(join(repositoryRoot, "packages/contracts/dist/index.js")).href;
  const childScript = [
    'const [helperModule, receiverModule, peerModule, contractsModule] = process.argv.slice(1);',
    'const { DescriptorHandoffHelperReceiver } = await import(helperModule);',
    'const { capturePeerProcessIdentity } = await import(peerModule);',
    'const { sha256 } = await import(contractsModule);',
    'const { fstatSync } = await import("node:fs");',
    'const receiver = new DescriptorHandoffHelperReceiver({ socketDescriptor: 3, expectedDescriptorCount: 1, maxPayloadBytes: 1024, peerPolicy: { expectedUid: process.getuid(), expectedGid: process.getgid(), allowedProcessIdentity: capturePeerProcessIdentity(process.ppid) } });',
    'await receiver.withHandoff(({ credentials, frame }) => { const descriptor = frame.descriptors[0]; if (descriptor === undefined) throw new Error("missing descriptor"); process.stdout.write(JSON.stringify({ pid: credentials.pid, payloadDigest: sha256(frame.payload), dev: fstatSync(descriptor).dev, ino: fstatSync(descriptor).ino }) + "\\n"); });'
  ].join("\n");
  let child: ChildProcess | undefined;
  try {
    child = spawn(process.execPath, ["--input-type=module", "-e", childScript, helperModule, receiverModule, peerModule, contractsModule], {
      cwd: "/",
      env: { PATH: process.env.PATH ?? "" },
      stdio: ["ignore", "pipe", "pipe", childSocket]
    });
    native.closeUnixDescriptor(childSocket);
    const payload = Buffer.from("cross-process-handoff-v1", "utf8");
    sendDescriptorHandoff(sender, payload, [source]);
    const output = await waitForChildOutput(child);
    const result = JSON.parse(output) as { pid: number; payloadDigest: string; dev: number; ino: number };
    assert.equal(result.pid, process.pid);
    assert.equal(result.payloadDigest, createHash("sha256").update(payload).digest("hex"));
    assert.equal(result.dev, sourceStat.dev);
    assert.equal(result.ino, sourceStat.ino);
  } finally {
    native.closeUnixDescriptor(source);
    native.closeUnixDescriptor(sender);
    if (child && child.exitCode === null) child.kill("SIGKILL");
    await rm(directory, { recursive: true, force: true });
  }
});

async function waitForChildOutput(child: ChildProcess): Promise<string> {
  const stdout = child.stdout;
  const stderr = child.stderr;
  if (!stdout || !stderr) throw new Error("Helper receiver pipes are unavailable");
  const chunks: Buffer[] = [];
  let bytes = 0;
  const stderrChunks: Buffer[] = [];
  stderr.on("data", (chunk: Buffer) => stderrChunks.push(Buffer.from(chunk).subarray(0, 4096)));
  stdout.on("data", (chunk: Buffer) => {
    bytes += chunk.length;
    if (bytes <= 16 * 1024) chunks.push(Buffer.from(chunk));
  });
  const status = await new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve, reject) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error("Helper receiver child timed out"));
    }, 5_000);
    child.once("error", (error) => { clearTimeout(timer); reject(error); });
    child.once("close", (code, signal) => { clearTimeout(timer); resolve({ code, signal }); });
  });
  if (status.code !== 0) {
    throw new Error(`Helper receiver child failed: ${status.code ?? status.signal ?? "unknown"} ${Buffer.concat(stderrChunks).toString("utf8")}`);
  }
  return Buffer.concat(chunks).toString("utf8").trim();
}
