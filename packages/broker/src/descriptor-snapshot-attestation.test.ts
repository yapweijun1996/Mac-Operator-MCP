import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { chmod, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import {
  assertDescriptorSnapshotIdentity,
  DescriptorSnapshotAttestationSigner,
  DescriptorSnapshotAttestationVerifier,
  DescriptorSnapshotRegistry,
  descriptorFileIdentityDigest,
  snapshotSignedDescriptorSnapshotAttestation,
  type DescriptorFileIdentity,
  type DescriptorSnapshotAttestation,
  type DescriptorSnapshotPreparationInput,
  type SignedDescriptorSnapshotAttestation
} from "./descriptor-snapshot-attestation.js";

const NOW = 1_800_000_000_000;

function input(executablePath: string, cwdPath: string): DescriptorSnapshotPreparationInput {
  return {
    profile: "tests.echo",
    executablePath,
    cwdPath,
    taskDescriptorDigest: "a".repeat(64),
    argsDigest: sha256(canonicalJson(["hello"])),
    environmentDigest: sha256(canonicalJson({ LANG: "C" })),
    filesystemRootsDigest: "b".repeat(64),
    sandboxProfile: "task-deny-default-v0.1",
    networkPolicy: "none",
    processTreePolicy: "single_process"
  };
}

function verifier(publicKey: ReturnType<typeof generateKeyPairSync>["publicKey"], now: () => number = () => NOW, revocationCheck?: (keyId: string) => boolean): DescriptorSnapshotAttestationVerifier {
  return DescriptorSnapshotAttestationVerifier.create({
    trustedKeys: [{
      keyId: "descriptor-key-1",
      publicKey,
      notBeforeMs: NOW - 60_000,
      expiresAtMs: NOW + 120_000
    }],
    ...(revocationCheck === undefined ? {} : { revocationCheck }),
    now,
    maxLifetimeMs: 60_000
  });
}

function expectBrokerError(action: () => unknown, errorClass: BrokerError["errorClass"]): void {
  assert.throws(action, (error: unknown) => error instanceof BrokerError && error.errorClass === errorClass);
}

async function fixture(): Promise<{ root: string; executablePath: string; keyPair: ReturnType<typeof generateKeyPairSync> }> {
  const root = await realpath(await mkdtemp("/tmp/mac-operator-descriptor-snapshot-"));
  const executablePath = join(root, "runner");
  await writeFile(executablePath, "#!/bin/sh\nprintf '%s\\n' safe\n", { mode: 0o700 });
  await chmod(executablePath, 0o700);
  return { root, executablePath, keyPair: generateKeyPairSync("ed25519") };
}

function signer(privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"]): DescriptorSnapshotAttestationSigner {
  return new DescriptorSnapshotAttestationSigner({
    keyId: "descriptor-key-1",
    privateKey,
    now: () => NOW,
    maxLifetimeMs: 30_000
  });
}

test("descriptor snapshot registry is disabled by default before filesystem access", async () => {
  const registry = new DescriptorSnapshotRegistry();
  await assert.rejects(
    registry.prepare(input("/does/not/exist", "/does/not/exist")),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNSUPPORTED_CAPABILITY"
  );
});

test("descriptor snapshot handoff is opaque, signed, FD-bound, and one-shot", async () => {
  const { root, executablePath, keyPair } = await fixture();
  try {
    const check = verifier(keyPair.publicKey);
    const registry = new DescriptorSnapshotRegistry({ enabled: true, signer: signer(keyPair.privateKey), verifier: check, now: () => NOW });
    const prepared = await registry.prepare(input(executablePath, root));
    assert.match(prepared.snapshotRef, /^snapshot:[a-f0-9]{48}$/u);
    const serialized = JSON.stringify(prepared.attestation);
    assert.equal(serialized.includes(executablePath), false);
    assert.equal(serialized.includes("runner"), false);
    assert.equal(serialized.includes("safe"), false);
    assert.equal(serialized.includes("LANG"), false);
    const verified = check.verify(prepared.attestation);
    assert.equal(verified.attestation.snapshotRef, prepared.snapshotRef);
    assert.equal(verified.attestation.immutableSelection, "revalidation-only");

    let handoffFdPair: [number, number] | undefined;
    const result = await registry.withSnapshot(prepared, async (handoff) => {
      handoffFdPair = [handoff.executableFd, handoff.cwdFd];
      assert.equal(handoff.attestation, prepared.attestation);
      assert.ok(handoff.executableFd > 0);
      assert.ok(handoff.cwdFd > 0);
      return "accepted";
    });
    assert.equal(result, "accepted");
    assert.ok(handoffFdPair);
    await assert.rejects(
      registry.withSnapshot(prepared, () => "replayed"),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REPLAY_DENIED"
    );
    await registry.close();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("descriptor snapshot revalidates the held executable before handing off", async () => {
  const { root, executablePath, keyPair } = await fixture();
  try {
    const registry = new DescriptorSnapshotRegistry({
      enabled: true,
      signer: signer(keyPair.privateKey),
      verifier: verifier(keyPair.publicKey),
      now: () => NOW
    });
    const prepared = await registry.prepare(input(executablePath, root));
    await writeFile(executablePath, "#!/bin/sh\nprintf '%s\\n' changed\n", { mode: 0o700 });
    await assert.rejects(
      registry.withSnapshot(prepared, () => undefined),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    await registry.close();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("descriptor snapshot can bind a bounded script descriptor without exposing its pathname", async () => {
  const { root, executablePath, keyPair } = await fixture();
  const scriptPath = join(root, "task.sh");
  await writeFile(scriptPath, "#!/bin/sh\nprintf '%s\\n' bounded\n", { mode: 0o700 });
  try {
    const check = verifier(keyPair.publicKey);
    const registry = new DescriptorSnapshotRegistry({
      enabled: true,
      signer: signer(keyPair.privateKey),
      verifier: check,
      now: () => NOW
    });
    const prepared = await registry.prepare({ ...input(executablePath, root), scriptPath });
    assert.equal(JSON.stringify(prepared.attestation).includes(scriptPath), false);
    let scriptFd = -1;
    let scriptDigest = "";
    await registry.withSnapshot(prepared, async (handoff) => {
      scriptFd = handoff.scriptFd ?? -1;
      scriptDigest = handoff.scriptContentSha256 ?? "";
    });
    assert.ok(scriptFd > 0);
    assert.match(scriptDigest, /^[a-f0-9]{64}$/u);
    await registry.close();
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("descriptor snapshot signatures reject tampering, expiry, and key revocation", () => {
  const keyPair = generateKeyPairSync("ed25519");
  const payload: DescriptorSnapshotAttestation = {
    schemaVersion: "0.1",
    audience: "mac-operator-descriptor-helper-v0.1",
    snapshotRef: `snapshot:${"1".repeat(48)}`,
    profile: "tests.echo",
    taskDescriptorDigest: "a".repeat(64),
    argsDigest: "b".repeat(64),
    environmentDigest: "c".repeat(64),
    filesystemRootsDigest: "d".repeat(64),
    sandboxProfile: "task-deny-default-v0.1",
    networkPolicy: "none",
    processTreePolicy: "single_process",
    credentialPolicy: "none",
    immutableSelection: "revalidation-only",
    executableContentSha256: "e".repeat(64),
    executableIdentityDigest: "f".repeat(64),
    cwdIdentityDigest: "0".repeat(64)
  };
  const signed = signer(keyPair.privateKey).sign(payload);
  const check = verifier(keyPair.publicKey);
  assert.equal(check.verify(signed).attestation.profile, "tests.echo");
  expectBrokerError(() => check.verify({ ...signed, payload: { ...payload, profile: "tampered" } }), "POLICY_DENIED");
  expectBrokerError(() => verifier(keyPair.publicKey, () => NOW + 30_000).verify(signed), "POLICY_DENIED");
  expectBrokerError(() => verifier(keyPair.publicKey, () => NOW, () => true).verify(signed), "POLICY_DENIED");
  expectBrokerError(() => snapshotSignedDescriptorSnapshotAttestation({ ...signed, extra: true }), "POLICY_DENIED");
});

test("descriptor snapshot identity binding contains no pathname authority", () => {
  const executable: DescriptorFileIdentity = {
    device: 1, inode: 2, ownerUid: 3, ownerGid: 4, mode: 0o700, size: 5,
    mtimeMs: 6, ctimeMs: 7, contentSha256: "a".repeat(64)
  };
  const cwd: DescriptorFileIdentity = {
    device: 8, inode: 9, ownerUid: 3, ownerGid: 4, mode: 0o700, size: 10, mtimeMs: 11, ctimeMs: 12
  };
  const payload: DescriptorSnapshotAttestation = {
    schemaVersion: "0.1",
    audience: "mac-operator-descriptor-helper-v0.1",
    snapshotRef: `snapshot:${"2".repeat(48)}`,
    profile: "tests.echo",
    taskDescriptorDigest: "b".repeat(64),
    argsDigest: "c".repeat(64),
    environmentDigest: "d".repeat(64),
    filesystemRootsDigest: "e".repeat(64),
    sandboxProfile: "task-deny-default-v0.1",
    networkPolicy: "none",
    processTreePolicy: "single_process",
    credentialPolicy: "none",
    immutableSelection: "revalidation-only",
    executableContentSha256: executable.contentSha256!,
    executableIdentityDigest: descriptorFileIdentityDigest(executable),
    cwdIdentityDigest: descriptorFileIdentityDigest(cwd)
  };
  assert.doesNotThrow(() => assertDescriptorSnapshotIdentity(payload, { executable, cwd }));
  expectBrokerError(() => assertDescriptorSnapshotIdentity(payload, { executable: { ...executable, inode: 99 }, cwd }), "POLICY_DENIED");
});
