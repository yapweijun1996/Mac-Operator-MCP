import assert from "node:assert/strict";
import { generateKeyPairSync, sign, type KeyObject } from "node:crypto";
import { lstat, mkdtemp, rm, writeFile } from "node:fs/promises";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import {
  VirtualizationGuestAttestationVerifier,
  virtualizationGuestAttestationSigningPayload,
  type SignedVirtualizationGuestAttestation,
  type VirtualizationGuestAttestation,
  type VirtualizationGuestIdentity
} from "./virtualization-guest-attestation.js";
import { loadVirtualizationGuestImage } from "./virtualization-guest-image.js";
import { VirtualizationTaskRunner, type TaskExecutionResult, type TaskIsolationProof, type VirtualizationTaskExecutor } from "./task-runner.js";

const NOW = 1_800_000_000_000;

function guestAttestation(guestIdentity: VirtualizationGuestIdentity): VirtualizationGuestAttestation {
  const unsigned = {
    schemaVersion: "0.1" as const,
    guestIdentity,
    sandboxProfile: "guest-deny-default-v0.1",
    filesystem: "guest-private" as const,
    network: "profile-bound" as const,
    credentials: "host-credentials-unavailable" as const,
    processTree: "guest-owned" as const,
    processTreePolicy: "single_process" as const,
    evidenceRef: "evidence://guest-attestation"
  };
  return { ...unsigned, attestationDigest: sha256(canonicalJson(unsigned)) };
}

function signedAttestation(
  payload: VirtualizationGuestAttestation,
  keyId: string,
  privateKey: KeyObject,
  issuedAtMs = NOW,
  expiresAtMs = NOW + 60_000
): SignedVirtualizationGuestAttestation {
  const unsigned = {
    schemaVersion: "0.1" as const,
    keyId,
    algorithm: "Ed25519" as const,
    issuedAtMs,
    expiresAtMs,
    payloadDigest: sha256(canonicalJson(payload)),
    payload
  };
  return {
    ...unsigned,
    signature: sign(null, virtualizationGuestAttestationSigningPayload(unsigned), privateKey).toString("base64")
  };
}

function verifier(publicKey: KeyObject, now: () => number = () => NOW, revocationCheck?: (keyId: string) => boolean): VirtualizationGuestAttestationVerifier {
  return VirtualizationGuestAttestationVerifier.create({
    trustedKeys: [{ keyId: "guest-key-1", publicKeyPem: publicKey.export({ type: "spki", format: "pem" }), notBeforeMs: NOW - 60_000, expiresAtMs: NOW + 120_000 }],
    ...(revocationCheck === undefined ? {} : { revocationCheck }),
    now
  });
}

function expectDenied(action: () => unknown): void {
  assert.throws(action, (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED");
}

test("signed guest attestation binds claims, key, freshness, and payload digest", () => {
  const keys = generateKeyPairSync("ed25519");
  const payload = guestAttestation({ imageSha256: "a".repeat(64), runtimeVersion: "macos-26.2-vz-1" });
  const signed = signedAttestation(payload, "guest-key-1", keys.privateKey);
  const verified = verifier(keys.publicKey).verify(signed);
  assert.deepEqual(verified, {
    attestation: payload,
    keyId: "guest-key-1",
    payloadDigest: sha256(canonicalJson(payload)),
    issuedAtMs: NOW,
    expiresAtMs: NOW + 60_000
  });
});

test("signed guest attestation rejects envelope mutation, expiry, unknown keys, and revocation", () => {
  const keys = generateKeyPairSync("ed25519");
  const payload = guestAttestation({ imageSha256: "b".repeat(64), runtimeVersion: "macos-26.2-vz-1" });
  const signed = signedAttestation(payload, "guest-key-1", keys.privateKey);
  const check = verifier(keys.publicKey);
  expectDenied(() => check.verify({ ...signed, expiresAtMs: NOW + 120_000 }));
  expectDenied(() => check.verify({ ...signed, payload: { ...payload, evidenceRef: "evidence://changed" } }));
  expectDenied(() => check.verify({ ...signed, keyId: "guest-key-unknown" }));
  expectDenied(() => verifier(keys.publicKey, () => NOW + 60_000).verify(signed));
  expectDenied(() => verifier(keys.publicKey, () => NOW, (keyId) => keyId === "guest-key-1").verify(signed));
  expectDenied(() => check.verify({ ...signed, algorithm: "RSA" } as unknown as SignedVirtualizationGuestAttestation));
});

test("guest attestation verifier rejects private-key material", () => {
  const keyPair = generateKeyPairSync("ed25519");
  assert.throws(
    () => VirtualizationGuestAttestationVerifier.create({
      trustedKeys: [{ keyId: "guest-key-1", publicKeyPem: keyPair.privateKey.export({ type: "pkcs8", format: "pem" }) }]
    }),
    /public material only/u
  );
});

test("VirtualizationTaskRunner revalidates signed guest provenance before dispatch", async () => {
  const keys = generateKeyPairSync("ed25519");
  const directory = await mkdtemp("/tmp/mac-operator-signed-guest-");
  const imagePath = `${directory}/guest.img`;
  const imageBytes = Buffer.from("signed-guest-image\n", "utf8");
  const guest: VirtualizationGuestIdentity = { imageSha256: sha256(imageBytes), runtimeVersion: "macos-26.2-vz-1" };
  const attestation = guestAttestation(guest);
  const signed = signedAttestation(attestation, "guest-key-1", keys.privateKey, NOW, NOW + 60_000);
  let currentNow = NOW;
  const guestVerifier = verifier(keys.publicKey, () => currentNow);
  await writeFile(imagePath, imageBytes, { mode: 0o600 });
  const image = await loadVirtualizationGuestImage({
    path: imagePath,
    expectedSha256: sha256(imageBytes),
    runtimeVersion: guest.runtimeVersion
  });
  const proof: TaskIsolationProof = {
    schemaVersion: "0.1",
    sandboxMechanism: "virtualization",
    sandboxProfile: attestation.sandboxProfile,
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    persistence: "isolated",
    credentialIsolation: "virtualization-no-host-credentials-v1",
    processTree: "owned",
    processTreePolicy: "single_process",
    evidenceRef: attestation.evidenceRef,
    virtualizationGuest: guest
  };
  let calls = 0;
  const result: TaskExecutionResult = {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    stdout: "ok",
    stderr: "",
    truncated: false,
    durationMs: 1,
    verification: { status: "verified" }
  };
  const executor: VirtualizationTaskExecutor = {
    available: true,
    guestIdentity: guest,
    attestation,
    signedAttestation: signed,
    async run() {
      calls += 1;
      return result;
    }
  };
  const runner = new VirtualizationTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    isolationProof: proof,
    executor,
    guestImage: image,
    attestationVerifier: guestVerifier
  });
  try {
    assert.equal(runner.available, true);
    await runner.run({
      profile: "guest-task",
      cwd: directory,
      process: { executable: "/usr/bin/true", args: [], cwd: directory, environment: {}, timeoutMs: 2_000, outputCapBytes: 4_096 },
      filesystemRoots: [directory],
      networkPolicy: "none",
      networkAllowlist: [],
      credentialPolicy: "none",
      processTreePolicy: "single_process",
      sandboxProfile: attestation.sandboxProfile,
      verificationStrategy: "exit_status_and_declared_task_verification"
    }, { timeoutMs: 1_000, shouldCancel: () => false });
    assert.equal(calls, 1);
    currentNow = NOW + 60_000;
    await assert.rejects(
      runner.run({
        profile: "guest-task",
        cwd: directory,
        process: { executable: "/usr/bin/true", args: [], cwd: directory, environment: {}, timeoutMs: 2_000, outputCapBytes: 4_096 },
        filesystemRoots: [directory],
        networkPolicy: "none",
        networkAllowlist: [],
        credentialPolicy: "none",
        processTreePolicy: "single_process",
        sandboxProfile: attestation.sandboxProfile,
        verificationStrategy: "exit_status_and_declared_task_verification"
      }, { timeoutMs: 1_000, shouldCancel: () => false }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    assert.equal(calls, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
