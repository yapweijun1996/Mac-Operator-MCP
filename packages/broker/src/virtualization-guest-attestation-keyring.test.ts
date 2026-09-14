import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { chmod, lstat, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";
import {
  VirtualizationGuestAttestationKeyManager,
  loadVirtualizationGuestAttestationKeyConfig,
  writeVirtualizationGuestAttestationKeyConfig,
  type VirtualizationGuestAttestationKeyConfig
} from "./virtualization-guest-attestation-keyring.js";
import {
  virtualizationGuestAttestationSigningPayload,
  type VirtualizationGuestAttestation,
  type SignedVirtualizationGuestAttestation
} from "./virtualization-guest-attestation.js";

const NOW = 1_700_000_000_000;

function publicKeyPem(key: ReturnType<typeof generateKeyPairSync>["publicKey"]): Buffer {
  return Buffer.from(key.export({ type: "spki", format: "pem" }));
}

function publicKeyDigest(key: ReturnType<typeof generateKeyPairSync>["publicKey"]): string {
  return sha256(publicKeyPem(key));
}

function entry(keyId: string, path: string, digest: string, notBeforeMs = NOW - 1_000, expiresAtMs = NOW + 60_000) {
  return { keyId, path, publicKeyDigest: digest, notBeforeMs, expiresAtMs } as const;
}

function attestation(): VirtualizationGuestAttestation {
  const unsigned = {
    schemaVersion: "0.1" as const,
    guestIdentity: { imageSha256: "a".repeat(64), runtimeVersion: "guest-runtime-1" },
    sandboxProfile: "guest-task",
    filesystem: "guest-private" as const,
    network: "profile-bound" as const,
    credentials: "host-credentials-unavailable" as const,
    processTree: "guest-owned" as const,
    processTreePolicy: "single_process" as const,
    evidenceRef: "guest:evidence:1"
  };
  return { ...unsigned, attestationDigest: sha256(canonicalJson(unsigned)) };
}

function signed(value: VirtualizationGuestAttestation, privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], keyId: string): SignedVirtualizationGuestAttestation {
  const payloadDigest = sha256(canonicalJson(value));
  const unsigned = {
    schemaVersion: "0.1" as const,
    keyId,
    algorithm: "Ed25519" as const,
    issuedAtMs: NOW,
    expiresAtMs: NOW + 30_000,
    payloadDigest,
    payload: value
  };
  return { ...unsigned, signature: sign(null, virtualizationGuestAttestationSigningPayload(unsigned), privateKey).toString("base64") };
}

test("guest attestation key config is protected, digest-bound, and reloadable", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-attestation-config-"));
  const configPath = join(directory, "guest-attestation-keys.json");
  const keyPath = join(directory, "guest-key-1.pem");
  const keys = generateKeyPairSync("ed25519");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    await writeFile(keyPath, publicKeyPem(keys.publicKey), { mode: 0o600 });
    const document: VirtualizationGuestAttestationKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [entry("guest-key-1", keyPath, publicKeyDigest(keys.publicKey))]
    };
    const digest = await writeVirtualizationGuestAttestationKeyConfig(configPath, document);
    assert.equal((await lstat(configPath)).mode & 0o777, 0o600);
    const loaded = await loadVirtualizationGuestAttestationKeyConfig(configPath);
    assert.equal(loaded.payloadDigest, digest);
    assert.equal(loaded.keys[0]?.keyId, "guest-key-1");
    await chmod(keyPath, 0o640);
    await assert.rejects(loadVirtualizationGuestAttestationKeyConfig(configPath), /not be accessible/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("guest attestation key manager persists activation, revocation, restore, and rollback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-attestation-manager-"));
  const configPath = join(directory, "guest-attestation-keys.json");
  const firstPath = join(directory, "guest-key-1.pem");
  const secondPath = join(directory, "guest-key-2.pem");
  const databasePath = join(directory, "broker.sqlite");
  const first = generateKeyPairSync("ed25519");
  const second = generateKeyPairSync("ed25519");
  let store = new BrokerStore(databasePath);
  try {
    await writeFile(firstPath, publicKeyPem(first.publicKey), { mode: 0o600 });
    await writeFile(secondPath, publicKeyPem(second.publicKey), { mode: 0o600 });
    const firstDocument: VirtualizationGuestAttestationKeyConfig = {
      schemaVersion: "0.1", revision: 1, keys: [entry("guest-key-1", firstPath, publicKeyDigest(first.publicKey))]
    };
    const secondDocument: VirtualizationGuestAttestationKeyConfig = {
      schemaVersion: "0.1", revision: 2,
      keys: [
        entry("guest-key-1", firstPath, publicKeyDigest(first.publicKey)),
        entry("guest-key-2", secondPath, publicKeyDigest(second.publicKey), NOW, NOW + 120_000)
      ]
    };
    await writeVirtualizationGuestAttestationKeyConfig(configPath, firstDocument);
    const manager = new VirtualizationGuestAttestationKeyManager(configPath, store, () => NOW);
    await assert.rejects(manager.restore(), /does not match persisted activation/u);
    await manager.activate();
    assert.equal(store.activeGuestAttestationKeyConfigIdentity()?.revision, 1);
    assert.equal(manager.createVerifier().verify(signed(attestation(), first.privateKey, "guest-key-1")).keyId, "guest-key-1");

    await writeVirtualizationGuestAttestationKeyConfig(configPath, secondDocument);
    await manager.reload(1);
    await manager.revoke("guest-key-1", "COMPROMISED", NOW + 1);
    assert.throws(() => manager.createVerifier().verify(signed(attestation(), first.privateKey, "guest-key-1")), /key is revoked/u);
    assert.equal(manager.createVerifier().verify(signed(attestation(), second.privateKey, "guest-key-2")).keyId, "guest-key-2");

    store.close();
    store = new BrokerStore(databasePath);
    const restarted = new VirtualizationGuestAttestationKeyManager(configPath, store, () => NOW + 2);
    await restarted.restore();
    assert.equal(store.activeGuestAttestationKeyConfigIdentity()?.revision, 2);
    await writeVirtualizationGuestAttestationKeyConfig(configPath, firstDocument);
    await restarted.rollback({ expectedCurrentRevision: 2, reasonCode: "OPERATOR_RECOVERY" });
    assert.equal(store.activeGuestAttestationKeyConfigIdentity()?.revision, 1);
    assert.equal(store.isRevoked("guest_attestation_key", "guest-key-1"), true);
    const audits = store.auditRows();
    assert.equal(audits.filter((row) => row.tool === "internal_guest_attestation_key_config_activate" && row.event_type === "completion").length, 2);
    assert.equal(audits.filter((row) => row.tool === "internal_authority_revoke" && row.event_type === "completion").length, 1);
    assert.equal(audits.filter((row) => row.tool === "internal_guest_attestation_key_config_rollback" && row.event_type === "completion").length, 1);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("guest attestation key config rejects duplicate paths and symlinked configs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-attestation-deny-"));
  const configPath = join(directory, "guest-attestation-keys.json");
  const linkPath = join(directory, "guest-attestation-link.json");
  const keyPath = join(directory, "guest-key.pem");
  const keys = generateKeyPairSync("ed25519");
  try {
    await writeFile(keyPath, publicKeyPem(keys.publicKey), { mode: 0o600 });
    const digest = publicKeyDigest(keys.publicKey);
    const duplicate = {
      schemaVersion: "0.1", revision: 1,
      keys: [entry("guest-key-1", keyPath, digest), entry("guest-key-2", keyPath, digest)]
    } as const;
    await assert.rejects(writeVirtualizationGuestAttestationKeyConfig(configPath, duplicate), /Duplicate guest attestation key/u);
    await writeVirtualizationGuestAttestationKeyConfig(configPath, { schemaVersion: "0.1", revision: 1, keys: [entry("guest-key-1", keyPath, digest)] });
    await symlink(configPath, linkPath);
    await assert.rejects(loadVirtualizationGuestAttestationKeyConfig(linkPath), /non-symlink/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("guest attestation key loader rejects private-key files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-attestation-private-"));
  const configPath = join(directory, "guest-attestation-keys.json");
  const keyPath = join(directory, "guest-key-private.pem");
  const keys = generateKeyPairSync("ed25519");
  try {
    await writeFile(keyPath, keys.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
    await writeVirtualizationGuestAttestationKeyConfig(configPath, {
      schemaVersion: "0.1",
      revision: 1,
      keys: [entry("guest-key-private", keyPath, sha256(Buffer.from(keys.privateKey.export({ type: "pkcs8", format: "pem" }))))]
    });
    await assert.rejects(loadVirtualizationGuestAttestationKeyConfig(configPath), /public material only/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
