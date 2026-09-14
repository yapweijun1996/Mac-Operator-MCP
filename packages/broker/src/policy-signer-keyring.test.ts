import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { chmod, lstat, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";
import {
  PolicySignerKeyManager,
  loadPolicySignerKeyConfig,
  writePolicySignerKeyConfig,
  type PolicySignerKeyConfig
} from "./policy-signer-keyring.js";
import type { PolicyDocument, SignedPolicyBundle } from "./policy-loader.js";

const NOW = 1_700_000_000_000;
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

function policyDocument(): PolicyDocument {
  return {
    schema_version: "0.1",
    revision: 1,
    audience: "mac-operator-broker",
    issued_at_ms: NOW,
    trusted_edge_keys: [{
      edge_id: "edge-1",
      key_id: "edge-key-1",
      not_before_ms: NOW - 60_000,
      expires_at_ms: NOW + 60_000
    }],
    principal_grants: [{
      principal_id: "principal-1",
      issuer: "test-issuer",
      scopes: ["mac.control.read"],
      enabled: true
    }],
    target_rules: [{
      rule_id: "allow-broker-observe",
      effect: "allow",
      principal_id: "principal-1",
      scope: "mac.control.read",
      target: { kind: "host", reference: "broker" }
    }],
    filesystem_roots: [],
    tool_enablement: [
      { tool: "mac_health", enabled: true },
      { tool: "mac_capabilities", enabled: true },
      { tool: "mac_policy_explain", enabled: true }
    ],
    kill_switches: {
      global: false, mutations: false, process: false, network: false,
      gui: false, destructive: false, privileged: false
    }
  };
}

function signedBundle(document: PolicyDocument, privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], keyId: string): SignedPolicyBundle {
  const payloadBytes = Buffer.from(canonicalJson(document), "utf8");
  return {
    bundle_version: "0.1",
    key_id: keyId,
    algorithm: "Ed25519",
    payload_digest: sha256(payloadBytes),
    payload: document,
    signature: sign(null, payloadBytes, privateKey).toString("base64")
  };
}

function publicKeyDigest(publicKey: ReturnType<typeof generateKeyPairSync>["publicKey"]): string {
  return sha256(Buffer.from(publicKey.export({ type: "spki", format: "pem" })));
}

function entry(keyId: string, path: string, digest: string, notBeforeMs = NOW - 1_000, expiresAtMs = NOW + 60_000) {
  return { keyId, path, publicKeyDigest: digest, notBeforeMs, expiresAtMs } as const;
}

test("policy signer config is owner-only, versioned, atomic, and reloadable", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-signer-config-"));
  const configPath = join(directory, "policy-signers.json");
  const firstPath = join(directory, "policy-key-1.pem");
  const secondPath = join(directory, "policy-key-2.pem");
  const first = generateKeyPairSync("ed25519");
  const second = generateKeyPairSync("ed25519");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    await writeFile(firstPath, first.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    await writeFile(secondPath, second.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    const document: PolicySignerKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [entry("policy-key-1", firstPath, publicKeyDigest(first.publicKey))]
    };
    const digest = await writePolicySignerKeyConfig(configPath, document);
    assert.equal((await lstat(configPath)).mode & 0o777, 0o600);
    const loaded = await loadPolicySignerKeyConfig(configPath);
    assert.equal(loaded.payloadDigest, digest);
    assert.equal(loaded.document.revision, 1);
    assert.equal(loaded.keys[0]?.keyId, "policy-key-1");

    const next: PolicySignerKeyConfig = {
      schemaVersion: "0.1",
      revision: 2,
      keys: [
        entry("policy-key-1", firstPath, publicKeyDigest(first.publicKey)),
        entry("policy-key-2", secondPath, publicKeyDigest(second.publicKey), NOW, NOW + 120_000)
      ]
    };
    const nextDigest = await writePolicySignerKeyConfig(configPath, next);
    assert.notEqual(nextDigest, digest);
    assert.equal((await loadPolicySignerKeyConfig(configPath)).keys.length, 2);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy signer manager persists activation, revocation, restore, and operator rollback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-signer-manager-"));
  const configPath = join(directory, "policy-signers.json");
  const firstPath = join(directory, "policy-key-1.pem");
  const secondPath = join(directory, "policy-key-2.pem");
  const databasePath = join(directory, "broker.sqlite");
  const first = generateKeyPairSync("ed25519");
  const second = generateKeyPairSync("ed25519");
  let store = new BrokerStore(databasePath);
  try {
    await writeFile(firstPath, first.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    await writeFile(secondPath, second.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    const firstDocument: PolicySignerKeyConfig = {
      schemaVersion: "0.1", revision: 1, keys: [entry("policy-key-1", firstPath, publicKeyDigest(first.publicKey))]
    };
    const secondDocument: PolicySignerKeyConfig = {
      schemaVersion: "0.1", revision: 2,
      keys: [
        entry("policy-key-1", firstPath, publicKeyDigest(first.publicKey)),
        entry("policy-key-2", secondPath, publicKeyDigest(second.publicKey), NOW, NOW + 120_000)
      ]
    };
    await writePolicySignerKeyConfig(configPath, firstDocument);
    const manager = new PolicySignerKeyManager(configPath, join(repositoryRoot, "schemas"), store, () => NOW);
    await assert.rejects(manager.restore(), /does not match persisted activation/u);
    await manager.activate();
    assert.equal(store.activePolicySignerConfigIdentity()?.revision, 1);
    let verifier = await manager.createVerifier();
    assert.equal(verifier.verify(signedBundle(policyDocument(), first.privateKey, "policy-key-1")).keyId, "policy-key-1");
    await writeFile(firstPath, second.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    await assert.rejects(manager.restore(), /digest does not match configuration/u);
    await writeFile(firstPath, first.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });

    await writePolicySignerKeyConfig(configPath, secondDocument);
    await manager.reload(1);
    await manager.revoke("policy-key-1", "COMPROMISED", NOW + 1);
    verifier = await manager.createVerifier();
    assert.throws(
      () => verifier.verify(signedBundle(policyDocument(), first.privateKey, "policy-key-1")),
      /signing key is revoked/u
    );
    assert.equal(verifier.verify(signedBundle(policyDocument(), second.privateKey, "policy-key-2")).keyId, "policy-key-2");

    store.close();
    store = new BrokerStore(databasePath);
    const restarted = new PolicySignerKeyManager(configPath, join(repositoryRoot, "schemas"), store, () => NOW + 2);
    await restarted.restore();
    assert.equal(store.activePolicySignerConfigIdentity()?.revision, 2);

    await writePolicySignerKeyConfig(configPath, firstDocument);
    await restarted.rollback({ expectedCurrentRevision: 2, reasonCode: "OPERATOR_RECOVERY" });
    assert.equal(store.activePolicySignerConfigIdentity()?.revision, 1);
    assert.equal(store.isRevoked("policy_signer", "policy-key-1"), true);
    const audits = store.auditRows();
    assert.equal(audits.filter((row) => row.tool === "internal_policy_signer_config_activate" && row.event_type === "completion").length, 2);
    assert.equal(audits.filter((row) => row.tool === "internal_policy_signer_revoke" && row.event_type === "completion").length, 1);
    assert.equal(audits.filter((row) => row.tool === "internal_policy_signer_config_rollback" && row.event_type === "completion").length, 1);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy signer config rejects unsafe paths, duplicate identities, and non-Ed25519 keys", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-signer-deny-"));
  const configPath = join(directory, "policy-signers.json");
  const keyPath = join(directory, "policy-key.pem");
  const linkPath = join(directory, "policy-signers-link.json");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const keys = generateKeyPairSync("ed25519");
    await writeFile(keyPath, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    const digest = publicKeyDigest(keys.publicKey);
    const duplicate = { schemaVersion: "0.1", revision: 1, keys: [entry("policy-key-1", keyPath, digest), entry("policy-key-1", keyPath, digest)] } as const;
    await assert.rejects(writePolicySignerKeyConfig(configPath, duplicate), /Duplicate policy signer key/u);
    await writePolicySignerKeyConfig(configPath, { schemaVersion: "0.1", revision: 1, keys: [entry("policy-key-1", keyPath, digest)] });
    await symlink(configPath, linkPath);
    await assert.rejects(loadPolicySignerKeyConfig(linkPath), /non-symlink/u);
    await chmod(configPath, 0o640);
    await assert.rejects(loadPolicySignerKeyConfig(configPath), /not be accessible/u);

    const rsa = generateKeyPairSync("rsa", { modulusLength: 2048 });
    await chmod(configPath, 0o600);
    await writeFile(keyPath, rsa.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    await assert.rejects(loadPolicySignerKeyConfig(configPath), /must be Ed25519/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy signer key loader rejects private-key files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-signer-private-"));
  const configPath = join(directory, "policy-signers.json");
  const keyPath = join(directory, "policy-key-private.pem");
  const keys = generateKeyPairSync("ed25519");
  try {
    const privatePem = Buffer.from(keys.privateKey.export({ type: "pkcs8", format: "pem" }));
    await writeFile(keyPath, privatePem, { mode: 0o600 });
    await writePolicySignerKeyConfig(configPath, {
      schemaVersion: "0.1",
      revision: 1,
      keys: [entry("policy-key-private", keyPath, sha256(privatePem))]
    });
    await assert.rejects(loadPolicySignerKeyConfig(configPath), /public material only/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
