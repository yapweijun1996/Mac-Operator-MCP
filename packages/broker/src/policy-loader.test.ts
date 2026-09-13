import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { chmod, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import { PolicyBundleVerifier, PolicyManager, type PolicyDocument, type SignedPolicyBundle } from "./policy-loader.js";

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
      expires_at_ms: NOW + 120_000
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

function signedBundle(
  document: PolicyDocument,
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"],
  keyId = "policy-key-1"
): SignedPolicyBundle {
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

async function verifier() {
  const keys = generateKeyPairSync("ed25519");
  const instance = await PolicyBundleVerifier.create({
    schemaDirectory: join(repositoryRoot, "schemas"),
    expectedKeyId: "policy-key-1",
    publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }),
    now: () => NOW
  });
  return { instance, keys };
}

test("a verified signed policy atomically activates Broker-owned authority", async () => {
  const { instance, keys } = await verifier();
  const verified = instance.verify(signedBundle(policyDocument(), keys.privateKey));
  const manager = new PolicyManager(createDefaultPolicy("edge-1"));
  manager.activate(verified);
  assert.equal(manager.current().version, "policy-1");
  assert.equal(manager.current().tools.get("mac_health")?.enabled, true);

  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  const broker = new Broker({ store, policy: manager, edgeAuthenticationKeys: testKeyring(edgeKey), now: () => NOW });
  try {
    const result = await broker.handle(signRequest(unsignedRequest(), edgeKey));
    assert.equal(result.ok, true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a signed filesystem root authorizes descriptor-backed mac_stat_path", async () => {
  const { instance, keys } = await verifier();
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-root-"));
  const path = join(directory, "sample.txt");
  await writeFile(path, "hello");
  const document = policyDocument();
  document.principal_grants[0]!.scopes.push("mac.files.read");
  document.filesystem_roots.push({
    root_id: "test-root",
    path: directory,
    metadata: true,
    content_read: true,
    deny_relative_paths: []
  });
  document.target_rules.push({
    rule_id: "allow-test-root",
    effect: "allow",
    principal_id: "principal-1",
    scope: "mac.files.read",
    target: { kind: "path", reference: "test-root" }
  });
  document.tool_enablement.push({ tool: "mac_stat_path", enabled: true });
  const manager = new PolicyManager(createDefaultPolicy("edge-1"));
  manager.activate(instance.verify(signedBundle(document, keys.privateKey)));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  const broker = new Broker({ store, policy: manager, edgeAuthenticationKeys: testKeyring(edgeKey), now: () => NOW });
  try {
    const request = unsignedRequest();
    request.tool = "mac_stat_path";
    request.arguments = { path };
    request.principal = { ...request.principal, scopes: ["mac.files.read"] };
    const result = await broker.handle(signRequest(request, edgeKey));
    assert.equal(result.ok, true);
    if (result.ok) assert.equal((result.data as { path: string }).path, await realpath(path));
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy verification rejects tampering, unknown fields, and unimplemented enablement", async () => {
  const { instance, keys } = await verifier();
  const logPolicy = policyDocument();
  logPolicy.principal_grants[0]!.scopes.push("mac.log.read");
  logPolicy.target_rules.push({
    rule_id: "allow-system-log",
    effect: "allow",
    principal_id: "principal-1",
    scope: "mac.log.read",
    target: { kind: "log_source", reference: "system" }
  });
  logPolicy.tool_enablement.push({ tool: "mac_log_tail", enabled: true });
  assert.equal(instance.verify(signedBundle(logPolicy, keys.privateKey)).policy.tools.get("mac_log_tail")?.enabled, true);

  const bundle = signedBundle(policyDocument(), keys.privateKey);
  bundle.payload.audience = "altered-audience";
  assert.throws(() => instance.verify(bundle), /digest does not match/u);

  const unknownField = signedBundle(policyDocument(), keys.privateKey) as SignedPolicyBundle & { unexpected?: boolean };
  unknownField.unexpected = true;
  assert.throws(() => instance.verify(unknownField), /schema validation failed/u);

  const document = policyDocument();
  document.tool_enablement.push({ tool: "mac_ui_type", enabled: true });
  assert.throws(() => instance.verify(signedBundle(document, keys.privateKey)), /cannot enable an unimplemented tool/u);

  const invalidRoot = policyDocument();
  invalidRoot.filesystem_roots.push({
    root_id: "root-1",
    path: "/tmp/../etc",
    metadata: true,
    content_read: false,
    deny_relative_paths: []
  });
  assert.throws(() => instance.verify(signedBundle(invalidRoot, keys.privateKey)), /not lexically normalized/u);

  const invalidProject = policyDocument();
  invalidProject.principal_grants[0]!.scopes.push("mac.git.read");
  invalidProject.target_rules.push({
    rule_id: "invalid-project-target",
    effect: "allow",
    principal_id: "principal-1",
    scope: "mac.git.read",
    target: { kind: "project", reference: "/tmp/../etc" }
  });
  assert.throws(() => instance.verify(signedBundle(invalidProject, keys.privateKey)), /Project target rule is not a canonical absolute path/u);

  const invalidApp = policyDocument();
  invalidApp.principal_grants[0]!.scopes.push("mac.app.control");
  invalidApp.target_rules.push({
    rule_id: "invalid-app-target",
    effect: "allow",
    principal_id: "principal-1",
    scope: "mac.app.control",
    target: { kind: "app", reference: "com.example.Editor" }
  });
  assert.throws(() => instance.verify(signedBundle(invalidApp, keys.privateKey)), /schema validation failed/u);

  const invalidAppWindow = policyDocument();
  invalidAppWindow.principal_grants[0]!.scopes.push("mac.ui.observe");
  invalidAppWindow.target_rules.push({
    rule_id: "invalid-app-window-target",
    effect: "allow",
    principal_id: "principal-1",
    scope: "mac.ui.observe",
    target: { kind: "app_window", reference: "window:com.example.Editor" }
  });
  assert.throws(() => instance.verify(signedBundle(invalidAppWindow, keys.privateKey)), /schema validation failed/u);
});

test("policy verifier supports bounded signing-key rotation and revocation", async () => {
  const first = generateKeyPairSync("ed25519");
  const second = generateKeyPairSync("ed25519");
  let revoked = false;
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-rotation-"));
  try {
    const firstPath = join(directory, "policy-key-1.pem");
    const secondPath = join(directory, "policy-key-2.pem");
    await writeFile(firstPath, first.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    await writeFile(secondPath, second.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    const instance = await PolicyBundleVerifier.createFromKeyFiles({
      schemaDirectory: join(repositoryRoot, "schemas"),
      keys: [
        { keyId: "policy-key-1", publicKeyPath: firstPath, notBeforeMs: NOW - 60_000, expiresAtMs: NOW + 60_000 },
        { keyId: "policy-key-2", publicKeyPath: secondPath, notBeforeMs: NOW, expiresAtMs: NOW + 60_000 }
      ],
      revocationCheck: (keyId) => revoked && keyId === "policy-key-1",
      now: () => NOW
    });
    assert.equal(instance.verify(signedBundle(policyDocument(), first.privateKey, "policy-key-1")).keyId, "policy-key-1");
    assert.equal(instance.verify(signedBundle(policyDocument(), second.privateKey, "policy-key-2")).keyId, "policy-key-2");
    revoked = true;
    assert.throws(
      () => instance.verify(signedBundle(policyDocument(), first.privateKey, "policy-key-1")),
      /signing key is revoked/u
    );
    const unknown = generateKeyPairSync("ed25519");
    assert.throws(
      () => instance.verify(signedBundle(policyDocument(), unknown.privateKey, "policy-key-3")),
      /key ID is not trusted/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy verifier rejects signing keys outside their validity window", async () => {
  const keys = generateKeyPairSync("ed25519");
  const instance = await PolicyBundleVerifier.create({
    schemaDirectory: join(repositoryRoot, "schemas"),
    trustedKeys: [{
      keyId: "policy-key-future",
      publicKeyPem: keys.publicKey.export({ type: "spki", format: "pem" }),
      notBeforeMs: NOW + 60_001,
      expiresAtMs: NOW + 120_000
    }],
    now: () => NOW,
    allowedClockSkewMs: 5_000
  });
  assert.throws(
    () => instance.verify(signedBundle(policyDocument(), keys.privateKey, "policy-key-future")),
    /outside its validity window/u
  );
});

test("policy manager rejects downgrade or same-revision replacement by default", async () => {
  const { instance, keys } = await verifier();
  const verified = instance.verify(signedBundle(policyDocument(), keys.privateKey));
  const manager = new PolicyManager(createDefaultPolicy("edge-1"));
  manager.activate(verified);
  assert.throws(() => manager.activate(verified), /revision must increase/u);
});

test("policy activation persists intent, active identity, completion, and restart matching", async () => {
  const { instance, keys } = await verifier();
  const verified = instance.verify(signedBundle(policyDocument(), keys.privateKey));
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-ledger-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  try {
    const manager = new PolicyManager(createDefaultPolicy("edge-1"), store, () => NOW);
    manager.activate(verified);
    assert.deepEqual(store.activePolicyIdentity(), {
      revision: 1,
      version: "policy-1",
      payloadDigest: verified.payloadDigest,
      keyId: "policy-key-1",
      activatedAtMs: NOW
    });
    assert.deepEqual(store.auditRows().map((row) => [row.event_type, row.result_class]), [
      ["intent", "INTENT_RECORDED"],
      ["completion", "SUCCEEDED"]
    ]);
    store.close();
    store = new BrokerStore(databasePath);
    const restored = new PolicyManager(createDefaultPolicy("edge-1"), store, () => NOW);
    restored.restore(verified);
    assert.equal(restored.current().version, "policy-1");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy restart restore rejects a different verified payload", async () => {
  const { instance, keys } = await verifier();
  const verified = instance.verify(signedBundle(policyDocument(), keys.privateKey));
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-mismatch-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const manager = new PolicyManager(createDefaultPolicy("edge-1"), store, () => NOW);
    manager.activate(verified);
    const changed = policyDocument();
    changed.revision = 2;
    const different = instance.verify(signedBundle(changed, keys.privateKey));
    const restored = new PolicyManager(createDefaultPolicy("edge-1"), store, () => NOW);
    assert.throws(() => restored.restore(different), /does not match persisted/u);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy rollback requires verified history, current revision, and durable audit", async () => {
  const { instance, keys } = await verifier();
  const revisionOne = instance.verify(signedBundle(policyDocument(), keys.privateKey));
  const nextDocument = policyDocument();
  nextDocument.revision = 2;
  const revisionTwo = instance.verify(signedBundle(nextDocument, keys.privateKey));
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-rollback-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const manager = new PolicyManager(createDefaultPolicy("edge-1"), store, () => NOW);
    manager.activate(revisionOne);
    manager.activate(revisionTwo);
    assert.throws(
      () => manager.rollback(revisionOne, { expectedCurrentRevision: 99, reasonCode: "OPERATOR_RECOVERY" }),
      /does not match rollback precondition/u
    );
    manager.rollback(revisionOne, { expectedCurrentRevision: 2, reasonCode: "OPERATOR_RECOVERY" });
    assert.equal(manager.current().revision, 1);
    assert.equal(store.activePolicyIdentity()?.payloadDigest, revisionOne.payloadDigest);
    assert.deepEqual(store.auditRows().slice(-2).map((row) => [row.tool, row.event_type, row.result_class]), [
      ["internal_policy_rollback", "intent", "INTENT_RECORDED"],
      ["internal_policy_rollback", "completion", "SUCCEEDED"]
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("an exact target deny overrides an allow", async () => {
  const { instance, keys } = await verifier();
  const document = policyDocument();
  document.target_rules.push({
    rule_id: "deny-broker-observe",
    effect: "deny",
    principal_id: "principal-1",
    scope: "mac.control.read",
    target: { kind: "host", reference: "broker" }
  });
  const manager = new PolicyManager(createDefaultPolicy("edge-1"));
  manager.activate(instance.verify(signedBundle(document, keys.privateKey)));
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-deny-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  try {
    const broker = new Broker({ store, policy: manager, edgeAuthenticationKeys: testKeyring(edgeKey), now: () => NOW });
    const result = await broker.handle(signRequest(unsignedRequest(), edgeKey));
    assert.equal(result.result_class, "POLICY_DENIED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a signed global kill switch overrides tool enablement", async () => {
  const { instance, keys } = await verifier();
  const document = policyDocument();
  document.kill_switches.global = true;
  const manager = new PolicyManager(createDefaultPolicy("edge-1"));
  manager.activate(instance.verify(signedBundle(document, keys.privateKey)));
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-switch-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  try {
    const broker = new Broker({ store, policy: manager, edgeAuthenticationKeys: testKeyring(edgeKey), now: () => NOW });
    const result = await broker.handle(signRequest(unsignedRequest(), edgeKey));
    assert.equal(result.result_class, "REVOKED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("a request bound to an inactive policy revision fails closed", async () => {
  const { instance, keys } = await verifier();
  const manager = new PolicyManager(createDefaultPolicy("edge-1"));
  manager.activate(instance.verify(signedBundle(policyDocument(), keys.privateKey)));
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-version-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  try {
    const broker = new Broker({ store, policy: manager, edgeAuthenticationKeys: testKeyring(edgeKey), now: () => NOW });
    const request = unsignedRequest();
    request.policyVersion = "policy-0.1";
    const result = await broker.handle(signRequest(request, edgeKey));
    assert.equal(result.result_class, "POLICY_DENIED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("signed policy Edge-key expiry overrides a still-loaded local key", async () => {
  const { instance, keys } = await verifier();
  const document = policyDocument();
  document.trusted_edge_keys[0]!.expires_at_ms = NOW;
  const manager = new PolicyManager(createDefaultPolicy("edge-1"));
  manager.activate(instance.verify(signedBundle(document, keys.privateKey)));
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-edge-expiry-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  try {
    const broker = new Broker({ store, policy: manager, edgeAuthenticationKeys: testKeyring(edgeKey), now: () => NOW });
    const result = await broker.handle(signRequest(unsignedRequest(), edgeKey));
    assert.equal(result.result_class, "AUTH_EXPIRED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy file loading rejects weak permissions and symlinks", async () => {
  const { instance, keys } = await verifier();
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-file-"));
  const path = join(directory, "policy.json");
  const link = join(directory, "policy-link.json");
  try {
    await writeFile(path, JSON.stringify(signedBundle(policyDocument(), keys.privateKey)), { mode: 0o600 });
    assert.equal((await instance.verifyFile(path)).policy.version, "policy-1");
    await chmod(path, 0o660);
    await assert.rejects(instance.verifyFile(path), /must not be writable/u);
    await chmod(path, 0o600);
    await symlink(path, link);
    await assert.rejects(instance.verifyFile(link), /non-symlink/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("policy verification key file requires protected ownership and mode", async () => {
  const keys = generateKeyPairSync("ed25519");
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-key-"));
  const keyPath = join(directory, "policy-public.pem");
  try {
    await writeFile(keyPath, keys.publicKey.export({ type: "spki", format: "pem" }), { mode: 0o600 });
    const instance = await PolicyBundleVerifier.createFromKeyFile({
      schemaDirectory: join(repositoryRoot, "schemas"),
      expectedKeyId: "policy-key-1",
      publicKeyPath: keyPath,
      now: () => NOW
    });
    assert.equal(instance.verify(signedBundle(policyDocument(), keys.privateKey)).policy.revision, 1);
    await chmod(keyPath, 0o666);
    await assert.rejects(
      PolicyBundleVerifier.createFromKeyFile({
        schemaDirectory: join(repositoryRoot, "schemas"),
        expectedKeyId: "policy-key-1",
        publicKeyPath: keyPath,
        now: () => NOW
      }),
      /must not be writable/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function unsignedRequest(): UnsignedBrokerRequest {
  return {
    protocolVersion: "0.1",
    requestId: "policy-request-1",
    contractVersion: "0.1",
    tool: "mac_health",
    arguments: {},
    principal: {
      principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer",
      audience: "mac-operator-broker", scopes: ["mac.control.read"],
      issuedAtMs: NOW - 1_000, expiresAtMs: NOW + 60_000, edgeId: "edge-1"
    },
    timestampMs: NOW,
    nonce: "policy-nonce-1",
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-1",
    authenticationKeyId: "edge-key-1"
  };
}

function testKeyring(key: Buffer): EdgeKeyring {
  return new EdgeKeyring([{
    edgeId: "edge-1", keyId: "edge-key-1", key,
    notBeforeMs: NOW - 60_000, expiresAtMs: NOW + 60_000
  }]);
}
