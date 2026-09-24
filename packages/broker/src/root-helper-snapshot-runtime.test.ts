import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import { DescriptorSnapshotAttestationVerifier } from "./descriptor-snapshot-attestation.js";
import { capturePeerProcessIdentity } from "./peer-credentials.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { writePrivilegedHelperKeyConfig, type PrivilegedHelperKeyConfig } from "./privileged-helper-keyring.js";
import {
  createRootHelperSnapshotRuntimeFromKeyMaterial,
  RootHelperSnapshotRuntime,
  RootHelperSnapshotRuntimeStartupError
} from "./root-helper-snapshot-runtime.js";
import type { RootHelperSnapshotServer } from "./root-helper-snapshot-transport.js";
import type { RootHelperSnapshotStatusIpcServer } from "./root-helper-snapshot-status-ipc.js";

function currentPeerPolicy() {
  return {
    expectedUid: process.getuid?.() ?? 1,
    ...(process.getgid?.() === undefined ? {} : { expectedGid: process.getgid() }),
    allowedProcessIdentity: capturePeerProcessIdentity(process.pid)
  };
}

function verifier(): DescriptorSnapshotAttestationVerifier {
  const keyPair = generateKeyPairSync("ed25519");
  return DescriptorSnapshotAttestationVerifier.create({
    trustedKeys: [{ keyId: "snapshot-test-key", publicKey: keyPair.publicKey }]
  });
}

test("root-helper snapshot runtime loads protected key material but stays unavailable on a non-root host", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-runtime-"));
  const keyPath = join(root, "helper.key");
  const configPath = join(root, "helper-keys.json");
  const snapshotRoot = join(root, "snapshots");
  const socketPath = join(root, "helper.sock");
  const brokerSocketPath = join(root, "broker.sock");
  const authoritySocketPath = join(root, "authority.sock");
  const now = Date.now();
  try {
    const provisioned = await provisionAuthenticationKey(keyPath);
    const key = await loadAuthenticationKey(keyPath);
    const config: PrivilegedHelperKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        keyId: "snapshot-helper-key",
        keySource: "file",
        path: keyPath,
        keyDigest: sha256(key),
        notBeforeMs: now - 1_000,
        expiresAtMs: now + 60_000
      }]
    };
    key.fill(0);
    await writePrivilegedHelperKeyConfig(configPath, config);
    const runtime = await createRootHelperSnapshotRuntimeFromKeyMaterial({
      helperKeyConfigPath: configPath,
      socketPath,
      brokerSocketPath,
      authoritySocketPath,
      peerPolicy: currentPeerPolicy(),
      verifier: verifier(),
      snapshotRoot,
      sandboxPolicies: new Map([[
        "tests.echo",
        {
          profile: "tests.echo",
          sandboxProfile: "task-deny-default-v0.1",
          filesystemRoots: [root],
          networkPolicy: "none",
          networkAllowlist: [],
          processTreePolicy: "single_process"
        }
      ]]),
      enabled: true,
      hostEvidenceAccepted: true,
      sandboxIsolationAccepted: true,
      sandboxEvidenceRef: "evidence://root-helper-sandbox-test",
      attestationVerificationAccepted: true,
      attestationEvidenceRef: "evidence://root-helper-attestation-test",
      evidenceRef: "evidence://root-helper-runtime-test"
    });
    assert.equal(runtime.state, "stopped");
    assert.equal(runtime.available, false);
    assert.equal(runtime.capability.available, false);
    await assert.rejects(
      runtime.start(),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    await runtime.close();
    assert.equal(provisioned.digest, config.keys[0].keyDigest);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("root-helper snapshot runtime rejects enabled startup without supported sandbox evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-runtime-sandbox-gate-"));
  try {
    await assert.rejects(
      createRootHelperSnapshotRuntimeFromKeyMaterial({
        helperKeyConfigPath: join(root, "missing.json"),
        socketPath: join(root, "helper.sock"),
        brokerSocketPath: join(root, "broker.sock"),
        peerPolicy: currentPeerPolicy(),
        verifier: verifier(),
        snapshotRoot: root,
        sandboxPolicies: new Map(),
        enabled: true,
        hostEvidenceAccepted: true
      }),
      (error: unknown) => error instanceof RootHelperSnapshotRuntimeStartupError && error.code === "SANDBOX_UNAVAILABLE"
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("root-helper snapshot runtime rejects enabled startup without native attestation verification evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-runtime-attestation-gate-"));
  try {
    await assert.rejects(
      createRootHelperSnapshotRuntimeFromKeyMaterial({
        helperKeyConfigPath: join(root, "missing.json"),
        socketPath: join(root, "helper.sock"),
        brokerSocketPath: join(root, "broker.sock"),
        peerPolicy: currentPeerPolicy(),
        verifier: verifier(),
        snapshotRoot: root,
        sandboxPolicies: new Map(),
        enabled: true,
        hostEvidenceAccepted: true,
        sandboxIsolationAccepted: true,
        sandboxEvidenceRef: "evidence://root-helper-sandbox-test"
      }),
      (error: unknown) => error instanceof RootHelperSnapshotRuntimeStartupError && error.code === "ATTESTATION_VERIFICATION_UNAVAILABLE"
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("root-helper snapshot runtime rejects socket identity reuse before loading key material", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-runtime-boundary-"));
  try {
    await assert.rejects(
      createRootHelperSnapshotRuntimeFromKeyMaterial({
        helperKeyConfigPath: join(root, "missing.json"),
        socketPath: join(root, "same.sock"),
        brokerSocketPath: join(root, "same.sock"),
        peerPolicy: currentPeerPolicy(),
        verifier: verifier(),
        snapshotRoot: root,
        sandboxPolicies: new Map()
      }),
      (error: unknown) => error instanceof RootHelperSnapshotRuntimeStartupError && error.code === "SOCKET_INVALID"
    );
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("root-helper snapshot runtime fails closed before listening when status metadata is unbound", async () => {
  const events: string[] = [];
  const server = fakeRuntimeServer(events);
  const statusServer = fakeStatusServer(events);
  const runtime = new RootHelperSnapshotRuntime(
    server,
    statusServer,
    { value: "stopped" },
    { value: undefined }
  );

  await assert.rejects(
    runtime.start(),
    (error: unknown) => error instanceof RootHelperSnapshotRuntimeStartupError &&
      error.code === "SERVER_UNAVAILABLE" &&
      error.message === "Root-helper status metadata is not bound"
  );
  assert.deepEqual(events, ["status-close", "server-close"]);
  assert.equal(runtime.state, "stopped");
});

test("root-helper snapshot runtime rejects status metadata changes after startup", async () => {
  const events: string[] = [];
  const server = fakeRuntimeServer(events);
  const statusServer = fakeStatusServer(events);
  const runtime = new RootHelperSnapshotRuntime(
    server,
    statusServer,
    { value: "stopped" },
    {
      value: {
        sourceRevision: "0123456789abcdef0123456789abcdef01234567",
        contractVersion: "0.1",
        evidenceRef: "evidence://root-helper-status-test"
      }
    }
  );

  await runtime.start();
  assert.equal(runtime.state, "running");
  assert.throws(
    () => runtime.setStatusMetadata({
      sourceRevision: "fedcba9876543210fedcba9876543210fedcba98",
      contractVersion: "0.1",
      evidenceRef: "evidence://root-helper-status-replaced"
    }),
    (error: unknown) => error instanceof RootHelperSnapshotRuntimeStartupError &&
      error.code === "SERVER_UNAVAILABLE"
  );
  await runtime.close();
  assert.equal(runtime.state, "stopped");
  assert.deepEqual(events, ["server-listen", "status-listen", "status-close", "server-close"]);
});

function fakeRuntimeServer(events: string[]): RootHelperSnapshotServer {
  return {
    available: true,
    capability: {} as RootHelperSnapshotServer["capability"],
    async listen() { events.push("server-listen"); },
    async close() { events.push("server-close"); }
  } as unknown as RootHelperSnapshotServer;
}

function fakeStatusServer(events: string[]): RootHelperSnapshotStatusIpcServer {
  return {
    async listen() { events.push("status-listen"); },
    async close() { events.push("status-close"); }
  } as unknown as RootHelperSnapshotStatusIpcServer;
}
