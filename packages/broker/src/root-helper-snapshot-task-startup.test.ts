import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { BrokerStore } from "./persistence.js";
import { DescriptorSnapshotAttestationSigner, DescriptorSnapshotAttestationVerifier } from "./descriptor-snapshot-attestation.js";
import { createRootHelperSnapshotTaskRunnerFromActiveKeyConfig } from "./root-helper-snapshot-task-startup.js";

test("root-helper task startup assembles a disabled runner without key or launchd dependencies", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-task-startup-"));
  const store = new BrokerStore(join(root, "broker.sqlite"));
  try {
    const assembly = await createRootHelperSnapshotTaskRunnerFromActiveKeyConfig({
      store,
      startup: { enabled: false, hostEvidenceAccepted: false }
    });
    assert.equal(assembly.taskRunner.available, false);
    assert.equal(assembly.executor.available, false);
    assert.equal(assembly.snapshotRegistry.available, false);
    assert.equal(assembly.transport.capability.available, false);
    await assembly.taskRunner.close();
  } finally {
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("enabled root-helper task startup requires independent capability evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-task-startup-gate-"));
  const store = new BrokerStore(join(root, "broker.sqlite"));
  try {
    const keyPair = generateKeyPairSync("ed25519");
    const signer = new DescriptorSnapshotAttestationSigner({ keyId: "snapshot-test-key", privateKey: keyPair.privateKey });
    const verifier = DescriptorSnapshotAttestationVerifier.create({
      trustedKeys: [{ keyId: "snapshot-test-key", publicKey: keyPair.publicKey }]
    });
    await assert.rejects(
      createRootHelperSnapshotTaskRunnerFromActiveKeyConfig({
        store,
        startup: {
          enabled: true,
          hostEvidenceAccepted: true,
          signer,
          verifier,
          socketPath: join(root, "helper.sock"),
          brokerSocketPath: join(root, "broker.sock"),
          helperKeyConfigPath: join(root, "helper-keys.json"),
          rootHelperServiceId: "system/com.mac-operator.root-helper-snapshot"
        }
      }),
      /independent capability evidence/u
    );
  } finally {
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});
