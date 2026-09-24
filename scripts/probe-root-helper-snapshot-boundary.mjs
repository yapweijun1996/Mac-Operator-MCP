import assert from "node:assert/strict";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { constants, openSync, closeSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  DescriptorSnapshotAttestationVerifier,
  RootHelperSnapshotServer,
  getDescriptorPath
} from "@mac-operator/broker";

assert.equal(process.platform, "darwin", "This probe requires macOS");
const root = await mkdtemp(join(tmpdir(), "mac-operator-root-helper-probe-"));
const socketPath = join(tmpdir(), "mop-root-helper-probe.sock");
const keyPair = generateKeyPairSync("ed25519");
const verifier = DescriptorSnapshotAttestationVerifier.create({
  trustedKeys: [{ keyId: "probe-key", publicKey: keyPair.publicKey }]
});
const server = new RootHelperSnapshotServer({
  socketPath,
  authenticationKey: randomBytes(32),
  peerPolicy: { expectedUid: process.getuid?.() ?? 0 },
  verifier,
  snapshotRoot: root,
  sandboxPolicies: new Map([[
    "probe.echo",
    {
      profile: "probe.echo",
      sandboxProfile: "task-deny-default-v0.1",
      filesystemRoots: [root],
      networkPolicy: "none",
      networkAllowlist: [],
      processTreePolicy: "single_process"
    }
  ]]),
  enabled: true,
  hostEvidenceAccepted: true,
  releaseMode: "development-probe",
  evidenceRef: "evidence://root-helper-snapshot-boundary"
});
const directoryFd = openSync(process.cwd(), constants.O_RDONLY | constants.O_DIRECTORY);
let startResult = "not_attempted";
try {
  assert.equal(server.available, false, "The non-root probe host must not advertise the root helper");
  assert.equal(server.capability.available, false);
  try {
    await server.listen();
  } catch (error) {
    startResult = error?.errorClass ?? "POLICY_DENIED";
  }
  assert.equal(startResult, "POLICY_DENIED");
  assert.equal(getDescriptorPath(directoryFd), process.cwd());
  console.log(JSON.stringify({
    schema_version: "0.1",
    probe: "root-helper-snapshot-boundary",
    platform: process.platform,
    arch: process.arch,
    uid: process.getuid?.() ?? null,
    root_owned_snapshot_gate: "unavailable",
    server_available: server.available,
    server_start: startResult,
    capability: server.capability,
    descriptor_path_readback: "verified",
    public_task_scope: "disabled"
  }, null, 2));
} finally {
  closeSync(directoryFd);
  await server.close();
  await rm(root, { recursive: true, force: true });
}
