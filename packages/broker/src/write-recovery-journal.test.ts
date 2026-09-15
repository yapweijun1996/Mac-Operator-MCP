import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import { sha256 } from "@mac-operator/contracts";

const principalId = "principal-1";

function policyFor(root: string) {
  return createDefaultPolicy(
    "edge-1",
    true,
    ["mac.files.write", "mac.job.read"],
    ["edge-key-1"],
    [{ rootId: "test-root", path: root, metadata: true, contentRead: false, write: true, denyRelativePaths: [] }]
  );
}

async function reopenUnknownJob(directory: string, jobId: string, temporaryName: string, target: string, metadataExtras: Record<string, unknown> = {}) {
  const databasePath = join(directory, "broker.sqlite");
  const createdAtMs = Date.now() - 2_000;
  const store = new BrokerStore(databasePath);
  store.createJob({
    jobId,
    ownerPrincipalId: principalId,
    ownerSessionId: "session-1",
    tool: "mac_write_file_atomic",
    targetRef: "path:test-root",
    policyVersion: "policy-0.1",
    payloadDigest: "a".repeat(64),
    idempotencyKey: jobId.slice(4),
    createdAtMs,
    writeMetadata: {
      rootId: "test-root",
      path: target,
      bytes: 6,
      desiredSha256: sha256(Buffer.from("orphan")),
      expectedSha256: null,
      createOnly: true,
      temporaryName,
      ...metadataExtras
    }
  });
  store.startJob(jobId, principalId, 0, createdAtMs + 1);
  store.close();
  return new BrokerStore(databasePath);
}

test("restart cleanup journals the temporary identity before unlink", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("requires the macOS native filesystem adapter");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-write-journal-"));
  const temporaryName = ".mac-operator-write-journal";
  const temporaryPath = join(directory, temporaryName);
  const target = join(directory, "target.txt");
  let store: BrokerStore | undefined;
  let broker: Broker | undefined;
  try {
    await writeFile(temporaryPath, "orphan", { mode: 0o600 });
    const identity = await lstat(temporaryPath);
    store = await reopenUnknownJob(directory, "job:write-journal", temporaryName, target);
    broker = new Broker({
      store,
      policy: policyFor(directory),
      edgeAuthenticationKeys: {} as EdgeKeyring,
      now: () => Date.now()
    });

    assert.deepEqual(broker.reconcileRestartedWriteArtifacts(), { inspected: 1, removed: 1, absent: 0, skipped: 0 });
    const job = store.ownedJob("job:write-journal", principalId);
    assert.equal(job?.writeMetadata?.temporaryDevice, String(identity.dev));
    assert.equal(job?.writeMetadata?.temporaryInode, String(identity.ino));
    assert.match(job?.writeMetadata?.temporaryInode ?? "", /^\d+$/u);
    assert.ok(Number.isSafeInteger(job?.writeMetadata?.temporaryRecoveryRecordedAtMs));
    await assert.rejects(readFile(temporaryPath), /ENOENT/u);
    assert.equal(store.auditEventResult("job-temp-cleanup-job:write-journal-2", "completion"), "TEMPORARY_REMOVED");
  } finally {
    await broker?.close().catch(() => undefined);
    store?.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("restart cleanup recovers a stale native unlink quarantine from the journal", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("requires the macOS native filesystem adapter");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-write-orphan-"));
  const temporaryName = ".mac-operator-write-orphan";
  const target = join(directory, "target.txt");
  const quarantineName = `.mac-operator-unlink-${Date.now() - 120_000}-0123456789abcdef-${createHash("sha256").update(temporaryName, "utf8").digest("hex")}`;
  const quarantinePath = join(directory, quarantineName);
  let store: BrokerStore | undefined;
  let broker: Broker | undefined;
  try {
    await writeFile(quarantinePath, "orphan", { mode: 0o600 });
    const identity = await lstat(quarantinePath);
    store = await reopenUnknownJob(directory, "job:write-orphan", temporaryName, target, {
      temporaryDevice: String(identity.dev),
      temporaryInode: String(identity.ino),
      temporaryRecoveryRecordedAtMs: Date.now() - 120_000
    });
    broker = new Broker({
      store,
      policy: policyFor(directory),
      edgeAuthenticationKeys: {} as EdgeKeyring,
      now: () => Date.now()
    });

    assert.deepEqual(broker.reconcileRestartedWriteArtifacts(), { inspected: 1, removed: 1, absent: 0, skipped: 0 });
    await assert.rejects(lstat(quarantinePath), /ENOENT/u);
    assert.equal(store.auditEventResult("job-temp-cleanup-job:write-orphan-2", "completion"), "TEMPORARY_RECOVERED");
    const evidence = store.auditRows().find((row) => row.request_id === "job-temp-cleanup-job:write-orphan-2" && row.event_type === "completion");
    assert.match(String(evidence?.evidence_json ?? ""), /"recoveryStatus":"recovered"/u);
  } finally {
    await broker?.close().catch(() => undefined);
    store?.close();
    await rm(directory, { recursive: true, force: true });
  }
});
