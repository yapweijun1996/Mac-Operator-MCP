import assert from "node:assert/strict";
import { lstat } from "node:fs/promises";
import { mkdtemp, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { FilesystemInspector } from "./filesystem-inspector.js";
import { BrokerStore } from "./persistence.js";

test("restart write recovery rejects a replacement policy root", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("requires the macOS native filesystem adapter");
    return;
  }
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-write-root-recovery-"));
  const directory = join(parent, "allowed");
  const movedDirectory = join(parent, "allowed-moved");
  const target = join(directory, "target.txt");
  const temporaryName = ".mac-operator-write-root-recovery";
  const replacementTemporaryPath = join(directory, temporaryName);
  const databasePath = join(parent, "broker.sqlite");
  let store: BrokerStore | undefined;
  let broker: Broker | undefined;
  try {
    await mkdir(directory, { mode: 0o700 });
    const plan = new FilesystemInspector([{
      rootId: "test-root",
      path: directory,
      metadata: true,
      contentRead: false,
      write: true,
      denyRelativePaths: []
    }]).planPath(target, "write");
    const rootStat = await lstat(directory);
    assert.equal(plan.rootIdentity.device, String(rootStat.dev));
    assert.equal(plan.rootIdentity.inode, String(rootStat.ino));

    await writeFile(replacementTemporaryPath, "replacement", { mode: 0o600 });
    store = new BrokerStore(databasePath);
    store.createJob({
      jobId: "job:write-root-recovery",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_write_file_atomic",
      targetRef: "path:test-root",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      idempotencyKey: "write-root-recovery",
      createdAtMs: 1,
      writeMetadata: {
        rootId: plan.rootId,
        rootPath: plan.rootIdentity.rootPath,
        rootDevice: plan.rootIdentity.device,
        rootInode: plan.rootIdentity.inode,
        path: target,
        bytes: 11,
        desiredSha256: "b".repeat(64),
        expectedSha256: null,
        createOnly: true,
        temporaryName
      }
    });
    store.startJob("job:write-root-recovery", "principal-1", 0, 2);
    store.close();
    store = new BrokerStore(databasePath);

    await rename(directory, movedDirectory);
    await mkdir(directory, { mode: 0o700 });
    await writeFile(replacementTemporaryPath, "replacement", { mode: 0o600 });
    broker = new Broker({
      store,
      policy: createDefaultPolicy(
        "edge-1",
        true,
        ["mac.files.write", "mac.job.read"],
        ["edge-key-1"],
        [{ rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] }]
      ),
      edgeAuthenticationKeys: {} as EdgeKeyring
    });

    assert.deepEqual(broker.reconcileRestartedWriteArtifacts(), { inspected: 1, removed: 0, absent: 0, skipped: 1 });
    assert.equal(await readFile(replacementTemporaryPath, "utf8"), "replacement");
  } finally {
    await broker?.close().catch(() => undefined);
    store?.close();
    await rm(parent, { recursive: true, force: true });
  }
});
