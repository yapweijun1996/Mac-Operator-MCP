import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { lstat, mkdtemp, realpath, readdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import { sha256 } from "@mac-operator/contracts";

const require = createRequire(import.meta.url);

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
  const rootIdentity = await lstat(directory);
  const canonicalRoot = await realpath(directory);
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
      rootPath: canonicalRoot,
      rootDevice: String(rootIdentity.dev),
      rootInode: String(rootIdentity.ino),
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

    const reconciliation = broker.reconcileRestartedWriteArtifacts();
    assert.deepEqual(reconciliation, { inspected: 1, removed: 1, absent: 0, skipped: 0 }, JSON.stringify(store.auditRows()));
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

const crashChildSource = `
  const { createRequire } = await import("node:module");
  const require = createRequire(import.meta.url);
  const configuration = JSON.parse(process.env.MOPS_WRITE_CRASH_CASE || "{}");
  const { BrokerStore } = await import(configuration.persistenceModule);
  const { FilesystemInspector } = await import(configuration.filesystemModule);
  const native = require(configuration.nativePath);
  native.setWriteFaultPoint("after_unlink_quarantine_rename");
  const store = new BrokerStore(configuration.databasePath);
  const job = store.ownedJob(configuration.jobId, configuration.principalId);
  if (!job || !job.writeMetadata || !job.writeMetadata.temporaryName) throw new Error("crash fixture Job metadata is missing");
  const inspector = new FilesystemInspector([configuration.root], native);
  const plan = inspector.planPath(job.writeMetadata.path, "write");
  inspector.cleanupWriteTemporary(plan, job.writeMetadata.temporaryName, (artifact) => {
    store.recordWriteUnlinkRecovery(job.jobId, job.ownerPrincipalId, job.revision, {
      device: artifact.device,
      inode: artifact.inode
    }, Date.now());
  });
`;

function runWriteCrashChild(configuration: {
  databasePath: string;
  jobId: string;
  principalId: string;
  root: {
    rootId: string;
    path: string;
    metadata: boolean;
    contentRead: boolean;
    write: boolean;
    denyRelativePaths: readonly string[];
  };
  nativePath: string;
  persistenceModule: string;
  filesystemModule: string;
}): Promise<{ code: number | null; signal: NodeJS.Signals | null; stderr: string }> {
  const child = spawn(process.execPath, ["--input-type=module", "--eval", crashChildSource], {
    cwd: process.cwd(),
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      MOPS_WRITE_CRASH_CASE: JSON.stringify(configuration)
    },
    stdio: ["ignore", "ignore", "pipe"]
  });
  return new Promise((resolve, reject) => {
    let settled = false;
    let stderr = "";
    child.stderr?.setEncoding("utf8");
    child.stderr?.on("data", (chunk: string) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill("SIGKILL"), 5_000);
    child.once("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (code, signal) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ code, signal, stderr });
    });
  });
}

test("a process crash after native quarantine rename is recovered from persisted Job identity", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("requires the macOS native filesystem adapter");
    return;
  }
  let nativePath: string;
  try {
    nativePath = require.resolve("./peer_credentials_fault.node");
  } catch {
    t.skip("requires the opt-in native fault-injection adapter");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-write-crash-"));
  const temporaryName = ".mac-operator-write-crash";
  const temporaryPath = join(directory, temporaryName);
  const target = join(directory, "target.txt");
  const databasePath = join(directory, "broker.sqlite");
  let store: BrokerStore | undefined;
  let broker: Broker | undefined;
  try {
    await writeFile(temporaryPath, "orphan", { mode: 0o600 });
    store = await reopenUnknownJob(directory, "job:write-crash", temporaryName, target);
    store.close();
    store = undefined;
    const childResult = await runWriteCrashChild({
      databasePath,
      jobId: "job:write-crash",
      principalId,
      root: { rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] },
      nativePath,
      persistenceModule: new URL("./persistence.js", import.meta.url).href,
      filesystemModule: new URL("./filesystem-inspector.js", import.meta.url).href
    });
    assert.equal(childResult.code, null, childResult.stderr);
    assert.equal(childResult.signal, "SIGKILL", childResult.stderr);
    const quarantineEntry = (await readdir(directory)).find((entry) => entry.startsWith(".mac-operator-unlink-"));
    assert.ok(quarantineEntry);
    const agedQuarantineName = `.mac-operator-unlink-${Date.now() - 120_000}-fedcba9876543210-${createHash("sha256").update(temporaryName, "utf8").digest("hex")}`;
    await rename(join(directory, quarantineEntry), join(directory, agedQuarantineName));
    store = new BrokerStore(databasePath);
    broker = new Broker({
      store,
      policy: policyFor(directory),
      edgeAuthenticationKeys: {} as EdgeKeyring,
      now: () => Date.now()
    });
    const reconciliation = broker.reconcileRestartedWriteArtifacts();
    assert.deepEqual(reconciliation, { inspected: 1, removed: 1, absent: 0, skipped: 0 }, JSON.stringify(store.auditRows()));
    await assert.rejects(lstat(temporaryPath), /ENOENT/u);
    assert.equal(store.auditEventResult("job-temp-cleanup-job:write-crash-3", "completion"), "TEMPORARY_RECOVERED");
  } finally {
    await broker?.close().catch(() => undefined);
    store?.close();
    await rm(directory, { recursive: true, force: true });
  }
});
