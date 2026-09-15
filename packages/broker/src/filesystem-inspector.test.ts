import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { appendFileSync } from "node:fs";
import { link, lstat, mkdtemp, mkdir, readFile, readlink, readdir, realpath, rename, rm, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { Worker } from "node:worker_threads";
import { FilesystemInspector, type FilesystemNativeAdapter } from "./filesystem-inspector.js";

const require = createRequire(import.meta.url);

test("native filesystem boundary opens targets relative to a pinned root descriptor", async () => {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const source = await readFile(join(repositoryRoot, "packages/broker/native/peer_credentials.cc"), "utf8");
  assert.match(source, /RelativePathWithinRoot\(resolved_root, canonical_target, relative_target\)/gu);
  assert.match(source, /openat\(root_descriptor, relative_target/u);
  assert.match(source, /openat\(root_descriptor, relative_parent/u);
  assert.equal(source.match(/stat\(canonical_parent_path, &canonical_parent_stat\)/gu)?.length, 3);
  assert.equal(source.match(/SameDirectoryIdentity\(parent_stat, canonical_parent_stat\)/gu)?.length, 3);
  assert.doesNotMatch(source, /int target_descriptor = open\(requested_target/u);
  assert.match(source, /renameatx_np\(parent_descriptor, base_name, parent_descriptor, quarantine_name, RENAME_EXCL\)/u);
  assert.match(source, /linkat\(parent_descriptor, quarantine_name, parent_descriptor, base_name, 0\)/u);
  assert.match(source, /recoverUnlinkFileWithinRoot/u);
  assert.match(source, /\.mac-operator-unlink-%llu-%016llx-%s/u);
  assert.match(source, /after_unlink_quarantine_rename/u);
  assert.match(source, /actual\.f_flags == expected\.f_flags/u);
  assert.match(source, /fsid:%d:%d:flags:%llu/u);
});

const nativeFaultChildSource = `
  const configuration = JSON.parse(process.env.MOP_NATIVE_FAULT_CASE || "{}");
  const native = require(configuration.nativePath);
  native.setWriteFaultPoint(configuration.faultPoint);
  native.writeFileAtomicWithinRoot(
    configuration.root,
    configuration.target,
    Buffer.from(configuration.content, "utf8"),
    configuration.createOnly,
    configuration.expectedPresent,
    configuration.expectedDevice,
    configuration.expectedInode,
    configuration.tempName
  );
`;

function runNativeFaultChild(configuration: {
  nativePath: string;
  root: string;
  target: string;
  content: string;
  createOnly: boolean;
  expectedPresent: boolean;
  expectedDevice: string;
  expectedInode: string;
  tempName: string;
  faultPoint: string;
}, cwd: string): Promise<{ code: number | null; signal: NodeJS.Signals | null }> {
  const child = spawn(process.execPath, ["--eval", nativeFaultChildSource], {
    cwd,
    env: {
      PATH: process.env.PATH ?? "/usr/bin:/bin",
      MOP_NATIVE_FAULT_CASE: JSON.stringify(configuration)
    },
    stdio: "ignore"
  });
  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
    }, 5000);
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
      resolve({ code, signal });
    });
  });
}

test("descriptor-backed metadata returns the opened target identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-stat-"));
  const file = join(directory, "file.txt");
  await writeFile(file, "hello", { mode: 0o600 });
  try {
    const result = new FilesystemInspector([root(directory)]).statPath(file);
    assert.equal(result.rootId, "test-root");
    assert.equal(result.path, await realpath(file));
    assert.equal(result.type, "file");
    assert.equal(result.sizeBytes, 5);
    assert.match(result.inode, /^\d+$/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("filesystem native metadata and volume results reject unstable authority fields", () => {
  const rootPath = "/tmp/mac-operator-native-shape-root";
  const volume = {
    rootPath,
    id: "dev:1:fsid:1:1",
    name: "test",
    mountPath: "/tmp",
    totalBytes: 1_000_000,
    availableBytes: 500_000,
    usedBytes: 500_000
  };
  const metadata = {
    rootPath,
    path: `${rootPath}/file.txt`,
    type: "file" as const,
    sizeBytes: 1,
    modifiedAtMs: 0,
    mode: "0600",
    isSymlink: false,
    device: "1",
    inode: "2"
  };
  const native = {
    statStorageVolumeWithinRoot: () => volume,
    statPathWithinRoot: (_root: string, target: string) => target === rootPath ? {
      rootPath,
      path: rootPath,
      type: "directory" as const,
      sizeBytes: 0,
      modifiedAtMs: 0,
      mode: "0700",
      isSymlink: false,
      device: "1",
      inode: "2"
    } : { ...metadata, extra: "authority" }
  } as unknown as FilesystemNativeAdapter;
  const inspector = new FilesystemInspector([rootPolicy(rootPath)], native);
  assert.throws(() => inspector.statPath(metadata.path), /escaped its authorized root or volume/u);

  const volumeWithExtra = { ...volume, extra: "authority" };
  const volumeNative = { ...native, statStorageVolumeWithinRoot: () => volumeWithExtra } as unknown as FilesystemNativeAdapter;
  assert.throws(() => new FilesystemInspector([rootPolicy(rootPath)], volumeNative).planPath(metadata.path), /volume identity could not be established/u);
});

test("descriptor-backed atomic write creates and verifies a file", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-write-create-"));
  const file = join(directory, "created.txt");
  try {
    const inspector = new FilesystemInspector([writeRoot(directory)]);
    const result = inspector.writePlanned(
      inspector.planPath(file, "write"),
      Buffer.from("hello", "utf8"),
      undefined,
      true,
      ".mac-operator-write-create"
    );
    assert.equal(result.created, true);
    assert.equal(result.bytesWritten, 5);
    assert.equal(result.sha256, createHash("sha256").update("hello").digest("hex"));
    assert.equal((await readFile(file, "utf8")), "hello");
    assert.match(result.device, /^\d+$/u);
    assert.match(result.inode, /^\d+$/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("descriptor-backed atomic write enforces expected hash and create-only preconditions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-write-precondition-"));
  const file = join(directory, "existing.txt");
  await writeFile(file, "before");
  try {
    const inspector = new FilesystemInspector([writeRoot(directory)]);
    const plan = inspector.planPath(file, "write");
    assert.throws(
      () => inspector.writePlanned(plan, Buffer.from("bad"), "0".repeat(64), false, ".mac-operator-write-mismatch"),
      /expected hash did not match/u
    );
    assert.equal(await readFile(file, "utf8"), "before");
    const expected = createHash("sha256").update("before").digest("hex");
    const result = inspector.writePlanned(plan, Buffer.from("after"), expected, false, ".mac-operator-write-replace");
    assert.equal(result.created, false);
    assert.equal(result.expectedMatched, true);
    assert.equal(await readFile(file, "utf8"), "after");
    assert.throws(
      () => inspector.writePlanned(plan, Buffer.from("again"), undefined, true, ".mac-operator-write-create-only"),
      /create-only precondition failed/u
    );
    assert.equal(await readFile(file, "utf8"), "after");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("write postcondition probe distinguishes match, mismatch, and unavailable", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-write-postcondition-"));
  const file = join(directory, "target.txt");
  await writeFile(file, "safe", { mode: 0o600 });
  try {
    const inspector = new FilesystemInspector([writeRoot(directory)]);
    const plan = inspector.planPath(file, "write");
    const desired = createHash("sha256").update("safe").digest("hex");
    assert.equal(inspector.verifyWritePostcondition(plan, desired, 4).status, "matches");
    assert.equal(inspector.verifyWritePostcondition(plan, "0".repeat(64), 4).status, "mismatch");
    await rm(file);
    assert.equal(inspector.verifyWritePostcondition(plan, desired, 4).status, "unavailable");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("write temporary cleanup removes only an exact regular artifact and fails closed on symlinks", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-write-cleanup-"));
  const target = join(directory, "target.txt");
  const temporaryName = ".mac-operator-write-cleanup";
  const temporaryPath = join(directory, temporaryName);
  const outside = join(directory, "outside.txt");
  try {
    await writeFile(temporaryPath, "orphan", { mode: 0o600 });
    const canonicalTemporaryPath = await realpath(temporaryPath);
    const inspector = new FilesystemInspector([writeRoot(directory)]);
    const plan = inspector.planPath(target, "write");
    const removed = inspector.cleanupWriteTemporary(plan, temporaryName);
    assert.equal(removed.status, "removed");
    assert.equal(removed.path, canonicalTemporaryPath);
    await assert.rejects(readFile(temporaryPath), /ENOENT/u);
    assert.deepEqual(inspector.cleanupWriteTemporary(plan, temporaryName), {
      status: "absent",
      path: temporaryPath,
      device: null,
      inode: null
    });

    await writeFile(outside, "outside", { mode: 0o600 });
    await symlink(outside, temporaryPath);
    assert.throws(
      () => inspector.cleanupWriteTemporary(plan, temporaryName),
      /regular non-symlink file/u
    );
    assert.equal(await readFile(outside, "utf8"), "outside");
    assert.equal(await readlink(temporaryPath), outside);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native unlink recovery removes only stale identity-bound quarantine artifacts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-unlink-recovery-"));
  const target = join(directory, "target.txt");
  const basenameHash = createHash("sha256").update("target.txt", "utf8").digest("hex");
  const staleName = `.mac-operator-unlink-${Date.now() - 120_000}-${"a".repeat(16)}-${basenameHash}`;
  const stalePath = join(directory, staleName);
  try {
    const canonicalDirectory = await realpath(directory);
    await writeFile(stalePath, "orphan", { mode: 0o600 });
    const staleIdentity = await lstat(stalePath);
    const inspector = new FilesystemInspector([writeRoot(directory)]);
    const plan = inspector.planPath(target, "write");
    const recovered = inspector.recoverUnlinkOrphan(plan, {
      present: true,
      device: String(staleIdentity.dev),
      inode: String(staleIdentity.ino)
    }, 60_000);
    assert.equal(recovered.status, "recovered");
    assert.equal(recovered.path, join(canonicalDirectory, "target.txt"));
    assert.equal(recovered.device, String(staleIdentity.dev));
    assert.equal(recovered.inode, String(staleIdentity.ino));
    await assert.rejects(readFile(stalePath), /ENOENT/u);

    const recentName = `.mac-operator-unlink-${Date.now()}-${"b".repeat(16)}-${basenameHash}`;
    const recentPath = join(directory, recentName);
    await writeFile(recentPath, "recent", { mode: 0o600 });
    const recentIdentity = await lstat(recentPath);
    const recent = inspector.recoverUnlinkOrphan(plan, {
      present: true,
      device: String(recentIdentity.dev),
      inode: String(recentIdentity.ino)
    }, 60_000);
    assert.equal(recent.status, "not_stale");
    assert.equal(recent.quarantinePath, join(canonicalDirectory, recentName));
    assert.equal(await readFile(recentPath, "utf8"), "recent");

    const wrongPlan = inspector.planPath(join(directory, "other.txt"), "write");
    const wrongTarget = inspector.recoverUnlinkOrphan(wrongPlan, {
      present: true,
      device: String(recentIdentity.dev),
      inode: String(recentIdentity.ino)
    }, 60_000);
    assert.equal(wrongTarget.status, "absent");
    assert.equal(await readFile(recentPath, "utf8"), "recent");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native atomic write survives syscall-level process crash boundaries without partial target state", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-write-crash-boundary-"));
  const nativePath = require.resolve("./peer_credentials_fault.node");
  const productionNative = require("./peer_credentials.node") as Record<string, unknown>;
  assert.equal(Object.prototype.hasOwnProperty.call(productionNative, "setWriteFaultPoint"), false);
  const cases = [
    { name: "create-before-rename.txt", before: null, createOnly: true, faultPoint: "after_temp_fsync", expectedTarget: null, expectedTemporary: true },
    { name: "create-after-rename.txt", before: null, createOnly: true, faultPoint: "after_rename", expectedTarget: "after", expectedTemporary: false },
    { name: "replace-after-rename.txt", before: "before", createOnly: false, faultPoint: "after_rename", expectedTarget: "after", expectedTemporary: false }
  ] as const;
  try {
    for (const current of cases) {
      const target = join(directory, current.name);
      if (current.before !== null) await writeFile(target, current.before, { mode: 0o600 });
      const inspector = new FilesystemInspector([writeRoot(directory)]);
      const prior = current.before === null ? undefined : inspector.statPath(target, false);
      const tempName = `.mac-operator-write-fault-${current.name}`;
      const result = await runNativeFaultChild({
        nativePath,
        root: directory,
        target,
        content: "after",
        createOnly: current.createOnly,
        expectedPresent: prior !== undefined,
        expectedDevice: prior?.device ?? "0",
        expectedInode: prior?.inode ?? "0",
        tempName,
        faultPoint: current.faultPoint
      }, directory);
      assert.equal(result.code, null);
      assert.equal(result.signal, "SIGKILL");
      if (current.expectedTarget === null) {
        await assert.rejects(readFile(target), /ENOENT/u);
      } else {
        assert.equal(await readFile(target, "utf8"), current.expectedTarget);
      }
      assert.equal((await readdir(directory)).includes(tempName), current.expectedTemporary);
      await rm(join(directory, tempName), { force: true });
      await rm(target, { force: true });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native atomic write cleans temporary state on simulated ENOSPC", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-write-enospc-"));
  const nativePath = require.resolve("./peer_credentials_fault.node");
  const cases = [
    { name: "create-write-error.txt", before: null, createOnly: true, faultPoint: "before_temp_write", expectedTarget: null },
    { name: "create-fsync-error.txt", before: null, createOnly: true, faultPoint: "before_temp_fsync", expectedTarget: null },
    { name: "replace-fsync-error.txt", before: "before", createOnly: false, faultPoint: "before_temp_fsync", expectedTarget: "before" },
    { name: "create-directory-fsync-error.txt", before: null, createOnly: true, faultPoint: "before_directory_fsync", expectedTarget: "after" }
  ] as const;
  try {
    for (const current of cases) {
      const target = join(directory, current.name);
      if (current.before !== null) await writeFile(target, current.before, { mode: 0o600 });
      const inspector = new FilesystemInspector([writeRoot(directory)]);
      const prior = current.before === null ? undefined : inspector.statPath(target, false);
      const temporaryName = `.mac-operator-write-enospc-${current.name}`;
      const result = await runNativeFaultChild({
        nativePath,
        root: directory,
        target,
        content: "after",
        createOnly: current.createOnly,
        expectedPresent: prior !== undefined,
        expectedDevice: prior?.device ?? "0",
        expectedInode: prior?.inode ?? "0",
        tempName: temporaryName,
        faultPoint: current.faultPoint
      }, directory);
      assert.equal(result.signal, null);
      assert.notEqual(result.code, 0);
      if (current.expectedTarget === null) {
        await assert.rejects(readFile(target), /ENOENT/u);
      } else {
        assert.equal(await readFile(target, "utf8"), current.expectedTarget);
      }
      assert.equal((await readdir(directory)).includes(temporaryName), false);
      await rm(target, { force: true });
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("descriptor-backed create-only write resists a concurrent target create and symlink swap", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-fs-create-race-"));
  const directory = join(parent, "allowed");
  const target = join(directory, "target.txt");
  const outside = join(parent, "outside.txt");
  await mkdir(directory);
  await writeFile(outside, "outside");
  const attacker = new Worker(`
    const { parentPort, workerData } = require("node:worker_threads");
    const fs = require("node:fs");
    let running = true;
    parentPort.on("message", message => { if (message === "stop") running = false; });
    parentPort.postMessage("ready");
    function remove() { try { fs.unlinkSync(workerData.target); } catch {} }
    function cycle() {
      if (!running) return;
      remove();
      try { fs.writeFileSync(workerData.target, "attacker"); } catch {}
      remove();
      try { fs.symlinkSync(workerData.outside, workerData.target); } catch {}
      remove();
      setImmediate(cycle);
    }
    setTimeout(cycle, 5);
  `, { eval: true, workerData: { target, outside } });
  await new Promise<void>((resolve, reject) => {
    attacker.once("message", () => resolve());
    attacker.once("error", reject);
  });
  const inspector = new FilesystemInspector([writeRoot(directory)]);
  const plan = inspector.planPath(target, "write");
  let accepted = 0;
  try {
    for (let index = 0; index < 500; index += 1) {
      try {
        const result = inspector.writePlanned(
          plan,
          Buffer.from("safe", "utf8"),
          undefined,
          true,
          `.mac-operator-write-race-${index}`
        );
        assert.equal(result.created, true);
        accepted += 1;
      } catch (error) {
        assert.match(String(error), /create-only precondition failed|authorized root or changed|regular file or absent/u);
      }
    }
    assert.ok(accepted > 0);
  } finally {
    attacker.postMessage("stop");
    await attacker.terminate();
    assert.equal(await readFile(outside, "utf8"), "outside");
    try {
      const stat = await lstat(target);
      if (stat.isSymbolicLink()) {
        assert.equal(await readlink(target), outside);
      } else {
        assert.ok(["safe", "attacker"].includes(await readFile(target, "utf8")));
      }
    } catch (error) {
      assert.match(String(error), /ENOENT/u);
    }
    await rm(parent, { recursive: true, force: true });
  }
});

test("atomic write rejects final symlinks, intermediate escapes, and non-write roots", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-fs-write-escape-"));
  const directory = join(parent, "allowed");
  const outside = join(parent, "outside.txt");
  await mkdir(directory);
  await writeFile(outside, "outside");
  await symlink(outside, join(directory, "link.txt"));
  await symlink(parent, join(directory, "escape"));
  try {
    const inspector = new FilesystemInspector([writeRoot(directory)]);
    assert.throws(
      () => inspector.writePlanned(inspector.planPath(join(directory, "link.txt"), "write"), Buffer.from("x"), undefined, false, ".mac-operator-write-link"),
      /regular file or absent/u
    );
    assert.throws(
      () => inspector.writePlanned(
        inspector.planPath(join(directory, "escape", "new.txt"), "write"),
        Buffer.from("x"), undefined, true, ".mac-operator-write-escape"
      ),
      /escaped its authorized root/u
    );
    const readOnly = new FilesystemInspector([root(directory)]);
    assert.throws(() => readOnly.planPath(join(directory, "new.txt"), "write"), /outside authorized roots/u);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("generic filesystem tools fail closed on Unix socket entries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-special-"));
  const socketPath = join(directory, "control.sock");
  const server = createServer();
  try {
    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(socketPath, () => resolve());
    });
    const inspector = new FilesystemInspector([writeRoot(directory)]);
    const listing = inspector.listPlanned(inspector.planPath(directory, "metadata"), undefined, 32, false);
    assert.equal(listing.entries.find((entry) => entry.name === "control.sock")?.type, "other");
    assert.throws(
      () => inspector.readPlanned(inspector.planPath(socketPath, "content_read"), 0, 16),
      /escaped its authorized root, type, or volume/u
    );
    assert.throws(
      () => inspector.hashPlanned(inspector.planPath(socketPath, "content_read"), "sha256"),
      /escaped its authorized root, type, or volume/u
    );
    assert.throws(
      () => inspector.writePlanned(
        inspector.planPath(socketPath, "write"),
        Buffer.from("x"),
        undefined,
        false,
        ".mac-operator-write-special"
      ),
      /regular file or absent|escaped its authorized root/u
    );
  } finally {
    await new Promise<void>((resolve) => {
      if (!server.listening) {
        resolve();
        return;
      }
      server.close(() => resolve());
    });
    await rm(directory, { recursive: true, force: true });
  }
});

test("FIFO and pseudo-device targets cannot block or enter generic content tools", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-fifo-"));
  const fifoPath = join(directory, "events.fifo");
  try {
    execFileSync("/usr/bin/mkfifo", [fifoPath], {
      cwd: directory,
      env: { PATH: "/usr/bin:/bin" },
      stdio: "ignore"
    });
    const inspector = new FilesystemInspector([writeRoot(directory)]);
    assert.equal(inspector.statPath(fifoPath, false).type, "other");
    assert.throws(
      () => inspector.readPlanned(inspector.planPath(fifoPath, "content_read"), 0, 16),
      /escaped its authorized root, type, or volume/u
    );
    assert.throws(
      () => inspector.hashPlanned(inspector.planPath(fifoPath, "content_read"), "sha256"),
      /escaped its authorized root, type, or volume/u
    );
    assert.throws(
      () => inspector.writePlanned(
        inspector.planPath(fifoPath, "write"),
        Buffer.from("x"),
        undefined,
        false,
        ".mac-operator-write-fifo"
      ),
      /regular file or absent/u
    );

    const hostInspector = new FilesystemInspector([root("/")]);
    for (const characterDevice of ["/dev/null", "/dev/tty", "/dev/random"]) {
      assert.throws(
        () => hostInspector.statPath(characterDevice, false),
        /escaped its authorized root or volume/u
      );
    }
    let blockDevicePresent = true;
    try {
      await lstat("/dev/disk0");
    } catch {
      blockDevicePresent = false;
    }
    if (blockDevicePresent) {
      assert.throws(
        () => hostInspector.statPath("/dev/disk0", false),
        /escaped its authorized root or volume/u
      );
    }
    assert.throws(
      () => hostInspector.listPlanned(hostInspector.planPath("/dev", "metadata"), undefined, 8, false),
      /escaped its authorized root, type, or volume/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("descriptor-backed content read is bounded and rejects final symlinks", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-read-"));
  const file = join(directory, "file.txt");
  const link = join(directory, "link.txt");
  await writeFile(file, "hello world", { mode: 0o600 });
  await symlink(file, link);
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    const plan = inspector.planPath(file, "content_read");
    const result = inspector.readPlanned(plan, 6, 3);
    assert.equal(result.content.toString("utf8"), "wor");
    assert.equal(result.sizeBytes, 11);
    assert.equal(result.truncated, true);
    assert.match(result.inode, /^\d+$/u);
    assert.throws(
      () => inspector.readPlanned(inspector.planPath(link, "content_read"), 0, 16),
      /escaped its authorized root, type, or volume/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("descriptor-backed hash returns only a bounded digest and stable identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-hash-"));
  const file = join(directory, "file.txt");
  await writeFile(file, "hello world", { mode: 0o600 });
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    const plan = inspector.planPath(file, "metadata");
    const sha256 = inspector.hashPlanned(plan, "sha256");
    const sha512 = inspector.hashPlanned(plan, "sha512");
    assert.deepEqual(sha256, {
      rootId: "test-root",
      path: await realpath(file),
      algorithm: "sha256",
      digest: createHash("sha256").update("hello world").digest("hex"),
      sizeBytes: 11,
      device: sha256.device,
      inode: sha256.inode
    });
    assert.equal(sha512.algorithm, "sha512");
    assert.equal(sha512.digest, createHash("sha512").update("hello world").digest("hex"));
    assert.equal(sha512.sizeBytes, 11);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("descriptor-backed hash denies protected secret paths", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-hash-secret-"));
  const secretDirectory = join(directory, ".ssh");
  const file = join(secretDirectory, "known_hosts");
  await mkdir(secretDirectory);
  await writeFile(file, "private");
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    assert.throws(
      () => inspector.hashPlanned(inspector.planPath(file, "metadata"), "sha256"),
      /protected secret zone/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("descriptor-backed directory listing paginates and filters protected entries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-list-"));
  await writeFile(join(directory, "a.txt"), "a");
  await writeFile(join(directory, "b.txt"), "b");
  await writeFile(join(directory, "c.txt"), "c");
  await writeFile(join(directory, ".hidden"), "hidden");
  await mkdir(join(directory, ".ssh"));
  await writeFile(join(directory, ".ssh", "known_hosts"), "private");
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    const plan = inspector.planPath(directory, "content_read");
    const first = inspector.listPlanned(plan, undefined, 2, false);
    assert.deepEqual(first.entries.map((entry) => entry.name), ["a.txt", "b.txt"]);
    assert.equal(first.entries.every((entry) => !entry.hidden), true);
    assert.ok(first.nextCursor);
    const second = inspector.listPlanned(plan, first.nextCursor ?? undefined, 2, false);
    assert.deepEqual(second.entries.map((entry) => entry.name), ["c.txt"]);
    assert.equal(second.nextCursor, null);
    const hidden = inspector.listPlanned(plan, undefined, 20, true);
    assert.equal(hidden.entries.some((entry) => entry.name === ".hidden"), true);
    assert.equal(hidden.entries.some((entry) => entry.name === ".ssh"), false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("descriptor-backed directory tree bounds depth and filters protected entries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-tree-"));
  await writeFile(join(directory, "a.txt"), "a");
  await mkdir(join(directory, "nested"));
  await writeFile(join(directory, "nested", "inside.txt"), "inside");
  await writeFile(join(directory, ".env"), "TOKEN=private");
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    const plan = inspector.planPath(directory, "content_read");
    const tree = inspector.treePlanned(plan, 1, 20);
    assert.equal(tree.root, await realpath(directory));
    assert.deepEqual(tree.entries.map((entry) => [entry.path, entry.depth]), [
      [join(await realpath(directory), "a.txt"), 0],
      [join(await realpath(directory), "nested"), 0],
      [join(await realpath(directory), "nested", "inside.txt"), 1]
    ]);
    assert.equal(tree.entries.some((entry) => entry.path.endsWith(".env")), false);
    const bounded = inspector.treePlanned(plan, 8, 1);
    assert.equal(bounded.entries.length, 1);
    assert.equal(bounded.truncated, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("filesystem traversal stays within bounded pressure budgets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-pressure-"));
  const files = Array.from({ length: 600 }, (_, index) => join(directory, `entry-${String(index).padStart(4, "0")}.txt`));
  await Promise.all(files.map((file) => writeFile(file, "needle\n", { mode: 0o600 })));
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    const metadataPlan = inspector.planPath(directory, "metadata");
    const contentPlan = inspector.planPath(directory, "content_read");
    assert.throws(() => inspector.listPlanned(metadataPlan, undefined, 501, false), /entry limit/u);
    assert.throws(() => inspector.treePlanned(metadataPlan, 8, 5001), /entry limit/u);
    assert.throws(() => inspector.findFilesPlanned([metadataPlan], "entry-", 1001), /result limit/u);
    assert.throws(() => inspector.searchTextPlanned([contentPlan], "needle", undefined, 1001), /result limit/u);

    const listing = inspector.listPlanned(metadataPlan, undefined, 500, false);
    assert.equal(listing.entries.length, 500);
    assert.notEqual(listing.nextCursor, null);
    const tree = inspector.treePlanned(metadataPlan, 0, 128);
    assert.equal(tree.entries.length, 128);
    assert.equal(tree.truncated, true);
    const fileMatches = inspector.findFilesPlanned([metadataPlan], "entry-", 100);
    assert.equal(fileMatches.matches.length, 100);
    assert.equal(fileMatches.truncated, true);
    const textMatches = inspector.searchTextPlanned([contentPlan], "needle", undefined, 100);
    assert.equal(textMatches.matches.length, 100);
    assert.equal(textMatches.truncated, true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("content read requires independent root enablement", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-read-scope-"));
  const file = join(directory, "file.txt");
  await writeFile(file, "hello");
  try {
    const inspector = new FilesystemInspector([{ ...root(directory), contentRead: false }]);
    assert.throws(() => inspector.planPath(file, "content_read"), /outside authorized roots/u);
    assert.equal(inspector.statPath(file).type, "file");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("content read rejects multiply-linked files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-hardlink-"));
  const original = join(directory, "original.txt");
  const alias = join(directory, "alias.txt");
  await writeFile(original, "sensitive");
  await link(original, alias);
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    assert.throws(
      () => inspector.readPlanned(inspector.planPath(alias, "content_read"), 0, 32),
      /escaped its authorized root, type, or volume/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("canonical secret-zone authorization runs before descriptor content read", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-secret-alias-"));
  const secretDirectory = join(directory, ".ssh");
  const aliasDirectory = join(directory, "documents");
  await mkdir(secretDirectory);
  await writeFile(join(secretDirectory, "notes.txt"), "private material");
  await symlink(secretDirectory, aliasDirectory);
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    const plan = inspector.planPath(join(aliasDirectory, "notes.txt"), "content_read");
    assert.throws(() => inspector.readPlanned(plan, 0, 32), /escaped its authorized root, type, or volume/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native descriptor read rejects a file changed after authorization", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-readback-"));
  const file = join(directory, "file.txt");
  await writeFile(file, "stable");
  const native = require("./peer_credentials.node") as {
    readFileWithinRoot(rootPath: string, targetPath: string, offset: number, maxBytes: number, authorizer: () => void): unknown;
  };
  try {
    assert.throws(
      () => native.readFileWithinRoot(directory, file, 0, 32, () => appendFileSync(file, "changed")),
      /changed during read/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native descriptor hash rejects a file changed after authorization", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-hash-readback-"));
  const file = join(directory, "file.txt");
  await writeFile(file, "stable");
  const native = require("./peer_credentials.node") as {
    hashFileWithinRoot(rootPath: string, targetPath: string, algorithm: "sha256" | "sha512", authorizer: () => void): unknown;
  };
  try {
    assert.throws(
      () => native.hashFileWithinRoot(directory, file, "sha256", () => appendFileSync(file, "changed")),
      /changed during hash/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("filesystem metadata rejects traversal and symlink escape", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-fs-escape-"));
  const directory = join(parent, "allowed");
  const outside = join(parent, "outside.txt");
  await mkdir(directory);
  await writeFile(outside, "secret");
  await symlink(outside, join(directory, "escape"));
  const inspector = new FilesystemInspector([root(directory)]);
  try {
    assert.throws(() => inspector.statPath(join(directory, "..", "outside.txt")), /outside authorized roots/u);
    assert.throws(() => inspector.statPath(join(directory, "escape"), true), /escaped its authorized root/u);
    const link = inspector.statPath(join(directory, "escape"), false);
    assert.equal(link.type, "symlink");
    assert.equal(link.isSymlink, true);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("filesystem metadata follows an internal symlink but reports the opened canonical path", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-link-"));
  const target = join(directory, "target.txt");
  const link = join(directory, "link.txt");
  await writeFile(target, "safe");
  await symlink(target, link);
  try {
    const result = new FilesystemInspector([root(directory)]).statPath(link, true);
    assert.equal(result.path, await realpath(target));
    assert.equal(result.type, "file");
    assert.equal(result.isSymlink, false);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("deny-inside-allow applies to the resolved descriptor path", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-deny-"));
  const deniedDirectory = join(directory, "secrets");
  await mkdir(deniedDirectory);
  const deniedFile = join(deniedDirectory, "value.txt");
  const alias = join(directory, "alias.txt");
  await writeFile(deniedFile, "secret");
  await symlink(deniedFile, alias);
  try {
    const inspector = new FilesystemInspector([{ ...root(directory), denyRelativePaths: ["secrets"] }]);
    assert.throws(() => inspector.statPath(deniedFile), /denied zone/u);
    assert.throws(() => inspector.statPath(alias), /denied zone/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("filesystem root symlinks fail closed", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-fs-root-link-"));
  const directory = join(parent, "real");
  const rootLink = join(parent, "root-link");
  await mkdir(directory);
  await writeFile(join(directory, "file.txt"), "safe");
  await symlink(directory, rootLink);
  try {
    const inspector = new FilesystemInspector([root(rootLink)]);
    assert.throws(() => inspector.statPath(join(rootLink, "file.txt")), /root volume identity could not be established/u);
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("root filesystem containment supports child paths without prefix ambiguity", () => {
  const result = new FilesystemInspector([root("/")]).statPath("/System", true);
  assert.equal(result.rootId, "test-root");
  assert.equal(result.path, "/System");
  assert.equal(result.type, "directory");
});

test("filesystem lexical containment fails closed across case and Unicode aliases", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-unicode-case-"));
  const composedName = "Café.txt";
  const decomposedName = "Cafe\u0301.txt";
  const file = join(directory, composedName);
  await writeFile(file, "safe");
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    assert.throws(
      () => inspector.planPath(`${directory.toUpperCase()}/SAFE`, "metadata"),
      /outside authorized roots/u
    );
    const matches = inspector.findFilesPlanned(
      [inspector.planPath(directory, "metadata")],
      decomposedName,
      10
    );
    const canonicalFile = await realpath(file);
    assert.equal(matches.matches.some((match) => match.path === canonicalFile), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("filesystem plans fail closed when the authorized volume identity changes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-volume-identity-"));
  const file = join(directory, "value.txt");
  await writeFile(file, "safe");
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    const plan = inspector.planPath(file, "metadata");
    const forgedPlan = {
      ...plan,
      rootIdentity: { ...plan.rootIdentity, id: `${plan.rootIdentity.id}:replacement` }
    };
    assert.throws(
      () => inspector.statPlanned(forgedPlan),
      /root volume identity changed during authorization/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("filesystem authorization plans freeze target, policy, and volume snapshots", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-plan-freeze-"));
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    const plan = inspector.planPath(directory, "metadata");
    assert.equal(Object.isFrozen(plan), true);
    assert.equal(Object.isFrozen(plan.root), true);
    assert.equal(Object.isFrozen(plan.root.denyRelativePaths), true);
    assert.equal(Object.isFrozen(plan.rootIdentity), true);
    assert.throws(
      () => { (plan as unknown as { requestedPath: string }).requestedPath = "/tmp/escape"; },
      TypeError
    );
    assert.throws(
      () => { (plan.root as unknown as { path: string }).path = "/tmp/escape"; },
      TypeError
    );
    assert.throws(
      () => { (plan.rootIdentity as unknown as { inode: string }).inode = "0"; },
      TypeError
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("filesystem plans fail closed when the authorized root directory is replaced", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-fs-root-identity-"));
  const directory = join(parent, "allowed");
  const movedDirectory = join(parent, "allowed-moved");
  const file = join(directory, "value.txt");
  await mkdir(directory);
  await writeFile(file, "safe");
  try {
    const inspector = new FilesystemInspector([root(directory)]);
    const plan = inspector.planPath(file, "metadata");
    await rename(directory, movedDirectory);
    await mkdir(directory);
    assert.throws(
      () => inspector.statPlanned(plan, false),
      /root identity changed during authorization/u
    );
  } finally {
    await rm(parent, { recursive: true, force: true });
  }
});

test("descriptor readback resists an atomic symlink target-swap race", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-fs-swap-"));
  const directory = join(parent, "allowed");
  const inside = join(directory, "inside.txt");
  const outside = join(parent, "outside.txt");
  const active = join(directory, "active-link");
  await mkdir(directory);
  await writeFile(inside, "inside");
  await writeFile(outside, "outside");
  await symlink(inside, active);
  const worker = new Worker(`
    const { parentPort, workerData } = require("node:worker_threads");
    const fs = require("node:fs");
    let running = true;
    parentPort.on("message", message => { if (message === "stop") running = false; });
    parentPort.postMessage("ready");
    function replace(target, suffix) {
      const temporary = workerData.active + suffix;
      try { fs.unlinkSync(temporary); } catch {}
      fs.symlinkSync(target, temporary);
      fs.renameSync(temporary, workerData.active);
    }
    function cycle() {
      if (!running) return;
      replace(workerData.outside, ".outside");
      replace(workerData.inside, ".inside");
      setImmediate(cycle);
    }
    cycle();
  `, { eval: true, workerData: { active, inside, outside } });
  await new Promise<void>((resolve, reject) => {
    worker.once("message", () => resolve());
    worker.once("error", reject);
  });
  const inspector = new FilesystemInspector([root(directory)]);
  const canonicalInside = await realpath(inside);
  let accepted = 0;
  try {
    for (let index = 0; index < 2_000; index += 1) {
      try {
        const result = inspector.statPath(active, true);
        assert.equal(result.path, canonicalInside);
        accepted += 1;
      } catch (error) {
        assert.match(String(error), /escaped its authorized root/u);
      }
    }
    assert.ok(accepted > 0);
  } finally {
    worker.postMessage("stop");
    await worker.terminate();
    await rm(parent, { recursive: true, force: true });
  }
});

test("descriptor content read resists an intermediate symlink target-swap race", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-fs-read-swap-"));
  const directory = join(parent, "allowed");
  const insideDirectory = join(directory, "inside");
  const outsideDirectory = join(parent, "outside");
  const active = join(directory, "active");
  await mkdir(directory);
  await mkdir(insideDirectory);
  await mkdir(outsideDirectory);
  await writeFile(join(insideDirectory, "value.txt"), "inside");
  await writeFile(join(outsideDirectory, "value.txt"), "outside");
  await symlink(insideDirectory, active);
  const worker = new Worker(`
    const { parentPort, workerData } = require("node:worker_threads");
    const fs = require("node:fs");
    let running = true;
    parentPort.on("message", message => { if (message === "stop") running = false; });
    parentPort.postMessage("ready");
    function replace(target, suffix) {
      const temporary = workerData.active + suffix;
      try { fs.unlinkSync(temporary); } catch {}
      fs.symlinkSync(target, temporary);
      fs.renameSync(temporary, workerData.active);
    }
    function cycle() {
      if (!running) return;
      replace(workerData.outside, ".outside");
      replace(workerData.inside, ".inside");
      setImmediate(cycle);
    }
    cycle();
  `, { eval: true, workerData: { active, inside: insideDirectory, outside: outsideDirectory } });
  await new Promise<void>((resolve, reject) => {
    worker.once("message", () => resolve());
    worker.once("error", reject);
  });
  const inspector = new FilesystemInspector([root(directory)]);
  const plan = inspector.planPath(join(active, "value.txt"), "content_read");
  const canonicalInside = await realpath(join(insideDirectory, "value.txt"));
  let accepted = 0;
  try {
    for (let index = 0; index < 2_000; index += 1) {
      try {
        const result = inspector.readPlanned(plan, 0, 16);
        assert.equal(result.content.toString("utf8"), "inside");
        assert.equal(result.path, canonicalInside);
        accepted += 1;
      } catch (error) {
        assert.match(String(error), /escaped its authorized root, type, or volume/u);
      }
    }
    assert.ok(accepted > 0);
  } finally {
    worker.postMessage("stop");
    await worker.terminate();
    await rm(parent, { recursive: true, force: true });
  }
});

test("descriptor content read resists a directory rename and replacement race", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-fs-directory-rename-"));
  const directory = join(parent, "allowed");
  const nested = join(directory, "nested");
  const moved = join(directory, "nested.moved");
  const inside = join(nested, "value.txt");
  const outsideDirectory = join(parent, "outside");
  const outside = join(outsideDirectory, "value.txt");
  await mkdir(nested, { recursive: true });
  await mkdir(outsideDirectory);
  await writeFile(inside, "inside");
  await writeFile(outside, "outside");
  const canonicalDirectory = await realpath(directory);
  const worker = new Worker(`
    const { parentPort, workerData } = require("node:worker_threads");
    const fs = require("node:fs");
    let running = true;
    parentPort.on("message", message => { if (message === "stop") running = false; });
    parentPort.postMessage("ready");
    function cycle() {
      if (!running) return;
      try { fs.rmSync(workerData.moved, { recursive: true, force: true }); } catch {}
      try { fs.renameSync(workerData.nested, workerData.moved); } catch {}
      try { fs.symlinkSync(workerData.outsideDirectory, workerData.nested); } catch {}
      try { fs.unlinkSync(workerData.nested); } catch {}
      try { fs.renameSync(workerData.moved, workerData.nested); } catch {}
      setImmediate(cycle);
    }
    cycle();
  `, { eval: true, workerData: { nested, moved, outsideDirectory } });
  await new Promise<void>((resolve, reject) => {
    worker.once("message", () => resolve());
    worker.once("error", reject);
  });
  const inspector = new FilesystemInspector([root(directory)]);
  const plan = inspector.planPath(inside, "content_read");
  let accepted = 0;
  try {
    for (let index = 0; index < 2_000; index += 1) {
      try {
        const result = inspector.readPlanned(plan, 0, 16);
        assert.equal(result.content.toString("utf8"), "inside");
        assert.equal(result.path.startsWith(`${canonicalDirectory}/`), true);
        accepted += 1;
      } catch (error) {
        if (!/escaped its authorized root, type, or volume/u.test(String(error))) throw error;
      }
    }
    assert.ok(accepted > 0);
  } finally {
    worker.postMessage("stop");
    await worker.terminate();
    await rm(parent, { recursive: true, force: true });
  }
});

test("descriptor-backed atomic write resists a directory rename and replacement race", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-fs-write-directory-rename-"));
  const directory = join(parent, "allowed");
  const nested = join(directory, "nested");
  const moved = join(directory, "nested.moved");
  const target = join(nested, "value.txt");
  const outsideDirectory = join(parent, "outside");
  const outside = join(outsideDirectory, "value.txt");
  await mkdir(nested, { recursive: true });
  await mkdir(outsideDirectory);
  await writeFile(outside, "outside");
  const canonicalDirectory = await realpath(directory);
  const worker = new Worker(`
    const { parentPort, workerData } = require("node:worker_threads");
    const fs = require("node:fs");
    let running = true;
    parentPort.on("message", message => { if (message === "stop") running = false; });
    parentPort.postMessage("ready");
    function cycle() {
      if (!running) return;
      try { fs.rmSync(workerData.moved, { recursive: true, force: true }); } catch {}
      try { fs.renameSync(workerData.nested, workerData.moved); } catch {}
      try { fs.symlinkSync(workerData.outsideDirectory, workerData.nested); } catch {}
      try { fs.unlinkSync(workerData.nested); } catch {}
      try { fs.renameSync(workerData.moved, workerData.nested); } catch {}
      setImmediate(cycle);
    }
    cycle();
  `, { eval: true, workerData: { nested, moved, outsideDirectory } });
  await new Promise<void>((resolve, reject) => {
    worker.once("message", () => resolve());
    worker.once("error", reject);
  });
  const inspector = new FilesystemInspector([writeRoot(directory)]);
  const plan = inspector.planPath(target, "write");
  let accepted = 0;
  try {
    for (let index = 0; index < 500; index += 1) {
      try {
        const result = inspector.writePlanned(
          plan,
          Buffer.from("safe", "utf8"),
          undefined,
          false,
          `.mac-operator-write-directory-rename-${index}`
        );
        assert.equal(result.sha256, createHash("sha256").update("safe").digest("hex"));
        assert.equal(result.path.startsWith(`${canonicalDirectory}/`), true);
        accepted += 1;
      } catch (error) {
        if (!/authorized root or changed|regular file or absent/u.test(String(error))) throw error;
      }
    }
    assert.ok(accepted > 0);
  } finally {
    worker.postMessage("stop");
    await worker.terminate();
    assert.equal(await readFile(outside, "utf8"), "outside");
    await rm(parent, { recursive: true, force: true });
  }
});

function root(path: string) {
  return { rootId: "test-root", path, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
}

function rootPolicy(path: string) {
  return { rootId: "native-shape-root", path, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
}

function writeRoot(path: string) {
  return { rootId: "test-root", path, metadata: true, contentRead: true, write: true, denyRelativePaths: [] } as const;
}
