import assert from "node:assert/strict";
import { appendFileSync } from "node:fs";
import { link, mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { Worker } from "node:worker_threads";
import { FilesystemInspector } from "./filesystem-inspector.js";

const require = createRequire(import.meta.url);

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
    assert.throws(() => inspector.statPath(join(rootLink, "file.txt")), /escaped its authorized root/u);
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

function root(path: string) {
  return { rootId: "test-root", path, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
}

function writeRoot(path: string) {
  return { rootId: "test-root", path, metadata: true, contentRead: true, write: true, denyRelativePaths: [] } as const;
}
