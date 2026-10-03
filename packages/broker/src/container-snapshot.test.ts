import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sha256 } from "@mac-operator/contracts";
import { createWorkspaceArchive, importWorkspaceChanges, parseWorkspaceArchive, safeSnapshotPath, snapshotWorktree, snapshotWorktreeAsync } from "./container-snapshot.js";

test("container archive round trip preserves only regular source files", () => {
  const files = [{ path: "src/example.ts", content: Buffer.from("export const answer = 42;\n") }];
  const output = parseWorkspaceArchive(createWorkspaceArchive(files, ["src"]));
  assert.equal(output[0]?.path, files[0]!.path);
  assert.deepEqual(output[0]?.content, files[0]!.content);
});

for (const path of ["../escape", "/etc/passwd", "src/../../escape", ".git/config", ".ssh/id_rsa", ".env", "src//file", "src/./file", "src\\file", "src/\0file"]) {
  test(`container source rejects forbidden path ${JSON.stringify(path)}`, () => {
    assert.equal(safeSnapshotPath(path), false);
    assert.throws(() => createWorkspaceArchive([{ path, content: Buffer.from("safe") }]));
  });
}

for (const type of ["1", "2", "3", "4", "6", "x", "g", "L", "K"]) {
  test(`container output rejects archive type ${type}`, () => {
    const archive = createWorkspaceArchive([{ path: "source.txt", content: Buffer.from("safe") }]);
    archive[156] = type.charCodeAt(0);
    archive.fill(32, 148, 156);
    const sum = archive.subarray(0, 512).reduce((a, b) => a + b, 0);
    archive.write(`${sum.toString(8).padStart(7, "0")}\0`, 148, "ascii");
    assert.throws(() => parseWorkspaceArchive(archive));
  });
}

test("container archive rejects damaged checksum and duplicate entries", () => {
  const archive = createWorkspaceArchive([{ path: "source.txt", content: Buffer.from("safe") }]);
  archive[0] = 120;
  assert.throws(() => parseWorkspaceArchive(archive));
  assert.throws(() => createWorkspaceArchive([{ path: "a", content: Buffer.alloc(0) }, { path: "a", content: Buffer.alloc(0) }]));
});

test("native container import checks hashes, paths and authority before source changes", { skip: process.platform !== "darwin" }, () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "container-source-")));
  try {
    mkdirSync(join(root, ".git"));
    writeFileSync(join(root, ".git/HEAD"), "ref: refs/heads/main\n");
    writeFileSync(join(root, "source.txt"), "before");
    writeFileSync(join(root, ".env"), "DEMO_SETTING=value\n");
    symlinkSync("/etc", join(root, "escape"));
    const snapshot = snapshotWorktree(root);
    assert.deepEqual(snapshot.files.map(file => file.path), ["source.txt"]);
    assert.ok(snapshot.excluded.includes("escape"));
    const content = Buffer.from("after");
    const output = [{ path: "source.txt", content, sha256: sha256(content) }];
    assert.throws(() => importWorkspaceChanges(snapshot, output, ["other.txt"]));
    assert.throws(() => importWorkspaceChanges(snapshot, output, [], { beforeWrite: () => { throw new Error("revoked"); } }));
    assert.equal(readFileSync(join(root, "source.txt"), "utf8"), "before");
    assert.deepEqual(importWorkspaceChanges(snapshot, output, ["source.txt"]), ["source.txt"]);
    assert.equal(readFileSync(join(root, "source.txt"), "utf8"), "after");
    assert.equal(readFileSync(join(root, ".git/HEAD"), "utf8"), "ref: refs/heads/main\n");
    assert.throws(() => importWorkspaceChanges(snapshot, output));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("native container import creates pinned nested directories and rejects symlink aliases", { skip: process.platform !== "darwin" }, () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "container-nested-")));
  try {
    const snapshot = snapshotWorktree(root);
    const content = Buffer.from("new source\n");
    const output = [{ path: "src/nested/new.txt", content, sha256: sha256(content) }];
    assert.deepEqual(importWorkspaceChanges(snapshot, output), ["src/nested/new.txt"]);
    assert.equal(readFileSync(join(root, "src/nested/new.txt"), "utf8"), "new source\n");
    symlinkSync("/etc", join(root, "alias"));
    assert.throws(() => importWorkspaceChanges(snapshot, [{ path: "alias/new.txt", content, sha256: sha256(content) }]));
  } finally { rmSync(root, { recursive: true, force: true }); }
});

test("trusted snapshot exclusions omit persistent project data before reading file bytes", { skip: process.platform !== "darwin" }, () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "container-excluded-")));
  try {
    mkdirSync(join(root, "portal/data"), { recursive: true });
    writeFileSync(join(root, "portal/data/large.bin"), Buffer.alloc(9 * 1024 * 1024));
    writeFileSync(join(root, "source.txt"), "source\n");
    assert.throws(() => snapshotWorktree(root), /byte budget/u);
    const snapshot = snapshotWorktree(root, true, ["portal/data"]);
    assert.deepEqual(snapshot.files.map(file => file.path), ["source.txt"]);
    assert.ok(snapshot.excluded.includes("portal/data"));
    assert.throws(() => snapshotWorktree(root, false, ["../outside"]));
    assert.throws(() => snapshotWorktree(root, false, ["portal/data", "portal/data"]));
  } finally { rmSync(root, { recursive: true, force: true }); }
});


test("asynchronous snapshot permits authority heartbeats and preserves the synchronous boundary", { skip: process.platform !== "darwin" }, async () => {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "container-yield-")));
  try {
    for (let i = 0; i < 32; i++) writeFileSync(join(root, `source-${i}.txt`), "public source\n");
    writeFileSync(join(root, ".env"), "PRIVATE_SETTING=fixture\n");
    symlinkSync("/etc/passwd", join(root, "outside"));
    const expected = snapshotWorktree(root);
    let heartbeats = 0;
    const timer = setInterval(() => { heartbeats++; }, 1);
    let checks = 0;
    try {
      const result = await snapshotWorktreeAsync(root, false, [], () => { checks++; });
      assert.ok(heartbeats > 0);
      assert.ok(checks >= 32);
      assert.deepEqual(result.archive, expected.archive);
      assert.deepEqual(result.excluded, expected.excluded);
    } finally { clearInterval(timer); }
    await assert.rejects(snapshotWorktreeAsync(root, false, [], () => { throw new Error("authority revoked"); }), /authority revoked/u);
    assert.equal(readFileSync(join(root, "source-0.txt"), "utf8"), "public source\n");
  } finally { rmSync(root, { recursive: true, force: true }); }
});
