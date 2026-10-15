import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FilesystemInspector } from "./filesystem-inspector.js";

async function fixture(t: test.TestContext) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "project-pagination-")));
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  const inspector = new FilesystemInspector([{ rootId: "source", path: root, metadata: true, contentRead: false, denyRelativePaths: [] }]);
  return { root, inspector, discover: (types: string[] = [], limit = 10, roots = [root]) =>
    inspector.discoverProjectsPlanned(roots.map(path => inspector.planPath(path, "metadata")), types, limit) };
}

async function fillPage(root: string) {
  await Promise.all(Array.from({ length: 500 }, (_, index) => writeFile(join(root, `s${String(index).padStart(4, "0")}.txt`), "")));
}

async function depthPath(root: string, depth: number) {
  const path = join(root, ...Array.from({ length: depth }, () => "nested"));
  await mkdir(path, { recursive: true });
  return path;
}

test("project indicators merge across pages before the exact result limit is applied", async t => {
  const f = await fixture(t);
  await fillPage(f.root);
  await writeFile(join(f.root, "requirements.txt"), "not read");
  await writeFile(join(f.root, "setup.py"), "not executed");
  assert.deepEqual(f.discover(["python"], 1), {
    projects: [{ root: f.root, type: "python", indicators: ["setup.py", "requirements.txt"] }], truncated: false
  });
});

test("pagination retains distinct types, canonical roots and overlapping-root deduplication", async t => {
  const f = await fixture(t);
  await fillPage(f.root);
  await writeFile(join(f.root, "requirements.txt"), "");
  await writeFile(join(f.root, "setup.py"), "");
  await writeFile(join(f.root, "package.json"), "");
  await mkdir(join(f.root, "child"));
  await writeFile(join(f.root, "child", "setup.py"), "");
  assert.deepEqual(f.discover([], 10, [f.root, join(f.root, "child"), f.root]), {
    projects: [
      { root: f.root, type: "node", indicators: ["package.json"] },
      { root: f.root, type: "python", indicators: ["setup.py", "requirements.txt"] },
      { root: join(f.root, "child"), type: "python", indicators: ["setup.py"] }
    ], truncated: false
  });
  assert.deepEqual(f.discover(["python"], 1), {
    projects: [{ root: f.root, type: "python", indicators: ["setup.py", "requirements.txt"] }], truncated: true
  });
});

test("Swift bundle labels merge across pages without traversing their interiors", async t => {
  const f = await fixture(t);
  await fillPage(f.root);
  await mkdir(join(f.root, "a.xcodeproj"));
  await mkdir(join(f.root, "z.xcworkspace"));
  await writeFile(join(f.root, "z.xcworkspace", "package.json"), "not another project");
  assert.deepEqual(f.discover([], 1), {
    projects: [{ root: f.root, type: "swift", indicators: [".xcodeproj", ".xcworkspace"] }], truncated: false
  });
});

for (const depth of [16, 17]) {
  test(`project at depth ${depth} reports completeness honestly`, async t => {
    const f = await fixture(t);
    const path = await depthPath(f.root, depth);
    await writeFile(join(path, "package.json"), "");
    assert.deepEqual(f.discover(), {
      projects: depth === 16 ? [{ root: path, type: "node", indicators: ["package.json"] }] : [],
      truncated: depth > 16
    });
  });
}

test("depth omissions do not stop later directory pages or pending sibling projects", async t => {
  const f = await fixture(t);
  const path = await depthPath(f.root, 16);
  await mkdir(join(path, "a-omitted"));
  await fillPage(path);
  await writeFile(join(path, "setup.py"), "");
  // This sibling is visited after the depth-limited directory in the BFS queue.
  const sibling = join(f.root, ...Array.from({ length: 15 }, () => "nested"), "z-sibling");
  await mkdir(sibling);
  await writeFile(join(sibling, "package.json"), "");
  assert.deepEqual(f.discover(), { projects: [
    { root: path, type: "python", indicators: ["setup.py"] },
    { root: sibling, type: "node", indicators: ["package.json"] }
  ], truncated: true });
});

test("ignored directories, symlinks and opaque Xcode bundles are not depth omissions", async t => {
  const f = await fixture(t);
  const path = await depthPath(f.root, 16);
  await mkdir(join(path, "node_modules"));
  await mkdir(join(path, "Example.xcodeproj"));
  await symlink(f.root, join(path, "linked"));
  assert.deepEqual(f.discover(), {
    projects: [{ root: path, type: "swift", indicators: [".xcodeproj"] }], truncated: false
  });
});

test("explicit nested roots remain discoverable when an ancestor reaches its depth bound", async t => {
  const f = await fixture(t);
  const path = await depthPath(f.root, 17);
  await writeFile(join(path, "Cargo.toml"), "");
  const result = f.discover([], 10, [f.root, path]);
  assert.deepEqual(result.projects, [{ root: path, type: "rust", indicators: ["Cargo.toml"] }]);
  assert.equal(result.truncated, true);
});

for (const entries of [50_000, 50_001]) {
  test(`global entry budget remains bounded at ${entries} entries`, async t => {
    const f = await fixture(t);
    let calls = 0;
    f.inspector.listPlanned = (plan, cursor) => {
      calls += 1;
      const offset = Number(cursor ?? 0);
      const count = Math.min(500, entries - offset);
      return { rootId: plan.rootId, path: plan.requestedPath,
        entries: Array.from({ length: count }, (_, index) => ({ name: `plain-${offset + index}`, type: "file" as const,
          sizeBytes: 0, modifiedAt: null, hidden: false })),
        nextCursor: offset + count < entries ? String(offset + count) : null };
    };
    assert.deepEqual(f.discover(), { projects: [], truncated: entries > 50_000 });
    assert.equal(calls, Math.ceil(entries / 500));
  });
}

test("global directory budget still stops traversal after 10000 accepted directories", async t => {
  const f = await fixture(t);
  let childCalls = 0;
  f.inspector.listPlanned = (plan, cursor) => {
    if (plan.requestedPath !== f.root) {
      childCalls += 1;
      return { rootId: plan.rootId, path: plan.requestedPath, entries: [], nextCursor: null };
    }
    const offset = Number(cursor ?? 0);
    return { rootId: plan.rootId, path: plan.requestedPath,
      entries: Array.from({ length: 500 }, (_, index) => ({ name: `child-${offset + index}`, type: "directory" as const,
        sizeBytes: 0, modifiedAt: null, hidden: false })), nextCursor: offset + 500 < 10_000 ? String(offset + 500) : null };
  };
  assert.deepEqual(f.discover(), { projects: [], truncated: true });
  assert.equal(childCalls, 10_000);
});
