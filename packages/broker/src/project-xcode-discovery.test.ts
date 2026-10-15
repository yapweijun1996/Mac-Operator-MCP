import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FilesystemInspector } from "./filesystem-inspector.js";

async function fixture(t: test.TestContext) {
  const root = await realpath(await mkdtemp(join(tmpdir(), "project-xcode-")));
  t.after(async () => { await rm(root, { recursive: true, force: true }); });
  // Metadata-only discovery must not require content-read authority.
  const inspector = new FilesystemInspector([{ rootId: "source", path: root, metadata: true, contentRead: false, denyRelativePaths: [] }]);
  return { root, discover: (types: string[] = ["swift"]) => inspector.discoverProjectsPlanned([inspector.planPath(root, "metadata")], types, 10) };
}

for (const suffix of [".xcodeproj", ".xcworkspace"]) {
  test(`named ${suffix} directory identifies its parent without traversing bundle internals`, async t => {
    const f = await fixture(t);
    const bundle = join(f.root, `Example${suffix}`);
    await mkdir(join(bundle, "project.xcworkspace"), { recursive: true });
    await writeFile(join(bundle, "Package.swift"), "must not be read or discovered as another project");
    assert.deepEqual(f.discover(), { projects: [{ root: f.root, type: "swift", indicators: [suffix] }], truncated: false });
  });
}

test("Swift manifest and Xcode markers preserve bounded indicator labels", async t => {
  const f = await fixture(t);
  await writeFile(join(f.root, "Package.swift"), "manifest content is not needed");
  await mkdir(join(f.root, "Example.xcodeproj"));
  await mkdir(join(f.root, `${"Long".repeat(40)}.xcworkspace`));
  assert.deepEqual(f.discover(), { projects: [{ root: f.root, type: "swift", indicators: ["Package.swift", ".xcodeproj", ".xcworkspace"] }], truncated: false });
  assert.deepEqual(f.discover(["node"]), { projects: [], truncated: false });
});

for (const name of ["Example.xcodeproj.backup", "Example.xcworkspace.txt", ".xcodeproj", "Unrelated"]) {
  test(`unrelated directory ${name} is not an Xcode project`, async t => {
    const f = await fixture(t);
    await mkdir(join(f.root, name));
    assert.deepEqual(f.discover(), { projects: [], truncated: false });
  });
}

test("file lookalikes and symlinked Xcode bundles cannot create project markers", async t => {
  const f = await fixture(t);
  await writeFile(join(f.root, "Fake.xcodeproj"), "not a directory");
  await mkdir(join(f.root, "target"));
  await symlink(join(f.root, "target"), join(f.root, "Alias.xcworkspace"));
  await symlink(join(f.root, "Fake.xcodeproj"), join(f.root, "Package.swift"));
  assert.deepEqual(f.discover(), { projects: [], truncated: false });
});

test("automatic discovery retains exact Swift manifests and recognizes nested named bundles", async t => {
  const f = await fixture(t);
  await writeFile(join(f.root, "Package.swift"), "not read");
  await mkdir(join(f.root, "nested", "Example.xcworkspace"), { recursive: true });
  assert.deepEqual(f.discover([]), { projects: [
    { root: f.root, type: "swift", indicators: ["Package.swift"] },
    { root: join(f.root, "nested"), type: "swift", indicators: [".xcworkspace"] }
  ], truncated: false });
});
