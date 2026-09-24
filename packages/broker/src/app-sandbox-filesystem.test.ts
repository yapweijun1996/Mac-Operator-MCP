import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, mkdir, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { stageAppSandboxFilesystem } from "./app-sandbox-filesystem.js";

test("App Sandbox filesystem staging copies only native-authorized regular files", {
  skip: process.platform !== "darwin"
}, async () => {
  const sourceRoot = await mkdtemp(join(tmpdir(), "mop-app-sandbox-stage-source-"));
  const runDirectory = await mkdtemp(join(tmpdir(), "mop-app-sandbox-stage-run-"));
  try {
    const canonicalSourceRoot = await realpath(sourceRoot);
    const canonicalRunDirectory = await realpath(runDirectory);
    await mkdir(join(canonicalSourceRoot, "nested"), { mode: 0o700 });
    await writeFile(join(canonicalSourceRoot, "nested", "input.txt"), "staged\n", { mode: 0o600 });
    await writeFile(join(canonicalSourceRoot, ".hidden"), "hidden\n", { mode: 0o600 });
    const stage = await stageAppSandboxFilesystem({
      filesystemRoots: [canonicalSourceRoot],
      cwdPath: join(canonicalSourceRoot, "nested"),
      runDirectory: canonicalRunDirectory
    });
    assert.equal(await readFile(join(stage.stagedRoot, "r0", "nested", "input.txt"), "utf8"), "staged\n");
    assert.equal(await readFile(join(stage.stagedRoot, "r0", ".hidden"), "utf8"), "hidden\n");
    await stage.stagedCwdHandle.close();
  } finally {
    await rm(sourceRoot, { recursive: true, force: true });
    await rm(runDirectory, { recursive: true, force: true });
  }
});

test("App Sandbox filesystem staging rejects symlinks", {
  skip: process.platform !== "darwin"
}, async () => {
  const sourceRoot = await mkdtemp(join(tmpdir(), "mop-app-sandbox-stage-link-source-"));
  const runDirectory = await mkdtemp(join(tmpdir(), "mop-app-sandbox-stage-link-run-"));
  try {
    const canonicalSourceRoot = await realpath(sourceRoot);
    const canonicalRunDirectory = await realpath(runDirectory);
    await symlink("/etc/passwd", join(canonicalSourceRoot, "escape"));
    await assert.rejects(
      stageAppSandboxFilesystem({ filesystemRoots: [canonicalSourceRoot], cwdPath: canonicalSourceRoot, runDirectory: canonicalRunDirectory }),
      (error: unknown) => (error as { errorClass?: string }).errorClass === "POLICY_DENIED"
    );
  } finally {
    await rm(sourceRoot, { recursive: true, force: true });
    await rm(runDirectory, { recursive: true, force: true });
  }
});
