import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { FilesystemInspector, type FilesystemNativeAdapter } from "./filesystem-inspector.js";
import { applyFilesystemPatch } from "./filesystem-patch.js";
import { loadNativePeerAdapter } from "./peer-credentials.js";

test("bounded patch updates and adds files under one authorized project root", async () => {
  const project = await mkdtemp(join(tmpdir(), "mac-operator-patch-"));
  const existing = join(project, "src.txt");
  try {
    await writeFile(existing, "hello\nworld\n", { mode: 0o600 });
    const inspector = new FilesystemInspector([writeRoot(project)]);
    const patch = [
      "*** Begin Patch",
      "*** Update File: src.txt",
      "@@",
      " hello",
      "-world",
      "+operator",
      "*** Add File: new.txt",
      "+created",
      "*** End Patch",
      ""
    ].join("\n");
    const result = applyFilesystemPatch(inspector, inspector.planPath(project, "write"), patch, undefined);
    assert.equal(result.result, "applied");
    assert.deepEqual(result.changedPaths, ["src.txt", "new.txt"]);
    assert.equal(await readFile(existing, "utf8"), "hello\noperator\n");
    assert.equal(await readFile(join(project, "new.txt"), "utf8"), "created\n");
    assert.equal(result.files.length, 2);
    assert.equal(result.precondition.checked, false);
  } finally {
    await rm(project, { recursive: true, force: true });
  }
});

test("patch base hash and target safety fail closed before mutation", async () => {
  const project = await mkdtemp(join(tmpdir(), "mac-operator-patch-precondition-"));
  const existing = join(project, "src.txt");
  try {
    await writeFile(existing, "before\n", { mode: 0o600 });
    const inspector = new FilesystemInspector([writeRoot(project)]);
    const patch = ["*** Begin Patch", "*** Update File: src.txt", "@@", "-before", "+after", "*** End Patch", ""].join("\n");
    const first = applyFilesystemPatch(inspector, inspector.planPath(project, "write"), patch, undefined);
    assert.throws(
      () => applyFilesystemPatch(inspector, inspector.planPath(project, "write"), patch, first.precondition.actualSha256),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );
    assert.equal(await readFile(existing, "utf8"), "after\n");
    assert.throws(
      () => applyFilesystemPatch(inspector, inspector.planPath(project, "write"), patch.replace("src.txt", "../escape.txt"), undefined),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PATH_DENIED"
    );
  } finally {
    await rm(project, { recursive: true, force: true });
  }
});

test("patch rejects symlink targets and unsupported delete operations", async () => {
  const project = await mkdtemp(join(tmpdir(), "mac-operator-patch-boundary-"));
  try {
    await writeFile(join(project, "outside.txt"), "outside\n", { mode: 0o600 });
    await symlink(join(project, "outside.txt"), join(project, "link.txt"));
    const inspector = new FilesystemInspector([writeRoot(project)]);
    const symlinkPatch = ["*** Begin Patch", "*** Update File: link.txt", "@@", "-outside", "+changed", "*** End Patch", ""].join("\n");
    assert.throws(
      () => applyFilesystemPatch(inspector, inspector.planPath(project, "write"), symlinkPatch, undefined),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    const deletePatch = ["*** Begin Patch", "*** Delete File: outside.txt", "*** End Patch", ""].join("\n");
    assert.throws(
      () => applyFilesystemPatch(inspector, inspector.planPath(project, "write"), deletePatch, undefined),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );
    assert.equal(await readFile(join(project, "outside.txt"), "utf8"), "outside\n");
  } finally {
    await rm(project, { recursive: true, force: true });
  }
});

test("patch rolls back files already written when a later target fails", async () => {
  const project = await mkdtemp(join(tmpdir(), "mac-operator-patch-rollback-"));
  try {
    const first = join(project, "first.txt");
    const second = join(project, "second.txt");
    await writeFile(first, "one\n", { mode: 0o600 });
    await writeFile(second, "two\n", { mode: 0o600 });
    const native = loadNativePeerAdapter() as unknown as FilesystemNativeAdapter;
    let writes = 0;
    const failingNative: FilesystemNativeAdapter = {
      ...native,
      writeFileAtomicWithinRoot: (rootPath, targetPath, content, createOnly, expectedPresent, expectedDevice, expectedInode, temporaryName, authorizer) => {
        writes += 1;
        if (writes === 2) throw new Error("injected second-write failure");
        return native.writeFileAtomicWithinRoot(rootPath, targetPath, content, createOnly, expectedPresent, expectedDevice, expectedInode, temporaryName, authorizer);
      }
    };
    const inspector = new FilesystemInspector([writeRoot(project)], failingNative);
    const patch = [
      "*** Begin Patch",
      "*** Update File: first.txt",
      "@@",
      "-one",
      "+ONE",
      "*** Update File: second.txt",
      "@@",
      "-two",
      "+TWO",
      "*** End Patch",
      ""
    ].join("\n");
    assert.throws(
      () => applyFilesystemPatch(inspector, inspector.planPath(project, "write"), patch, undefined),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    assert.equal(await readFile(first, "utf8"), "one\n");
    assert.equal(await readFile(second, "utf8"), "two\n");
    assert.equal(writes, 3);
  } finally {
    await rm(project, { recursive: true, force: true });
  }
});

test("patch reports UNKNOWN_OUTCOME when rollback itself cannot be verified", async () => {
  const project = await mkdtemp(join(tmpdir(), "mac-operator-patch-rollback-unknown-"));
  try {
    const first = join(project, "first.txt");
    const second = join(project, "second.txt");
    await writeFile(first, "one\n", { mode: 0o600 });
    await writeFile(second, "two\n", { mode: 0o600 });
    const native = loadNativePeerAdapter() as unknown as FilesystemNativeAdapter;
    let writes = 0;
    const failingNative: FilesystemNativeAdapter = {
      ...native,
      writeFileAtomicWithinRoot: (rootPath, targetPath, content, createOnly, expectedPresent, expectedDevice, expectedInode, temporaryName, authorizer) => {
        writes += 1;
        if (writes >= 2) throw new Error("injected write and rollback failure");
        return native.writeFileAtomicWithinRoot(rootPath, targetPath, content, createOnly, expectedPresent, expectedDevice, expectedInode, temporaryName, authorizer);
      }
    };
    const inspector = new FilesystemInspector([writeRoot(project)], failingNative);
    const patch = ["*** Begin Patch", "*** Update File: first.txt", "@@", "-one", "+ONE", "*** Update File: second.txt", "@@", "-two", "+TWO", "*** End Patch", ""].join("\n");
    assert.throws(
      () => applyFilesystemPatch(inspector, inspector.planPath(project, "write"), patch, undefined),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME"
    );
    assert.equal(writes, 3);
  } finally {
    await rm(project, { recursive: true, force: true });
  }
});

function writeRoot(path: string) {
  return { rootId: "patch-root", path, metadata: true, contentRead: true, write: true, denyRelativePaths: [] } as const;
}
