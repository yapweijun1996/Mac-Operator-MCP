import assert from "node:assert/strict";
import { mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { FilesystemInspector } from "./filesystem-inspector.js";
import { validateFilesystemWorkerResult, WorkerFilesystemExecutor } from "./filesystem-executor.js";

test("filesystem worker searches multiple roots and recovers bounded capacity", async () => {
  const left = await mkdtemp(join(tmpdir(), "mac-operator-fs-worker-left-"));
  const right = await mkdtemp(join(tmpdir(), "mac-operator-fs-worker-right-"));
  const leftFile = join(left, "needle-left.txt");
  const rightFile = join(right, "needle-right.txt");
  await writeFile(leftFile, "left");
  await writeFile(rightFile, "right");
  try {
    const leftInspector = new FilesystemInspector([root("left-root", left)]);
    const rightInspector = new FilesystemInspector([root("right-root", right)]);
    const plans = [
      leftInspector.planPath(left, "metadata"),
      rightInspector.planPath(right, "metadata")
    ];
    const executor = new WorkerFilesystemExecutor(1);
    const control = { timeoutMs: 5_000, shouldCancel: () => false };
    const first = executor.find(plans, "needle", 10, control);
    await assert.rejects(
      executor.find(plans, "needle", 10, control),
      (error: unknown) => hasErrorClass(error, "CONFLICT")
    );

    const result = await first;
    assert.equal(result.operation, "find");
    if (result.operation !== "find") return;
    assert.deepEqual([...result.roots].sort(), [await realpath(left), await realpath(right)].sort());
    assert.deepEqual(result.matches.map((match) => match.path).sort(), [await realpath(leftFile), await realpath(rightFile)].sort());

    const releaseDeadline = Date.now() + 2_000;
    while (executor.activeCount() !== 0 && Date.now() < releaseDeadline) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
    assert.equal(executor.activeCount(), 0);
    const recovered = await executor.find(plans, "needle", 10, control);
    assert.equal(recovered.operation, "find");
  } finally {
    await rm(left, { recursive: true, force: true });
    await rm(right, { recursive: true, force: true });
  }
});

test("filesystem worker result validation rejects unstable authority fields", () => {
  const metadata = {
    rootId: "root",
    path: "/tmp",
    type: "directory" as const,
    sizeBytes: 0,
    modifiedAt: null,
    mode: "0755",
    isSymlink: false,
    device: "1",
    inode: "2"
  };
  const result = { operation: "stat" as const, metadata };
  assert.deepEqual(validateFilesystemWorkerResult(result), result);
  assert.throws(
    () => validateFilesystemWorkerResult({ ...result, extra: "authority" } as never),
    /malformed result/u
  );
  const accessorMetadata = { ...metadata } as Record<string, unknown>;
  Object.defineProperty(accessorMetadata, "path", { enumerable: true, get: () => "/tmp" });
  assert.throws(
    () => validateFilesystemWorkerResult({ operation: "stat", metadata: accessorMetadata } as never),
    /malformed result/u
  );
  const sparseRead = {
    operation: "read",
    path: "/tmp/file",
    encoding: "metadata",
    sizeBytes: 0,
    sha256: "a".repeat(64),
    truncated: false,
    rootId: "root",
    device: "1",
    inode: "2",
    bytesReturned: 0,
    extra: true
  };
  assert.throws(() => validateFilesystemWorkerResult(sparseRead as never), /malformed result/u);
});

test("filesystem worker normalizes structured-cloned Buffer content before secret inspection", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-worker-write-"));
  try {
    const inspector = new FilesystemInspector([{ ...root("write-root", directory), write: true }]);
    const plan = inspector.planPath(join(directory, "write.txt"), "write");
    const executor = new WorkerFilesystemExecutor(1);
    try {
      const result = await executor.write(
        plan,
        Buffer.from("d1-atomic-write", "utf8"),
        undefined,
        true,
        { timeoutMs: 5_000, shouldCancel: () => false }
      );
      assert.equal(result.operation, "write");
      if (result.operation === "write") {
        assert.equal(result.created, true);
        assert.equal(result.bytesWritten, Buffer.byteLength("d1-atomic-write", "utf8"));
      }
    } finally {
      await executor.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("filesystem worker denies a mutation at the pre-mutation authority gate", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-fs-worker-pre-mutation-"));
  const path = join(directory, "denied.txt");
  try {
    const inspector = new FilesystemInspector([{ ...root("write-root", directory), write: true }]);
    const plan = inspector.planPath(path, "write");
    const executor = new WorkerFilesystemExecutor(1);
    try {
      let checks = 0;
      await assert.rejects(
        executor.write(plan, Buffer.from("must-not-write", "utf8"), undefined, true, {
          timeoutMs: 5_000,
          shouldCancel: () => false,
          beforeMutation: () => {
            checks += 1;
            throw new BrokerError("REVOKED", "authority revoked at the mutation boundary");
          }
        }),
        (error: unknown) => error instanceof BrokerError && error.errorClass === "REVOKED"
      );
      assert.equal(checks, 1);
      await assert.rejects(readFile(path), /ENOENT/u);
      const releaseDeadline = Date.now() + 2_000;
      while (executor.activeCount() !== 0 && Date.now() < releaseDeadline) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
      assert.equal(executor.activeCount(), 0);
    } finally {
      await executor.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

function root(rootId: string, path: string) {
  return { rootId, path, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
}

function hasErrorClass(error: unknown, expected: string): boolean {
  return error !== null && typeof error === "object" && "errorClass" in error &&
    (error as { errorClass: unknown }).errorClass === expected;
}
