import assert from "node:assert/strict";
import { mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { FilesystemInspector } from "./filesystem-inspector.js";
import { WorkerFilesystemExecutor } from "./filesystem-executor.js";

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

function root(rootId: string, path: string) {
  return { rootId, path, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
}

function hasErrorClass(error: unknown, expected: string): boolean {
  return error !== null && typeof error === "object" && "errorClass" in error &&
    (error as { errorClass: unknown }).errorClass === expected;
}
