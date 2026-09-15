import assert from "node:assert/strict";
import test from "node:test";
import { validateProcessDetail, validateProcessResult } from "./process-executor.js";

const processInfo = {
  pid: 10,
  name: "worker",
  executable: "/usr/bin/worker",
  cpuPercent: 1.5,
  memoryBytes: 4_096,
  owner: "uid:501"
};

test("process worker validators project only strict native result fields", () => {
  const inventory = { processes: [processInfo], truncated: false };
  assert.deepEqual(validateProcessResult(inventory), inventory);
  assert.throws(() => validateProcessResult({ ...inventory, extra: true } as never), /malformed result/u);

  const sparseProcesses: unknown[] = [];
  sparseProcesses.length = 1;
  assert.throws(() => validateProcessResult({ processes: sparseProcesses, truncated: false } as never), /malformed result/u);

  const detail = {
    ...processInfo,
    state: "running" as const,
    parentPid: null,
    childPids: [11, 12]
  };
  assert.deepEqual(validateProcessDetail(detail), detail);
  assert.throws(() => validateProcessDetail({ ...detail, extra: true } as never), /malformed process detail/u);
  const accessorDetail = { ...detail } as Record<string, unknown>;
  Object.defineProperty(accessorDetail, "pid", { enumerable: true, get: () => 10 });
  assert.throws(() => validateProcessDetail(accessorDetail as never), /malformed process detail/u);
});
