import assert from "node:assert/strict";
import test from "node:test";
import { inspectProcesses } from "./process-inspector.js";

test("process inspector returns bounded redacted native metadata", () => {
  const inventory = inspectProcesses(20, "pid");
  assert.ok(inventory.processes.length <= 20);
  assert.equal([...inventory.processes].every((process) => process.pid > 0), true);
  assert.equal([...inventory.processes].every((process) => process.name.length > 0 && process.name.length <= 256), true);
  assert.equal([...inventory.processes].every((process) => process.executable.length > 0 && process.executable.length <= 4096), true);
  assert.equal([...inventory.processes].every((process) => process.cpuPercent >= 0 && process.cpuPercent <= 100), true);
  assert.equal([...inventory.processes].every((process) => process.memoryBytes >= 0 && process.memoryBytes <= 1_000_000_000_000), true);
  assert.equal([...inventory.processes].every((process) => /^uid:\d+$/u.test(process.owner)), true);
  for (let index = 1; index < inventory.processes.length; index += 1) {
    assert.ok(inventory.processes[index - 1]!.pid <= inventory.processes[index]!.pid);
  }
});

test("process inspector rejects unbounded limits and unsupported sorting", () => {
  assert.throws(() => inspectProcesses(0, "pid"), /outside the supported range/u);
  assert.throws(() => inspectProcesses(501, "pid"), /outside the supported range/u);
  assert.throws(() => inspectProcesses(10, "unsupported" as "pid"), /unsupported/u);
});
