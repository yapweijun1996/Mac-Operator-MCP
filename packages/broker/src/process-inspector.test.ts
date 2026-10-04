import assert from "node:assert/strict";
import test from "node:test";
import { assertProcessDetailIdentity, assertStableProcessIdentity, classifyProcessReadFailure, inspectProcess, inspectProcesses, parseProcessDetail, parseProcessInventory } from "./process-inspector.js";

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

test("process inspector returns bounded detail without argv or environment", () => {
  const process = inspectProcess(globalThis.process.pid);
  assert.equal(process.pid, globalThis.process.pid);
  assert.ok(process.name.length > 0 && process.name.length <= 256);
  assert.ok(process.executable.length > 0 && process.executable.length <= 4096);
  assert.ok(["running", "sleeping", "stopped", "zombie", "unknown"].includes(process.state));
  assert.ok(process.cpuPercent >= 0 && process.cpuPercent <= 100);
  assert.ok(process.memoryBytes >= 0 && process.memoryBytes <= 1_000_000_000_000);
  assert.match(process.owner, /^uid:\d+$/u);
  assert.ok(process.childPids.length <= 256);
  for (let index = 1; index < process.childPids.length; index += 1) {
    assert.ok(process.childPids[index - 1]! < process.childPids[index]!);
  }
});

test("process inspector rejects malformed pid", () => {
  assert.throws(() => inspectProcess(0), /outside the supported range/u);
  assert.throws(() => inspectProcess(100_000_000), /outside the supported range/u);
});

test("process inspector rejects PID reuse across native identity readbacks", () => {
  assert.doesNotThrow(() => assertStableProcessIdentity(
    42,
    { pid: 42, startTimeMicros: 100 },
    { pid: 42, startTimeMicros: 100 }
  ));
  assert.throws(
    () => assertStableProcessIdentity(42, { pid: 42, startTimeMicros: 100 }, { pid: 42, startTimeMicros: 101 }),
    /identity changed during inspection/u
  );
  assert.throws(
    () => assertStableProcessIdentity(42, { pid: 41, startTimeMicros: 100 }, { pid: 42, startTimeMicros: 100 }),
    /identity changed during inspection/u
  );
});

test("process inspector binds adapter detail to the requested PID", () => {
  assert.doesNotThrow(() => assertProcessDetailIdentity(42, { pid: 42 }));
  assert.throws(
    () => assertProcessDetailIdentity(42, { pid: 41 }),
    /identity changed during inspection/u
  );
});

test("process inspector result parsers reject non-data and unstable child identities", () => {
  const inventory = { processes: [], truncated: false };
  assert.deepEqual(parseProcessInventory(inventory), inventory);
  assert.throws(() => parseProcessInventory(Object.create(inventory)), /Malformed native process inventory/u);
  const accessorProcess = {
    pid: 1,
    name: "process",
    executable: "/usr/bin/process",
    cpuPercent: 0,
    memoryBytes: 0,
    owner: "uid:501"
  } as Record<string, unknown>;
  Object.defineProperty(accessorProcess, "name", { enumerable: true, get: () => "process" });
  assert.throws(
    () => parseProcessInventory({ processes: [accessorProcess], truncated: false }),
    /Malformed native process record/u
  );
  assert.throws(
    () => parseProcessDetail({
      pid: 1, name: "process", executable: "/usr/bin/process", state: "running", cpuPercent: 0,
      memoryBytes: 0, parentPid: null, childPids: [2, 2], owner: "uid:501"
    }),
    /Malformed native process child identity/u
  );
  const symbolicDetail = {
    pid: 1, name: "process", executable: "/usr/bin/process", state: "running", cpuPercent: 0,
    memoryBytes: 0, parentPid: null, childPids: [], owner: "uid:501"
  } as Record<string, unknown>;
  Object.defineProperty(symbolicDetail, Symbol("authority"), { value: true });
  assert.throws(() => parseProcessDetail(symbolicDetail), /Malformed native process detail/u);
});

test("process read failures are classified as missing or OS-denied", () => {
  const raw = new Error("Process identity could not be read");
  const failWith = (code: string) => () => { throw Object.assign(new Error(code), { code }); };
  const missing = classifyProcessReadFailure(4242, raw, failWith("ESRCH")) as { errorClass: string };
  assert.equal(missing.errorClass, "TARGET_NOT_FOUND");
  const denied = classifyProcessReadFailure(1, raw, failWith("EPERM")) as { errorClass: string; message: string };
  assert.equal(denied.errorClass, "POLICY_DENIED");
  assert.match(denied.message, /does not allow this account/u);
  assert.equal(classifyProcessReadFailure(4242, raw, () => true), raw);
  assert.equal(classifyProcessReadFailure(4242, raw, failWith("EINVAL")), raw);
});
