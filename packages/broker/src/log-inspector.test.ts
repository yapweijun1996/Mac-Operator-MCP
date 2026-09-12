import assert from "node:assert/strict";
import test from "node:test";
import { MacLogInspector, validateLogRequest } from "./log-inspector.js";

test("log inspector returns bounded sanitized records from the system source", async () => {
  const inspector = new MacLogInspector();
  const result = await inspector.tail("system", 5, 1, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(result.source, "system");
  assert.ok(result.entries.length <= 5);
  assert.ok(result.entries.every((entry) => entry.message.length <= 8192));
  assert.equal(result.entries.some((entry) => entry.message.includes("AKIA")), false);
  assert.ok(result.warnings.length <= 32);
});

test("log inspector rejects arbitrary sources and unbounded windows", () => {
  assert.doesNotThrow(() => validateLogRequest("system", 1, 0));
  assert.doesNotThrow(() => validateLogRequest("process/codex", 2000, 31_536_000));
  const invalid: Array<[string, number, number]> = [
    ["/var/log/system.log", 10, 60],
    ["process/../codex", 10, 60],
    ["user/501/codex", 10, 60],
    ["system", 0, 60],
    ["system", 10, 31_536_001]
  ];
  for (const args of invalid) {
    assert.throws(() => validateLogRequest(...args), /outside the supported range/u);
  }
});
