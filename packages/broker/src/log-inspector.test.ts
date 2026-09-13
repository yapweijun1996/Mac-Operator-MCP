import assert from "node:assert/strict";
import test from "node:test";
import { MacLogInspector, validateLogRequest } from "./log-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

function fakeResult(resultClass: ProcessExecutionResult["resultClass"], stdout: string): ProcessExecutionResult {
  return {
    state: resultClass === "SUCCEEDED" ? "completed" : resultClass === "OUTPUT_LIMIT" ? "failed" : "unknown",
    resultClass,
    exitCode: resultClass === "SUCCEEDED" ? 0 : null,
    signal: null,
    stdout,
    stderr: "",
    truncated: resultClass === "OUTPUT_LIMIT",
    durationMs: 1,
    processId: 123,
    processGroupId: 123,
    terminationObserved: true
  };
}

test("log inspector returns bounded sanitized records from the system source", async () => {
  const inspector = new MacLogInspector();
  const result = await inspector.tail("system", 5, 1, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(result.source, "system");
  assert.ok(result.entries.length <= 5);
  assert.ok(result.entries.every((entry) => entry.message.length <= 8192));
  assert.equal(result.entries.some((entry) => entry.message.includes("AKIA")), false);
  assert.ok(result.warnings.length <= 32);
});

test("log inspector returns a redacted bounded prefix when the source exceeds its output budget", async () => {
  const inspector = new MacLogInspector({
    run: async () => fakeResult(
      "OUTPUT_LIMIT",
      "2026-09-14 12:00:00.000 Default kernel [AKIAIOSFODNN7EXAMPLE] bounded\n"
    )
  });
  const result = await inspector.tail("system", 5, 1, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(result.entries.length, 1);
  assert.equal(result.entries[0]?.message.includes("AKIA"), false);
  assert.equal(result.truncated, true);
  assert.ok(result.warnings.includes("Log output was truncated by a fixed adapter budget"));
});

test("log inspector does not infer a result from an unresolved process outcome", async () => {
  const inspector = new MacLogInspector({
    run: async () => fakeResult("UNKNOWN_OUTCOME", "partial\n")
  });
  await assert.rejects(
    inspector.tail("system", 5, 1, { timeoutMs: 10_000, shouldCancel: () => false }),
    /outcome could not be verified/u
  );
});

test("log inspector rejects an output limit without observed termination", async () => {
  const inspector = new MacLogInspector({
    run: async () => ({ ...fakeResult("OUTPUT_LIMIT", "partial\n"), terminationObserved: false })
  });
  await assert.rejects(
    inspector.tail("system", 5, 1, { timeoutMs: 10_000, shouldCancel: () => false }),
    /termination could not be verified/u
  );
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
