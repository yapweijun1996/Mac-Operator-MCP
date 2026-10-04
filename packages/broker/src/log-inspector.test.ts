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
  assert.ok(result.warnings.some((warning) => warning.includes("newest records are missing")));
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
    assert.throws(() => validateLogRequest(...args), /source must be|lines must be|since_seconds must be/u);
  }
  assert.throws(() => validateLogRequest("system/com.apple.logd", 10, 60), /service id for mac_service_status/u);
  assert.throws(() => validateLogRequest("system", 0, 60), /lines must be an integer between 1 and 2000/u);
  assert.throws(() => validateLogRequest("system", 10, 31_536_001), /since_seconds must be an integer between 0 and 31536000/u);
});

test("log inspector folds continuation lines into their record and drops a cut-off final line", async () => {
  const stdout = [
    "Filtering the log data using \"process == x\"",
    "2026-09-14 12:00:00.000 Df app[1:2] [com.x] first line",
    "    continued detail",
    "2026-09-14 12:00:01.000 Df app[1:2] [com.x] second",
    "2026-09-14 12:00:02.000 Df app[1:2] [com.x] cut off mid-sen"
  ].join("\n");
  const inspector = new MacLogInspector({ run: async () => fakeResult("OUTPUT_LIMIT", stdout) });
  const result = await inspector.tail("system", 10, 1, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.deepEqual(result.entries.map((entry) => entry.message), ["first line\ncontinued detail", "second"]);
  assert.equal(result.warnings.some((warning) => /malformed/u.test(warning)), false);
  assert.ok(result.warnings.includes("The final partial log record was dropped"));
});

test("log inspector counts only date-prefixed lines it cannot parse as malformed", async () => {
  const stdout = "2026-09-14 12:00:00.000 Df app[1:2] ok\n2026-09-14 12:00:01 broken\n";
  const inspector = new MacLogInspector({ run: async () => fakeResult("SUCCEEDED", stdout) });
  const result = await inspector.tail("system", 10, 1, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(result.entries.length, 1);
  assert.ok(result.warnings.includes("1 malformed log record was omitted"));
});

test("log inspector narrows the window until the newest records fit the output budget", async () => {
  const windows: string[] = [];
  const inspector = new MacLogInspector({
    run: async (request) => {
      windows.push(request.args[2]!);
      return windows.length < 3
        ? fakeResult("OUTPUT_LIMIT", "2026-09-14 12:00:00.000 Default kernel [x] oldest\n")
        : fakeResult("SUCCEEDED", "2026-09-14 12:10:00.000 Default kernel [x] newest\n");
    }
  });
  const result = await inspector.tail("system", 5, 600, { timeoutMs: 10_000, shouldCancel: () => false });
  assert.deepEqual(windows, ["600s", "150s", "37s"]);
  assert.equal(result.entries[0]?.message, "newest");
  assert.ok(result.warnings.some((warning) => warning.includes("narrowed to the last 37s")));
  assert.ok(!result.warnings.some((warning) => warning.includes("newest records are missing")));
});
