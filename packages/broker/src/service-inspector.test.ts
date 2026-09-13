import assert from "node:assert/strict";
import test from "node:test";
import { LaunchdServiceInspector, validateServiceId } from "./service-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

test("launchd service inspector returns bounded status for an allowlisted system service", async () => {
  const inspector = new LaunchdServiceInspector();
  const status = await inspector.inspect("system/com.apple.logd", {
    timeoutMs: 5_000,
    shouldCancel: () => false
  });
  assert.equal(status.serviceId, "system/com.apple.logd");
  assert.equal(status.loaded, true);
  assert.ok(["loaded", "running", "stopped", "failed", "unknown"].includes(status.state));
  assert.equal(status.running, status.state === "running");
  assert.ok(status.pid === null || (Number.isSafeInteger(status.pid) && status.pid > 0 && status.pid <= 99_999_999));
  assert.ok(status.lastExitCode === null || Number.isSafeInteger(status.lastExitCode));
  assert.equal(status.truncated, false);
});

test("launchd service identifiers reject traversal and non-system domains", () => {
  assert.doesNotThrow(() => validateServiceId("system/com.apple.logd"));
  for (const serviceId of ["", "user/501/com.example", "system/../x", "system//x", "system/x\\y", "system/"]) {
    assert.throws(() => validateServiceId(serviceId), /system launchd identifier/u);
  }
});

test("launchd service inspector treats xpcproxy as loaded, not running", async () => {
  const serviceId = "system/com.apple.logd";
  const executor = {
    async run(): Promise<ProcessExecutionResult> {
      return {
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        signal: null,
        stdout: `${serviceId} = {\n\tstate = xpcproxy\n\tpid = 4123\n\tlast exit code = (never exited)\n}`,
        stderr: "",
        truncated: false,
        durationMs: 1,
        processId: 1,
        processGroupId: 1,
        terminationObserved: true
      };
    }
  } as never;
  const status = await new LaunchdServiceInspector(executor).inspect(serviceId, {
    timeoutMs: 5_000,
    shouldCancel: () => false
  });
  assert.equal(status.state, "loaded");
  assert.equal(status.running, false);
  assert.equal(status.pid, 4123);
});
