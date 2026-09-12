import assert from "node:assert/strict";
import test from "node:test";
import { LaunchdServiceInspector, validateServiceId } from "./service-inspector.js";

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
