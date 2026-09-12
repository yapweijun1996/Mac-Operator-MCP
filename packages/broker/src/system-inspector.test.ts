import assert from "node:assert/strict";
import test from "node:test";
import { inspectSystem } from "./system-inspector.js";

test("system inspector returns bounded host facts without user identity", () => {
  const summary = inspectSystem(true);
  assert.ok(summary.osVersion.length >= 1 && summary.osVersion.length <= 128);
  assert.ok(summary.architecture.length >= 1 && summary.architecture.length <= 128);
  assert.ok(summary.cpuCount >= 1 && summary.cpuCount <= 256);
  assert.ok(summary.memoryBytes >= 1 && summary.memoryBytes <= 1_000_000_000_000);
  assert.ok(summary.uptimeSeconds >= 0 && summary.uptimeSeconds <= 1_000_000_000);
  assert.ok(summary.load);
  assert.ok(summary.load.one >= 0 && summary.load.one <= 1_000_000);
  assert.ok(!summary.osVersion.includes("\0"));
});

test("system inspector omits load when not requested", () => {
  assert.equal(inspectSystem(false).load, undefined);
});
