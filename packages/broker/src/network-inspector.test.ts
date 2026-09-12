import assert from "node:assert/strict";
import test from "node:test";
import { inspectNetwork } from "./network-inspector.js";

test("network inspector returns bounded local interface metadata without active probes", () => {
  const status = inspectNetwork(false);
  assert.ok(status.interfaces.length <= 64);
  assert.ok(status.listeners.length === 0);
  assert.ok(["online", "limited", "offline", "unknown"].includes(status.connectivity));
  assert.equal(status.truncated, false);
  assert.equal(status.warnings.some((warning) => warning.includes("active network probe")), true);
  for (const networkInterface of status.interfaces) {
    assert.match(networkInterface.name, /^[A-Za-z0-9._:@/+-]+$/u);
    assert.ok(networkInterface.addresses.length <= 32);
    assert.ok(["up", "down", "unknown"].includes(networkInterface.state));
  }
});

test("network inspector fails closed for malformed listener option", () => {
  assert.throws(() => inspectNetwork("yes" as unknown as boolean), /include_listeners must be a boolean/u);
});
