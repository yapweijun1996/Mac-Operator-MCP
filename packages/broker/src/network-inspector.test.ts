import assert from "node:assert/strict";
import test from "node:test";
import { inspectNetwork, parseNativeNetwork } from "./network-inspector.js";

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

test("network native result validation rejects unstable authority fields", () => {
  const valid = {
    interfaces: [{ name: "en0", state: "up", addresses: ["192.0.2.10"] }],
    listeners: [{ protocol: "tcp", address: "127.0.0.1", port: 8080 }],
    listenerQueryFailed: false,
    listenersTruncated: false
  };
  assert.deepEqual(parseNativeNetwork(valid), valid);
  assert.throws(() => parseNativeNetwork({ ...valid, extra: true }), /malformed result/u);

  const accessorInterface = { ...valid.interfaces[0] } as Record<string, unknown>;
  Object.defineProperty(accessorInterface, "name", { enumerable: true, get: () => "en0" });
  assert.throws(
    () => parseNativeNetwork({ ...valid, interfaces: [accessorInterface] }),
    /malformed result/u
  );

  const sparseAddresses: unknown[] = [];
  sparseAddresses.length = 1;
  assert.throws(
    () => parseNativeNetwork({ ...valid, interfaces: [{ ...valid.interfaces[0], addresses: sparseAddresses }] }),
    /malformed result/u
  );

  assert.throws(
    () => parseNativeNetwork({ ...valid, listeners: [{ ...valid.listeners[0], extra: "authority" }] }),
    /malformed result/u
  );
});
