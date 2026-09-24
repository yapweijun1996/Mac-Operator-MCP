import assert from "node:assert/strict";
import test from "node:test";
import { createPrivilegedHelperAdapter } from "./privileged-helper-adapters.js";

test("privileged helper composition is fail-closed by default", () => {
  const adapter = createPrivilegedHelperAdapter();
  assert.equal(adapter.available, false);
  assert.deepEqual(adapter.enabledCapabilities, []);
});

test("privileged helper composition projects only adapters that are independently available", () => {
  const adapter = createPrivilegedHelperAdapter({
    serviceControl: {
      enabled: true,
      commandRunner: { run: async () => { throw new Error("test service runner must not execute"); } },
      inspector: { inspect: async () => { throw new Error("test service inspector must not execute"); } }
    }
  });
  assert.equal(adapter.available, true);
  assert.deepEqual(adapter.enabledCapabilities, ["mac_priv_service_control"]);
});
