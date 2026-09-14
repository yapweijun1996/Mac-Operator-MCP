import assert from "node:assert/strict";
import test from "node:test";
import { createDefaultPolicy } from "./default-policy.js";
import { validateBrokerPolicy } from "./policy.js";

test("runtime Broker policy accepts the default tool contract shape", () => {
  assert.doesNotThrow(() => validateBrokerPolicy(createDefaultPolicy("edge-1")));
});

test("runtime Broker policy rejects malformed tool authority before use", () => {
  const base = createDefaultPolicy("edge-1");
  const health = base.tools.get("mac_health");
  assert.ok(health);

  const missingScope = new Map(base.tools).set("mac_health", { ...health, requiredScopes: [] });
  assert.throws(
    () => validateBrokerPolicy({ ...base, tools: missingScope }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains a malformed tool policy"
  );

  const enabledUnimplemented = new Map(base.tools).set("mac_health", { ...health, implemented: false, enabled: true });
  assert.throws(
    () => validateBrokerPolicy({ ...base, tools: enabledUnimplemented }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains a malformed tool policy"
  );

  const unknownTool = new Map(base.tools).set("mac_unknown", { ...health, tool: "mac_unknown" });
  assert.throws(
    () => validateBrokerPolicy({ ...base, tools: unknownTool }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains a malformed tool policy"
  );
});
