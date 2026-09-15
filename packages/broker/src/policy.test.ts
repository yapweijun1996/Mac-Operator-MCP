import assert from "node:assert/strict";
import test from "node:test";
import { createDefaultPolicy } from "./default-policy.js";
import { authorizeTarget, cloneBrokerPolicy, validateBrokerPolicy } from "./policy.js";
import { PolicyManager } from "./policy-loader.js";

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

  const malformedTargetRules = [...base.targetRules, {
    ruleId: "bad-target-rule",
    effect: "allow" as const,
    principalId: "principal-1",
    scope: "mac.control.read" as const,
    target: { kind: "host" as const, reference: "*" }
  }];
  assert.throws(
    () => validateBrokerPolicy({ ...base, targetRules: malformedTargetRules }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains malformed target authority"
  );

  const malformedKeyWindows = new Map(base.trustedEdgeKeys).set("edge-1:edge-key-1", null as never);
  assert.throws(
    () => validateBrokerPolicy({ ...base, trustedEdgeKeys: malformedKeyWindows }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains malformed key authority"
  );
});

test("runtime Broker policy rejects inherited authority fields", () => {
  const base = createDefaultPolicy("edge-1", false, ["mac.control.read"]);
  const health = base.tools.get("mac_health");
  const principal = base.principalGrants.get("principal-1");
  assert.ok(health);
  assert.ok(principal);
  const inheritedKillSwitches = Object.create({
    global: false,
    mutations: false,
    process: false,
    network: false,
    gui: false,
    destructive: false,
    privileged: false
  }) as Record<string, boolean>;
  const inheritedTool = Object.create(health) as Record<string, unknown>;
  const inheritedGrant = Object.create(principal) as Record<string, unknown>;

  assert.throws(
    () => validateBrokerPolicy({ ...base, killSwitches: inheritedKillSwitches as never }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy is malformed"
  );
  assert.throws(
    () => validateBrokerPolicy({ ...base, tools: new Map([["mac_health", inheritedTool]]) as never }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains a malformed tool policy"
  );
  assert.throws(
    () => validateBrokerPolicy({ ...base, principalGrants: new Map([["principal-1", inheritedGrant]]) as never }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains malformed principal authority"
  );
});

test("policy authority snapshots isolate mutable caller references", () => {
  const base = createDefaultPolicy("edge-1", true, ["mac.control.read"]);
  const snapshot = cloneBrokerPolicy(base);
  const originalRuleCount = snapshot.targetRules.length;
  const originalScopeCount = snapshot.principalGrants.get("principal-1")?.scopes.length;

  const mutableRules = base.targetRules as Array<(typeof base.targetRules)[number]>;
  mutableRules.push({
    ruleId: "caller-added-target",
    effect: "allow",
    principalId: "principal-1",
    scope: "mac.control.read",
    target: { kind: "host", reference: "attacker-target" }
  });
  const grant = base.principalGrants.get("principal-1");
  assert.ok(grant);
  const mutableGrants = base.principalGrants as Map<string, typeof grant>;
  mutableGrants.set("principal-1", { ...grant, scopes: [...grant.scopes, "mac.files.read"] });
  const mutableSwitches = base.killSwitches as Record<string, boolean>;
  mutableSwitches.global = true;
  const health = base.tools.get("mac_health");
  assert.ok(health);
  const mutableTools = base.tools as Map<string, typeof health>;
  mutableTools.set("mac_health", { ...health, requiredScopes: [...health.requiredScopes, "mac.files.read"] });

  assert.equal(snapshot.targetRules.length, originalRuleCount);
  assert.equal(snapshot.principalGrants.get("principal-1")?.scopes.length, originalScopeCount);
  assert.equal(snapshot.killSwitches.global, false);
  assert.deepEqual(snapshot.tools.get("mac_health")?.requiredScopes, ["mac.control.read"]);
  assert.throws(
    () => authorizeTarget(snapshot, "principal-1", ["mac.control.read"], { kind: "host", reference: "attacker-target" }),
    (error: unknown) => error instanceof Error && error.message === "Target is not allowed for every required scope"
  );

  const manager = new PolicyManager(createDefaultPolicy("edge-1", true, ["mac.control.read"]));
  const exposed = manager.current();
  const exposedRules = exposed.targetRules as Array<(typeof exposed.targetRules)[number]>;
  exposedRules.push({
    ruleId: "exposed-target",
    effect: "allow",
    principalId: "principal-1",
    scope: "mac.control.read",
    target: { kind: "host", reference: "exposed-target" }
  });
  assert.equal(manager.current().targetRules.some((rule) => rule.ruleId === "exposed-target"), false);
});
