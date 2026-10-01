import assert from "node:assert/strict";
import test from "node:test";
import { PLANNED_TOOL_NAMES } from "@mac-operator/contracts";
import type { Scope } from "@mac-operator/contracts";
import { createDefaultPolicy } from "./default-policy.js";
import { authorizePrincipalProjection, authorizeTarget, authorizeTool, cloneBrokerPolicy, validateBrokerPolicy } from "./policy.js";
import type { BrokerStore } from "./persistence.js";
import { PolicyManager } from "./policy-loader.js";

test("runtime Broker policy accepts the default tool contract shape", () => {
  assert.doesNotThrow(() => validateBrokerPolicy(createDefaultPolicy("edge-1")));
});

test("default Broker policy represents every planned tool and keeps privileged tools explicit but disabled", () => {
  const policy = createDefaultPolicy("edge-1");
  const privileged = [
    ["mac_priv_service_control", "mac.priv.service", "service", 30_000, 262_144],
    ["mac_priv_package_install", "mac.priv.package", "package", 600_000, 1_048_576],
    ["mac_priv_power", "mac.priv.power", "broker", 30_000, 262_144]
  ] as const;
  assert.equal(policy.tools.size, PLANNED_TOOL_NAMES.length);
  assert.deepEqual(policy.tools.get("mac_service_control"), {
    tool: "mac_service_control",
    contractVersion: "0.1",
    requiredScopes: ["mac.service.control"],
    capabilityFamilies: ["write"],
    targetType: "service",
    mutation: true,
    approvalPolicy: "trusted_write",
    outputCapBytes: 262_144,
    timeoutMs: 30_000,
    implemented: true,
    enabled: false
  });
  for (const [toolName, scope, targetType, timeoutMs, outputCapBytes] of privileged) {
    const tool = policy.tools.get(toolName);
    assert.ok(tool);
    assert.deepEqual(tool.requiredScopes, [scope]);
    assert.equal(tool.capabilityFamilies[0], "privileged");
    assert.equal(tool.targetType, targetType);
    assert.equal(tool.timeoutMs, timeoutMs);
    assert.equal(tool.outputCapBytes, outputCapBytes);
    assert.equal(tool.implemented, true);
    assert.equal(tool.enabled, false);
  }
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

test("runtime Broker policy rejects accessor and sparse authority arrays", () => {
  const base = createDefaultPolicy("edge-1", true, ["mac.control.read"]);
  const principal = base.principalGrants.get("principal-1");
  assert.ok(principal);
  const accessorScopes = [...principal.scopes] as Scope[];
  Object.defineProperty(accessorScopes, "0", { enumerable: true, get: () => "mac.control.read" });
  const accessorGrants = new Map(base.principalGrants);
  accessorGrants.set("principal-1", { ...principal, scopes: accessorScopes });
  assert.throws(
    () => validateBrokerPolicy({ ...base, principalGrants: accessorGrants }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains malformed principal authority"
  );

  const sparseRules = new Array(base.targetRules.length) as typeof base.targetRules;
  assert.throws(
    () => validateBrokerPolicy({ ...base, targetRules: sparseRules }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy is malformed"
  );
});

test("runtime Broker policy rejects authority arrays with custom prototypes", () => {
  const base = createDefaultPolicy("edge-1", true, ["mac.control.read"]);
  const principal = base.principalGrants.get("principal-1");
  assert.ok(principal);

  const hostileScopes = [...principal.scopes] as Scope[];
  Object.setPrototypeOf(hostileScopes, { every: () => true });
  assert.throws(
    () => validateBrokerPolicy({
      ...base,
      principalGrants: new Map(base.principalGrants).set("principal-1", { ...principal, scopes: hostileScopes })
    }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains malformed principal authority"
  );

  const hostileRules = [...base.targetRules] as typeof base.targetRules;
  Object.setPrototypeOf(hostileRules, { filter: () => [] });
  assert.throws(
    () => validateBrokerPolicy({ ...base, targetRules: hostileRules }),
    (error: unknown) => error instanceof Error && error.message === "Active Broker policy is malformed"
  );
});

test("policy authorization rejects non-data projected scopes and targets", () => {
  const policy = createDefaultPolicy("edge-1", true, ["mac.control.read"]);
  const accessorScopes = ["mac.control.read"] as Scope[];
  Object.defineProperty(accessorScopes, "0", { enumerable: true, get: () => "mac.control.read" });
  assert.throws(
    () => authorizePrincipalProjection(policy, "principal-1", "issuer-1", accessorScopes),
    (error: unknown) => error instanceof Error && error.message === "Principal authority projection is malformed"
  );

  const accessorTarget = { kind: "host", reference: "broker" } as Record<string, string>;
  Object.defineProperty(accessorTarget, "reference", { enumerable: true, get: () => "broker" });
  assert.throws(
    () => authorizeTarget(policy, "principal-1", ["mac.control.read"], accessorTarget as never),
    (error: unknown) => error instanceof Error && error.message === "Target authority is malformed"
  );
});

test("tool authorization rejects malformed caller scope lists before policy checks", () => {
  const policy = createDefaultPolicy("edge-1", true, ["mac.control.read"]);
  const store = { isSwitchDisabled: () => false } as unknown as BrokerStore;
  const malformed = [
    ["mac.control.read", "mac.control.read"],
    ["mac.not-a-scope"],
    Object.assign(new Array(1), { 1: "mac.control.read" })
  ] as readonly (readonly string[])[];

  for (const scopes of malformed) {
    assert.throws(
      () => authorizeTool(store, policy, "mac_health", "0.1", scopes as never),
      (error: unknown) => error instanceof Error && error.message === "Principal scopes are malformed"
    );
  }
});

test("target authorization rejects disabled grants and scopes outside the grant", () => {
  const base = createDefaultPolicy("edge-1", true, ["mac.control.read"]);
  const target = { kind: "host" as const, reference: "broker" };
  const disabledGrant = new Map(base.principalGrants);
  const grant = disabledGrant.get("principal-1");
  assert.ok(grant);
  disabledGrant.set("principal-1", { ...grant, enabled: false });
  assert.throws(
    () => authorizeTarget({ ...base, principalGrants: disabledGrant }, "principal-1", ["mac.control.read"], target),
    (error: unknown) => error instanceof Error && error.message === "Principal authority is not enabled"
  );

  assert.throws(
    () => authorizeTarget(base, "principal-1", ["mac.files.read"], target),
    (error: unknown) => error instanceof Error && error.message === "Principal scope is not granted"
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
