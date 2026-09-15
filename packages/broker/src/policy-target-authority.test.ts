import assert from "node:assert/strict";
import test from "node:test";
import { SCOPES, type Scope } from "@mac-operator/contracts";
import { createDefaultPolicy } from "./default-policy.js";
import { authorizeTarget, validateBrokerPolicy, type BrokerPolicy, type NormalizedTarget, type TargetConstraint } from "./policy.js";

const root = {
  rootId: "workspace",
  path: "/tmp",
  metadata: true,
  contentRead: true,
  write: true,
  denyRelativePaths: []
} as const;

function policyWithTarget(scope: Scope, target: NormalizedTarget, targetConstraint?: TargetConstraint): BrokerPolicy {
  const base = createDefaultPolicy(
    "edge-1",
    true,
    [...SCOPES],
    ["edge-key-1"],
    [root],
    ["system/com.apple.logd"],
    ["system"],
    ["/tmp"],
    ["registry.example/image:1.2"],
    ["tests.echo"],
    ["bundle:com.example.Editor"]
  );
  return {
    ...base,
    targetRules: [...base.targetRules, {
      ruleId: `test-${scope.replace(/[^A-Za-z0-9]/gu, "-")}-${target.kind}`,
      effect: "allow",
      principalId: "principal-1",
      scope,
      target,
      ...(targetConstraint === undefined ? {} : { targetConstraint })
    }]
  };
}

test("policy target authority accepts the canonical resource references used by Broker adapters", () => {
  const base = createDefaultPolicy(
    "edge-1",
    true,
    [...SCOPES],
    ["edge-key-1"],
    [root],
    ["system/com.apple.logd"],
    ["system", "process/logd"],
    ["/tmp"],
    ["registry.example/image:1.2"],
    ["tests.echo"],
    ["bundle:com.example.Editor"]
  );
  assert.doesNotThrow(() => validateBrokerPolicy(base));
  assert.doesNotThrow(() => validateBrokerPolicy(policyWithTarget("mac.control.read", { kind: "host", reference: "local" })));
  assert.doesNotThrow(() => validateBrokerPolicy(policyWithTarget("mac.process.read", { kind: "process", reference: "pid:42" })));
  assert.doesNotThrow(() => validateBrokerPolicy(policyWithTarget("mac.ui.control", { kind: "ui_element", reference: "element:0123456789abcdef0123456789abcdef0123456789abcdef" })));
  assert.doesNotThrow(() => validateBrokerPolicy(policyWithTarget("mac.priv.power", { kind: "power", reference: "local" })));
});

test("policy target authority rejects malformed or cross-kind resource references", () => {
  const malformed: Array<[Scope, NormalizedTarget]> = [
    ["mac.files.read", { kind: "path", reference: "../workspace" }],
    ["mac.project.read", { kind: "project", reference: "/tmp/../etc" }],
    ["mac.process.read", { kind: "process", reference: "pid:000" }],
    ["mac.job.read", { kind: "job", reference: "job:actual" }],
    ["mac.task.run", { kind: "task_profile", reference: "tests/profile" }],
    ["mac.app.control", { kind: "app", reference: "com.example.Editor" }],
    ["mac.ui.observe", { kind: "app_window", reference: "window:com.example.Editor" }],
    ["mac.ui.control", { kind: "ui_element", reference: "element:short" }],
    ["mac.service.read", { kind: "service", reference: "system/../logd" }],
    ["mac.log.read", { kind: "log_source", reference: "process/../logd" }],
    ["mac.docker.read", { kind: "docker_runtime", reference: "broker" }],
    ["mac.docker.read", { kind: "docker_object", reference: "../image" }],
    ["mac.priv.package", { kind: "package", reference: " package" }],
    ["mac.priv.power", { kind: "power", reference: "broker" }]
  ];
  for (const [scope, target] of malformed) {
    assert.throws(
      () => validateBrokerPolicy(policyWithTarget(scope, target)),
      (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains malformed target authority",
      `${target.kind}:${target.reference}`
    );
  }
});

test("finite target constraints authorize only their canonical same-kind references", () => {
  const policy = policyWithTarget(
    "mac.service.read",
    { kind: "service", reference: "system/com.apple.logd" },
    { mode: "finite_set", references: ["system/com.apple.launchd", "system/com.apple.logd"] }
  );
  assert.doesNotThrow(() => validateBrokerPolicy(policy));
  assert.doesNotThrow(() => authorizeTarget(
    policy,
    "principal-1",
    ["mac.service.read"],
    { kind: "service", reference: "system/com.apple.launchd" }
  ));
  assert.throws(
    () => authorizeTarget(policy, "principal-1", ["mac.service.read"], { kind: "service", reference: "system/com.apple.WindowServer" }),
    (error: unknown) => error instanceof Error && error.message === "Target is not allowed for every required scope"
  );
});

test("finite target constraints reject duplicate, unsorted, missing-anchor, wildcard, and cross-kind references", () => {
  const cases: TargetConstraint[] = [
    { mode: "finite_set", references: ["system/com.apple.logd", "system/com.apple.logd"] },
    { mode: "finite_set", references: ["system/com.apple.logd", "system/com.apple.launchd"] },
    { mode: "finite_set", references: ["system/com.apple.launchd"] },
    { mode: "finite_set", references: ["system/com.apple.logd", "system/*"] },
    { mode: "finite_set", references: ["system/com.apple.logd", "bundle:com.example.Editor"] }
  ];
  for (const targetConstraint of cases) {
    const policy = policyWithTarget(
      "mac.service.read",
      { kind: "service", reference: "system/com.apple.logd" },
      targetConstraint
    );
    assert.throws(
      () => validateBrokerPolicy(policy),
      (error: unknown) => error instanceof Error && error.message === "Active Broker policy contains malformed target authority",
      JSON.stringify(targetConstraint)
    );
  }
});
