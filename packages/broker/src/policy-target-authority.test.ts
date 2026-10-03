import assert from "node:assert/strict";
import test from "node:test";
import { SCOPES, type Scope } from "@mac-operator/contracts";
import { createDefaultPolicy } from "./default-policy.js";
import { authorizeTarget, guiCapabilityProbeTarget, validateBrokerPolicy, type BrokerPolicy, type NormalizedTarget, type TargetConstraint } from "./policy.js";
import { isPolicyQueryTargetReference } from "./target-authority.js";

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
  assert.doesNotThrow(() => validateBrokerPolicy(policyWithTarget("mac.service.control", { kind: "service", reference: "gui/501/com.mac-operator.test" })));
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

test("desktop GUI anchors authorize only concrete same-kind applications under GUI scopes", () => {
  for (const kind of ["app", "app_window"] as const) {
    for (const scope of ["mac.app.control", "mac.ui.observe", "mac.ui.control"] as const) {
      const policy = policyWithTarget(scope, { kind, reference: "desktop" });
      const concrete = { kind, reference: `${kind === "app_window" ? "window:" : ""}bundle:com.apple.TextEdit` };
      assert.doesNotThrow(() => validateBrokerPolicy(policy));
      assert.doesNotThrow(() => authorizeTarget(policy, "principal-1", [scope], concrete));
      assert.throws(() => authorizeTarget(policy, "principal-1", [scope], { kind, reference: "desktop" }), /malformed/u);
      assert.equal(isPolicyQueryTargetReference(kind, "desktop"), false);
      for (const reference of ["com.apple.TextEdit", "bundle:", "bundle:com.apple.*", "window:com.apple.TextEdit"]) {
        assert.throws(() => authorizeTarget(policy, "principal-1", [scope], { kind, reference }));
      }
      const otherKind = kind === "app" ? "app_window" : "app";
      assert.throws(() => authorizeTarget(policy, "principal-1", [scope], {
        kind: otherKind, reference: `${otherKind === "app_window" ? "window:" : ""}bundle:com.apple.TextEdit`
      }), /not allowed/u);
    }
  }
});

test("desktop GUI anchors cannot broaden non-GUI scopes or finite constraints", () => {
  for (const kind of ["app", "app_window"] as const) {
    for (const scope of SCOPES.filter(scope => !["mac.app.control", "mac.ui.observe", "mac.ui.control"].includes(scope))) {
      assert.throws(() => validateBrokerPolicy(policyWithTarget(scope, { kind, reference: "desktop" })), /malformed target authority/u);
    }
    assert.throws(() => validateBrokerPolicy(policyWithTarget("mac.ui.observe", { kind, reference: "desktop" },
      { mode: "finite_set", references: ["desktop"] })), /malformed target authority/u);
    const anchor = `${kind === "app_window" ? "window:" : ""}bundle:com.example.Editor`;
    assert.throws(() => validateBrokerPolicy(policyWithTarget("mac.ui.observe", { kind, reference: anchor },
      { mode: "finite_set", references: [anchor, "desktop"].sort() })), /malformed target authority/u);
  }
});

test("specific and desktop-domain deny rules take priority over broad GUI allow rules", () => {
  const base = policyWithTarget("mac.ui.observe", { kind: "app_window", reference: "desktop" });
  const target = { kind: "app_window" as const, reference: "window:bundle:com.apple.TextEdit" };
  for (const reference of [target.reference, "desktop"]) {
    const policy = { ...base, targetRules: [...base.targetRules, {
      ruleId: "deny-gui", effect: "deny" as const, principalId: "principal-1", scope: "mac.ui.observe" as const,
      target: { kind: "app_window" as const, reference }
    }] };
    assert.throws(() => authorizeTarget(policy, "principal-1", ["mac.ui.observe"], target), /explicitly denied/u);
  }
});

test("GUI capability probes avoid exact and finite denials while respecting a desktop denial", () => {
  const base = policyWithTarget("mac.ui.observe", { kind: "app_window", reference: "desktop" });
  const reference = (index: number) => `window:bundle:dev.macoperator.capability-probe.${index}`;
  const policy = { ...base, targetRules: [...base.targetRules,
    { ruleId: "deny-probe-exact", effect: "deny" as const, principalId: "principal-1", scope: "mac.ui.observe" as const,
      target: { kind: "app_window" as const, reference: reference(0) } },
    { ruleId: "deny-probe-finite", effect: "deny" as const, principalId: "principal-1", scope: "mac.ui.observe" as const,
      target: { kind: "app_window" as const, reference: reference(1) },
      targetConstraint: { mode: "finite_set" as const, references: [reference(1), reference(2)] } }
  ] };
  const probe = guiCapabilityProbeTarget(policy, { kind: "app_window", reference: "desktop" });
  assert.deepEqual(probe, { kind: "app_window", reference: reference(3) });
  assert.doesNotThrow(() => authorizeTarget(policy, "principal-1", ["mac.ui.observe"], probe));
  const denied = { ...policy, targetRules: [...policy.targetRules, {
    ruleId: "deny-entire-desktop", effect: "deny" as const, principalId: "principal-1", scope: "mac.ui.observe" as const,
    target: { kind: "app_window" as const, reference: "desktop" }
  }] };
  assert.throws(() => authorizeTarget(denied, "principal-1", ["mac.ui.observe"], guiCapabilityProbeTarget(denied,
    { kind: "app_window", reference: "desktop" })), /explicitly denied/u);
});

test("virtual desktop displays retain exact and finite denials for every requested GUI scope", () => {
  const base = policyWithTarget("mac.ui.observe", { kind: "app_window", reference: "desktop" });
  const target = { kind: "app_window" as const, reference: "window:bundle:dev.macoperator.desktop" };
  const observe = base.targetRules.find(rule => rule.target.reference === "desktop")!;
  const policy = { ...base, targetRules: [...base.targetRules,
    { ...observe, ruleId: "desktop-control", scope: "mac.ui.control" as const },
    { ruleId: "deny-display-control", effect: "deny" as const, principalId: "principal-1", scope: "mac.ui.control" as const,
      target, targetConstraint: { mode: "finite_set" as const,
        references: [target.reference, "window:bundle:dev.macoperator.desktop.2"] } }
  ] };
  assert.doesNotThrow(() => authorizeTarget(policy, "principal-1", ["mac.ui.observe"], target));
  for (const reference of policy.targetRules.at(-1)!.targetConstraint!.references) {
    assert.throws(() => authorizeTarget(policy, "principal-1", ["mac.ui.control"], { ...target, reference }), /explicitly denied/u);
    assert.throws(() => authorizeTarget(policy, "principal-1", ["mac.ui.observe", "mac.ui.control"], { ...target, reference }), /explicitly denied/u);
  }
  const exact = { ...policy, targetRules: [...policy.targetRules,
    { ruleId: "deny-display-observe", effect: "deny" as const, principalId: "principal-1", scope: "mac.ui.observe" as const, target }
  ] };
  assert.throws(() => authorizeTarget(exact, "principal-1", ["mac.ui.observe"], target), /explicitly denied/u);
});

test("desktop GUI delegation does not interpret paths, URLs or shell text as application authority", () => {
  const policy = policyWithTarget("mac.app.control", { kind: "app", reference: "desktop" });
  for (const reference of ["/tmp/evil.app", "file:///tmp/evil.app", "https://example.test/", "bundle:/tmp/evil.app",
    "bundle:file:///tmp/evil.app", "bundle:com.example.Editor;id", "bundle:com.example.Editor\nid", "bundle:com.example.Editor --args"]) {
    assert.throws(() => authorizeTarget(policy, "principal-1", ["mac.app.control"], { kind: "app", reference }), reference);
  }
  for (const target of [{ kind: "path" as const, reference: "workspace" }, { kind: "project" as const, reference: "/tmp" },
    { kind: "host" as const, reference: "owner-terminal" }, { kind: "task_profile" as const, reference: "tests.echo" }]) {
    assert.throws(() => authorizeTarget(policy, "principal-1", ["mac.app.control"], target), /not allowed/u);
  }
});
