import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { normalizePolicyQueryTarget } from "./broker.js";

function assertMalformed(value: unknown): void {
  assert.throws(
    () => normalizePolicyQueryTarget(value),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
}

test("policy query target normalization accepts canonical resource identities", () => {
  const elementRef = "element:0123456789abcdef0123456789abcdef0123456789abcdef";
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "host", reference: "broker" }), { kind: "host", reference: "broker" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "path", reference: "/tmp/project with spaces/file.txt" }), { kind: "path", reference: "/tmp/project with spaces/file.txt" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "project", reference: "/tmp/project" }), { kind: "project", reference: "/tmp/project" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "app", reference: "bundle:com.example.Editor" }), { kind: "app", reference: "bundle:com.example.Editor" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "app_window", reference: "window:bundle:com.example.Editor" }), { kind: "app_window", reference: "window:bundle:com.example.Editor" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "ui_element", reference: elementRef }), { kind: "ui_element", reference: elementRef });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "docker_runtime", reference: "local" }), { kind: "docker_runtime", reference: "local" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "docker_object", reference: "registry.example/image:1.2" }), { kind: "docker_object", reference: "registry.example/image:1.2" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "service", reference: "system/com.apple.logd" }), { kind: "service", reference: "system/com.apple.logd" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "log_source", reference: "process/logd" }), { kind: "log_source", reference: "process/logd" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "job", reference: "job:write-123" }), { kind: "job", reference: "job:write-123" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "task_profile", reference: "tests.echo" }), { kind: "task_profile", reference: "tests.echo" });
  assert.deepEqual(normalizePolicyQueryTarget({ kind: "package", reference: "@scope/package" }), { kind: "package", reference: "@scope/package" });
});

test("policy query target normalization rejects traversal and cross-kind resource confusion", () => {
  const malformedTargets = [
    { kind: "app", reference: "com.example.Editor" },
    { kind: "app_window", reference: "window:com.example.Editor" },
    { kind: "ui_element", reference: "element:short" },
    { kind: "docker_runtime", reference: "broker" },
    { kind: "service", reference: "system/../com.example" },
    { kind: "log_source", reference: "process/../logd" },
    { kind: "path", reference: "/tmp/../etc" },
    { kind: "project", reference: "relative/project" },
    { kind: "host", reference: "all" },
    { kind: "unknown", reference: "value" },
    { kind: "app", reference: "bundle:com.example/Editor" }
  ];
  for (const target of malformedTargets) assertMalformed(target);
});

test("policy query target normalization defaults only an omitted target to the Broker host", () => {
  assert.deepEqual(normalizePolicyQueryTarget(undefined), { kind: "host", reference: "broker" });
  assertMalformed(null);
  assertMalformed({ kind: "host", reference: "broker", extra: true });
  assertMalformed({ kind: "path", reference: "/tmp/line\nfeed" });
});
