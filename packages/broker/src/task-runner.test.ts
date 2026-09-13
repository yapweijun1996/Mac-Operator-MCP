import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { FailClosedTaskRunner, requireTaskIsolationProof, validateTaskExecutionResult, validateTaskIsolationProof, type TaskExecutionResult } from "./task-runner.js";
import type { ResolvedTaskProfile } from "./task-profile.js";

test("default task runner is unavailable and fails closed", async () => {
  const runner = new FailClosedTaskRunner();
  assert.equal(runner.available, false);
  await assert.rejects(
    runner.run({} as never, { timeoutMs: 1, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("task runner result validation accepts bounded verified results", () => {
  const result: TaskExecutionResult = {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    stdout: "ok\n",
    stderr: "",
    truncated: false,
    durationMs: 12,
    verification: { status: "verified", summary: "exit status and postcondition checked" }
  };
  assert.deepEqual(validateTaskExecutionResult(result), result);
});

test("task runner result validation rejects malformed or oversized verification evidence", () => {
  assert.throws(
    () => validateTaskExecutionResult({
      state: "completed",
      resultClass: "SUCCEEDED",
      exitCode: 0,
      stdout: "",
      stderr: "",
      truncated: false,
      durationMs: 0,
      verification: { status: "verified", summary: "x".repeat(513) }
    } as TaskExecutionResult),
    /malformed verification summary/u
  );
  assert.throws(
    () => validateTaskExecutionResult({
      state: "completed",
      resultClass: "SUCCEEDED",
      exitCode: 0,
      stdout: "",
      stderr: "",
      truncated: false,
      durationMs: -1,
      verification: { status: "verified" }
    } as TaskExecutionResult),
    /malformed result/u
  );
});

test("task runner isolation proof requires every boundary and the selected sandbox profile", () => {
  const proof = {
    schemaVersion: "0.1",
    sandboxProfile: "deny-default-v0.1",
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    processTree: "owned",
    evidenceRef: "evidence://task-runner"
  } as const;
  assert.deepEqual(validateTaskIsolationProof(proof), proof);
  assert.throws(
    () => validateTaskIsolationProof({ ...proof, credentials: "unknown" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => validateTaskIsolationProof({ ...proof, evidenceRef: "contains whitespace" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );

  const profile = {
    sandboxProfile: "deny-default-v0.1"
  } as ResolvedTaskProfile;
  assert.deepEqual(requireTaskIsolationProof(proof, profile), proof);
  assert.throws(
    () => requireTaskIsolationProof({ ...proof, sandboxProfile: "other-profile" }, profile),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});
