import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { FailClosedTaskRunner, VirtualizationTaskRunner, requireTaskIsolationProof, validateTaskExecutionResult, validateTaskIsolationProof, type TaskExecutionResult, type VirtualizationGuestIdentity } from "./task-runner.js";
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
    sandboxMechanism: "sandbox-exec",
    sandboxProfile: "deny-default-v0.1",
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    processTree: "owned",
    processTreePolicy: "single_process",
    evidenceRef: "evidence://task-runner"
  } as const;
  assert.deepEqual(validateTaskIsolationProof(proof), proof);
  assert.throws(
    () => validateTaskIsolationProof({ ...proof, credentials: "unknown" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => validateTaskIsolationProof({ ...proof, sandboxMechanism: "app-sandbox" as never }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => validateTaskIsolationProof({ ...proof, evidenceRef: "contains whitespace" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );

  const profile = {
    sandboxProfile: "deny-default-v0.1"
  } as ResolvedTaskProfile;
  assert.deepEqual(requireTaskIsolationProof(proof, profile, "sandbox-exec"), proof);
  assert.throws(
    () => requireTaskIsolationProof(proof, profile),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => requireTaskIsolationProof(proof, profile, null),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => requireTaskIsolationProof({ ...proof, sandboxProfile: "other-profile" }, profile),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => requireTaskIsolationProof({ ...proof, processTreePolicy: "owned_group" }, profile),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => requireTaskIsolationProof(proof, { ...profile, credentialPolicy: "broker-managed" as never }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("virtualization isolation proofs require an immutable guest identity", () => {
  const guest: VirtualizationGuestIdentity = {
    imageSha256: "a".repeat(64),
    runtimeVersion: "macos-26.2-vz-1"
  };
  const proof = {
    schemaVersion: "0.1",
    sandboxMechanism: "virtualization",
    sandboxProfile: "guest-deny-default-v0.1",
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    processTree: "owned",
    processTreePolicy: "single_process",
    evidenceRef: "evidence://virtualization-guest",
    virtualizationGuest: guest
  } as const;
  assert.deepEqual(validateTaskIsolationProof(proof), proof);
  assert.throws(
    () => validateTaskIsolationProof({ ...proof, virtualizationGuest: { ...guest, imageSha256: "not-a-digest" } }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => validateTaskIsolationProof({ ...proof, virtualizationGuest: undefined }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => validateTaskIsolationProof({ ...proof, sandboxMechanism: "sandbox-exec", virtualizationGuest: guest }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("VirtualizationTaskRunner stays unavailable without matched native guest evidence", async () => {
  const guest: VirtualizationGuestIdentity = {
    imageSha256: "b".repeat(64),
    runtimeVersion: "macos-26.2-vz-1"
  };
  const runner = new VirtualizationTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    isolationProof: {
      schemaVersion: "0.1",
      sandboxMechanism: "virtualization",
      sandboxProfile: "guest-deny-default-v0.1",
      filesystem: "enforced",
      network: "enforced",
      credentials: "isolated",
      processTree: "owned",
      processTreePolicy: "single_process",
      evidenceRef: "evidence://virtualization-guest",
      virtualizationGuest: guest
    },
    executor: {
      available: true,
      guestIdentity: null,
      async run() { throw new Error("must not execute"); }
    }
  });
  assert.equal(runner.available, false);
  await assert.rejects(
    runner.run({} as never, { timeoutMs: 1_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("VirtualizationTaskRunner rechecks guest identity before dispatch", async () => {
  const guest: VirtualizationGuestIdentity = {
    imageSha256: "c".repeat(64),
    runtimeVersion: "macos-26.2-vz-1"
  };
  let executorGuest: VirtualizationGuestIdentity | null = guest;
  let calls = 0;
  const runner = new VirtualizationTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    isolationProof: {
      schemaVersion: "0.1",
      sandboxMechanism: "virtualization",
      sandboxProfile: "guest-deny-default-v0.1",
      filesystem: "enforced",
      network: "enforced",
      credentials: "isolated",
      processTree: "owned",
      processTreePolicy: "single_process",
      evidenceRef: "evidence://virtualization-guest",
      virtualizationGuest: guest
    },
    executor: {
      available: true,
      get guestIdentity() { return executorGuest; },
      async run() {
        calls += 1;
        return {
          state: "completed" as const,
          resultClass: "SUCCEEDED" as const,
          exitCode: 0,
          stdout: "guest-ok",
          stderr: "",
          truncated: false,
          durationMs: 1,
          verification: { status: "verified" as const, summary: "guest readback" }
        };
      }
    }
  });
  if (process.platform !== "darwin") {
    assert.equal(runner.available, false);
    return;
  }
  assert.equal(runner.available, true);
  const result = await runner.run({ sandboxProfile: "guest-deny-default-v0.1", processTreePolicy: "single_process", credentialPolicy: "none" } as never, { timeoutMs: 1_000, shouldCancel: () => false });
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(calls, 1);
  executorGuest = { ...guest, imageSha256: "d".repeat(64) };
  await assert.rejects(
    runner.run({ sandboxProfile: "guest-deny-default-v0.1", processTreePolicy: "single_process", credentialPolicy: "none" } as never, { timeoutMs: 1_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.equal(calls, 1);
});
