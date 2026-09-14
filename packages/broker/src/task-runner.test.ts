import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { FailClosedTaskRunner, VirtualizationTaskRunner, requireTaskIsolationProof, validateTaskExecutionResult, validateTaskIsolationProof, validateVirtualizationGuestAttestation, type TaskExecutionResult, type VirtualizationGuestAttestation, type VirtualizationGuestIdentity } from "./task-runner.js";
import type { ResolvedTaskProfile } from "./task-profile.js";

function guestAttestation(guestIdentity: VirtualizationGuestIdentity, evidenceRef = "evidence://virtualization-guest"): VirtualizationGuestAttestation {
  const unsigned = {
    schemaVersion: "0.1" as const,
    guestIdentity,
    sandboxProfile: "guest-deny-default-v0.1",
    filesystem: "guest-private" as const,
    network: "profile-bound" as const,
    credentials: "host-credentials-unavailable" as const,
    processTree: "guest-owned" as const,
    processTreePolicy: "single_process" as const,
    evidenceRef
  };
  return { ...unsigned, attestationDigest: sha256(canonicalJson(unsigned)) };
}

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
    credentialIsolation: "sandbox-exec-empty-env-deny-secret-zones-v1",
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
    () => validateTaskIsolationProof({ ...proof, credentialIsolation: "virtualization-no-host-credentials-v1" }),
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
    credentialIsolation: "virtualization-no-host-credentials-v1",
    processTree: "owned",
    processTreePolicy: "single_process",
    evidenceRef: "evidence://virtualization-guest",
    virtualizationGuest: guest
  } as const;
  assert.deepEqual(validateTaskIsolationProof(proof), proof);
  const attestation = guestAttestation(guest, proof.evidenceRef);
  assert.deepEqual(validateVirtualizationGuestAttestation(attestation), attestation);
  assert.throws(
    () => validateVirtualizationGuestAttestation({ ...attestation, attestationDigest: "0".repeat(64) }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
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
      credentialIsolation: "virtualization-no-host-credentials-v1",
      processTree: "owned",
      processTreePolicy: "single_process",
      evidenceRef: "evidence://virtualization-guest",
      virtualizationGuest: guest
    },
    executor: {
      available: true,
      guestIdentity: null,
      attestation: null,
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
  let executorAttestation: VirtualizationGuestAttestation | null = guestAttestation(guest);
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
      credentialIsolation: "virtualization-no-host-credentials-v1",
      processTree: "owned",
      processTreePolicy: "single_process",
      evidenceRef: "evidence://virtualization-guest",
      virtualizationGuest: guest
    },
    executor: {
      available: true,
      get guestIdentity() { return executorGuest; },
      get attestation() { return executorAttestation; },
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
  executorGuest = guest;
  executorAttestation = guestAttestation(guest, "evidence://other-guest");
  await assert.rejects(
    runner.run({ sandboxProfile: "guest-deny-default-v0.1", processTreePolicy: "single_process", credentialPolicy: "none" } as never, { timeoutMs: 1_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.equal(calls, 1);
});

test("VirtualizationTaskRunner maps native adapter transport loss to unknown", async () => {
  const guest: VirtualizationGuestIdentity = {
    imageSha256: "e".repeat(64),
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
      credentialIsolation: "virtualization-no-host-credentials-v1",
      processTree: "owned",
      processTreePolicy: "single_process",
      evidenceRef: "evidence://virtualization-guest",
      virtualizationGuest: guest
    },
    executor: {
      available: true,
      guestIdentity: guest,
      attestation: guestAttestation(guest),
      async run() { throw new Error("native transport closed"); }
    }
  });
  if (process.platform !== "darwin") {
    assert.equal(runner.available, false);
    return;
  }
  await assert.rejects(
    runner.run({ sandboxProfile: "guest-deny-default-v0.1", processTreePolicy: "single_process", credentialPolicy: "none" } as never, { timeoutMs: 1_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME" && error.retryable === true
  );
});
