import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { FailClosedTaskRunner, VirtualizationGuestTransportExecutor, VirtualizationTaskRunner, requireTaskIsolationProof, validateTaskExecutionResult, validateTaskIsolationProof, validateVirtualizationGuestAttestation, virtualizationProfileDigest, virtualizationTaskDigest, type TaskExecutionResult, type VirtualizationGuestTransport, type VirtualizationGuestAttestation, type VirtualizationGuestIdentity } from "./task-runner.js";
import type { LoadedVirtualizationGuestImage } from "./virtualization-guest-image.js";
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

function resolvedGuestProfile(): ResolvedTaskProfile {
  return {
    profile: "guest-task",
    cwd: "/tmp/mac-operator-guest",
    process: {
      executable: "/usr/bin/true",
      args: ["--bounded"],
      cwd: "/tmp/mac-operator-guest",
      environment: { LANG: "C" },
      timeoutMs: 2_000,
      outputCapBytes: 4_096
    },
    filesystemRoots: ["/tmp/mac-operator-guest"],
    networkPolicy: "none",
    networkAllowlist: [],
    credentialPolicy: "none",
    processTreePolicy: "single_process",
    sandboxProfile: "guest-deny-default-v0.1",
    verificationStrategy: "exit_status_and_declared_task_verification"
  };
}

async function guestImageFixture(runtimeVersion: string): Promise<{ guest: VirtualizationGuestIdentity; image: LoadedVirtualizationGuestImage; directory: string }> {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-runner-guest-"));
  const imagePath = join(directory, "guest.img");
  const content = Buffer.from(`guest-image-${runtimeVersion}\n`, "utf8");
  await writeFile(imagePath, content, { mode: 0o600 });
  const digest = createHash("sha256").update(content).digest("hex");
  const stat = await lstat(imagePath);
  const guest = { imageSha256: digest, runtimeVersion };
  return {
    guest,
    image: { path: imagePath, guestIdentity: guest, device: String(stat.dev), inode: String(stat.ino), sizeBytes: stat.size },
    directory
  };
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

test("task runner validators reject inherited, accessor, symbolic, and unknown fields", () => {
  const result = {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    stdout: "ok\n",
    stderr: "",
    truncated: false,
    durationMs: 12,
    verification: { status: "verified", summary: "checked" }
  } as const;
  const inheritedResult = Object.create(result) as unknown;
  assert.throws(
    () => validateTaskExecutionResult(inheritedResult),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
  const accessorResult = { ...result } as Record<string, unknown>;
  Object.defineProperty(accessorResult, "stdout", { enumerable: true, get: () => "injected" });
  assert.throws(
    () => validateTaskExecutionResult(accessorResult),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
  const symbolicResult = { ...result } as Record<string, unknown>;
  Object.defineProperty(symbolicResult, Symbol("hidden"), { value: "injected" });
  assert.throws(
    () => validateTaskExecutionResult(symbolicResult),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
  assert.throws(
    () => validateTaskExecutionResult({ ...result, extra: true }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
  assert.throws(
    () => validateTaskExecutionResult({ ...result, stdout: "x".repeat(2 * 1024 * 1024 + 1) }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
  assert.deepEqual(
    validateTaskExecutionResult({ ...result, verification: { status: "verified" } }),
    { ...result, verification: { status: "verified" } }
  );
  const accessorVerification = { ...result, verification: { ...result.verification } } as Record<string, unknown>;
  Object.defineProperty(accessorVerification.verification as Record<string, unknown>, "status", {
    enumerable: true,
    get: () => "verified"
  });
  assert.throws(
    () => validateTaskExecutionResult(accessorVerification),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );

  const proof = {
    schemaVersion: "0.1",
    sandboxMechanism: "sandbox-exec",
    sandboxProfile: "deny-default-v0.1",
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    persistence: "isolated",
    credentialIsolation: "sandbox-exec-empty-env-deny-secret-zones-v1",
    processTree: "owned",
    processTreePolicy: "single_process",
    evidenceRef: "evidence://task-runner"
  } as const;
  const inheritedProof = Object.create(proof) as unknown;
  assert.throws(
    () => validateTaskIsolationProof(inheritedProof),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  const accessorProof = { ...proof } as Record<string, unknown>;
  Object.defineProperty(accessorProof, "evidenceRef", { enumerable: true, get: () => "evidence://injected" });
  assert.throws(
    () => validateTaskIsolationProof(accessorProof),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  const symbolicProof = { ...proof } as Record<string, unknown>;
  Object.defineProperty(symbolicProof, Symbol("hidden"), { value: "injected" });
  assert.throws(
    () => validateTaskIsolationProof(symbolicProof),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => validateTaskIsolationProof({ ...proof, extra: true }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
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
    persistence: "isolated",
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
    () => validateTaskIsolationProof({ ...proof, persistence: "unknown" }),
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
    persistence: "isolated",
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
      persistence: "isolated",
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
  const fixture = await guestImageFixture("macos-26.2-vz-1");
  const { guest, image, directory } = fixture;
  try {
    let executorGuest: VirtualizationGuestIdentity | null = guest;
    let executorAttestation: VirtualizationGuestAttestation | null = guestAttestation(guest);
    let calls = 0;
    const runner = new VirtualizationTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    guestImage: image,
    isolationProof: {
      schemaVersion: "0.1",
      sandboxMechanism: "virtualization",
      sandboxProfile: "guest-deny-default-v0.1",
      filesystem: "enforced",
      network: "enforced",
      credentials: "isolated",
      persistence: "isolated",
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
    await writeFile(image.path, "guest-image-replaced\n", { mode: 0o600 });
    await assert.rejects(
      runner.run({ sandboxProfile: "guest-deny-default-v0.1", processTreePolicy: "single_process", credentialPolicy: "none" } as never, { timeoutMs: 1_000, shouldCancel: () => false }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    assert.equal(calls, 1);
    await writeFile(image.path, "guest-image-macos-26.2-vz-1\n", { mode: 0o600 });
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
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("VirtualizationTaskRunner maps native adapter transport loss to unknown", async () => {
  const fixture = await guestImageFixture("macos-26.2-vz-1");
  const { guest, image, directory } = fixture;
  try {
    const runner = new VirtualizationTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    guestImage: image,
    isolationProof: {
      schemaVersion: "0.1",
      sandboxMechanism: "virtualization",
      sandboxProfile: "guest-deny-default-v0.1",
      filesystem: "enforced",
      network: "enforced",
      credentials: "isolated",
      persistence: "isolated",
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
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("VirtualizationGuestTransportExecutor sends only bound digests and maps verified results", async () => {
  const guest: VirtualizationGuestIdentity = {
    imageSha256: "f".repeat(64),
    runtimeVersion: "macos-26.2-vz-1"
  };
  const profile = resolvedGuestProfile();
  let sent: Record<string, unknown> | undefined;
  let admitted: Record<string, unknown> | undefined;
  let closed = false;
  const transport: VirtualizationGuestTransport = {
    async execute(input, options) {
      sent = input as unknown as Record<string, unknown>;
      options?.onRequestAdmitted?.({
        schemaVersion: "0.1",
        protocolVersion: "0.1",
        contractVersion: "0.1",
        kind: "virtualization_guest_task",
        requestId: "request:guest-0123456789abcdef",
        nonce: "guest-nonce-0123456789abcdef",
        timestampMs: 1,
        expiresAtMs: 30_001,
        guestIdentity: guest,
        sandboxProfile: profile.sandboxProfile,
        profileDigest: virtualizationProfileDigest(profile),
        taskDigest: virtualizationTaskDigest(profile),
        processTreePolicy: profile.processTreePolicy,
        timeoutMs: 1_500,
        outputCapBytes: 4_096,
        operation: "task_run"
      });
      return {
        schemaVersion: "0.1",
        protocolVersion: "0.1",
        contractVersion: "0.1",
        kind: "virtualization_guest_task_result",
        requestId: "request:guest-0123456789abcdef",
        nonce: "guest-nonce-0123456789abcdef",
        guestIdentity: guest,
        requestDigest: "a".repeat(64),
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        stdout: "guest-ok",
        stderr: "",
        truncated: false,
        durationMs: 4,
        outputPolicy: "broker-redacted-v1",
        verification: { status: "verified", summary: "guest postcondition readback" }
      };
    },
    close() { closed = true; }
  };
  const executor = new VirtualizationGuestTransportExecutor({
    available: true,
    transport,
    guestIdentity: guest,
    attestation: guestAttestation(guest)
  });
  const result = await executor.run({
    profile,
    guestIdentity: guest,
    control: {
      timeoutMs: 1_500,
      shouldCancel: () => false,
      onGuestRequestAdmitted: (value) => { admitted = value as unknown as Record<string, unknown>; }
    }
  });
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(sent?.sandboxProfile, profile.sandboxProfile);
  assert.equal(sent?.timeoutMs, 1_500);
  assert.equal(sent?.outputCapBytes, 4_096);
  assert.equal(sent?.profileDigest, virtualizationProfileDigest(profile));
  assert.equal(sent?.taskDigest, virtualizationTaskDigest(profile));
  assert.equal(admitted?.requestId, "request:guest-0123456789abcdef");
  assert.equal(admitted?.requestDigest, sha256(canonicalJson({
    schemaVersion: "0.1",
    protocolVersion: "0.1",
    contractVersion: "0.1",
    kind: "virtualization_guest_task",
    requestId: "request:guest-0123456789abcdef",
    nonce: "guest-nonce-0123456789abcdef",
    timestampMs: 1,
    expiresAtMs: 30_001,
    guestIdentity: guest,
    sandboxProfile: profile.sandboxProfile,
    profileDigest: virtualizationProfileDigest(profile),
    taskDigest: virtualizationTaskDigest(profile),
    processTreePolicy: profile.processTreePolicy,
    timeoutMs: 1_500,
    outputCapBytes: 4_096,
    operation: "task_run"
  })));
  assert.equal("cwd" in (sent ?? {}), false);
  assert.equal("executable" in (sent ?? {}), false);
  assert.equal("args" in (sent ?? {}), false);
  assert.equal("environment" in (sent ?? {}), false);
  await executor.close();
  assert.equal(closed, true);
  await assert.rejects(
    executor.run({ profile, guestIdentity: guest, control: { timeoutMs: 1_500, shouldCancel: () => false } }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("VirtualizationGuestTransportExecutor recovers only through the bound status lookup", async () => {
  const guest: VirtualizationGuestIdentity = {
    imageSha256: "2".repeat(64),
    runtimeVersion: "macos-26.2-vz-1"
  };
  let authorized = false;
  const metadata = {
    requestId: "request:guest-0123456789abcdef",
    nonce: "guest-nonce-0123456789abcdef",
    requestDigest: "3".repeat(64),
    guestIdentity: guest,
    profileDigest: "4".repeat(64),
    taskDigest: "5".repeat(64),
    timeoutMs: 1_000,
    outputCapBytes: 1_024,
    recordedAtMs: 2
  } as const;
  const transport: VirtualizationGuestTransport = {
    async execute() { throw new Error("must not execute during recovery"); },
    async lookup(input, options) {
      options?.authorizeStatusLookup?.(input);
      authorized = true;
      return {
        schemaVersion: "0.1",
        protocolVersion: "0.1",
        contractVersion: "0.1",
        kind: "virtualization_guest_task_status_result",
        requestId: "request:guest-status-0123456789abcdef",
        nonce: "guest-status-nonce-0123456789abcdef",
        guestIdentity: guest,
        originalRequestId: metadata.requestId,
        originalNonce: metadata.nonce,
        originalRequestDigest: metadata.requestDigest,
        statusRequestDigest: "6".repeat(64),
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        stdout: "recovered",
        stderr: "",
        truncated: false,
        durationMs: 5,
        outputPolicy: "broker-redacted-v1",
        verification: { status: "verified", summary: "guest status readback" }
      };
    },
    close() {}
  };
  const executor = new VirtualizationGuestTransportExecutor({
    available: true,
    transport,
    guestIdentity: guest,
    attestation: guestAttestation(guest)
  });
  const result = await executor.recoverUnknownTask({
    metadata,
    authorizeStatusLookup: (input) => {
      assert.equal(input.originalRequestId, metadata.requestId);
      assert.equal(input.originalRequestDigest, metadata.requestDigest);
    }
  });
  assert.equal(authorized, true);
  assert.equal(result.state, "completed");
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.verification.status, "verified");
});

test("VirtualizationGuestTransportExecutor never publishes an unverified guest success", async () => {
  const guest: VirtualizationGuestIdentity = {
    imageSha256: "1".repeat(64),
    runtimeVersion: "macos-26.2-vz-1"
  };
  const response = {
    schemaVersion: "0.1" as const,
    protocolVersion: "0.1" as const,
    contractVersion: "0.1" as const,
    kind: "virtualization_guest_task_result" as const,
    requestId: "request:guest-0123456789abcdef",
    nonce: "guest-nonce-0123456789abcdef",
    guestIdentity: guest,
    requestDigest: "b".repeat(64),
    state: "completed" as const,
    resultClass: "SUCCEEDED" as const,
    exitCode: 0,
    stdout: "",
    stderr: "",
    truncated: false,
    durationMs: 1,
    outputPolicy: "broker-redacted-v1" as const,
    verification: { status: "unknown" as const }
  };
  const executor = new VirtualizationGuestTransportExecutor({
    available: true,
    transport: { async execute() { return response; }, close() {} },
    guestIdentity: guest,
    attestation: guestAttestation(guest)
  });
  await assert.rejects(
    executor.run({ profile: resolvedGuestProfile(), guestIdentity: guest, control: { timeoutMs: 1_500, shouldCancel: () => false } }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "VERIFICATION_FAILED"
  );
});

test("VirtualizationGuestTransportExecutor rejects a response from another guest identity", async () => {
  const guest: VirtualizationGuestIdentity = {
    imageSha256: "2".repeat(64),
    runtimeVersion: "macos-26.2-vz-1"
  };
  const response = {
    schemaVersion: "0.1" as const,
    protocolVersion: "0.1" as const,
    contractVersion: "0.1" as const,
    kind: "virtualization_guest_task_result" as const,
    requestId: "request:guest-0123456789abcdef",
    nonce: "guest-nonce-0123456789abcdef",
    guestIdentity: { ...guest, imageSha256: "3".repeat(64) },
    requestDigest: "c".repeat(64),
    state: "completed" as const,
    resultClass: "SUCCEEDED" as const,
    exitCode: 0,
    stdout: "",
    stderr: "",
    truncated: false,
    durationMs: 1,
    outputPolicy: "broker-redacted-v1" as const,
    verification: { status: "verified" as const }
  };
  const executor = new VirtualizationGuestTransportExecutor({
    available: true,
    transport: { async execute() { return response; }, close() {} },
    guestIdentity: guest,
    attestation: guestAttestation(guest)
  });
  await assert.rejects(
    executor.run({ profile: resolvedGuestProfile(), guestIdentity: guest, control: { timeoutMs: 1_500, shouldCancel: () => false } }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "VERIFICATION_FAILED"
  );
});
