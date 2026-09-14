import assert from "node:assert/strict";
import { mkdtemp, rm, chmod, realpath, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { createVirtualizationGuestProfileAgent } from "./virtualization-guest-agent.js";
import {
  VirtualizationGuestProfileExecutor,
  VirtualizationGuestProcessExecutor,
  VirtualizationGuestTaskProfileRegistry,
  virtualizationGuestProfileDigest,
  virtualizationGuestTaskDigest,
  type VirtualizationGuestExecutionResult,
  type VirtualizationGuestTaskProfile
} from "./virtualization-guest-executor.js";
import {
  InMemoryVirtualizationGuestReplayGuard,
  createVirtualizationGuestRequest,
  createVirtualizationGuestStatusRequest,
  virtualizationGuestRequestDigest,
  type UnsignedVirtualizationGuestRequest
} from "./virtualization-guest-transport.js";

const guestIdentity = { imageSha256: "a".repeat(64), runtimeVersion: "macos-26.2-vz-1" } as const;
const key = Buffer.alloc(32, 0x61);
const now = 1_800_000_000_000;

async function profileFixture(): Promise<{ profile: VirtualizationGuestTaskProfile; request: UnsignedVirtualizationGuestRequest; directory: string }> {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-operator-guest-executor-")));
  const executable = join(directory, "task.bin");
  await writeFile(executable, "#!/bin/sh\n", { mode: 0o700 });
  await chmod(executable, 0o700);
  const profile: VirtualizationGuestTaskProfile = {
    schemaVersion: "0.1",
    profile: "guest.echo",
    sandboxProfile: "guest-deny-default-v0.1",
    executable,
    args: ["fixed"],
    cwd: directory,
    environment: { LANG: "C" },
    filesystemRoots: [directory],
    networkPolicy: "none",
    networkAllowlist: [],
    credentialPolicy: "none",
    processTreePolicy: "single_process",
    timeoutMs: 10_000,
    outputCapBytes: 4_096,
    verificationStrategy: "exit_status_and_declared_task_verification",
    enabled: true
  };
  const signed = createVirtualizationGuestRequest({
    guestIdentity,
    sandboxProfile: profile.sandboxProfile,
    profileDigest: virtualizationGuestProfileDigest(profile),
    taskDigest: virtualizationGuestTaskDigest(profile),
    processTreePolicy: profile.processTreePolicy,
    timeoutMs: 2_000,
    outputCapBytes: 1_024,
    requestId: "request:guest-executor-0123456789",
    nonce: "guest-nonce-executor-0123456789",
    timestampMs: now,
    expiresAtMs: now + 30_000
  }, key, { now });
  const { authenticationProof: _authenticationProof, ...request } = signed;
  return { profile, request, directory };
}

function successfulResult(): VirtualizationGuestExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    stdout: "guest-ok",
    stderr: "",
    truncated: false,
    durationMs: 4,
    verification: { status: "verified", summary: "guest postcondition" }
  };
}

test("guest profile registry resolves only the digest-bound startup manifest", async () => {
  const fixture = await profileFixture();
  try {
    const registry = new VirtualizationGuestTaskProfileRegistry([fixture.profile]);
    const resolved = await registry.resolve(fixture.request);
    assert.equal(resolved.executable, fixture.profile.executable);
    assert.deepEqual(resolved.args, ["fixed"]);
    assert.equal(resolved.cwd, fixture.profile.cwd);
    assert.deepEqual(resolved.environment, { LANG: "C" });
    assert.equal(registry.taskDigest(fixture.profile.profile), fixture.request.taskDigest);
    await assert.rejects(
      registry.resolve({ ...fixture.request, taskDigest: "b".repeat(64) }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "TARGET_NOT_FOUND"
    );
    await assert.rejects(
      registry.resolve({ ...fixture.request, timeoutMs: fixture.profile.timeoutMs + 1 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    await rm(fixture.profile.executable);
    await symlink("/usr/bin/true", fixture.profile.executable);
    await assert.rejects(
      registry.resolve(fixture.request),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("guest profile registry rejects shell executables and unsafe environment material", async () => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-operator-guest-executor-invalid-")));
  try {
    const base = {
      schemaVersion: "0.1" as const,
      profile: "guest.invalid",
      sandboxProfile: "guest-deny-default-v0.1",
      executable: "/bin/sh",
      args: [],
      cwd: directory,
      filesystemRoots: [directory],
      networkPolicy: "none" as const,
      networkAllowlist: [],
      credentialPolicy: "none" as const,
      processTreePolicy: "single_process" as const,
      timeoutMs: 1_000,
      outputCapBytes: 1_024,
      verificationStrategy: "exit_status_and_declared_task_verification" as const,
      enabled: true
    };
    assert.throws(() => new VirtualizationGuestTaskProfileRegistry([base]), /manifest is malformed/u);
    assert.throws(() => new VirtualizationGuestTaskProfileRegistry([{ ...base, executable: "/usr/bin/true", environment: { API_TOKEN: "secret" } }]), /unsafe entry/u);
    assert.throws(() => new VirtualizationGuestTaskProfileRegistry([{ ...base, executable: "/usr/bin/true", extra: true } as never]), /manifest is malformed/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("guest profile executor returns bounded results and serves terminal status recovery", async () => {
  const fixture = await profileFixture();
  try {
    let captured: unknown;
    const executor = new VirtualizationGuestProfileExecutor(
      new VirtualizationGuestTaskProfileRegistry([fixture.profile]),
      {
        available: true,
        async run(input) {
          captured = input;
          return {
            ...successfulResult(),
            stdout: "token=super-secret-value",
            verification: { status: "verified", summary: "token=another-secret-value" }
          };
        }
      }
    );
    const result = await executor.execute(fixture.request);
    assert.equal(result.resultClass, "SUCCEEDED");
    assert.equal(result.stdout, "[REDACTED]");
    assert.equal(result.verification.summary, "[REDACTED]");
    assert.equal((captured as { profile: VirtualizationGuestTaskProfile }).profile.executable, fixture.profile.executable);
    const statusRequest = createVirtualizationGuestStatusRequest({
      guestIdentity,
      originalRequestId: fixture.request.requestId,
      originalNonce: fixture.request.nonce,
      originalRequestDigest: virtualizationGuestRequestDigest(fixture.request),
      timeoutMs: 2_000,
      outputCapBytes: 1_024,
      requestId: "request:guest-status-executor-0123456789",
      nonce: "guest-status-nonce-executor-0123456789",
      timestampMs: now,
      expiresAtMs: now + 30_000
    }, key, { now });
    const { authenticationProof: _authenticationProof, ...unsignedStatusRequest } = statusRequest;
    const status = await executor.lookup(unsignedStatusRequest);
    assert.equal(status.state, "completed");
    assert.equal(status.resultClass, "SUCCEEDED");
    assert.equal(status.stdout, "[REDACTED]");
    assert.equal(status.verification.summary, "[REDACTED]");
    await executor.close();
    await assert.rejects(
      executor.execute(fixture.request),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("profile agent factory exposes only the authenticated digest-bound service", async () => {
  const fixture = await profileFixture();
  try {
    const { agent, executor } = createVirtualizationGuestProfileAgent({
      authenticationKey: key,
      replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
      expectedGuestIdentity: guestIdentity,
      expectedSandboxProfile: fixture.profile.sandboxProfile,
      expectedProfileDigest: virtualizationGuestProfileDigest(fixture.profile),
      now: () => now,
      profiles: [fixture.profile],
      processAdapter: { available: true, async run() { return successfulResult(); } }
    });
    const signed = createVirtualizationGuestRequest({
      guestIdentity,
      sandboxProfile: fixture.profile.sandboxProfile,
      profileDigest: virtualizationGuestProfileDigest(fixture.profile),
      taskDigest: virtualizationGuestTaskDigest(fixture.profile),
      processTreePolicy: fixture.profile.processTreePolicy,
      timeoutMs: 2_000,
      outputCapBytes: 1_024,
      requestId: "request:guest-agent-factory-0123456789",
      nonce: "guest-nonce-agent-factory-0123456789",
      timestampMs: now,
      expiresAtMs: now + 30_000
    }, key, { now });
    const response = JSON.parse(Buffer.from(await agent.exchange(Buffer.from(JSON.stringify(signed), "utf8"))).toString("utf8")) as Record<string, unknown>;
    assert.equal(response.kind, "virtualization_guest_task_result");
    assert.equal(response.resultClass, "SUCCEEDED");
    assert.equal("executable" in response, false);
    agent.close();
    await executor.close();
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("guest profile executor maps bounded adapter failures without leaking error text", async () => {
  const fixture = await profileFixture();
  try {
    const executor = new VirtualizationGuestProfileExecutor(
      new VirtualizationGuestTaskProfileRegistry([fixture.profile]),
      {
        available: true,
        async run() {
          throw new BrokerError("TIMEOUT", "internal path /Users/secret should not cross the guest boundary");
        }
      }
    );
    const result = await executor.execute(fixture.request);
    assert.equal(result.state, "timed_out");
    assert.equal(result.resultClass, "TIMEOUT");
    assert.equal(result.verification.summary, "guest task exceeded its execution budget");
    assert.equal(result.verification.summary?.includes("/Users/secret"), false);
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});

test("guest process executor remains fail-closed until explicit isolation evidence", async () => {
  const fixture = await profileFixture();
  try {
    const unavailable = new VirtualizationGuestProcessExecutor({ enabled: false, hostEvidenceAccepted: false, supervisor: { async run() { throw new Error("must not run"); } } });
    assert.equal(unavailable.available, false);
    await assert.rejects(
      unavailable.run({ request: fixture.request, profile: fixture.profile, timeoutMs: 1_000, outputCapBytes: 1_024, signal: new AbortController().signal }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    await rm(fixture.directory, { recursive: true, force: true });
  }
});
