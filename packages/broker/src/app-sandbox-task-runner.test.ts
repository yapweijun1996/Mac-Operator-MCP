import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { DescriptorSnapshotAttestationSigner } from "./descriptor-snapshot-attestation.js";
import {
  assertTaskRunnerPublicEnablement,
  AppSandboxTaskRunner,
  type DescriptorSnapshotTaskRegistry,
  type TaskIsolationProof
} from "./task-runner.js";
import type { ResolvedTaskProfile } from "./task-profile.js";

function profile(overrides: Partial<ResolvedTaskProfile> = {}): ResolvedTaskProfile {
  return {
    profile: "app-sandbox-task",
    cwd: "/tmp/mac-operator-app-sandbox-task",
    process: {
      executable: "/usr/bin/true",
      args: ["--bounded"],
      cwd: "/tmp/mac-operator-app-sandbox-task",
      environment: { LANG: "C" },
      timeoutMs: 2_000,
      outputCapBytes: 4_096
    },
    filesystemRoots: ["/tmp/mac-operator-app-sandbox-task"],
    networkPolicy: "none",
    networkAllowlist: [],
    credentialPolicy: "none",
    processTreePolicy: "single_process",
    sandboxProfile: "app-sandbox-deny-default-v0.1",
    verificationStrategy: "exit_status_and_declared_task_verification",
    ...overrides
  };
}

function proof(): TaskIsolationProof {
  return {
    schemaVersion: "0.1",
    sandboxMechanism: "app-sandbox",
    sandboxProfile: "app-sandbox-deny-default-v0.1",
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    persistence: "isolated",
    credentialIsolation: "app-sandbox-container-no-host-credentials-v1",
    processTree: "observer-only",
    processTreePolicy: "single_process",
    evidenceRef: "evidence://app-sandbox-task-runner",
    executableSelection: "app-sandbox-helper-v1"
  };
}

function snapshotRegistry(): DescriptorSnapshotTaskRegistry {
  const keyPair = generateKeyPairSync("ed25519");
  const signer = new DescriptorSnapshotAttestationSigner({ keyId: "app-sandbox-test-key", privateKey: keyPair.privateKey });
  return {
    available: true,
    async prepare(input) {
      return {
        snapshotRef: "snapshot:" + "1".repeat(48),
        attestation: signer.sign({
          schemaVersion: "0.1",
          audience: "mac-operator-app-sandbox-helper-v0.1",
          snapshotRef: "snapshot:" + "1".repeat(48),
          profile: input.profile,
          taskDescriptorDigest: input.taskDescriptorDigest,
          argsDigest: input.argsDigest,
          environmentDigest: input.environmentDigest,
          filesystemRootsDigest: input.filesystemRootsDigest,
          sandboxProfile: input.sandboxProfile,
          networkPolicy: input.networkPolicy,
          processTreePolicy: input.processTreePolicy,
          credentialPolicy: "none",
          immutableSelection: "revalidation-only",
          executableContentSha256: "a".repeat(64),
          executableIdentityDigest: "b".repeat(64),
          cwdIdentityDigest: "c".repeat(64)
        })
      };
    },
    async withSnapshot(snapshot, callback) {
      return callback({ executableFd: 11, cwdFd: 12, attestation: snapshot.attestation });
    },
    async close() {}
  };
}

test("AppSandboxTaskRunner stays unavailable without independent helper evidence", () => {
  const runner = new AppSandboxTaskRunner({ isolationProof: proof() });
  assert.equal(runner.available, false);
});

test("App Sandbox proof rejects an unsupported process-tree ownership claim", () => {
  assert.throws(
    () => new AppSandboxTaskRunner({ isolationProof: { ...proof(), processTree: "owned" } }),
    /Task isolation proof is not complete/u
  );
});

test("AppSandboxTaskRunner cannot promote process-event-only containment to production", { skip: process.platform !== "darwin" }, () => {
  const runner = new AppSandboxTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    isolationProof: proof(),
    snapshotRegistry: snapshotRegistry(),
    executor: {
      available: true,
      publicEnablement: "production",
      async run() { throw new Error("not expected"); }
    }
  });
  assert.equal(runner.available, true);
  assert.equal(runner.publicEnablement, "staging-only");
  assert.throws(() => assertTaskRunnerPublicEnablement(true, runner), /production task runner release/u);
});

test("AppSandboxTaskRunner reflects executor quarantine before snapshot or task execution", { skip: process.platform !== "darwin" }, async () => {
  let executorAvailable = true;
  let runCalls = 0;
  const runner = new AppSandboxTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    isolationProof: proof(),
    snapshotRegistry: snapshotRegistry(),
    executor: {
      get available() { return executorAvailable; },
      publicEnablement: "staging-only",
      async run() {
        runCalls += 1;
        throw new Error("quarantined task must not execute");
      }
    }
  });

  assert.equal(runner.available, true);
  executorAvailable = false;
  assert.equal(runner.available, false);
  assert.equal(runner.publicEnablement, "unavailable");
  await assert.rejects(
    runner.run(profile(), { timeoutMs: 1_000, shouldCancel: () => false }),
    (error: unknown) => (error as { errorClass?: string }).errorClass === "POLICY_DENIED"
  );
  assert.equal(runCalls, 0);
});

test("AppSandboxTaskRunner binds a descriptor snapshot and does not send host paths", { skip: process.platform !== "darwin" }, async () => {
  let received: unknown;
  const runner = new AppSandboxTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    isolationProof: proof(),
    snapshotRegistry: snapshotRegistry(),
    executor: {
      available: true,
      async run(request) {
        received = request;
        assert.equal(request.executableFd, 11);
        assert.equal(request.cwdFd, 12);
        assert.equal(request.executionKind, "binary");
        assert.deepEqual(request.args, ["--bounded"]);
        assert.deepEqual(request.environment, { LANG: "C" });
        assert.equal("executablePath" in request, false);
        assert.equal("cwdPath" in request, false);
        return {
          state: "completed" as const,
          resultClass: "SUCCEEDED" as const,
          exitCode: 0,
          signal: null,
          stdout: "ok",
          stderr: "",
          truncated: false,
          durationMs: 4,
          processId: 321,
          processGroupId: 321,
          terminationObserved: true
        };
      }
    }
  });
  const result = await runner.run(profile(), { timeoutMs: 1_000, shouldCancel: () => false });
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(received !== undefined, true);
});

test("AppSandboxTaskRunner binds a script descriptor to the fixed interpreter mode", { skip: process.platform !== "darwin" }, async () => {
  let received: unknown;
  const registry = snapshotRegistry();
  const scriptedRegistry: DescriptorSnapshotTaskRegistry = {
    ...registry,
    async prepare(input) {
      assert.equal(input.scriptPath, "/tmp/mac-operator-app-sandbox-task/task.sh");
      return registry.prepare(input);
    },
    async withSnapshot(snapshot, callback) {
      return callback({
        executableFd: 11,
        cwdFd: 12,
        scriptFd: 13,
        scriptContentSha256: "d".repeat(64),
        attestation: snapshot.attestation
      });
    }
  };
  const runner = new AppSandboxTaskRunner({
    enabled: true,
    hostEvidenceAccepted: true,
    isolationProof: proof(),
    snapshotRegistry: scriptedRegistry,
    executor: {
      available: true,
      async run(request) {
        received = request;
        assert.equal(request.executionKind, "posix-sh-script");
        assert.equal(request.scriptFd, 13);
        assert.equal(request.scriptContentSha256, "d".repeat(64));
        assert.equal("scriptPath" in request, false);
        return {
          state: "completed" as const,
          resultClass: "SUCCEEDED" as const,
          exitCode: 0,
          signal: null,
          stdout: "ok",
          stderr: "",
          truncated: false,
          durationMs: 4,
          processId: 321,
          processGroupId: 321,
          terminationObserved: true
        };
      }
    }
  });
  const result = await runner.run(profile({
    executionKind: "posix-sh-script",
    scriptPath: "/tmp/mac-operator-app-sandbox-task/task.sh",
    scriptContentSha256: "d".repeat(64),
    process: {
      ...profile().process,
      executable: "/bin/sh"
    }
  }), { timeoutMs: 1_000, shouldCancel: () => false });
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(received !== undefined, true);
});
