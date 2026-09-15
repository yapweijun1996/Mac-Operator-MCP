import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore, type ProcessJobMetadata } from "./persistence.js";
import { taskDescriptorDigest } from "./task-runner.js";
import type { ResolvedTaskProfile } from "./task-profile.js";

function resolvedProfile(): ResolvedTaskProfile {
  return {
    profile: "tests.descriptor",
    cwd: "/tmp/mac-operator-descriptor",
    process: {
      executable: "/usr/bin/true",
      args: ["--bounded"],
      cwd: "/tmp/mac-operator-descriptor",
      environment: { LANG: "C" },
      timeoutMs: 2_000,
      outputCapBytes: 4_096
    },
    filesystemRoots: ["/tmp/mac-operator-descriptor"],
    networkPolicy: "none",
    networkAllowlist: [],
    credentialPolicy: "none",
    processTreePolicy: "single_process",
    sandboxProfile: "deny-default-v0.1",
    verificationStrategy: "exit_status_and_declared_task_verification"
  };
}

function metadata(descriptorDigest: string, recordedAtMs: number): ProcessJobMetadata {
  return {
    pid: 1234,
    processGroupId: 1234,
    startTimeMicros: 987654321,
    recordedAtMs,
    descendants: [],
    taskDescriptorDigest: descriptorDigest
  };
}

test("task descriptor digest binds the complete resolved process descriptor", () => {
  const profile = resolvedProfile();
  const digest = taskDescriptorDigest(profile);
  assert.match(digest, /^[a-f0-9]{64}$/u);
  assert.notEqual(digest, taskDescriptorDigest({
    ...profile,
    process: { ...profile.process, args: ["--changed"] }
  }));
  assert.notEqual(digest, taskDescriptorDigest({
    ...profile,
    process: { ...profile.process, environment: { LANG: "en_US" } }
  }));
});

test("running task Job persists and fences its descriptor digest", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-descriptor-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  const descriptorDigest = taskDescriptorDigest(resolvedProfile());
  const lease = {
    ownerId: "broker:descriptor-test",
    token: "lease:descriptor-test-123456",
    expiresAtMs: 30_000
  } as const;
  try {
    store.createJob({
      jobId: "job:descriptor",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task_profile:tests.descriptor",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      idempotencyKey: "descriptor-test",
      createdAtMs: 1
    });
    const started = store.startJob("job:descriptor", "principal-1", 0, 2, lease);
    const recorded = store.recordJobProcessOwnership(
      "job:descriptor",
      "principal-1",
      started.revision,
      metadata(descriptorDigest, 3),
      lease,
      3
    );
    assert.equal(recorded.processMetadata?.taskDescriptorDigest, descriptorDigest);

    assert.throws(
      () => store.updateJobProcessOwnership(
        "job:descriptor",
        "principal-1",
        recorded.revision,
        metadata("b".repeat(64), 4),
        lease,
        4
      ),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );

    const updated = store.updateJobProcessOwnership(
      "job:descriptor",
      "principal-1",
      recorded.revision,
      metadata(descriptorDigest, 4),
      lease,
      4
    );
    assert.equal(updated.processMetadata?.taskDescriptorDigest, descriptorDigest);
  } finally {
    store.close();
    const reopened = new BrokerStore(databasePath);
    try {
      assert.equal(reopened.ownedJob("job:descriptor", "principal-1")?.processMetadata?.taskDescriptorDigest, descriptorDigest);
    } finally {
      reopened.close();
      await rm(directory, { recursive: true, force: true });
    }
  }
});
