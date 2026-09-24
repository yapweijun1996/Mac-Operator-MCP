import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import {
  BrokerStore,
  type CreateJobInput,
  type ServiceControlJobMetadata
} from "./persistence.js";
import {
  UserServiceControlAdapter,
  type UserServiceControlCommandRunner,
  type UserServiceReadbackObserver,
  type UserServiceSourceRevisionReader
} from "./user-service-control.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";
import type { LaunchdJobReadback } from "./launchd-readback.js";
import {
  UserServiceControlJobExecutor,
  createServiceControlJobMetadata
} from "./user-service-control-executor.js";

const UID = typeof process.getuid === "function" ? process.getuid() : 501;
const SERVICE_ID = `gui/${UID}/com.mac-operator.test`;
const SOURCE_REVISION = "abcdef1";
const NOW = 1_700_000_000_000;

function launchd(state: "running" | "stopped"): LaunchdJobReadback {
  return {
    serviceId: SERVICE_ID,
    domain: `gui/${UID}`,
    label: "com.mac-operator.test",
    type: "LaunchAgent",
    state,
    pid: state === "running" ? 1234 : null,
    program: "/bin/true",
    arguments: ["/bin/true"],
    plistPath: "/Users/test/Library/LaunchAgents/com.mac-operator.test.plist",
    lastExitCode: 0,
    truncated: false
  };
}

function processResult(resultClass: ProcessExecutionResult["resultClass"] = "SUCCEEDED"): ProcessExecutionResult {
  return {
    state: resultClass === "SUCCEEDED" ? "completed" : "failed",
    resultClass,
    exitCode: resultClass === "SUCCEEDED" ? 0 : 1,
    signal: null,
    stdout: "",
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: 123,
    processGroupId: 123,
    terminationObserved: true
  };
}

function adapterFixture(
  readbackStates: Array<"running" | "stopped">,
  commandResults: Array<ProcessExecutionResult["resultClass"]> = []
): { adapter: UserServiceControlAdapter; commands: ProcessExecutionRequest[] } {
  const commands: ProcessExecutionRequest[] = [];
  const observer: UserServiceReadbackObserver = {
    inspect: async () => {
      const state = readbackStates.shift();
      if (state === undefined) throw new BrokerError("EXECUTION_FAILED", "fixture readback exhausted");
      return { launchd: launchd(state), sourceRevision: SOURCE_REVISION };
    }
  };
  const sourceRevisionReader: UserServiceSourceRevisionReader = {
    read: async () => SOURCE_REVISION
  };
  const commandRunner: UserServiceControlCommandRunner = {
    run: async (request) => {
      commands.push(request);
      return processResult(commandResults.shift() ?? "SUCCEEDED");
    }
  };
  const adapter = new UserServiceControlAdapter({
    enabled: true,
    uid: UID,
    bindings: [{
      serviceId: SERVICE_ID,
      sourceRevision: SOURCE_REVISION,
      plistPath: "/Users/test/Library/LaunchAgents/com.mac-operator.test.plist",
      program: "/bin/true",
      arguments: ["/bin/true"]
    }],
    commandRunner,
    inspector: observer,
    sourceRevisionReader,
    now: () => NOW
  });
  return { adapter, commands };
}

function metadata(preState: "running" | "stopped" = "stopped"): ServiceControlJobMetadata {
  return createServiceControlJobMetadata(
    { serviceId: SERVICE_ID, action: "start", expectedState: "running" },
    { state: preState, sourceRevision: SOURCE_REVISION }
  );
}

function jobInput(metadataValue: ServiceControlJobMetadata, id = "job:service-control-executor"): CreateJobInput {
  return {
    jobId: id,
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_service_control",
    targetRef: `service:${SERVICE_ID}`,
    policyVersion: "policy-0.1",
    payloadDigest: sha256(canonicalJson({ service_id: SERVICE_ID, action: "start", expected_state: "running" })),
    idempotencyKey: id.replace(/^job:/u, "idem-"),
    createdAtMs: NOW,
    serviceMetadata: metadataValue
  };
}

async function withStore<T>(callback: (store: BrokerStore) => Promise<T> | T): Promise<T> {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-service-control-job-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    return await callback(store);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
}

function lease() {
  return {
    ownerId: "broker:service-control-test",
    token: "lease:service-control-test-123456",
    expiresAtMs: NOW + 30_000
  } as const;
}

test("user service-control Job executor persists a verified terminal result", async () => {
  await withStore(async (store) => {
    const { adapter, commands } = adapterFixture(["stopped", "running"]);
    const executor = new UserServiceControlJobExecutor({ store, adapter, enabled: true, now: () => NOW });
    const created = store.createJob(jobInput(metadata()));
    const started = store.startJob(created.job.jobId, "principal-1", created.job.revision, NOW, lease());
    const outcome = await executor.execute({
      requestId: "92f9541b-b7d7-4959-a0e0-626fc465a06a",
      principalId: "principal-1",
      sessionId: "session-1",
      job: started,
      lease: lease(),
      timeoutMs: 5_000,
      assertAuthority: () => undefined
    });
    assert.equal(outcome.result.resultClass, "SUCCEEDED");
    assert.equal(outcome.job.state, "completed");
    assert.equal(outcome.job.serviceMetadata, undefined);
    assert.deepEqual(commands[0]?.args, ["kickstart", SERVICE_ID]);
    assert.equal(store.ownedJob(started.jobId, "principal-1")?.state, "completed");
  });
});

test("user service-control Job executor retains metadata for an unresolved outcome", async () => {
  await withStore(async (store) => {
    const { adapter } = adapterFixture(["stopped", "running", "stopped"], ["EXECUTION_FAILED", "SUCCEEDED"]);
    const executor = new UserServiceControlJobExecutor({ store, adapter, enabled: true, now: () => NOW });
    const created = store.createJob(jobInput(metadata(), "job:service-control-unknown"));
    const started = store.startJob(created.job.jobId, "principal-1", created.job.revision, NOW, lease());
    const outcome = await executor.execute({
      requestId: "request:service-control-executor-2",
      principalId: "principal-1",
      sessionId: "session-1",
      job: started,
      lease: lease(),
      timeoutMs: 5_000,
      assertAuthority: () => undefined
    });
    assert.equal(outcome.result.resultClass, "UNKNOWN_OUTCOME");
    assert.equal(outcome.job.state, "unknown");
    assert.deepEqual(outcome.job.serviceMetadata, metadata());
  });
});

test("user service-control Job executor is disabled without explicit enablement", async () => {
  await withStore(async (store) => {
    const { adapter } = adapterFixture(["stopped"]);
    const executor = new UserServiceControlJobExecutor({ store, adapter });
    assert.equal(executor.available, false);
    await assert.rejects(
      () => executor.execute({
        requestId: "request:service-control-executor-3",
        principalId: "principal-1",
        sessionId: "session-1",
        job: {} as never,
        lease: {} as never,
        timeoutMs: 5_000,
        assertAuthority: () => undefined
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "UNSUPPORTED_CAPABILITY"
    );
  });
});

test("user service-control Job executor closes a queued cancellation before dispatch", async () => {
  await withStore(async (store) => {
    const { adapter, commands } = adapterFixture(["stopped"]);
    const executor = new UserServiceControlJobExecutor({ store, adapter, enabled: true, now: () => NOW });
    const created = store.createJob(jobInput(metadata(), "job:service-control-cancelled"));
    const started = store.startJob(created.job.jobId, "principal-1", created.job.revision, NOW, lease());
    store.requestJobCancellation(started.jobId, "principal-1", "OWNER_CANCELLED", NOW);
    await assert.rejects(
      () => executor.execute({
        requestId: "request:service-control-executor-4",
        principalId: "principal-1",
        sessionId: "session-1",
        job: started,
        lease: lease(),
        timeoutMs: 5_000,
        assertAuthority: () => undefined
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
    );
    assert.equal(store.ownedJob(started.jobId, "principal-1")?.state, "cancelled");
    assert.equal(commands.length, 0);
  });
});

test("user service-control Job executor preserves UNKNOWN after authority revocation", async () => {
  await withStore(async (store) => {
    const { adapter } = adapterFixture(["stopped", "running"]);
    const executor = new UserServiceControlJobExecutor({ store, adapter, enabled: true, now: () => NOW });
    const created = store.createJob(jobInput(metadata(), "job:service-control-revoked"));
    const started = store.startJob(created.job.jobId, "principal-1", created.job.revision, NOW, lease());
    let authorityChecks = 0;
    await assert.rejects(
      () => executor.execute({
        requestId: "request:service-control-executor-5",
        principalId: "principal-1",
        sessionId: "session-1",
        job: started,
        lease: lease(),
        timeoutMs: 5_000,
        assertAuthority: () => {
          authorityChecks += 1;
          if (authorityChecks > 1) throw new BrokerError("REVOKED", "authority revoked");
        }
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME"
    );
    const persisted = store.ownedJob(started.jobId, "principal-1");
    assert.equal(persisted?.state, "unknown");
    assert.deepEqual(persisted?.serviceMetadata, metadata());
  });
});

test("user service-control recovery performs readback but never promotes a restarted Job", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-service-recovery-"));
  const databasePath = join(directory, "broker.sqlite");
  let store = new BrokerStore(databasePath);
  try {
    const created = store.createJob(jobInput(metadata(), "job:service-control-recovery"));
    store.startJob(created.job.jobId, "principal-1", created.job.revision, NOW, lease());
    store.close();
    store = new BrokerStore(databasePath);
    const { adapter } = adapterFixture(["stopped"]);
    const executor = new UserServiceControlJobExecutor({ store, adapter, enabled: true, now: () => NOW });
    const recovery = await executor.reconcileRestartedJobs();
    assert.deepEqual(recovery, { inspected: 1, readback: 1, identityMismatch: 0, unavailable: 0, unknown: 0 });
    assert.equal(store.ownedJob("job:service-control-recovery", "principal-1")?.state, "unknown");
    assert.equal(store.auditEventResult("job-service-recovery-job:service-control-recovery-2", "completion"), "SERVICE_READBACK");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
