import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, realpath, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { WorkerFilesystemExecutor, type FilesystemExecutor } from "./filesystem-executor.js";
import { FilesystemInspector } from "./filesystem-inspector.js";
import { BrokerStore, redactEvidence, type BrokerJob, type JobLease } from "./persistence.js";
import type { DockerInspector } from "./docker-inspector.js";
import { TaskProfileRegistry, type TaskProfile } from "./task-profile.js";
import type { TaskIsolationProof, TaskRunner } from "./task-runner.js";
import { UiSnapshotRegistry } from "./ui-inspector.js";
import type { FilesystemWorkerResult } from "./filesystem-worker-protocol.js";
import { ProcessSupervisor } from "./process-supervisor.js";

const NOW = 1_700_000_000_000;

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-test-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const policy = createDefaultPolicy("edge-1", true, ["mac.control.read"]);
  const broker = new Broker({ store, policy, edgeAuthenticationKeys: testKeyring(key), now: () => NOW });
  return {
    broker,
    key,
    store,
    close: async () => { store.close(); await rm(directory, { recursive: true, force: true }); }
  };
}

function unsigned(overrides: Partial<UnsignedBrokerRequest> = {}, scopes: Scope[] = ["mac.control.read"]): UnsignedBrokerRequest {
  return {
    protocolVersion: "0.1",
    requestId: "request-1",
    contractVersion: "0.1",
    tool: "mac_health",
    arguments: {},
    principal: {
      principalId: "principal-1",
      sessionId: "session-1",
      issuer: "test-issuer",
      audience: "mac-operator-broker",
      scopes,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000,
      edgeId: "edge-1"
    },
    timestampMs: NOW,
    nonce: "nonce-1",
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-1",
    ...overrides
  };
}

function taskProfile(root: string): TaskProfile {
  return {
    schemaVersion: "0.1",
    profile: "tests.echo",
    executable: "/bin/echo",
    allowedCwdRoots: [root],
    allowedArgumentPattern: "^[a-z0-9._=-]{1,32}$",
    maxArguments: 2,
    environment: { LANG: "C" },
    filesystemRoots: [root],
    networkPolicy: "none",
    sandboxProfile: "deny-default-v0.1",
    timeoutMs: 1_000,
    outputCapBytes: 1_024,
    verificationStrategy: "exit_status_and_declared_task_verification",
    enabled: true
  };
}

function testTaskIsolationProof(): TaskIsolationProof {
  return {
    schemaVersion: "0.1",
    sandboxMechanism: "sandbox-exec",
    sandboxProfile: "deny-default-v0.1",
    filesystem: "enforced",
    network: "enforced",
    credentials: "isolated",
    processTree: "owned",
    processTreePolicy: "single_process",
    evidenceRef: "test://task-runner-isolation"
  };
}

test("authorized health request succeeds and writes decision plus completion audit", async () => {
  const context = await fixture();
  try {
    const result = await context.broker.handle(signRequest(unsigned(), context.key));
    assert.equal(result.ok, true);
    assert.equal(context.store.requestRecord("request-1")?.state, "SUCCEEDED");
    assert.equal(context.store.auditRows().length, 2);
  } finally { await context.close(); }
});

test("Broker privileged helper seam remains disabled by default", async () => {
  const context = await fixture();
  try {
    const request = signRequest(unsigned({ requestId: "request-helper-seam" }), context.key);
    await assert.rejects(
      () => context.broker.executePrivilegedHelperJob({
        request,
        requestId: request.requestId,
        principalId: request.principal.principalId,
        sessionId: request.principal.sessionId,
        job: {} as BrokerJob,
        lease: {} as JobLease,
        operation: "power",
        timeoutMs: 1_000,
        target: { kind: "host", reference: "broker" }
      }),
      (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "PRIVILEGE_DENIED"
    );
  } finally { await context.close(); }
});

test("Broker close drains its shared OS process supervisor", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-process-close-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const supervisor = new ProcessSupervisor({ maxConcurrent: 1, pollIntervalMs: 5, terminationGraceMs: 50 });
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]),
    edgeAuthenticationKeys: testKeyring(randomBytes(32)),
    processSupervisor: supervisor,
    now: () => NOW
  });
  try {
    const running = supervisor.run({
      executable: "/bin/sleep",
      args: ["10"],
      cwd: process.cwd(),
      timeoutMs: 5_000,
      outputCapBytes: 100
    });
    await new Promise((resolve) => setTimeout(resolve, 20));
    await broker.close();
    const result = await running;
    assert.equal(result.resultClass, "CANCELLED");
    assert.equal(result.terminationObserved, true);
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("restarted Broker recovers an exact task process identity without resolving the Job", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("Cross-Broker task process recovery is a macOS native boundary");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-process-recovery-"));
  const databasePath = join(directory, "broker.sqlite");
  const key = randomBytes(32);
  let store = new BrokerStore(databasePath);
  const supervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  const recoverySupervisor = new ProcessSupervisor({ pollIntervalMs: 5, terminationGraceMs: 50 });
  const policy = createDefaultPolicy("edge-1", true, ["mac.control.read"]);
  const broker = new Broker({ store, policy, edgeAuthenticationKeys: testKeyring(key), processSupervisor: supervisor, now: () => Date.now() });
  let restartedBroker: Broker | undefined;
  let running: Promise<unknown> | undefined;
  try {
    const nowMs = Date.now();
    const lease = {
      ownerId: "broker:test-recovery",
      token: "lease:task-process-recovery-1234",
      expiresAtMs: nowMs + 30_000
    };
    store.createJob({
      jobId: "job:task-process-recovery",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task_profile:tests.echo",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      idempotencyKey: "task-process-recovery",
      createdAtMs: nowMs
    });
    const started = store.startJob("job:task-process-recovery", "principal-1", 0, nowMs, lease);
    let capturedIdentity: import("./process-supervisor.js").ProcessOwnershipIdentity | undefined;
    running = supervisor.run({
      executable: "/bin/sleep",
      args: ["10"],
      cwd: process.cwd(),
      timeoutMs: 5_000,
      outputCapBytes: 100,
      onStarted: (snapshot) => {
        capturedIdentity = snapshot.identity;
        const recordedAtMs = Date.now();
        store.recordJobProcessOwnership(
          "job:task-process-recovery",
          "principal-1",
          started.revision,
          {
            ...snapshot.identity,
            recordedAtMs,
            descendants: snapshot.descendants.map((descendant) => ({ ...descendant }))
          },
          lease,
          recordedAtMs
        );
      }
    });
    await new Promise((resolve) => setTimeout(resolve, 25));
    assert.ok(capturedIdentity);
    store.close();
    store = new BrokerStore(databasePath);
    assert.equal(store.ownedJob("job:task-process-recovery", "principal-1")?.state, "unknown");
    restartedBroker = new Broker({
      store,
      policy,
      edgeAuthenticationKeys: testKeyring(key),
      processSupervisor: recoverySupervisor,
      now: () => Date.now()
    });
    assert.deepEqual(await restartedBroker.reconcileRestartedTaskProcesses(), {
      inspected: 1,
      drained: 1,
      absent: 0,
      identityMismatch: 0,
      unknown: 0
    });
    assert.equal(store.ownedJob("job:task-process-recovery", "principal-1")?.state, "unknown");
    assert.equal(store.auditEventResult("job-process-recovery-job:task-process-recovery-3", "completion"), "PROCESS_DRAINED");
    await running;
    assert.equal(supervisor.activeCount(), 0);
  } finally {
    await restartedBroker?.close();
    await broker.close();
    await running?.catch(() => undefined);
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_process_list returns bounded redacted process metadata", async () => {
  const key = randomBytes(32);
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-list-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.process.read"]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "process-list-request",
      nonce: "process-list-nonce",
      tool: "mac_process_list",
      arguments: { limit: 20, sort: "pid" }
    }, ["mac.process.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as { processes: Array<{ pid: number; owner?: string; cpu_percent: number; memory_bytes: number }> };
    assert.ok(data.processes.length <= 20);
    assert.equal(data.processes.every((process) => process.pid > 0), true);
    assert.equal(data.processes.every((process) => process.cpu_percent >= 0 && process.cpu_percent <= 100), true);
    assert.equal(data.processes.every((process) => process.memory_bytes >= 0), true);
    assert.equal(data.processes.every((process) => process.owner === undefined || /^uid:\d+$/u.test(process.owner)), true);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_process_inspect returns bounded detail for an authorized pid", async () => {
  const key = randomBytes(32);
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-process-inspect-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.process.read"]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "process-inspect-request",
      nonce: "process-inspect-nonce",
      tool: "mac_process_inspect",
      arguments: { pid: process.pid }
    }, ["mac.process.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as {
      process: {
        pid: number;
        name: string;
        executable: string;
        state: string;
        cpu_percent: number;
        memory_bytes: number;
        parent_pid: number | null;
        child_pids: number[];
        owner: string;
      };
    };
    assert.equal(data.process.pid, process.pid);
    assert.ok(data.process.name.length > 0 && data.process.name.length <= 256);
    assert.ok(data.process.executable.length > 0 && data.process.executable.length <= 4096);
    assert.ok(["running", "sleeping", "stopped", "zombie", "unknown"].includes(data.process.state));
    assert.ok(data.process.cpu_percent >= 0 && data.process.cpu_percent <= 100);
    assert.ok(data.process.memory_bytes >= 0);
    assert.match(data.process.owner, /^uid:\d+$/u);
    assert.ok(data.process.child_pids.length <= 256);
    assert.equal(JSON.stringify(result).includes("argv"), false);
    assert.equal(JSON.stringify(result).includes("environment"), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_network_status returns local interface metadata without active probing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-network-status-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.network.read"]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "network-status-request",
      nonce: "network-status-nonce",
      tool: "mac_network_status",
      arguments: { include_listeners: false }
    }, ["mac.network.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as {
      interfaces: Array<{ name: string; state: string; addresses: string[] }>;
      listeners: Array<{ protocol: string; address: string; port: number }>;
      connectivity: string;
    };
    assert.ok(data.interfaces.length <= 64);
    assert.deepEqual(data.listeners, []);
    assert.ok(["online", "limited", "offline", "unknown"].includes(data.connectivity));
    assert.equal(result.warnings.some((warning) => warning.includes("active network probe")), true);
    assert.equal(store.auditRows().some((row) => JSON.stringify(row).includes("packet")), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_service_status requires an allowlisted service target and returns bounded launchd state", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-service-status-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.service.read"], ["edge-key-1"], [], ["system/com.apple.logd"]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "service-status-request",
      nonce: "service-status-nonce",
      tool: "mac_service_status",
      arguments: { service_id: "system/com.apple.logd" }
    }, ["mac.service.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as {
      service: {
        service_id: string;
        loaded: boolean;
        running: boolean;
        state: string;
        last_exit_code: number | null;
        pid: number | null;
      };
    };
    assert.equal(data.service.service_id, "system/com.apple.logd");
    assert.equal(data.service.loaded, true);
    assert.ok(["loaded", "running", "stopped", "failed", "unknown"].includes(data.service.state));
    assert.equal(data.service.running, data.service.state === "running");
    assert.ok(data.service.pid === null || (Number.isSafeInteger(data.service.pid) && data.service.pid > 0));
    assert.equal(store.auditRows().some((row) => JSON.stringify(row).includes("launchctl")), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_log_tail requires an allowlisted source and returns sanitized bounded entries", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-log-tail-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.log.read"], ["edge-key-1"], [], [], ["system"]),
    edgeAuthenticationKeys: testKeyring(key),
    logInspector: {
      tail: async () => ({
        source: "system",
        entries: [{ timestamp: null, level: "info", message: "safe broker log" }],
        truncated: false,
        warnings: []
      })
    },
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "log-tail-request",
      nonce: "log-tail-nonce",
      tool: "mac_log_tail",
      arguments: { source: "system", lines: 5, since_seconds: 1 }
    }, ["mac.log.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as {
      source: string;
      entries: Array<{ timestamp: string | null; level?: string; message: string }>;
      truncated: boolean;
    };
    assert.equal(data.source, "system");
    assert.ok(data.entries.length <= 5);
    assert.ok(data.entries.every((entry) => entry.message.length <= 8192));
    assert.equal(JSON.stringify(result).includes("launchctl"), false);
    assert.equal(JSON.stringify(result).includes("/usr/bin/log"), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_git_status requires an exact project target and returns bounded status", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-status-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const projectRoot = await realpath(process.cwd());
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.git.read"], ["edge-key-1"], [], [], [], [projectRoot]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "git-status-request",
      nonce: "git-status-nonce",
      tool: "mac_git_status",
      arguments: { project_root: projectRoot, include_untracked: false }
    }, ["mac.git.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as {
      project_root: string;
      branch: string;
      head: string;
      staged_paths: string[];
      unstaged_paths: string[];
      untracked_paths: string[];
      conflicted_paths: string[];
      dirty: boolean;
    };
    assert.equal(data.project_root, projectRoot);
    assert.match(data.head, /^[A-Fa-f0-9]{40,128}$/u);
    assert.ok(data.branch.length <= 256);
    assert.ok(data.staged_paths.length <= 5_000);
    assert.ok(data.unstaged_paths.length <= 5_000);
    assert.ok(data.untracked_paths.length <= 5_000);
    assert.ok(data.conflicted_paths.length <= 5_000);
    assert.equal(JSON.stringify(result).includes("/usr/bin/git"), false);

    const denied = unsigned({
      requestId: "git-status-denied-request",
      nonce: "git-status-denied-nonce",
      tool: "mac_git_status",
      arguments: { project_root: "/tmp", include_untracked: false }
    }, ["mac.git.read"]);
    assert.equal((await broker.handle(signRequest(denied, key))).result_class, "POLICY_DENIED");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_git_branch_list returns bounded local branch metadata without network", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-branches-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const projectRoot = await realpath(process.cwd());
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.git.read"], ["edge-key-1"], [], [], [], [projectRoot]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "git-branches-request",
      nonce: "git-branches-nonce",
      tool: "mac_git_branch_list",
      arguments: { project_root: projectRoot, include_remote: false }
    }, ["mac.git.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as { project_root: string; branches: Array<{ name: string; current: boolean; upstream?: string; ahead?: number; behind?: number }> };
    assert.equal(data.project_root, projectRoot);
    assert.ok(data.branches.length <= 500);
    assert.equal(data.branches.filter((branch) => branch.current).length <= 1, true);
    assert.equal(data.branches.every((branch) => branch.name.length <= 256), true);
    assert.equal(JSON.stringify(result).includes("/usr/bin/git"), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_git_log returns bounded redacted commit metadata", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-log-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const projectRoot = await realpath(process.cwd());
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.git.read"], ["edge-key-1"], [], [], [], [projectRoot]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "git-log-request",
      nonce: "git-log-nonce",
      tool: "mac_git_log",
      arguments: { project_root: projectRoot, limit: 5, ref: "HEAD" }
    }, ["mac.git.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as { project_root: string; commits: Array<{ id: string; author?: string; timestamp: string; subject: string }>; truncated: boolean };
    assert.equal(data.project_root, projectRoot);
    assert.ok(data.commits.length <= 5);
    assert.equal(data.commits.every((commit) => /^[A-Fa-f0-9]{40,64}$/u.test(commit.id)), true);
    assert.equal(data.commits.every((commit) => !Number.isNaN(Date.parse(commit.timestamp))), true);
    assert.equal(data.commits.every((commit) => commit.subject.length <= 500), true);
    assert.equal(JSON.stringify(result).includes("/usr/bin/git"), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_git_diff returns bounded sanitized diff metadata for an authorized project", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-git-diff-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const projectRoot = await realpath(process.cwd());
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.git.read"], ["edge-key-1"], [], [], [], [projectRoot]),
    edgeAuthenticationKeys: testKeyring(key),
    gitDiffInspector: {
      diff: async (root, paths, staged, base) => ({
        projectRoot: root,
        diff: "safe diff\n",
        changedPaths: [...paths],
        staged,
        ...(base !== undefined ? { base } : {}),
        sha256: "a".repeat(64),
        truncated: false,
        warnings: []
      })
    },
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "git-diff-request",
      nonce: "git-diff-nonce",
      tool: "mac_git_diff",
      arguments: { project_root: projectRoot, paths: ["packages/broker/src/broker.ts"], staged: false, base: "HEAD", max_bytes: 65_536 }
    }, ["mac.git.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as {
      project_root: string;
      diff: string;
      changed_paths: string[];
      staged: boolean;
      base?: string;
      sha256: string;
      truncated: boolean;
    };
    assert.equal(data.project_root, projectRoot);
    assert.equal(data.staged, false);
    assert.equal(data.base, "HEAD");
    assert.ok(data.changed_paths.includes("packages/broker/src/broker.ts"));
    assert.ok(Buffer.byteLength(data.diff, "utf8") <= 65_536);
    assert.match(data.sha256, /^[A-Fa-f0-9]{64}$/u);
    assert.equal(JSON.stringify(result.verification).includes("/usr/bin/git"), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_package_inspect returns bounded manifest metadata without executing scripts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-package-broker-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const projectRoot = await realpath(process.cwd());
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.package.read"], ["edge-key-1"], [], [], [], [projectRoot]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "package-inspect-request",
      nonce: "package-inspect-nonce",
      tool: "mac_package_inspect",
      arguments: { project_root: projectRoot, manager: "npm", check_outdated: false }
    }, ["mac.package.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as {
      project_root: string;
      manager: string;
      dependencies: Array<{ name: string; version: string; source?: string }>;
      lockfile: { present: boolean; path?: string };
      outdated: unknown[];
      truncated: boolean;
    };
    assert.equal(data.project_root, projectRoot);
    assert.equal(data.manager, "npm");
    assert.ok(data.dependencies.some((dependency) => dependency.name === "typescript"));
    assert.deepEqual(data.lockfile, { present: true, path: "package-lock.json" });
    assert.deepEqual(data.outdated, []);
    assert.equal(data.truncated, false);
    assert.equal(JSON.stringify(result.verification).includes("npm install"), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Docker handlers remain fixed-scope and redact object/log secrets", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-docker-broker-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const dockerInspector: DockerInspector = {
    async status() {
      return {
        daemon: { available: true, version: "27.5.1", context: "local" },
        containers: [{ id: "abc123", name: "web", state: "running" }],
        images: [],
        warnings: [],
        truncated: false
      };
    },
    async inspect() {
      return {
        objectType: "container",
        id: "abc123",
        name: "/web",
        state: "running",
        image: "example/app:latest",
        ports: [{ protocol: "tcp", containerPort: 8080, hostPort: 18080 }],
        mounts: [{ source: "[REDACTED]", target: "/app", readOnly: true }],
        warnings: [],
        truncated: false
      };
    },
    async logs() {
      return {
        containerId: "abc123",
        entries: [{ timestamp: null, line: "token=[REDACTED]" }],
        warnings: [],
        truncated: false
      };
    }
  };
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.docker.read"], ["edge-key-1"], [], [], [], [], ["abc123"]),
    edgeAuthenticationKeys: testKeyring(key),
    dockerInspector,
    now: () => NOW
  });
  try {
    const status = await broker.handle(signRequest(unsigned({
      requestId: "docker-status-request",
      nonce: "docker-status-nonce",
      tool: "mac_docker_status",
      arguments: { include_images: false, include_storage: false }
    }, ["mac.docker.read"]), key));
    assert.equal(status.ok, true, JSON.stringify(status));
    const inspect = await broker.handle(signRequest(unsigned({
      requestId: "docker-inspect-request",
      nonce: "docker-inspect-nonce",
      tool: "mac_docker_inspect",
      arguments: { object_type: "container", id: "abc123" }
    }, ["mac.docker.read"]), key));
    assert.equal(inspect.ok, true, JSON.stringify(inspect));
    const logs = await broker.handle(signRequest(unsigned({
      requestId: "docker-logs-request",
      nonce: "docker-logs-nonce",
      tool: "mac_docker_logs",
      arguments: { container_id: "abc123", tail: 20, since_seconds: 60 }
    }, ["mac.docker.read"]), key));
    assert.equal(logs.ok, true, JSON.stringify(logs));
    assert.equal(JSON.stringify(inspect).includes("TOKEN"), false);
    assert.equal(JSON.stringify(logs).includes("super-secret-value"), false);
    assert.equal(store.auditRows().some((row) => JSON.stringify(row).includes("docker inspect")), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("tampered authenticated request fails before execution", async () => {
  const context = await fixture();
  try {
    const request = signRequest(unsigned(), context.key);
    const result = await context.broker.handle({ ...request, tool: "mac_capabilities" });
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "AUTH_INVALID");
    assert.equal(context.store.auditRows().length, 0);
  } finally { await context.close(); }
});

test("duplicate nonce is denied and remains denied after store reopen", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-replay-"));
  const path = join(directory, "broker.sqlite");
  const key = randomBytes(32);
  let store = new BrokerStore(path);
  let broker = new Broker({ store, policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]), edgeAuthenticationKeys: testKeyring(key), now: () => NOW });
  const request = signRequest(unsigned(), key);
  assert.equal((await broker.handle(request)).ok, true);
  store.close();
  store = new BrokerStore(path);
  broker = new Broker({ store, policy: createDefaultPolicy("edge-1", true, ["mac.control.read"]), edgeAuthenticationKeys: testKeyring(key), now: () => NOW });
  const replay = await broker.handle(request);
  assert.equal(replay.ok, false);
  assert.equal(replay.result_class, "REPLAY_DENIED");
  store.close();
  await rm(directory, { recursive: true, force: true });
});

test("expired requests and sessions fail closed", async () => {
  const context = await fixture();
  try {
    const old = signRequest(unsigned({ timestampMs: NOW - 60_001 }), context.key);
    assert.equal((await context.broker.handle(old)).result_class, "AUTH_EXPIRED");
    const expiredSession = unsigned({ requestId: "request-2", nonce: "nonce-2" });
    expiredSession.principal = { ...expiredSession.principal, expiresAtMs: NOW };
    assert.equal((await context.broker.handle(signRequest(expiredSession, context.key))).result_class, "AUTH_EXPIRED");
  } finally { await context.close(); }
});

test("scope is exact and tool arguments cannot grant authority", async () => {
  const context = await fixture();
  try {
    const request = unsigned({ arguments: { scopes: ["mac.control.read"] } }, ["mac.files.read"]);
    const result = await context.broker.handle(signRequest(request, context.key));
    assert.equal(result.result_class, "SCOPE_DENIED");
  } finally { await context.close(); }
});

test("a signed Edge request cannot project scopes outside the Broker-owned grant", async () => {
  const context = await fixture();
  try {
    const request = unsigned({}, ["mac.control.read", "mac.files.write"]);
    const result = await context.broker.handle(signRequest(request, context.key));
    assert.equal(result.result_class, "SCOPE_DENIED");
  } finally { await context.close(); }
});

test("a post-authorization failure is audited as a failed completion", async () => {
  const context = await fixture();
  try {
    const request = unsigned({ arguments: { unknown: true } });
    const result = await context.broker.handle(signRequest(request, context.key));
    assert.equal(result.result_class, "PRECONDITION_FAILED");
    assert.equal(context.store.requestRecord("request-1")?.state, "FAILED");
    const rows = context.store.auditRows();
    assert.deepEqual(rows.map((row) => [row.event_type, row.decision, row.result_class]), [
      ["decision", "allow", "AUTHORIZED"],
      ["completion", "allow", "PRECONDITION_FAILED"]
    ]);
  } finally { await context.close(); }
});

test("revocation and global kill switch reject new work", async () => {
  const context = await fixture();
  try {
    context.store.revoke("session", "session-1", "test", NOW);
    const revoked = await context.broker.handle(signRequest(unsigned(), context.key));
    assert.equal(revoked.result_class, "REVOKED");
    context.store.setSwitch("global", true, "test", NOW);
    const next = signRequest(unsigned({ requestId: "request-2", nonce: "nonce-2", principal: { ...unsigned().principal, sessionId: "session-2" } }), context.key);
    assert.equal((await context.broker.handle(next)).result_class, "REVOKED");
  } finally { await context.close(); }
});

test("host Edge lifecycle revocation is durable and rejects new work", async () => {
  const context = await fixture();
  try {
    context.broker.revokeEdge("edge-1", "peer-identity-loss", NOW);
    assert.equal(context.store.isRevoked("edge", "edge-1"), true);
    const revoked = await context.broker.handle(signRequest(unsigned({ requestId: "edge-revoked", nonce: "edge-revoked-nonce" }), context.key));
    assert.equal(revoked.result_class, "REVOKED");
    assert.deepEqual(
      context.store.auditRows()
        .filter((row) => row.target_ref === "revocation:edge:edge-1")
        .map((row) => [row.event_type, row.result_class]),
      [["intent", "INTENT_RECORDED"], ["completion", "SUCCEEDED"]]
    );
  } finally {
    await context.close();
  }
});

test("capability discovery separates planned, implemented, and enabled", async () => {
  const context = await fixture();
  try {
    const request = signRequest(unsigned({ tool: "mac_capabilities" }), context.key);
    const result = await context.broker.handle(request);
    assert.equal(result.ok, true);
    if (result.ok) {
      const capabilities = (result.data as { capabilities: Array<{ name: string; enabled: boolean; reason: string }> }).capabilities;
      assert.equal(capabilities.length, 44);
      assert.deepEqual(capabilities.find((tool) => tool.name === "mac_health"), {
        name: "mac_health", enabled: true, scopes: ["mac.control.read"], contract_version: "0.1", reason: "enabled"
      });
      assert.deepEqual(capabilities.find((tool) => tool.name === "mac_policy_explain"), {
        name: "mac_policy_explain", enabled: false, scopes: ["mac.policy.explain"], contract_version: "0.1", reason: "scope_not_granted"
      });
      assert.deepEqual(capabilities.find((tool) => tool.name === "mac_task_run"), {
        name: "mac_task_run", enabled: false, scopes: ["mac.task.run"], contract_version: "0.1", reason: "disabled_by_policy"
      });
    }
  } finally { await context.close(); }
});

test("mac_app_list binds app-set authority and returns sanitized metadata", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-app-list-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  let observed: { runningOnly: boolean; includeInstalled: boolean } | undefined;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.app.read"]),
    edgeAuthenticationKeys: testKeyring(key),
    appInspector: {
      async list(runningOnly, includeInstalled, control) {
        observed = { runningOnly, includeInstalled };
        assert.equal(control.shouldCancel(), false);
        return {
          apps: [{ appId: "bundle:com.example.App", bundleId: "com.example.App", name: "Example", running: true, version: "1.0" }],
          warnings: [],
          truncated: false
        };
      }
    },
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "app-list-request",
      nonce: "app-list-nonce",
      tool: "mac_app_list",
      arguments: { running_only: true, include_installed: false }
    }, ["mac.app.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(observed, { runningOnly: true, includeInstalled: false });
    if (result.ok) {
      assert.deepEqual(result.data, {
        apps: [{ app_id: "bundle:com.example.App", bundle_id: "com.example.App", name: "Example", running: true, version: "1.0" }]
      });
    }
    assert.deepEqual(store.auditRows().filter((row) => row.request_id === "app-list-request").map((row) => row.target_ref), ["app_set:all", "app_set:all"]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_ui_observe binds an independent app-window scope and returns redacted opaque nodes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ui-observe-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const appId = "bundle:com.example.Accessible";
  const policy = createDefaultPolicy("edge-1", true, ["mac.ui.observe"], ["edge-key-1"], [], [], [], [], [], [], [appId]);
  let observed: { appId: string; windowHint: string | undefined; maxNodes: number } | undefined;
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    uiInspector: {
      async observe(requestedAppId, windowHint, maxNodes, control) {
        observed = { appId: requestedAppId, windowHint, maxNodes };
        assert.equal(control.shouldCancel(), false);
        return {
          appId: requestedAppId,
          windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
          windowTitle: "Example",
          focused: true,
          nodes: [{
            elementRef: "element:0123456789abcdef0123456789abcdef0123456789abcdef",
            role: "AXWindow",
            label: "Example",
            enabled: true,
            focused: true,
            secure: false
          }],
          truncated: false,
          warnings: []
        };
      }
    },
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "ui-observe-request",
      nonce: "ui-observe-nonce",
      tool: "mac_ui_observe",
      arguments: { app_id: appId, window_hint: "Example", max_nodes: 25 }
    }, ["mac.ui.observe"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.deepEqual(observed, { appId, windowHint: "Example", maxNodes: 25 });
    if (result.ok) {
      assert.deepEqual(result.data, {
        app_id: appId,
        window_id: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
        window_title: "Example",
        focused: true,
        nodes: [{
          element_ref: "element:0123456789abcdef0123456789abcdef0123456789abcdef",
          role: "AXWindow",
          label: "Example",
          enabled: true,
          focused: true,
          secure: false
        }],
        truncated: false
      });
    }
    assert.deepEqual(store.auditRows().filter((row) => row.request_id === "ui-observe-request").map((row) => row.target_ref), [
      `app_window:window:${appId}`, "app_window:window:0123456789abcdef0123456789abcdef0123456789abcdef"
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_ui_action binds a short-lived owned snapshot, GUI approval, and reobserved action", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ui-action-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const appId = "bundle:com.example.Accessible";
  const elementRef = "element:0123456789abcdef0123456789abcdef0123456789abcdef";
  const registry = new UiSnapshotRegistry();
  registry.recordObservation({
    appId,
    windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
    windowIndex: 0,
    windowTitle: "Example",
    focused: true,
    nodes: [{ elementRef, role: "AXButton", label: "Save", enabled: true, focused: false, secure: false }],
    truncated: false,
    warnings: []
  }, "principal-1", "session-1", NOW);
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.ui.control"], ["edge-key-1"], [], [], [], [], [], [], [appId]);
  const uiTool = basePolicy.tools.get("mac_ui_action")!;
  const policy = { ...basePolicy, tools: new Map(basePolicy.tools).set("mac_ui_action", { ...uiTool, enabled: true }) };
  let actionCalls = 0;
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    uiSnapshotRegistry: registry,
    uiInspector: {
      async observe() { throw new Error("unused"); },
      async action(execution, control) {
        actionCalls += 1;
        assert.equal(execution.snapshot.elementRef, elementRef);
        assert.equal(execution.snapshot.ownerPrincipalId, "principal-1");
        assert.equal(execution.action, "press");
        assert.equal(control.shouldCancel(), false);
        return {
          elementRef,
          action: "press",
          accepted: true,
          appId,
          windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
          reobserved: { role: "AXButton", enabled: true, focused: false, secure: false },
          warnings: [],
          truncated: false,
          verified: true
        };
      }
    },
    now: () => NOW
  });
  const argumentsValue = { element_ref: elementRef, action: "press" };
  const request = unsigned({ requestId: "ui-action-request", nonce: "ui-action-nonce", tool: "mac_ui_action", arguments: argumentsValue }, ["mac.ui.control"]);
  try {
    store.issueApproval({
      approvalId: "approval:ui-action",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_ui_action",
      contractVersion: "0.1",
      targetKind: "ui_element",
      targetRef: `ui_element:${elementRef}`,
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_gui",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(actionCalls, 1);
    if (result.ok) assert.deepEqual(result.data, {
      element_ref: elementRef,
      action: "press",
      accepted: true,
      job_id: store.requestRecord("ui-action-request")?.jobId,
      reobserved: { role: "AXButton", enabled: true, focused: false }
    });
    assert.equal(store.ownedJobByIdempotencyKey("ui-action:ui-action-request", "principal-1")?.state, "completed");
    assert.equal(store.approvalRecord("approval:ui-action")?.usedCount, 1);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_ui_action never publishes success after active session revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ui-action-revoke-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const appId = "bundle:com.example.Accessible";
  const elementRef = "element:0123456789abcdef0123456789abcdef0123456789abcdef";
  const registry = new UiSnapshotRegistry();
  registry.recordObservation({
    appId,
    windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
    windowIndex: 0,
    windowTitle: "Example",
    focused: true,
    nodes: [{ elementRef, role: "AXButton", label: "Save", enabled: true, focused: false, secure: false }],
    truncated: false,
    warnings: []
  }, "principal-1", "session-1", NOW);
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.ui.control"], ["edge-key-1"], [], [], [], [], [], [], [appId]);
  const uiTool = basePolicy.tools.get("mac_ui_action")!;
  const policy = { ...basePolicy, tools: new Map(basePolicy.tools).set("mac_ui_action", { ...uiTool, enabled: true }) };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    uiSnapshotRegistry: registry,
    uiInspector: {
      async observe() { throw new Error("unused"); },
      async action() {
        store.revoke("session", "session-1", "TEST_REVOKE", NOW);
        return {
          elementRef,
          action: "press",
          accepted: true,
          appId,
          windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
          reobserved: { role: "AXButton", enabled: true, focused: false, secure: false },
          warnings: [],
          truncated: false,
          verified: true
        };
      }
    },
    now: () => NOW
  });
  const argumentsValue = { element_ref: elementRef, action: "press" };
  const request = unsigned({ requestId: "ui-action-revoke", nonce: "ui-action-revoke-nonce", tool: "mac_ui_action", arguments: argumentsValue }, ["mac.ui.control"]);
  try {
    store.issueApproval({
      approvalId: "approval:ui-action-revoke",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_ui_action",
      contractVersion: "0.1",
      targetKind: "ui_element",
      targetRef: `ui_element:${elementRef}`,
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_gui",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.result_class, "CANCELLED");
    assert.equal(store.ownedJobByIdempotencyKey("ui-action:ui-action-revoke", "principal-1")?.state, "unknown");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_app_open binds GUI approval, app target, Job lease, and launch readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-app-open-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const appId = "bundle:com.example.Editor";
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.app.control"], ["edge-key-1"], [], [], [], [], [], [], [appId]);
  const appTool = basePolicy.tools.get("mac_app_open")!;
  const policy = { ...basePolicy, tools: new Map(basePolicy.tools).set("mac_app_open", { ...appTool, enabled: true }) };
  let calls = 0;
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    appControlInspector: {
      async open(target, documentPath, url, control) {
        calls += 1;
        assert.equal(target, appId);
        assert.equal(documentPath, undefined);
        assert.equal(url, undefined);
        assert.equal(control.shouldCancel(), false);
        return {
          appId,
          state: "launched",
          processId: null,
          target: { kind: "app", reference: appId },
          verified: true,
          warnings: [],
          truncated: false
        };
      }
    },
    now: () => NOW
  });
  const argumentsValue = { app_id: appId };
  const request = unsigned({
    requestId: "app-open-request",
    nonce: "app-open-nonce",
    tool: "mac_app_open",
    arguments: argumentsValue
  }, ["mac.app.control"]);
  try {
    store.issueApproval({
      approvalId: "approval:app-open",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_app_open",
      contractVersion: "0.1",
      targetKind: "app",
      targetRef: `app:${appId}`,
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_gui",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(calls, 1);
    if (result.ok) {
      assert.deepEqual(result.data, {
        app_id: appId,
        state: "launched",
        process_id: null,
        target: { kind: "app", reference: appId },
        verified: true,
        job_id: store.requestRecord("app-open-request")?.jobId
      });
    }
    assert.equal(store.approvalRecord("approval:app-open")?.usedCount, 1);
    assert.equal(store.ownedJobByIdempotencyKey("app-open:app-open-request", "principal-1")?.state, "completed");
    assert.deepEqual(store.auditRows().filter((row) => row.request_id === "app-open-request").map((row) => row.target_ref), [
      `app:${appId}`, `app:${appId}`, `app:${appId}`
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_app_focus binds GUI approval, app-window target, Job lease, and focus readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-app-focus-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const appId = "bundle:com.example.Editor";
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.app.control"], ["edge-key-1"], [], [], [], [], [], [], [appId]);
  const appTool = basePolicy.tools.get("mac_app_focus")!;
  const policy = { ...basePolicy, tools: new Map(basePolicy.tools).set("mac_app_focus", { ...appTool, enabled: true }) };
  let calls = 0;
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    appControlInspector: {
      async open() { throw new Error("unused"); },
      async focus(target, windowHint, control) {
        calls += 1;
        assert.equal(target, appId);
        assert.equal(windowHint, "Example");
        assert.equal(control.shouldCancel(), false);
        return {
          appId,
          windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
          windowTitle: "Example",
          focused: true,
          verified: true,
          warnings: [],
          truncated: false
        };
      }
    },
    now: () => NOW
  });
  const argumentsValue = { app_id: appId, window_hint: "Example" };
  const request = unsigned({
    requestId: "app-focus-request",
    nonce: "app-focus-nonce",
    tool: "mac_app_focus",
    arguments: argumentsValue
  }, ["mac.app.control"]);
  try {
    store.issueApproval({
      approvalId: "approval:app-focus",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_app_focus",
      contractVersion: "0.1",
      targetKind: "app_window",
      targetRef: `app_window:window:${appId}`,
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_gui",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(calls, 1);
    if (result.ok) {
      assert.deepEqual(result.data, {
        app_id: appId,
        window_id: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
        window_title: "Example",
        focused: true,
        reobserved_at: new Date(NOW).toISOString(),
        verified: true,
        job_id: store.requestRecord("app-focus-request")?.jobId
      });
    }
    assert.equal(store.approvalRecord("approval:app-focus")?.usedCount, 1);
    assert.equal(store.ownedJobByIdempotencyKey("app-focus:app-focus-request", "principal-1")?.state, "completed");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_app_open never publishes success after active session revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-app-open-revoke-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const appId = "bundle:com.example.Editor";
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.app.control"], ["edge-key-1"], [], [], [], [], [], [], [appId]);
  const appTool = basePolicy.tools.get("mac_app_open")!;
  const policy = { ...basePolicy, tools: new Map(basePolicy.tools).set("mac_app_open", { ...appTool, enabled: true }) };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    appControlInspector: {
      async open() {
        store.revoke("session", "session-1", "TEST_REVOKE", NOW);
        return {
          appId,
          state: "launched",
          processId: null,
          target: { kind: "app", reference: appId },
          verified: true,
          warnings: [],
          truncated: false
        };
      }
    },
    now: () => NOW
  });
  const argumentsValue = { app_id: appId };
  const request = unsigned({ requestId: "app-open-revoke", nonce: "app-open-revoke-nonce", tool: "mac_app_open", arguments: argumentsValue }, ["mac.app.control"]);
  try {
    store.issueApproval({
      approvalId: "approval:app-open-revoke",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_app_open",
      contractVersion: "0.1",
      targetKind: "app",
      targetRef: `app:${appId}`,
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_gui",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.result_class, "CANCELLED");
    assert.equal(store.ownedJobByIdempotencyKey("app-open:app-open-revoke", "principal-1")?.state, "unknown");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_app_focus never publishes success after active session revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-app-focus-revoke-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const appId = "bundle:com.example.Editor";
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.app.control"], ["edge-key-1"], [], [], [], [], [], [], [appId]);
  const appTool = basePolicy.tools.get("mac_app_focus")!;
  const policy = { ...basePolicy, tools: new Map(basePolicy.tools).set("mac_app_focus", { ...appTool, enabled: true }) };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    appControlInspector: {
      async open() { throw new Error("unused"); },
      async focus() {
        store.revoke("session", "session-1", "TEST_REVOKE", NOW);
        return {
          appId,
          windowId: "window:0123456789abcdef0123456789abcdef0123456789abcdef",
          windowTitle: "Example",
          focused: true,
          verified: true,
          warnings: [],
          truncated: false
        };
      }
    },
    now: () => NOW
  });
  const argumentsValue = { app_id: appId, window_hint: "Example" };
  const request = unsigned({ requestId: "app-focus-revoke", nonce: "app-focus-revoke-nonce", tool: "mac_app_focus", arguments: argumentsValue }, ["mac.app.control"]);
  try {
    store.issueApproval({
      approvalId: "approval:app-focus-revoke",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_app_focus",
      contractVersion: "0.1",
      targetKind: "app_window",
      targetRef: `app_window:window:${appId}`,
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_gui",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.result_class, "CANCELLED");
    assert.equal(store.ownedJobByIdempotencyKey("app-focus:app-focus-revoke", "principal-1")?.state, "unknown");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("production-default policy enables no tool or filesystem root", () => {
  const policy = createDefaultPolicy("edge-1");
  assert.equal([...policy.tools.values()].filter((tool) => tool.enabled).length, 0);
  assert.equal([...policy.tools.values()].filter((tool) => tool.implemented).length, 40);
  assert.deepEqual(policy.filesystemRoots, []);
});

test("mac_git_stage binds approval, explicit paths, Job lease, and staged readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-git-stage-"));
  const projectRoot = await realpath(directory);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const basePolicy = createDefaultPolicy(
    "edge-1", true, ["mac.git.write"], ["edge-key-1"], [], [], [], [projectRoot]
  );
  const gitTool = basePolicy.tools.get("mac_git_stage")!;
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_git_stage", { ...gitTool, enabled: true })
  };
  let calls = 0;
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    gitWriteInspector: {
      async stage(root, paths, control) {
        calls += 1;
        assert.equal(root, projectRoot);
        assert.deepEqual(paths, ["src/main.ts"]);
        assert.equal(control.shouldCancel(), false);
        return {
          projectRoot,
          stagedPaths: ["src/main.ts"],
          skippedPaths: [],
          stagedDiffSha256: "a".repeat(64),
          indexChanged: true,
          warnings: [],
          truncated: false
        };
      },
      async commit() { throw new Error("commit must not run in stage test"); }
    },
    now: () => NOW
  });
  const argumentsValue = { project_root: projectRoot, paths: ["src/main.ts"] };
  const request = unsigned({
    requestId: "git-stage-request",
    nonce: "git-stage-nonce",
    tool: "mac_git_stage",
    arguments: argumentsValue
  }, ["mac.git.write"]);
  try {
    store.issueApproval({
      approvalId: "approval:git-stage",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_git_stage",
      contractVersion: "0.1",
      targetKind: "project",
      targetRef: `project:${projectRoot}`,
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(calls, 1);
    if (result.ok) {
      assert.deepEqual(result.data, {
        project_root: projectRoot,
        staged_paths: ["src/main.ts"],
        skipped_paths: [],
        staged_diff_sha256: "a".repeat(64),
        index_changed: true
      });
    }
    const job = store.ownedJobByIdempotencyKey("git:mac_git_stage:git-stage-request", "principal-1");
    assert.equal(job?.state, "completed");
    assert.equal(store.approvalRecord("approval:git-stage")?.usedCount, 1);
    assert.deepEqual(store.auditRows()
      .filter((row) => row.request_id === "git-stage-request")
      .map((row) => row.event_type), ["decision", "intent", "completion"]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_task_run fails closed before consuming approval when runner mechanism is unavailable", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-fail-closed-"));
  const root = await realpath(directory);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const basePolicy = createDefaultPolicy(
    "edge-1", true, ["mac.task.run"], ["edge-key-1"],
    [{ rootId: "task-root", path: root, metadata: true, contentRead: true, denyRelativePaths: [] }],
    [], [], [], [], ["tests.echo"]
  );
  const taskTool = basePolicy.tools.get("mac_task_run")!;
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_task_run", { ...taskTool, enabled: true })
  };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    taskProfileRegistry: new TaskProfileRegistry([taskProfile(root)]),
    taskRunner: {
      available: true,
      mechanism: null,
      isolationProof: testTaskIsolationProof(),
      async run() { throw new Error("must not execute without a bound isolation mechanism"); }
    },
    now: () => NOW
  });
  const argumentsValue = { profile: "tests.echo", cwd: root, args: ["safe"] };
  const request = unsigned({
    requestId: "task-fail-closed",
    nonce: "task-fail-closed-nonce",
    tool: "mac_task_run",
    arguments: argumentsValue
  }, ["mac.task.run"]);
  try {
    store.issueApproval({
      approvalId: "approval:task-fail-closed",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_task_run",
      contractVersion: "0.1",
      targetKind: "task_profile",
      targetRef: "task_profile:tests.echo",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_profile",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.result_class, "POLICY_DENIED");
    assert.equal(store.approvalRecord("approval:task-fail-closed")?.usedCount, 0);
    assert.equal(store.requestRecord("task-fail-closed")?.state, "DENIED");
    assert.equal(store.ownedJobByIdempotencyKey("task:task-fail-closed", "principal-1"), undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_task_run binds approval, profile resolution, and verified Job completion", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-run-"));
  const root = await realpath(directory);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const basePolicy = createDefaultPolicy(
    "edge-1", true, ["mac.task.run"], ["edge-key-1"],
    [{ rootId: "task-root", path: root, metadata: true, contentRead: true, denyRelativePaths: [] }],
    [], [], [], [], ["tests.echo"]
  );
  const taskTool = basePolicy.tools.get("mac_task_run")!;
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_task_run", { ...taskTool, enabled: true })
  };
  let runnerCalls = 0;
  const taskRunner: TaskRunner = {
    available: true,
    mechanism: "sandbox-exec",
    isolationProof: testTaskIsolationProof(),
    async run(profile, control) {
      runnerCalls += 1;
      assert.equal(profile.process.executable, "/bin/echo");
      assert.equal(profile.networkPolicy, "none");
      assert.equal(control.timeoutMs, 600_000);
      assert.equal(control.shouldCancel(), false);
      control.onProcessStarted?.({
        identity: { pid: 1234, processGroupId: 1234, startTimeMicros: 987654321 },
        descendants: []
      });
      return {
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        stdout: runnerCalls === 1 ? "ok\n" : "x".repeat(2_048),
        stderr: "",
        truncated: false,
        durationMs: 1,
        verification: { status: "verified", summary: "fake isolated runner read back its postcondition" }
      };
    }
  };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    taskProfileRegistry: new TaskProfileRegistry([taskProfile(root)]),
    taskRunner,
    now: () => NOW
  });
  const argumentsValue = { profile: "tests.echo", cwd: root, args: ["safe"] };
  const request = unsigned({
    requestId: "task-success",
    nonce: "task-success-nonce",
    tool: "mac_task_run",
    arguments: argumentsValue
  }, ["mac.task.run"]);
  try {
    store.issueApproval({
      approvalId: "approval:task-success",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_task_run",
      contractVersion: "0.1",
      targetKind: "task_profile",
      targetRef: "task_profile:tests.echo",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_profile",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.equal(store.approvalRecord("approval:task-success")?.usedCount, 1);
    assert.equal(store.requestRecord("task-success")?.state, "SUCCEEDED");
    assert.ok(store.requestRecord("task-success")?.jobId);
    if (result.ok) {
      assert.deepEqual(result.data, {
        profile: "tests.echo",
        cwd: root,
        state: "completed",
        job_id: store.requestRecord("task-success")?.jobId,
        exit_code: 0,
        stdout: "ok\n",
        stderr: "",
        truncated: false
      });
      assert.equal(result.verification.status, "verified");
    }
    const jobId = store.requestRecord("task-success")!.jobId!;
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "completed");
    assert.equal(store.ownedJob(jobId, "principal-1")?.resultClass, "success");

    const oversizedArguments = { profile: "tests.echo", cwd: root, args: ["oversized"] };
    const oversizedRequest = unsigned({
      requestId: "task-output-limit",
      nonce: "task-output-limit-nonce",
      tool: "mac_task_run",
      arguments: oversizedArguments
    }, ["mac.task.run"]);
    store.issueApproval({
      approvalId: "approval:task-output-limit",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_task_run",
      contractVersion: "0.1",
      targetKind: "task_profile",
      targetRef: "task_profile:tests.echo",
      payloadDigest: sha256(canonicalJson(oversizedArguments)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_profile",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const oversized = await broker.handle(signRequest(oversizedRequest, key));
    assert.equal(oversized.result_class, "OUTPUT_LIMIT");
    const oversizedJobId = store.requestRecord("task-output-limit")?.jobId;
    assert.ok(oversizedJobId);
    assert.equal(store.ownedJob(oversizedJobId, "principal-1")?.state, "failed");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_task_run does not publish success after active session revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-task-revoke-"));
  const root = await realpath(directory);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const basePolicy = createDefaultPolicy(
    "edge-1", true, ["mac.task.run"], ["edge-key-1"],
    [{ rootId: "task-root", path: root, metadata: true, contentRead: true, denyRelativePaths: [] }],
    [], [], [], [], ["tests.echo"]
  );
  const taskTool = basePolicy.tools.get("mac_task_run")!;
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_task_run", { ...taskTool, enabled: true })
  };
  const taskRunner: TaskRunner = {
    available: true,
    mechanism: "sandbox-exec",
    isolationProof: testTaskIsolationProof(),
    async run(_profile, control) {
      store.revoke("session", "session-1", "active-revocation-test", NOW);
      assert.equal(control.shouldCancel(), true);
      return {
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        stdout: "must-not-publish",
        stderr: "",
        truncated: false,
        durationMs: 1,
        verification: { status: "verified", summary: "runner returned after revocation" }
      };
    }
  };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    taskProfileRegistry: new TaskProfileRegistry([taskProfile(root)]),
    taskRunner,
    now: () => NOW
  });
  const argumentsValue = { profile: "tests.echo", cwd: root, args: ["safe"] };
  const request = unsigned({
    requestId: "task-revoked",
    nonce: "task-revoked-nonce",
    tool: "mac_task_run",
    arguments: argumentsValue
  }, ["mac.task.run"]);
  try {
    store.issueApproval({
      approvalId: "approval:task-revoked",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_task_run",
      contractVersion: "0.1",
      targetKind: "task_profile",
      targetRef: "task_profile:tests.echo",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_profile",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.result_class, "CANCELLED");
    assert.equal(store.requestRecord("task-revoked")?.state, "CANCELLED");
    const jobId = store.requestRecord("task-revoked")?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "unknown");
    assert.equal(store.ownedJob(jobId, "principal-1")?.resultClass, "unknown");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("job status and queued cancellation are owner-bound and durably audited", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-job-tools-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  store.createJob({
    jobId: "job:test-1",
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_task_run",
    targetRef: "task:test",
    policyVersion: "policy-0.1",
    payloadDigest: "a".repeat(64),
    idempotencyKey: "job-tool-test",
    createdAtMs: NOW - 5_000
  });
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.job.read", "mac.job.cancel"]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const statusRequest = unsigned({
      requestId: "job-status-request",
      nonce: "job-status-nonce",
      tool: "mac_job_status",
      arguments: { job_id: "job:test-1", tail_bytes: 128 }
    }, ["mac.job.read", "mac.job.cancel"]);
    const status = await broker.handle(signRequest(statusRequest, key));
    assert.equal(status.ok, true);
    if (status.ok) assert.equal((status.data as { state: string }).state, "queued");

    const cancelRequest = unsigned({
      requestId: "job-cancel-request",
      nonce: "job-cancel-nonce",
      tool: "mac_job_cancel",
      arguments: { job_id: "job:test-1", reason: "test" }
    }, ["mac.job.read", "mac.job.cancel"]);
    const unapprovedRequest = {
      ...cancelRequest,
      requestId: "job-cancel-unapproved",
      nonce: "job-cancel-unapproved-nonce"
    };
    const unapproved = await broker.handle(signRequest(unapprovedRequest, key));
    assert.equal(unapproved.result_class, "POLICY_DENIED");
    assert.equal(store.ownedJob("job:test-1", "principal-1")?.state, "queued");
    assert.equal(store.requestRecord("job-cancel-unapproved")?.state, "FAILED");
    assert.deepEqual(store.auditRows().filter((row) => row.request_id === "job-cancel-unapproved")
      .map((row) => [row.event_type, row.result_class]), [
      ["decision", "AUTHORIZED"],
      ["completion", "POLICY_DENIED"]
    ]);
    store.issueApproval({
      approvalId: "approval:job-cancel",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_job_cancel",
      contractVersion: "0.1",
      targetKind: "job",
      targetRef: "job:job:test-1",
      payloadDigest: sha256(canonicalJson(cancelRequest.arguments)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const cancellation = await broker.handle(signRequest(cancelRequest, key));
    assert.equal(cancellation.ok, true);
    assert.equal(store.approvalRecord("approval:job-cancel")?.usedCount, 1);
    assert.equal(store.requestRecord("job-cancel-request")?.approvalId, "approval:job-cancel");
    if (cancellation.ok) assert.deepEqual(cancellation.data, {
      job_id: "job:test-1",
      prior_state: "queued",
      new_state: "cancelled",
      cancel_requested: true,
      termination_observed: true
    });
    assert.deepEqual(store.auditRows()
      .filter((row) => row.request_id === "job-status-request" || row.request_id === "job-cancel-request")
      .map((row) => [row.request_id, row.event_type, row.target_ref]), [
      ["job-status-request", "decision", "job:job:test-1"],
      ["job-status-request", "completion", "job:job:test-1"],
      ["job-cancel-request", "decision", "job:job:test-1"],
      ["job-cancel-request", "intent", "job:job:test-1"],
      ["job-cancel-request", "completion", "job:job:test-1"]
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("job tools do not reveal a job owned by another principal", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-job-owner-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  store.createJob({
    jobId: "job:other",
    ownerPrincipalId: "principal-2",
    ownerSessionId: "session-2",
    tool: "mac_task_run",
    targetRef: "task:test",
    policyVersion: "policy-0.1",
    payloadDigest: "a".repeat(64),
    idempotencyKey: "other-job",
    createdAtMs: NOW - 1_000
  });
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.job.read"]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({ tool: "mac_job_status", arguments: { job_id: "job:other" } }, ["mac.job.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "TARGET_NOT_FOUND");
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_stat_path authorizes a signed root before descriptor-backed observation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-stat-"));
  const path = join(directory, "sample.txt");
  await writeFile(path, "hello", { mode: 0o600 });
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({ tool: "mac_stat_path", arguments: { path } }, ["mac.files.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true);
    if (result.ok) assert.equal((result.data as { path: string }).path, await realpath(path));
    assert.deepEqual(store.auditRows().map((row) => [row.event_type, row.target_ref]), [
      ["decision", "path:test-root"],
      ["completion", `path:${await realpath(path)}`]
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_stat_path does not execute when the signed root target is not authorized", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-stat-deny-"));
  const path = join(directory, "sample.txt");
  await writeFile(path, "hello");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const policy = createDefaultPolicy("edge-1", true, ["mac.files.read"], ["edge-key-1"], [root]);
  const broker = new Broker({
    store,
    policy: { ...policy, targetRules: [] },
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({ tool: "mac_stat_path", arguments: { path } }, ["mac.files.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.result_class, "POLICY_DENIED");
    assert.deepEqual(store.auditRows().map((row) => row.event_type), ["decision"]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_policy_explain maps a proposed path to the Broker-owned filesystem root", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-policy-explain-path-"));
  const path = join(directory, "sample.txt");
  await writeFile(path, "hello");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy(
      "edge-1",
      true,
      ["mac.policy.explain", "mac.files.read"],
      ["edge-key-1"],
      [root]
    ),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      tool: "mac_policy_explain",
      arguments: {
        proposed_tool: "mac_stat_path",
        target: { kind: "path", reference: path }
      }
    }, ["mac.policy.explain", "mac.files.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true);
    if (result.ok) {
      assert.deepEqual(result.data, {
        decision: "allow",
        normalized_target: { kind: "path", reference: path },
        required_scopes: ["mac.files.read"],
        missing_scopes: [],
        reason_codes: ["AUTHORIZED"],
        policy_version: "policy-0.1"
      });
    }
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_read_file returns a bounded descriptor-backed range", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-read-"));
  const path = join(directory, "sample.txt");
  await writeFile(path, "hello world", { mode: 0o600 });
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      tool: "mac_read_file",
      arguments: { path, offset: 6, max_bytes: 3, encoding: "utf8" }
    }, ["mac.files.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true);
    if (result.ok) {
      const data = result.data as { path: string; encoding: string; content: string; size_bytes: number; sha256: string; truncated: boolean };
      assert.equal(data.path, await realpath(path));
      assert.equal(data.encoding, "utf8");
      assert.equal(data.content, "wor");
      assert.equal(data.size_bytes, 11);
      assert.match(data.sha256, /^[a-f0-9]{64}$/u);
      assert.equal(data.truncated, true);
      assert.equal(result.truncated, true);
      assert.equal(result.verification.status, "verified");
    }
    assert.deepEqual(store.auditRows().map((row) => [row.event_type, row.target_ref]), [
      ["decision", "path:test-root"],
      ["completion", `path:${await realpath(path)}`]
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_read_file fails closed before returning secret-shaped content", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-secret-read-"));
  const path = join(directory, "notes.txt");
  const secret = "api_key=supersecretvalue";
  await writeFile(path, secret, { mode: 0o600 });
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({ tool: "mac_read_file", arguments: { path } }, ["mac.files.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "POLICY_DENIED");
    assert.equal(JSON.stringify(result).includes(secret), false);
    assert.equal(JSON.stringify(store.auditRows()).includes(secret), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_hash_file returns a descriptor-verified digest without content", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-hash-"));
  const path = join(directory, "sample.txt");
  await writeFile(path, "hash me", { mode: 0o600 });
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.hash"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      tool: "mac_hash_file",
      arguments: { path, algorithm: "sha256" }
    }, ["mac.files.hash"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    if (result.ok) {
      assert.deepEqual(result.data, {
        path: await realpath(path),
        algorithm: "sha256",
        digest: createHash("sha256").update("hash me").digest("hex"),
        size_bytes: 7
      });
      assert.equal(result.verification.strategy, "digest_result_validation");
      assert.equal(JSON.stringify(result).includes("hash me"), false);
    }
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_list_directory paginates descriptor metadata and filters secret entries", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-list-"));
  const directory = join(parent, "workspace");
  await mkdir(directory);
  await writeFile(join(directory, "a.txt"), "a");
  await writeFile(join(directory, "b.txt"), "b");
  await writeFile(join(directory, "c.txt"), "c");
  await writeFile(join(directory, ".env"), "TOKEN=private");
  await writeFile(join(directory, ".visible"), "safe");
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const firstRequest = unsigned({
      requestId: "list-first",
      nonce: "list-first-nonce",
      tool: "mac_list_directory",
      arguments: { path: directory, limit: 2, include_hidden: false }
    }, ["mac.files.read"]);
    const first = await broker.handle(signRequest(firstRequest, key));
    assert.equal(first.ok, true, JSON.stringify(first));
    assert.ok(first.ok);
    const firstData = first.data as { entries: Array<{ name: string }>; next_cursor: string | null };
    assert.deepEqual(firstData.entries.map((entry) => entry.name), ["a.txt", "b.txt"]);
    assert.ok(firstData.next_cursor);
    const secondRequest = unsigned({
      requestId: "list-second",
      nonce: "list-second-nonce",
      tool: "mac_list_directory",
      arguments: { path: directory, cursor: firstData.next_cursor, limit: 2, include_hidden: false }
    }, ["mac.files.read"]);
    const second = await broker.handle(signRequest(secondRequest, key));
    assert.equal(second.ok, true, JSON.stringify(second));
    assert.ok(second.ok);
    const secondData = second.data as { entries: Array<{ name: string }>; next_cursor: string | null };
    assert.deepEqual(secondData.entries.map((entry) => entry.name), ["c.txt"]);
    assert.equal(secondData.next_cursor, null);
    assert.equal(JSON.stringify(first).includes("TOKEN=private"), false);
    assert.equal(store.auditRows().some((row) => JSON.stringify(row).includes(".env")), false);
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_directory_tree bounds depth and excludes protected entries", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-tree-"));
  const directory = join(parent, "workspace");
  await mkdir(join(directory, "nested"), { recursive: true });
  await writeFile(join(directory, "a.txt"), "a");
  await writeFile(join(directory, "nested", "inside.txt"), "inside");
  await writeFile(join(directory, ".env"), "TOKEN=private");
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "tree-request",
      nonce: "tree-nonce",
      tool: "mac_directory_tree",
      arguments: { path: directory, depth: 1, max_entries: 20 }
    }, ["mac.files.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as { entries: Array<{ path: string; depth: number }>; truncated: boolean };
    assert.deepEqual(data.entries.map((entry) => [entry.path.split("/").pop(), entry.depth]), [
      ["a.txt", 0],
      ["nested", 0],
      ["inside.txt", 1]
    ]);
    assert.equal(data.entries.some((entry) => entry.path.endsWith(".env")), false);
    assert.equal(data.truncated, false);
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_find_files searches metadata-only roots with bounded secret filtering", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-find-"));
  const directory = join(parent, "workspace");
  await mkdir(join(directory, "nested"), { recursive: true });
  await writeFile(join(directory, "sample.txt"), "safe");
  await writeFile(join(directory, "nested", "sample-two.log"), "safe");
  await writeFile(join(directory, "credentials"), "TOKEN=private");
  await writeFile(join(directory, ".env"), "TOKEN=private");
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.search"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "find-request",
      nonce: "find-nonce",
      tool: "mac_find_files",
      arguments: { roots: [directory], query: "sample", max_results: 10 }
    }, ["mac.files.search"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as { roots: string[]; matches: Array<{ path: string; type: string }> ; truncated: boolean };
    assert.deepEqual(data.roots, [await realpath(directory)]);
    assert.deepEqual(data.matches.map((match) => [match.path, match.type]), [
      [await realpath(join(directory, "sample.txt")), "file"],
      [await realpath(join(directory, "nested", "sample-two.log")), "file"]
    ]);
    assert.equal(data.truncated, false);
    assert.equal(JSON.stringify(result).includes("TOKEN=private"), false);
    assert.equal(store.auditRows().some((row) => JSON.stringify(row).includes("credentials")), false);
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_find_files authorizes every requested root independently", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-find-targets-"));
  const firstDirectory = join(parent, "first");
  const secondDirectory = join(parent, "second");
  await mkdir(firstDirectory);
  await mkdir(secondDirectory);
  await writeFile(join(firstDirectory, "allowed.txt"), "safe");
  await writeFile(join(secondDirectory, "also.txt"), "safe");
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const roots = [
    { rootId: "first-root", path: firstDirectory, metadata: true, contentRead: false, denyRelativePaths: [] },
    { rootId: "second-root", path: secondDirectory, metadata: true, contentRead: false, denyRelativePaths: [] }
  ] as const;
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.files.search"], ["edge-key-1"], roots);
  const policy = { ...basePolicy, targetRules: basePolicy.targetRules.filter((rule) => rule.target.reference !== "second-root") };
  const broker = new Broker({ store, policy, edgeAuthenticationKeys: testKeyring(key), now: () => NOW });
  try {
    const request = unsigned({
      requestId: "find-targets-request",
      nonce: "find-targets-nonce",
      tool: "mac_find_files",
      arguments: { roots: [firstDirectory, secondDirectory], query: ".txt", max_results: 10 }
    }, ["mac.files.search"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "POLICY_DENIED");
    assert.equal(store.auditRows().some((row) => row.event_type === "completion" && row.result_class === "SUCCEEDED"), false);
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_recent_files returns bounded metadata without reading protected contents", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-recent-"));
  const directory = join(parent, "workspace");
  await mkdir(directory);
  const recentPath = join(directory, "recent.txt");
  const oldPath = join(directory, "old.txt");
  await writeFile(recentPath, "safe");
  await writeFile(oldPath, "old");
  await writeFile(join(directory, "credentials"), "TOKEN=private");
  await writeFile(join(directory, ".env"), "TOKEN=private");
  await utimes(recentPath, new Date(NOW - 3_600_000), new Date(NOW - 3_600_000));
  await utimes(oldPath, new Date(NOW - 172_800_000), new Date(NOW - 172_800_000));
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.search"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "recent-request",
      nonce: "recent-nonce",
      tool: "mac_recent_files",
      arguments: { roots: [directory], since_seconds: 86_400, limit: 10 }
    }, ["mac.files.search"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as { files: Array<{ path: string; type: string; size_bytes: number }>; truncated: boolean };
    assert.deepEqual(data.files.map((file) => [file.path, file.type, file.size_bytes]), [[await realpath(recentPath), "file", 4]]);
    assert.equal(data.truncated, false);
    assert.equal(JSON.stringify(result).includes("TOKEN=private"), false);
    assert.equal(store.auditRows().some((row) => JSON.stringify(row).includes("credentials")), false);
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_search_text returns bounded sanitized matches from content-authorized roots", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-search-text-"));
  const directory = join(parent, "workspace");
  await mkdir(directory);
  const notesPath = join(directory, "notes.txt");
  await writeFile(notesPath, "hello world\nsecond hello\n");
  await writeFile(join(directory, "binary.txt"), Buffer.from([0, 1, 2, 3]));
  await writeFile(join(directory, "credentials"), "token=private-value");
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.search"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "search-text-request",
      nonce: "search-text-nonce",
      tool: "mac_search_text",
      arguments: { roots: [directory], query: "hello", glob: "*.txt", max_results: 10 }
    }, ["mac.files.search"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as { query: string; matches: Array<{ path: string; line: number; start_column: number; end_column: number; snippet: string }>; truncated: boolean };
    assert.equal(data.query, "hello");
    assert.deepEqual(data.matches, [
      { path: await realpath(notesPath), line: 1, start_column: 1, end_column: 6, snippet: "hello world" },
      { path: await realpath(notesPath), line: 2, start_column: 8, end_column: 13, snippet: "second hello" }
    ]);
    assert.equal(data.truncated, false);
    assert.equal(JSON.stringify(result).includes("private-value"), false);
    assert.equal(store.auditRows().some((row) => JSON.stringify(row).includes("private-value")), false);
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_search_text denies metadata-only roots before content execution", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-search-text-policy-"));
  const directory = join(parent, "workspace");
  await mkdir(directory);
  await writeFile(join(directory, "notes.txt"), "hello");
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.search"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "search-text-policy-request",
      nonce: "search-text-policy-nonce",
      tool: "mac_search_text",
      arguments: { roots: [directory], query: "hello" }
    }, ["mac.files.search"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "POLICY_DENIED");
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_project_discover reports safe project markers from metadata-only roots", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-project-discover-"));
  const directory = join(parent, "workspace");
  const nested = join(directory, "services", "api");
  await mkdir(join(directory, ".git"), { recursive: true });
  await mkdir(nested, { recursive: true });
  await writeFile(join(directory, "package.json"), "{\"name\":\"safe\"}");
  await writeFile(join(nested, "pyproject.toml"), "[project]\nname='safe'\n");
  await mkdir(join(directory, ".ssh"), { recursive: true });
  await writeFile(join(directory, ".ssh", "id_rsa"), "PRIVATE-KEY-MATERIAL");
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.project.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "project-discover-request",
      nonce: "project-discover-nonce",
      tool: "mac_project_discover",
      arguments: { roots: [directory], types: ["git", "node", "python"], max_results: 10 }
    }, ["mac.project.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as { projects: Array<{ root: string; type: string; indicators: string[] }>; truncated: boolean };
    assert.deepEqual(data.projects, [
      { root: await realpath(directory), type: "git", indicators: [".git"] },
      { root: await realpath(directory), type: "node", indicators: ["package.json"] },
      { root: await realpath(nested), type: "python", indicators: ["pyproject.toml"] }
    ]);
    assert.equal(data.truncated, false);
    assert.equal(JSON.stringify(result).includes("PRIVATE-KEY-MATERIAL"), false);
    assert.equal(store.auditRows().some((row) => JSON.stringify(row).includes("PRIVATE-KEY-MATERIAL")), false);
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_project_discover rejects unsupported project types", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-project-discover-policy-"));
  const directory = join(parent, "workspace");
  await mkdir(directory);
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.project.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "project-discover-policy-request",
      nonce: "project-discover-policy-nonce",
      tool: "mac_project_discover",
      arguments: { roots: [directory], types: ["unknown"] }
    }, ["mac.project.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "PRECONDITION_FAILED");
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_project_summary returns safe structure metadata without reading project content", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-project-summary-"));
  const directory = join(parent, "workspace");
  const sourceDirectory = join(directory, "src");
  await mkdir(join(directory, ".git"), { recursive: true });
  await mkdir(sourceDirectory, { recursive: true });
  await writeFile(join(directory, "package.json"), "{\"name\":\"safe\",\"token\":\"should-not-be-read\"}");
  await writeFile(join(sourceDirectory, "index.ts"), "const token = 'should-not-be-read';\n");
  await writeFile(join(directory, ".env"), "TOKEN=private-value");
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.project.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "project-summary-request",
      nonce: "project-summary-nonce",
      tool: "mac_project_summary",
      arguments: { project_root: directory, include_tree: true, tree_depth: 1 }
    }, ["mac.project.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as {
      project_root: string;
      vcs: { system: string; branch?: string; dirty?: boolean };
      manifests: string[];
      languages: string[];
      tree_entries: Array<{ path: string; type: string; depth: number }>;
      warnings: string[];
    };
    assert.equal(data.project_root, await realpath(directory));
    assert.deepEqual(data.vcs, { system: "git" });
    assert.deepEqual(data.manifests, ["package.json"]);
    assert.deepEqual(data.languages, ["javascript", "typescript"]);
    const envPath = await realpath(join(directory, ".env"));
    const sourcePath = await realpath(join(sourceDirectory, "index.ts"));
    assert.equal(data.tree_entries.some((entry) => entry.path === envPath), false);
    assert.equal(data.tree_entries.some((entry) => entry.path === sourcePath && entry.depth === 1), true);
    assert.equal(data.warnings.some((warning) => warning.includes("branch and dirty state")), true);
    assert.equal(result.truncated, false);
    assert.equal(JSON.stringify(result).includes("should-not-be-read"), false);
    assert.equal(JSON.stringify(result).includes("private-value"), false);
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_storage_analysis returns bounded capacity and ranked metadata consumers", async () => {
  const parent = await mkdtemp(join(tmpdir(), "mac-operator-broker-storage-analysis-"));
  const directory = join(parent, "workspace");
  const nested = join(directory, "nested");
  await mkdir(nested, { recursive: true });
  await mkdir(join(directory, ".ssh"), { recursive: true });
  await writeFile(join(directory, "small.txt"), "small");
  await writeFile(join(nested, "large.bin"), "0123456789abcdef");
  await writeFile(join(directory, ".ssh", "id_rsa"), "PRIVATE-KEY-MATERIAL");
  const store = new BrokerStore(join(parent, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.storage.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    const request = unsigned({
      requestId: "storage-analysis-request",
      nonce: "storage-analysis-nonce",
      tool: "mac_storage_analysis",
      arguments: { roots: [directory], top_n: 10, max_depth: 2 }
    }, ["mac.storage.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as {
      volumes: Array<{ id: string; mount_path: string; total_bytes: number; available_bytes: number; used_bytes: number }>;
      consumers: Array<{ path: string; size_bytes: number; type: string }>;
      analyzed_roots: string[];
    };
    assert.equal(data.analyzed_roots[0], await realpath(directory));
    assert.ok(data.volumes.length >= 1);
    assert.equal(data.volumes.every((volume) => volume.total_bytes >= volume.available_bytes && volume.total_bytes >= volume.used_bytes), true);
    assert.equal(data.consumers.length <= 10, true);
    const largePath = await realpath(join(nested, "large.bin"));
    assert.equal(data.consumers.some((consumer) => consumer.path === largePath), true);
    assert.equal(data.consumers.some((consumer) => consumer.path.includes(".ssh")), false);
    assert.equal(JSON.stringify(result).includes("PRIVATE-KEY-MATERIAL"), false);
    assert.equal(store.auditRows().some((row) => JSON.stringify(row).includes("PRIVATE-KEY-MATERIAL")), false);
  } finally {
    store.close();
    await rm(parent, { recursive: true, force: true });
  }
});

test("mac_write_file_atomic requires a bound approval and verifies atomic readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-write-"));
  const path = join(directory, "written.txt");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: true, write: true, denyRelativePaths: [] } as const;
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.files.write", "mac.job.read"], ["edge-key-1"], [root]);
  const writeTool = basePolicy.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_write_file_atomic", { ...writeTool, enabled: true })
  };
  const broker = new Broker({ store, policy, edgeAuthenticationKeys: testKeyring(key), now: () => NOW });
  try {
    const argumentsValue = { path, content: "safe", idempotency_key: "write-test-1", encoding: "utf8", create_only: true };
    const unsignedRequest = unsigned({
      requestId: "write-request",
      nonce: "write-nonce",
      tool: "mac_write_file_atomic",
      arguments: argumentsValue
    }, ["mac.files.write", "mac.job.read"]);
    const unapproved = await broker.handle(signRequest(unsignedRequest, key));
    assert.equal(unapproved.result_class, "POLICY_DENIED");
    assert.equal(store.requestRecord("write-request")?.state, "FAILED");

    store.issueApproval({
      approvalId: "approval:write",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const approvedRequest = { ...unsignedRequest, requestId: "write-approved-request", nonce: "write-approved-nonce" };
    const approved = await broker.handle(signRequest(approvedRequest, key));
    assert.equal(approved.ok, true, JSON.stringify(approved));
    if (approved.ok) {
      const data = approved.data as { path: string; job_id: string; bytes_written: number; sha256: string; created: boolean; precondition: { matched: boolean; create_only: boolean } };
      assert.equal(data.path, await realpath(path));
      assert.equal(data.bytes_written, 4);
      assert.equal(data.created, true);
      assert.equal(data.precondition.matched, true);
      assert.equal(data.precondition.create_only, true);
      assert.equal(approved.verification.status, "verified");
      assert.equal(store.requestRecord("write-approved-request")?.jobId, data.job_id);
    }
    assert.equal(await readFile(path, "utf8"), "safe");
    assert.equal(store.approvalRecord("approval:write")?.usedCount, 1);
    assert.deepEqual(store.auditRows().filter((row) => row.request_id === "write-approved-request").map((row) => [row.event_type, row.target_ref]), [
      ["decision", "path:test-root"],
      ["intent", "path:test-root"],
      ["completion", `path:${await realpath(path)}`]
    ]);

    store.issueApproval({
      approvalId: "approval:write-retry",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const retryRequest = { ...unsignedRequest, requestId: "write-retry-request", nonce: "write-retry-nonce" };
    const retry = await broker.handle(signRequest(retryRequest, key));
    assert.equal(retry.ok, true);
    if (retry.ok && approved.ok) {
      assert.equal((retry.data as { job_id: string }).job_id, (approved.data as { job_id: string }).job_id);
    }
    const statusRequest = unsigned({
      requestId: "write-status-request",
      nonce: "write-status-nonce",
      tool: "mac_job_status",
      arguments: { job_id: (approved.data as { job_id: string }).job_id, tail_bytes: 1024 }
    }, ["mac.job.read"]);
    const status = await broker.handle(signRequest(statusRequest, key));
    assert.equal(status.ok, true);
    if (status.ok) {
      assert.equal((status.data as { state: string }).state, "completed");
      assert.match((status.data as { stdout: string }).stdout, /bytes_written/u);
    }
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("mac_apply_patch requires project write scopes, approval, and bounded readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-patch-"));
  const projectRoot = await realpath(directory);
  const path = join(projectRoot, "README.txt");
  await writeFile(path, "before\n", { mode: 0o600 });
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: projectRoot, metadata: true, contentRead: true, write: true, denyRelativePaths: [] } as const;
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.files.write", "mac.project.write", "mac.job.read"], ["edge-key-1"], [root], [], [], [projectRoot]);
  const patchTool = basePolicy.tools.get("mac_apply_patch");
  assert.ok(patchTool);
  const policy = { ...basePolicy, tools: new Map(basePolicy.tools).set("mac_apply_patch", { ...patchTool, enabled: true }) };
  const broker = new Broker({ store, policy, edgeAuthenticationKeys: testKeyring(key), now: () => NOW });
  try {
    const patchText = ["*** Begin Patch", "*** Update File: README.txt", "@@", "-before", "+after", "*** End Patch", ""].join("\n");
    const argumentsValue = { project_root: projectRoot, patch: patchText };
    const unsignedRequest = unsigned({ requestId: "patch-request", nonce: "patch-nonce", tool: "mac_apply_patch", arguments: argumentsValue }, ["mac.files.write", "mac.project.write", "mac.job.read"]);
    const unapproved = await broker.handle(signRequest(unsignedRequest, key));
    assert.equal(unapproved.result_class, "POLICY_DENIED");
    store.issueApproval({
      approvalId: "approval:patch",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_apply_patch",
      contractVersion: "0.1",
      targetKind: "project",
      targetRef: `project:${projectRoot}`,
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const approvedRequest = { ...unsignedRequest, requestId: "patch-approved-request", nonce: "patch-approved-nonce" };
    const approved = await broker.handle(signRequest(approvedRequest, key));
    assert.equal(approved.ok, true, JSON.stringify(approved));
    if (approved.ok) {
      const data = approved.data as { project_root: string; result: string; changed_paths: string[]; files: Array<{ path: string; sha256: string; size_bytes: number }>; job_id: string };
      assert.equal(data.project_root, projectRoot);
      assert.equal(data.result, "applied");
      assert.deepEqual(data.changed_paths, ["README.txt"]);
      assert.equal(data.files[0]?.path, await realpath(path));
      assert.equal(data.files[0]?.size_bytes, 6);
      assert.equal(store.requestRecord("patch-approved-request")?.jobId, data.job_id);
      assert.equal(approved.verification.status, "verified");
    }
    assert.equal(await readFile(path, "utf8"), "after\n");
    assert.deepEqual(store.auditRows().filter((row) => row.request_id === "patch-approved-request").map((row) => [row.event_type, row.target_ref]), [
      ["decision", `project:${projectRoot}`],
      ["intent", `project:${projectRoot}`],
      ["completion", `project:${projectRoot}`]
    ]);
  } finally {
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("unknown write status probes the postcondition but never infers Broker success", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-write-recovery-status-"));
  const path = join(directory, "recovered.txt");
  const content = Buffer.from("safe");
  await writeFile(path, content, { mode: 0o600 });
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] } as const;
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.job.read"], ["edge-key-1"], [root]);
  const writeTool = basePolicy.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_write_file_atomic", { ...writeTool, enabled: true })
  };
  const argumentsValue = { path, content: content.toString("utf8"), idempotency_key: "recovery-status", encoding: "utf8", create_only: true };
  const job = store.createJob({
    jobId: "job:write-recovery-status",
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_write_file_atomic",
    targetRef: "path:test-root",
    policyVersion: "policy-0.1",
    payloadDigest: sha256(canonicalJson(argumentsValue)),
    idempotencyKey: "recovery-status",
    createdAtMs: NOW - 2_000,
    writeMetadata: {
      rootId: "test-root",
      path,
      bytes: content.length,
      desiredSha256: sha256(content),
      expectedSha256: null,
      createOnly: true
    }
  }).job;
  store.startJob(job.jobId, "principal-1", job.revision, NOW - 1_000);
  store.finishJob(job.jobId, "principal-1", job.revision + 1, {
    state: "unknown",
    resultClass: "unknown",
    finishedAtMs: NOW - 500
  });
  const broker = new Broker({ store, policy, edgeAuthenticationKeys: testKeyring(key), now: () => NOW });
  try {
    const request = unsigned({
      requestId: "write-recovery-status-request",
      nonce: "write-recovery-status-nonce",
      tool: "mac_job_status",
      arguments: { job_id: job.jobId, tail_bytes: 128 }
    }, ["mac.job.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, true, JSON.stringify(result));
    assert.ok(result.ok);
    const data = result.data as { state: string; recovery?: { postcondition: string; resolution: string } };
    assert.equal(data.state, "unknown");
    assert.deepEqual(data.recovery, { postcondition: "matches", resolution: "remains_unknown", observed_at: new Date(NOW).toISOString() });
    assert.equal(store.ownedJob(job.jobId, "principal-1")?.state, "unknown");
    assert.equal(JSON.stringify(result).includes("safe"), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("write completion failure leaves an atomic postcondition and an UNKNOWN Job", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-write-crash-window-"));
  const path = join(directory, "crash-window.txt");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] } as const;
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.files.write", "mac.job.read"], ["edge-key-1"], [root]);
  const writeTool = basePolicy.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_write_file_atomic", { ...writeTool, enabled: true })
  };
  const content = "after";
  const argumentsValue = { path, content, idempotency_key: "crash-window", encoding: "utf8", create_only: true };
  const executor: FilesystemExecutor = {
    stat: async () => { throw new Error("Unexpected stat"); },
    read: async () => { throw new Error("Unexpected read"); },
    write: async (plan, requestedContent, expectedSha256, createOnly, _control, temporaryName) => {
      assert.match(temporaryName ?? "", /^\.mac-operator-write-[A-Za-z0-9._-]{1,96}$/u);
      const committed = new FilesystemInspector([root]).writePlanned(
        plan,
        requestedContent,
        expectedSha256,
        createOnly,
        temporaryName!
      );
      assert.equal(committed.sha256, sha256(requestedContent));
      throw new Error("simulated completion persistence crash");
    }
  };
  const broker = new Broker({ store, policy, edgeAuthenticationKeys: testKeyring(key), filesystemExecutor: executor, now: () => NOW });
  try {
    store.issueApproval({
      approvalId: "approval:crash-window",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const request = unsigned({
      requestId: "write-crash-window-request",
      nonce: "write-crash-window-nonce",
      tool: "mac_write_file_atomic",
      arguments: argumentsValue
    }, ["mac.files.write", "mac.job.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "EXECUTION_FAILED");
    const jobId = store.requestRecord(request.requestId)?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "unknown");
    assert.equal(await readFile(path, "utf8"), content);

    const statusRequest = unsigned({
      requestId: "write-crash-window-status",
      nonce: "write-crash-window-status-nonce",
      tool: "mac_job_status",
      arguments: { job_id: jobId, tail_bytes: 128 }
    }, ["mac.job.read"]);
    const status = await broker.handle(signRequest(statusRequest, key));
    assert.equal(status.ok, true, JSON.stringify(status));
    assert.ok(status.ok);
    assert.deepEqual((status.data as { recovery?: unknown }).recovery, {
      postcondition: "matches",
      resolution: "remains_unknown",
      observed_at: new Date(NOW).toISOString()
    });
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("real filesystem worker failure leaves the Broker write Job UNKNOWN", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-write-worker-failure-"));
  const path = join(directory, "worker-failure.txt");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] } as const;
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.files.write", "mac.job.read"], ["edge-key-1"], [root]);
  const writeTool = basePolicy.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_write_file_atomic", { ...writeTool, enabled: true })
  };
  const argumentsValue = { path, content: "after", idempotency_key: "worker-failure", encoding: "utf8", create_only: true };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    filesystemExecutor: new WorkerFilesystemExecutor(1),
    now: () => NOW
  });
  try {
    store.issueApproval({
      approvalId: "approval:worker-failure",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    // Authorization and plan capture still succeed, but the worker cannot
    // create its temporary file after the parent directory becomes read-only.
    await chmod(directory, 0o500);
    const request = unsigned({
      requestId: "write-worker-failure-request",
      nonce: "write-worker-failure-nonce",
      tool: "mac_write_file_atomic",
      arguments: argumentsValue
    }, ["mac.files.write", "mac.job.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "POLICY_DENIED");
    const jobId = store.requestRecord(request.requestId)?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "unknown");
    await assert.rejects(readFile(path), /ENOENT/u);

    const statusRequest = unsigned({
      requestId: "write-worker-failure-status",
      nonce: "write-worker-failure-status-nonce",
      tool: "mac_job_status",
      arguments: { job_id: jobId, tail_bytes: 128 }
    }, ["mac.job.read"]);
    const status = await broker.handle(signRequest(statusRequest, key));
    assert.equal(status.ok, true, JSON.stringify(status));
    assert.ok(status.ok);
    assert.deepEqual((status.data as { state: string; recovery?: unknown }).recovery, {
      postcondition: "unavailable",
      resolution: "remains_unknown",
      observed_at: new Date(NOW).toISOString()
    });
  } finally {
    await chmod(directory, 0o700);
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("real filesystem worker post-rename failure leaves the Broker write Job UNKNOWN", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-write-worker-post-rename-"));
  const path = join(directory, "worker-post-rename.txt");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] } as const;
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.files.write", "mac.job.read"], ["edge-key-1"], [root]);
  const writeTool = basePolicy.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_write_file_atomic", { ...writeTool, enabled: true })
  };
  const argumentsValue = { path, content: "after", idempotency_key: "worker-post-rename", encoding: "utf8", create_only: true };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    filesystemExecutor: new WorkerFilesystemExecutor(1, {
      workerUrl: new URL("./filesystem-fault-worker.js", import.meta.url)
    }),
    now: () => NOW
  });
  try {
    store.issueApproval({
      approvalId: "approval:worker-post-rename",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const request = unsigned({
      requestId: "write-worker-post-rename-request",
      nonce: "write-worker-post-rename-nonce",
      tool: "mac_write_file_atomic",
      arguments: argumentsValue
    }, ["mac.files.write", "mac.job.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "POLICY_DENIED");
    const jobId = store.requestRecord(request.requestId)?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "unknown");
    assert.equal(await readFile(path, "utf8"), "after");

    const statusRequest = unsigned({
      requestId: "write-worker-post-rename-status",
      nonce: "write-worker-post-rename-status-nonce",
      tool: "mac_job_status",
      arguments: { job_id: jobId, tail_bytes: 128 }
    }, ["mac.job.read"]);
    const status = await broker.handle(signRequest(statusRequest, key));
    assert.equal(status.ok, true, JSON.stringify(status));
    assert.ok(status.ok);
    assert.deepEqual((status.data as { state: string; recovery?: unknown }).recovery, {
      postcondition: "matches",
      resolution: "remains_unknown",
      observed_at: new Date(NOW).toISOString()
    });
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("real filesystem worker crash after commit leaves the Broker write Job UNKNOWN", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-write-worker-crash-"));
  const path = join(directory, "worker-crash.txt");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] } as const;
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.files.write", "mac.job.read"], ["edge-key-1"], [root]);
  const writeTool = basePolicy.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_write_file_atomic", { ...writeTool, enabled: true })
  };
  const argumentsValue = { path, content: "crashed", idempotency_key: "worker-crash", encoding: "utf8", create_only: true };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    filesystemExecutor: new WorkerFilesystemExecutor(1, {
      workerUrl: new URL("./filesystem-crash-worker.js", import.meta.url)
    }),
    now: () => NOW
  });
  try {
    store.issueApproval({
      approvalId: "approval:worker-crash",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const request = unsigned({
      requestId: "write-worker-crash-request",
      nonce: "write-worker-crash-nonce",
      tool: "mac_write_file_atomic",
      arguments: argumentsValue
    }, ["mac.files.write", "mac.job.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "EXECUTION_FAILED");
    const jobId = store.requestRecord(request.requestId)?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "unknown");
    assert.equal(await readFile(path, "utf8"), "crashed");

    const statusRequest = unsigned({
      requestId: "write-worker-crash-status",
      nonce: "write-worker-crash-status-nonce",
      tool: "mac_job_status",
      arguments: { job_id: jobId, tail_bytes: 128 }
    }, ["mac.job.read"]);
    const status = await broker.handle(signRequest(statusRequest, key));
    assert.equal(status.ok, true, JSON.stringify(status));
    assert.ok(status.ok);
    assert.deepEqual((status.data as { state: string; recovery?: unknown }).recovery, {
      postcondition: "matches",
      resolution: "remains_unknown",
      observed_at: new Date(NOW).toISOString()
    });
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("reopened Broker rejects a stale completion from the prior Broker instance", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-stale-completion-"));
  const databasePath = join(directory, "broker.sqlite");
  const path = join(directory, "stale-completion.txt");
  const store = new BrokerStore(databasePath);
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] } as const;
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.files.write", "mac.job.read"], ["edge-key-1"], [root]);
  const writeTool = basePolicy.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_write_file_atomic", { ...writeTool, enabled: true })
  };
  let startedResolve!: () => void;
  let releaseWrite: ((value: FilesystemWorkerResult) => void) | undefined;
  const writeStarted = new Promise<void>((resolve) => { startedResolve = resolve; });
  const delayedExecutor = {
    write: async () => {
      startedResolve();
      return await new Promise<FilesystemWorkerResult>((resolve) => { releaseWrite = resolve; });
    },
    close: async () => {}
  } as unknown as FilesystemExecutor;
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: testKeyring(key),
    filesystemExecutor: delayedExecutor,
    now: () => NOW
  });
  let restartedStore: BrokerStore | undefined;
  let restartedBroker: Broker | undefined;
  try {
    const argumentsValue = { path, content: "stale", idempotency_key: "stale-completion", encoding: "utf8", create_only: true };
    store.issueApproval({
      approvalId: "approval:stale-completion",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const request = unsigned({
      requestId: "stale-completion-request",
      nonce: "stale-completion-nonce",
      tool: "mac_write_file_atomic",
      arguments: argumentsValue
    }, ["mac.files.write", "mac.job.read"]);
    const priorResult = broker.handle(signRequest(request, key));
    await writeStarted;
    const jobId = store.requestRecord(request.requestId)?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "running");

    restartedStore = new BrokerStore(databasePath);
    assert.equal(restartedStore.ownedJob(jobId, "principal-1")?.state, "unknown");
    restartedBroker = new Broker({
      store: restartedStore,
      policy,
      edgeAuthenticationKeys: testKeyring(key),
      filesystemExecutor: delayedExecutor,
      now: () => NOW
    });
    releaseWrite?.({
      operation: "write",
      path,
      bytesWritten: 5,
      sha256: sha256(Buffer.from("stale")),
      created: true,
      expectedSha256: null,
      expectedMatched: true,
      rootId: "test-root",
      device: "device:test",
      inode: "inode:test"
    });
    const priorResultValue = await priorResult;
    assert.equal(priorResultValue.ok, false, JSON.stringify(priorResultValue));
    assert.equal(restartedStore.ownedJob(jobId, "principal-1")?.state, "unknown");

    const statusRequest = unsigned({
      requestId: "stale-completion-status",
      nonce: "stale-completion-status-nonce",
      tool: "mac_job_status",
      arguments: { job_id: jobId, tail_bytes: 128 }
    }, ["mac.job.read"]);
    const status = await restartedBroker.handle(signRequest(statusRequest, key));
    assert.equal(status.ok, true, JSON.stringify(status));
    assert.ok(status.ok);
    assert.equal((status.data as { state: string }).state, "unknown");
  } finally {
    await broker.close();
    await restartedBroker?.close();
    restartedStore?.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("restart write recovery cleans only the recorded temporary artifact", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-write-cleanup-"));
  const databasePath = join(directory, "broker.sqlite");
  const target = join(directory, "target.txt");
  const temporaryName = ".mac-operator-write-restart-cleanup";
  const temporaryPath = join(directory, temporaryName);
  await writeFile(temporaryPath, "orphan", { mode: 0o600 });
  let store = new BrokerStore(databasePath);
  store.createJob({
    jobId: "job:write-cleanup",
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: "mac_write_file_atomic",
    targetRef: "path:test-root",
    policyVersion: "policy-0.1",
    payloadDigest: "a".repeat(64),
    idempotencyKey: "write-cleanup",
    createdAtMs: 1,
    writeMetadata: {
      rootId: "test-root",
      path: target,
      bytes: 6,
      desiredSha256: sha256(Buffer.from("orphan")),
      expectedSha256: null,
      createOnly: true,
      temporaryName
    }
  });
  store.startJob("job:write-cleanup", "principal-1", 0, 2);
  store.close();
  store = new BrokerStore(databasePath);
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] } as const;
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.write", "mac.job.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    now: () => NOW
  });
  try {
    assert.deepEqual(broker.reconcileRestartedWriteArtifacts(), { inspected: 1, removed: 1, absent: 0, skipped: 0 });
    await assert.rejects(readFile(temporaryPath), /ENOENT/u);
    assert.deepEqual(
      store.auditRows().filter((row) => row.tool === "internal_write_temporary_cleanup").map((row) => [row.event_type, row.result_class]),
      [["intent", "INTENT_RECORDED"], ["completion", "TEMPORARY_REMOVED"]]
    );
    assert.deepEqual(broker.reconcileRestartedWriteArtifacts(), { inspected: 1, removed: 0, absent: 1, skipped: 0 });
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Broker marks a filesystem mutation UNKNOWN when the mutations kill switch trips during execution", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-active-kill-switch-"));
  const path = join(directory, "kill-switch.txt");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: false, write: true, denyRelativePaths: [] } as const;
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.files.write", "mac.job.read"], ["edge-key-1"], [root]);
  const writeTool = basePolicy.tools.get("mac_write_file_atomic");
  assert.ok(writeTool);
  const policy = {
    ...basePolicy,
    tools: new Map(basePolicy.tools).set("mac_write_file_atomic", { ...writeTool, enabled: true })
  };
  const content = "after-kill-switch";
  const argumentsValue = { path, content, idempotency_key: "active-kill-switch", encoding: "utf8", create_only: true };
  const executor: FilesystemExecutor = {
    stat: async () => { throw new Error("Unexpected stat"); },
    read: async () => { throw new Error("Unexpected read"); },
    write: async (_plan, _content, _expectedSha256, _createOnly, control) => {
      store.setSwitch("mutations", true, "active-test", NOW);
      assert.equal(control.shouldCancel(), true);
      return {
        operation: "write",
        path,
        bytesWritten: content.length,
        sha256: sha256(content),
        created: true,
        expectedSha256: null,
        expectedMatched: true,
        rootId: "test-root",
        device: "1",
        inode: "1"
      };
    }
  };
  const broker = new Broker({ store, policy, edgeAuthenticationKeys: testKeyring(key), filesystemExecutor: executor, now: () => NOW });
  try {
    store.issueApproval({
      approvalId: "approval:active-kill-switch",
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: "mac_write_file_atomic",
      contractVersion: "0.1",
      targetKind: "path",
      targetRef: "path:test-root",
      payloadDigest: sha256(canonicalJson(argumentsValue)),
      policyVersion: "policy-0.1",
      approvalClass: "trusted_write",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 1_000
    });
    const request = unsigned({
      requestId: "active-kill-switch-request",
      nonce: "active-kill-switch-nonce",
      tool: "mac_write_file_atomic",
      arguments: argumentsValue
    }, ["mac.files.write", "mac.job.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "CANCELLED");
    const jobId = store.requestRecord(request.requestId)?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "unknown");
    assert.deepEqual(store.auditRows().filter((row) => row.request_id === request.requestId).map((row) => [row.event_type, row.result_class]), [
      ["decision", "AUTHORIZED"],
      ["intent", "INTENT_RECORDED"],
      ["completion", "CANCELLED"]
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Broker discards a filesystem result when session authority is revoked during execution", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-broker-active-revoke-"));
  const path = join(directory, "sample.txt");
  await writeFile(path, "hello", { mode: 0o600 });
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const root = { rootId: "test-root", path: directory, metadata: true, contentRead: true, denyRelativePaths: [] } as const;
  const executor: FilesystemExecutor = {
    stat: async () => { throw new Error("Unexpected stat"); },
    read: async (_plan, _offset, _maxBytes, encoding, control) => {
      store.revoke("session", "session-1", "active-test", NOW);
      assert.equal(control.shouldCancel(), true);
      return {
        operation: "read",
        path,
        encoding,
        content: "hello",
        sizeBytes: 5,
        sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        truncated: false,
        rootId: "test-root",
        device: "1",
        inode: "1",
        bytesReturned: 5
      };
    }
  };
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1", true, ["mac.files.read"], ["edge-key-1"], [root]),
    edgeAuthenticationKeys: testKeyring(key),
    filesystemExecutor: executor,
    now: () => NOW
  });
  try {
    const request = unsigned({ tool: "mac_read_file", arguments: { path } }, ["mac.files.read"]);
    const result = await broker.handle(signRequest(request, key));
    assert.equal(result.ok, false);
    assert.equal(result.result_class, "CANCELLED");
    assert.deepEqual(store.auditRows().filter((row) => row.request_id === request.requestId).map((row) => [row.event_type, row.result_class]), [
      ["decision", "AUTHORIZED"],
      ["completion", "CANCELLED"]
    ]);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit evidence redacts secret-bearing fields recursively", () => {
  assert.deepEqual(
    redactEvidence({ token: "secret-value", nested: { password: "hunter2", safe: "ok" } }),
    { token: "[REDACTED]", nested: { password: "[REDACTED]", safe: "ok" } }
  );
});

function testKeyring(key: Buffer): EdgeKeyring {
  return new EdgeKeyring([{
    edgeId: "edge-1", keyId: "edge-key-1", key,
    notBeforeMs: NOW - 60_000, expiresAtMs: NOW + 60_000
  }]);
}
