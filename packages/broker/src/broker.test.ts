import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import type { FilesystemExecutor } from "./filesystem-executor.js";
import { BrokerStore, redactEvidence } from "./persistence.js";

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

test("authorized health request succeeds and writes decision plus completion audit", async () => {
  const context = await fixture();
  try {
    const result = await context.broker.handle(signRequest(unsigned(), context.key));
    assert.equal(result.ok, true);
    assert.equal(context.store.requestRecord("request-1")?.state, "SUCCEEDED");
    assert.equal(context.store.auditRows().length, 2);
  } finally { await context.close(); }
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
        name: "mac_health", enabled: true, scopes: ["mac.control.read"], reason: "enabled"
      });
      assert.deepEqual(capabilities.find((tool) => tool.name === "mac_policy_explain"), {
        name: "mac_policy_explain", enabled: false, scopes: ["mac.policy.explain"], reason: "scope_not_granted"
      });
      assert.deepEqual(capabilities.find((tool) => tool.name === "mac_task_run"), {
        name: "mac_task_run", enabled: false, scopes: [], reason: "not_implemented"
      });
    }
  } finally { await context.close(); }
});

test("production-default policy enables no tool or filesystem root", () => {
  const policy = createDefaultPolicy("edge-1");
  assert.equal([...policy.tools.values()].filter((tool) => tool.enabled).length, 0);
    assert.equal([...policy.tools.values()].filter((tool) => tool.implemented).length, 18);
  assert.deepEqual(policy.filesystemRoots, []);
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
    assert.deepEqual(store.auditRows().map((row) => [row.event_type, row.result_class]), [
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
