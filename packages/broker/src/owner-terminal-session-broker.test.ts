import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { signRequest, type BrokerResult, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import { OwnerTerminalSessionManager } from "./owner-terminal-session.js";

const supported = process.platform === "darwin" && process.getuid?.() !== 0;

async function until(check: () => Promise<boolean> | boolean, ms = 15_000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error("condition not reached");
    await delay(50);
  }
}

test("Broker owner terminal sessions: delegated per-call authority, owner binding, redaction, stop and revocation", { skip: !supported }, async () => {
  const root = await realpath(await mkdtemp("/tmp/owner-session-broker-"));
  const store = new BrokerStore(join(root, "broker.sqlite"), { runtimeFence: true });
  const key = randomBytes(32);
  const base = createDefaultPolicy("edge-1", true, ["mac.terminal.exec", "mac.control.read"], ["edge-key-1"]);
  const rule = (principalId: string) => ({ ruleId: `owner-terminal-${principalId}`, effect: "allow" as const, principalId,
    scope: "mac.terminal.exec" as const, target: { kind: "host" as const, reference: "owner-terminal" } });
  const grant = base.principalGrants.get("principal-1")!;
  const policy = { ...base, principalGrants: new Map(base.principalGrants).set("principal-2", { ...grant, ...("principalId" in grant ? { principalId: "principal-2" } : {}) }), killSwitches: { ...base.killSwitches, mutations: false },
    tools: new Map(base.tools).set("mac_terminal_session", { ...base.tools.get("mac_terminal_session")!, enabled: true }),
    targetRules: [...base.targetRules, rule("principal-1"), rule("principal-2")] };
  let delegations = 0;
  const operations: { tool: string; timeoutMs: number }[] = [];
  let delegate = true;
  const broker = new Broker({ store, policy, ownerTerminalSessions: new OwnerTerminalSessionManager({ enabled: true }),
    edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: Date.now() - 60000, expiresAtMs: Date.now() + 300000 }]),
    authorizeOwnerTerminal: async operation => {
      if (!delegate) return false;
      delegations += 1;
      operations.push({ tool: operation.tool, timeoutMs: operation.timeoutMs });
      const now = Date.now();
      store.issueApproval({ approvalId: `approval:${operation.requestId}`, approverPrincipalId: "owner-delegate",
        requestingPrincipalId: operation.principalId, tool: operation.tool, contractVersion: operation.contractVersion,
        targetKind: operation.targetKind, targetRef: operation.targetRef, payloadDigest: operation.payloadDigest,
        policyVersion: operation.policyVersion, approvalClass: "trusted_profile", unattended: true,
        issuedAtMs: now, expiresAtMs: now + 30000, useLimit: 1 });
      return true;
    } });
  let sequence = 0;
  const call = (args: Record<string, unknown>, options: { principalId?: string; sessionId?: string; scopes?: UnsignedBrokerRequest["principal"]["scopes"] } = {}) => {
    const now = Date.now(); sequence += 1;
    const request: UnsignedBrokerRequest = { protocolVersion: "0.1", requestId: `session-req-${sequence}`, contractVersion: "0.1",
      tool: "mac_terminal_session", arguments: args, principal: { principalId: options.principalId ?? "principal-1", sessionId: options.sessionId ?? "session-1",
        issuer: "test-issuer", audience: "mac-operator-broker", scopes: options.scopes ?? ["mac.terminal.exec"], issuedAtMs: now - 1000,
        expiresAtMs: now + 120000, edgeId: "edge-1" },
      timestampMs: now, nonce: `session-nonce-${sequence}`, policyAudience: "mac-operator-broker", policyVersion: policy.version, authenticationKeyId: "edge-key-1" };
    return broker.handle(signRequest(request, key));
  };
  const require = createRequire(import.meta.url);
  const Ajv = require("ajv/dist/2020").default;
  const ajv = new Ajv({ strict: true, allErrors: true });
  require("ajv-formats").default(ajv);
  const contract = JSON.parse(await readFile(fileURLToPath(new URL("../../../tool-contracts/mac_terminal_session.json", import.meta.url)), "utf8"));
  const validate = ajv.compile(contract.output_schema);
  const data = (result: BrokerResult) => { assert.equal(result.ok, true, JSON.stringify(result)); assert.equal(validate(result), true, ajv.errorsText(validate.errors)); return (result as { data: Record<string, unknown> }).data; };
  try {
    assert.equal((await call({ action: "start", cwd: root, idempotency_key: "scope" }, { scopes: ["mac.control.read"] })).ok, false);
    delegate = false;
    assert.equal((await call({ action: "start", cwd: root, idempotency_key: "undelegated" })).ok, false);
    assert.equal(store.ownedJobByIdempotencyKey("undelegated", "principal-1"), undefined);
    delegate = true;

    const startRequestId = `session-req-${sequence + 1}`;
    const started = data(await call({ action: "start", cwd: root, idempotency_key: "interactive", rows: 30, cols: 100 }));
    const sessionId = started.session_id as string;
    assert.equal(started.state, "running");
    // The start approval is consumed by assertRequestApprovalActive for the whole session, so it must
    // be issued for the session lifetime rather than the short per-call window.
    assert.equal(operations.at(-1)!.timeoutMs, 300_000);
    const job = store.ownedJobByIdempotencyKey("interactive", "principal-1")!;
    assert.equal(job.jobId, started.job_id); assert.equal(job.state, "running"); assert.ok(job.processMetadata);

    assert.equal((await call({ action: "start", cwd: root, idempotency_key: "interactive", rows: 30, cols: 100 })).result_class, "CONFLICT");
    assert.equal((await call({ action: "start", cwd: root, idempotency_key: "interactive", rows: 31 })).result_class, "CONFLICT");

    const before = delegations;
    data(await call({ action: "write", session_id: sessionId, data: "stty size; read -r word; echo got:$word; printf marker > written\n" }));
    data(await call({ action: "write", session_id: sessionId, data: "hello\n" }));
    assert.equal(delegations, before + 2, "every write needs its own delegated approval");
    assert.equal(operations.at(-1)!.timeoutMs, 30_000);
    let cursor = 0; let output = "";
    await until(async () => {
      const read = data(await call({ action: "read", session_id: sessionId, cursor, wait_ms: 500 }));
      output += read.output as string; cursor = read.next_cursor as number;
      return output.includes("got:hello");
    });
    assert.match(output, /30 100/u);
    assert.equal(await readFile(join(root, "written"), "utf8"), "marker");

    assert.equal((await call({ action: "write", session_id: sessionId, data: "echo -----BEGIN OPENSSH PRIVATE KEY-----\n" })).ok, false);
    assert.equal((await call({ action: "write", session_id: sessionId, data: "x", cwd: root })).ok, false);
    assert.equal((await call({ action: "read", session_id: sessionId, cursor: 0 }, { principalId: "principal-2" })).ok, false);
    delegate = false;
    assert.equal((await call({ action: "write", session_id: sessionId, data: "echo denied > denied\n" })).ok, false);
    delegate = true;
    await assert.rejects(readFile(join(root, "denied")), { code: "ENOENT" });

    const stopped = data(await call({ action: "stop", session_id: sessionId }));
    assert.equal(stopped.finished, true);
    await until(() => store.ownedJob(job.jobId, "principal-1")?.state === "completed");
    assert.equal(store.ownedJob(job.jobId, "principal-1")?.processMetadata, undefined);
    // The start request stays open until the session ends, then records its completion.
    await until(() => store.auditEventExists(startRequestId, "completion"));
    assert.equal((await call({ action: "write", session_id: sessionId, data: "x\n" })).ok, false);

    const revoked = data(await call({ action: "start", cwd: root, idempotency_key: "revoked" }, { sessionId: "revoked-session" }));
    const revokedJob = store.ownedJobByIdempotencyKey("revoked", "principal-1")!;
    assert.equal(revokedJob.state, "running");
    store.revoke("session", "revoked-session", "OAUTH_AUTHORITY_REVOKED");
    await until(() => store.ownedJob(revokedJob.jobId, "principal-1")?.state === "cancelled", 20_000);
    assert.equal(store.ownedJob(revokedJob.jobId, "principal-1")?.processMetadata, undefined);
    assert.equal((await call({ action: "write", session_id: revoked.session_id, data: "x\n" }, { sessionId: "revoked-session" })).ok, false);

    const cancelled = data(await call({ action: "start", cwd: root, idempotency_key: "job-cancel" }));
    const cancelJob = store.ownedJobByIdempotencyKey("job-cancel", "principal-1")!;
    store.requestJobCancellation(cancelJob.jobId, "principal-1", "OWNER_CANCELLED", Date.now());
    await until(() => store.ownedJob(cancelJob.jobId, "principal-1")?.state === "cancelled", 20_000);
    assert.equal(typeof cancelled.session_id, "string");

    const idle = data(await call({ action: "start", cwd: root, idempotency_key: "idle", idle_timeout_ms: 1000, lifetime_ms: 60_000 }));
    const idleStart = `session-req-${sequence}`;
    const idleJob = store.ownedJobByIdempotencyKey("idle", "principal-1")!;
    await until(() => store.ownedJob(idleJob.jobId, "principal-1")?.state === "cancelled", 20_000);
    assert.equal(store.ownedJob(idleJob.jobId, "principal-1")?.processMetadata, undefined);
    assert.equal(store.ownedJob(idleJob.jobId, "principal-1")?.cancelRequested, true);
    await until(() => store.requestRecord(idleStart)?.state === "CANCELLED" || store.requestRecord(idleStart)?.state === "FAILED", 5_000);
    assert.equal((await call({ action: "read", session_id: idle.session_id, cursor: 0 })).ok, true);

    const lifetime = data(await call({ action: "start", cwd: root, idempotency_key: "lifetime", lifetime_ms: 1500, idle_timeout_ms: 1500 }));
    const lifetimeJob = store.ownedJobByIdempotencyKey("lifetime", "principal-1")!;
    for (let i = 0; i < 2; i += 1) { await delay(500); data(await call({ action: "write", session_id: lifetime.session_id, data: " \n" })); }
    await until(() => store.ownedJob(lifetimeJob.jobId, "principal-1")?.state === "failed", 20_000);
    assert.equal(store.ownedJob(lifetimeJob.jobId, "principal-1")?.processMetadata, undefined);
  } finally { await broker.close(); store.close(); key.fill(0); await rm(root, { recursive: true, force: true }); }
});
