import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import test from "node:test";
import { signRequest, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import { homedir } from "node:os";
import { PersonalOwnerTerminalExecutor, ownerTerminalPath, parseOwnerTerminalRequest } from "./owner-terminal.js";

const supported = process.platform === "darwin" && process.getuid?.() !== 0;

test("owner terminal validates authority fields and stays disabled without opt-in", async () => {
  const executor = new PersonalOwnerTerminalExecutor();
  try {
    assert.equal(executor.available, false);
    const valid = { command: "printf ok", cwd: "/tmp", idempotency_key: "test-1" };
    assert.throws(() => parseOwnerTerminalRequest({ ...valid, env: { TOKEN: "value" } }));
    assert.throws(() => parseOwnerTerminalRequest({ ...valid, cwd: "relative" }));
    assert.throws(() => parseOwnerTerminalRequest({ ...valid, timeout_ms: 120001 }));
    assert.throws(() => parseOwnerTerminalRequest({ ...valid, command: "" }));
  } finally { await executor.close(); }
});

test("owner shell runs pipelines, local CLIs and file writes after ownership is recorded", { skip: !supported }, async () => {
  const root = await realpath(await mkdtemp("/tmp/owner-terminal-test-"));
  const executor = new PersonalOwnerTerminalExecutor({ enabled: true });
  let recorded = false;
  const previous = process.env.OWNER_TERMINAL_SECRET_SENTINEL;
  process.env.OWNER_TERMINAL_SECRET_SENTINEL = "must-not-be-inherited";
  try {
    const request = parseOwnerTerminalRequest({ command: "printf payload > marker; cat marker | tr a-z A-Z; git --version; printf '\n%s' ${OWNER_TERMINAL_SECRET_SENTINEL-unset}", cwd: root, idempotency_key: "shell" });
    const result = await executor.run(request, { timeoutMs: 30000, shouldCancel: () => false,
      onProcessStarted: () => { recorded = true; } });
    assert.equal(recorded, true);
    assert.equal(result.state, "completed", JSON.stringify(result));
    assert.match(result.stdout, /^PAYLOADgit version .*\n\nunset$/u);
    assert.equal(await readFile(join(root, "marker"), "utf8"), "payload");
    const pathResult = await executor.run({ ...request, command: "printf %s \"$PATH\"" }, { timeoutMs: 30000, shouldCancel: () => false });
    assert.equal(pathResult.stdout, ownerTerminalPath(homedir()));
    assert.ok(pathResult.stdout.endsWith("/.local/bin"));
    const failure = await executor.run({ ...request, command: "exit 7" }, { timeoutMs: 30000, shouldCancel: () => false });
    assert.equal(failure.exitCode, 7);
    assert.equal(failure.state, "failed");
    const denied = { ...request, command: "printf forbidden > denied" };
    await assert.rejects(executor.run(denied, { timeoutMs: 30000, shouldCancel: () => false,
      onProcessStarted: () => { throw new Error("audit unavailable"); } }));
    await assert.rejects(readFile(join(root, "denied")), { code: "ENOENT" });
    const timed = await executor.run({ ...request, command: "sleep 2; printf late > late", timeoutMs: 150 },
      { timeoutMs: 150, shouldCancel: () => false });
    assert.equal(timed.state, "timed_out", JSON.stringify(timed));
    assert.equal(timed.terminationObserved, true);
    await assert.rejects(readFile(join(root, "late")), { code: "ENOENT" });
  } finally {
    if (previous === undefined) delete process.env.OWNER_TERMINAL_SECRET_SENTINEL;
    else process.env.OWNER_TERMINAL_SECRET_SENTINEL = previous;
    await executor.close(); await rm(root, { recursive: true, force: true });
  }
});

test("Broker owner terminal requires scope and delegation, audits before execution, and reuses results", { skip: !supported }, async () => {
  const root = await realpath(await mkdtemp("/tmp/owner-terminal-broker-"));
  const store = new BrokerStore(join(root, "broker.sqlite"), { runtimeFence: true });
  const key = randomBytes(32);
  const base = createDefaultPolicy("edge-1", true, ["mac.terminal.exec", "mac.control.read"], ["edge-key-1"]);
  const policy = { ...base, killSwitches: { ...base.killSwitches, mutations: false },
    tools: new Map(base.tools).set("mac_terminal_exec", { ...base.tools.get("mac_terminal_exec")!, enabled: true }),
    targetRules: [...base.targetRules, { ruleId: "owner-terminal", effect: "allow" as const, principalId: "principal-1",
      scope: "mac.terminal.exec" as const, target: { kind: "host" as const, reference: "owner-terminal" } }] };
  let delegate = true;
  const broker = new Broker({ store, policy, ownerTerminalExecutor: new PersonalOwnerTerminalExecutor({ enabled: true }),
    edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: Date.now() - 60000, expiresAtMs: Date.now() + 300000 }]),
    authorizeOwnerTerminal: async operation => {
      if (!delegate) return false;
      const now = Date.now();
      store.issueApproval({ approvalId: `approval:${operation.requestId}`, approverPrincipalId: "owner-delegate",
        requestingPrincipalId: operation.principalId, tool: operation.tool, contractVersion: operation.contractVersion,
        targetKind: operation.targetKind, targetRef: operation.targetRef, payloadDigest: operation.payloadDigest,
        policyVersion: operation.policyVersion, approvalClass: "trusted_profile", unattended: true,
        issuedAtMs: now, expiresAtMs: now + 30000, useLimit: 1 });
      return true;
    } });
  let sequence = 0;
  const args = { command: "printf once >> counter; printf verified", cwd: root, idempotency_key: "same-operation" };
  const call = (argumentsValue = args, scopes: UnsignedBrokerRequest["principal"]["scopes"] = ["mac.terminal.exec"], sessionId = "session-1") => {
    const now = Date.now(); sequence += 1;
    const request: UnsignedBrokerRequest = { protocolVersion: "0.1", requestId: `terminal-${sequence}`, contractVersion: "0.1",
      tool: "mac_terminal_exec", arguments: argumentsValue, principal: { principalId: "principal-1", sessionId, issuer: "test-issuer",
        audience: "mac-operator-broker", scopes, issuedAtMs: now - 1000, expiresAtMs: now + 120000, edgeId: "edge-1" },
      timestampMs: now, nonce: `terminal-nonce-${sequence}`, policyAudience: "mac-operator-broker", policyVersion: policy.version, authenticationKeyId: "edge-key-1" };
    return broker.handle(signRequest(request, key));
  };
  try {
    for (const terminalScopeGranted of [true, false]) {
      const now = Date.now();
      const request: UnsignedBrokerRequest = { protocolVersion: "0.1", requestId: `capabilities-${terminalScopeGranted}`, contractVersion: "0.1",
        tool: "mac_capabilities", arguments: {}, principal: { principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer",
          audience: "mac-operator-broker", scopes: terminalScopeGranted ? ["mac.control.read", "mac.terminal.exec"] : ["mac.control.read"],
          issuedAtMs: now - 1000, expiresAtMs: now + 120000, edgeId: "edge-1" },
        timestampMs: now, nonce: `capabilities-nonce-${terminalScopeGranted}`, policyAudience: "mac-operator-broker",
        policyVersion: policy.version, authenticationKeyId: "edge-key-1" };
      const capabilities = await broker.handle(signRequest(request, key));
      assert.equal(capabilities.ok, true, JSON.stringify(capabilities));
      if (capabilities.ok) {
        const terminal = (capabilities.data as { capabilities: { name: string; enabled: boolean; reason: string }[] }).capabilities
          .find(capability => capability.name === "mac_terminal_exec");
        assert.equal(terminal?.enabled, terminalScopeGranted);
        assert.equal(terminal?.reason, terminalScopeGranted ? "enabled" : "scope_not_granted");
      }
    }
    assert.equal((await call(args, ["mac.control.read"])).ok, false);
    delegate = false; assert.equal((await call()).ok, false);
    await assert.rejects(readFile(join(root, "counter")), { code: "ENOENT" });
    delegate = true;
    const first = await call(); assert.equal(first.ok, true, JSON.stringify(first));
    const require = createRequire(import.meta.url);
    const Ajv = require("ajv/dist/2020").default;
    const ajv = new Ajv({ strict: true, allErrors: true });
    require("ajv-formats").default(ajv);
    const contract = JSON.parse(await readFile(fileURLToPath(new URL("../../../tool-contracts/mac_terminal_exec.json", import.meta.url)), "utf8"));
    const validate = ajv.compile(contract.output_schema);
    assert.equal(validate(first), true, ajv.errorsText(validate.errors));

    const replay = await call(); assert.equal(replay.ok, true, JSON.stringify(replay));
    if (replay.ok) assert.equal((replay.data as { reused: boolean }).reused, true);
    assert.equal(await readFile(join(root, "counter"), "utf8"), "once");
    const job = store.ownedJobByIdempotencyKey("same-operation", "principal-1")!;
    assert.equal(job.state, "completed"); assert.equal(job.stdout, "verified");
    const different = await call({ ...args, command: "printf different >> counter" });
    const failureSchema = JSON.parse(await readFile(fileURLToPath(new URL("../../../schemas/broker-failure.schema.json", import.meta.url)), "utf8"));
    const validateFailure = ajv.compile(failureSchema);
    assert.equal(validateFailure(different), true, ajv.errorsText(validateFailure.errors));
    assert.equal(different.ok, false); assert.equal(different.result_class, "CONFLICT");
    if (!different.ok) assert.equal(different.error.message, `IDEMPOTENCY_KEY_IN_USE: this idempotency_key already belongs to job ${job.jobId} ` +
      `(mac_terminal_exec, completed, created ${new Date(job.createdAtMs).toISOString()}), but the new request differs in arguments. Use a new idempotency_key.`);
    // A key held by another tool names that tool.
    store.createJob({ jobId: "job:write-held", ownerPrincipalId: "principal-1", ownerSessionId: "session-1", tool: "mac_write_file_atomic",
      targetRef: "path:test-root", policyVersion: policy.version, payloadDigest: "d".repeat(64), idempotencyKey: "write-held-key", createdAtMs: 1_000 });
    const crossTool = await call({ ...args, idempotency_key: "write-held-key" });
    assert.equal(crossTool.ok, false); assert.equal(crossTool.result_class, "CONFLICT");
    if (!crossTool.ok) assert.equal(crossTool.error.message, "IDEMPOTENCY_KEY_IN_USE: this idempotency_key already belongs to job job:write-held " +
      "(mac_write_file_atomic, queued, created 1970-01-01T00:00:01.000Z), but the new request differs in tool. Use a new idempotency_key.");
    // A command ended by a signal has no exit code; it is still an observed failure and must not wedge the next start.
    const signalled = await call({ ...args, command: "kill -9 $$", idempotency_key: "signal-exit" });
    assert.equal(signalled.ok, true, JSON.stringify(signalled));
    const signalledJob = store.ownedJobByIdempotencyKey("signal-exit", "principal-1")!;
    assert.equal(signalledJob.state, "failed"); assert.equal(signalledJob.exitCode, null);
    assert.equal(store.requestRecord(`terminal-${sequence}`)?.state, "SUCCEEDED");
    // Opening a second handle runs the same startup ledger integrity check a service restart does.
    new BrokerStore(join(root, "broker.sqlite")).close();
    assert.equal(store.auditEventExists("terminal-3", "intent"), true);
    assert.equal(store.auditEventExists("terminal-3", "completion"), true);
    const pending = call({ command: "printf started > cancel-started; sleep 5; printf late > cancel-late", cwd: root, idempotency_key: "cancel-operation" });
    let active;
    for (let attempt = 0; attempt < 100; attempt += 1) {
      active = store.ownedJobByIdempotencyKey("cancel-operation", "principal-1");
      if (active?.processMetadata) {
        try { if (await readFile(join(root, "cancel-started"), "utf8") === "started") break; } catch {}
      }
      await delay(10);
    }
    assert.ok(active?.processMetadata);
    store.requestJobCancellation(active.jobId, "principal-1", "OWNER_CANCELLED", Date.now());
    const cancelled = await pending;
    assert.equal(cancelled.ok, false);
    assert.equal(store.ownedJob(active.jobId, "principal-1")?.state, "cancelled");
    await assert.rejects(readFile(join(root, "cancel-late")), { code: "ENOENT" });
    const revoked = call({ command: "printf started > revocation-started; sleep 5; printf late > revocation-late", cwd: root,
      idempotency_key: "revoked-operation" }, ["mac.terminal.exec"], "revoked-session");
    for (let attempt = 0; attempt < 100; attempt += 1) {
      try { if (await readFile(join(root, "revocation-started"), "utf8") === "started") break; } catch {}
      await delay(10);
    }
    assert.equal(await readFile(join(root, "revocation-started"), "utf8"), "started");
    store.revoke("session", "revoked-session", "OAUTH_AUTHORITY_REVOKED");
    const revokedResult = await revoked;
    assert.equal(revokedResult.result_class, "CANCELLED", JSON.stringify(revokedResult));
    const revokedJob = store.ownedJobByIdempotencyKey("revoked-operation", "principal-1");
    assert.equal(revokedJob?.state, "cancelled");
    assert.equal(revokedJob?.cancelRequested, true);
    assert.equal(revokedJob?.processMetadata, undefined);
    await assert.rejects(readFile(join(root, "revocation-late")), { code: "ENOENT" });
    const archiveKey = randomBytes(32);
    try {
      await store.rotateLedgerArchive(root, { keySource: { keyId: "terminal-test-archive", loadKey: () => Buffer.from(archiveKey) },
        nowMs: Date.now() + 2000, retainRequestCount: 0, retainJobCount: 0, minAgeMs: 1000 });
      assert.equal(store.ownedJobByIdempotencyKey("same-operation", "principal-1"), undefined);
      const archivedReplay = await call();
      assert.equal(archivedReplay.result_class, "CONFLICT");
      if (!archivedReplay.ok) assert.match(archivedReplay.error.message, new RegExp(`^IDEMPOTENCY_KEY_IN_USE: this idempotency_key or Job id belongs to archived job ${job.jobId} \\(mac_terminal_exec, completed, finished `, "u"));
      assert.equal(await readFile(join(root, "counter"), "utf8"), "once");
    } finally { archiveKey.fill(0); }


  } finally { await broker.close(); store.close(); key.fill(0); await rm(root, { recursive: true, force: true }); }
});
