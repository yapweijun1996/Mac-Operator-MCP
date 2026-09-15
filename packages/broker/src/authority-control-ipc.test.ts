import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { connect } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerStore, type SwitchName, type RevocationKind } from "./persistence.js";
import {
  AuthorityControlIpcClient,
  AuthorityControlIpcServer,
  authenticateAuthorityControlCommand,
  authenticateAuthorityControlResponse,
  signAuthorityControlCommand,
  validateUnsignedAuthorityControlCommand,
  type AuthorityControlIpcResponse,
  type AuthorityControlOperation,
  type UnsignedAuthorityControlCommand
} from "./authority-control-ipc.js";

const NOW = 1_700_000_000_000;

function command(
  operation: AuthorityControlOperation,
  sequence: number,
  fields: Partial<Omit<UnsignedAuthorityControlCommand, "protocolVersion" | "requestId" | "nonce" | "nonceExpiresAtMs" | "timestampMs" | "operation">> = {}
): UnsignedAuthorityControlCommand {
  return {
    protocolVersion: "0.1",
    requestId: `authority-command-${sequence}`,
    nonce: `authority-nonce-${String(sequence).padStart(16, "0")}`,
    nonceExpiresAtMs: NOW + 30_000,
    timestampMs: NOW,
    operation,
    reason: "TEST_OPERATOR_ACTION",
    ...fields
  };
}

async function sendCommand(socketPath: string, payload: unknown, suffix = ""): Promise<AuthorityControlIpcResponse> {
  return new Promise((resolvePromise, reject) => {
    const socket = connect(socketPath);
    const chunks: Buffer[] = [];
    socket.once("error", reject);
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      socket.destroy();
      try {
        resolvePromise(JSON.parse(combined.subarray(0, newline).toString("utf8")) as AuthorityControlIpcResponse);
      } catch (error) {
        reject(error);
      }
    });
    socket.on("close", () => {
      if (chunks.length === 0) reject(new Error("Authority control IPC closed without a response"));
    });
    socket.on("connect", () => socket.write(`${JSON.stringify(payload)}\n${suffix}`));
  });
}

test("authority control parser rejects accessor command fields", () => {
  const key = randomBytes(32);
  const signed = signAuthorityControlCommand(command("set_switch", 0, {
    switchName: "process",
    disabled: true,
    expectedDisabled: false
  }), key) as unknown as Record<string, unknown>;
  Object.defineProperty(signed, "switchName", { enumerable: true, get: () => "process" });
  assert.throws(
    () => authenticateAuthorityControlCommand(signed, key, NOW),
    (error: unknown) => error instanceof Error && "errorClass" in error &&
      (error as { errorClass: string }).errorClass === "PRECONDITION_FAILED"
  );
  key.fill(0);
});

test("authority control accepts the bounded maximum Edge-key revocation identity", () => {
  const edgeId = `e${"x".repeat(127)}`;
  const keyId = `k${"y".repeat(127)}`;
  const subjectId = `${edgeId}:${keyId}`;
  assert.equal(subjectId.length, 257);
  assert.doesNotThrow(() => validateUnsignedAuthorityControlCommand(command("revoke", 1, {
    revocationKind: "edge_key",
    subjectId
  })));
});

test("authority control IPC authenticates, persists replay, and applies bounded operator actions", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ac-"));
  const databasePath = join(directory, "broker.sqlite");
  const socketPath = join(directory, "a.sock");
  const authenticationKey = randomBytes(32);
  let store = new BrokerStore(databasePath);
  const server = new AuthorityControlIpcServer({
    socketPath,
    store,
    authenticationKey,
    peerPolicy: currentProcessPeerPolicy(),
    now: () => NOW
  });
  try {
    store.createJob({
      jobId: "job:authority-control",
      ownerPrincipalId: "principal-1",
      ownerSessionId: "session-1",
      tool: "mac_task_run",
      targetRef: "task:test",
      policyVersion: "policy-0.1",
      payloadDigest: "a".repeat(64),
      idempotencyKey: "authority-control-job",
      createdAtMs: NOW
    });
    await server.listen();

    const trailing = command("set_switch", 99, {
      switchName: "process" as SwitchName,
      disabled: true,
      expectedDisabled: false
    });
    const trailingResponse = await sendCommand(socketPath, signAuthorityControlCommand(trailing, authenticationKey), "{}\n");
    assert.equal(trailingResponse.ok, false);
    if (!trailingResponse.ok) assert.equal(trailingResponse.result_class, "PRECONDITION_FAILED");
    assert.equal(store.isSwitchDisabled("process"), false);

    const disable = command("set_switch", 1, {
      switchName: "process" as SwitchName,
      disabled: true,
      expectedDisabled: false
    });
    const disableResponse = await sendCommand(socketPath, signAuthorityControlCommand(disable, authenticationKey));
    assert.equal(disableResponse.ok, true);
    if (disableResponse.ok) {
      assert.equal(disableResponse.operation, "set_switch");
      assert.equal(disableResponse.switch_name, "process");
      assert.equal(disableResponse.disabled, true);
      assert.match(disableResponse.responseProof, /^[a-f0-9]{64}$/u);
      assert.throws(
        () => authenticateAuthorityControlResponse({ ...disableResponse, responseProof: "0".repeat(64) }, disable, authenticationKey),
        (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "AUTH_INVALID"
      );
    }
    assert.equal(store.isSwitchDisabled("process"), true);
    assert.equal(store.ownedJob("job:authority-control", "principal-1")?.state, "cancelled");

    const replay = await sendCommand(socketPath, signAuthorityControlCommand(disable, authenticationKey));
    assert.equal(replay.ok, false);
    if (!replay.ok) assert.equal(replay.result_class, "REPLAY_DENIED");

    const wrongProof = signAuthorityControlCommand(command("revoke", 2, {
      revocationKind: "session" as RevocationKind,
      subjectId: "session-1"
    }), randomBytes(32));
    const wrongResponse = await sendCommand(socketPath, wrongProof);
    assert.equal(wrongResponse.ok, false);
    if (!wrongResponse.ok) assert.equal(wrongResponse.result_class, "AUTH_INVALID");

    const enable = command("set_switch", 3, {
      switchName: "process" as SwitchName,
      disabled: false,
      expectedDisabled: true
    });
    const enableResponse = await sendCommand(socketPath, signAuthorityControlCommand(enable, authenticationKey));
    assert.equal(enableResponse.ok, true);
    if (enableResponse.ok) {
      assert.equal(enableResponse.operation, "set_switch");
      assert.equal(enableResponse.switch_name, "process");
      assert.equal(enableResponse.disabled, false);
    }
    assert.equal(store.isSwitchDisabled("process"), false);

    const revoke = command("revoke", 4, {
      revocationKind: "session" as RevocationKind,
      subjectId: "session-1"
    });
    const revokeResponse = await sendCommand(socketPath, signAuthorityControlCommand(revoke, authenticationKey));
    assert.equal(revokeResponse.ok, true);
    if (revokeResponse.ok) {
      assert.equal(revokeResponse.operation, "revoke");
      assert.equal(revokeResponse.revocation_kind, "session");
      assert.equal(revokeResponse.subject_id, "session-1");
    }
    assert.equal(store.isRevoked("session", "session-1"), true);
    const client = new AuthorityControlIpcClient({ socketPath, authenticationKey, now: () => NOW });
    assert.equal(await client.readSwitch("process"), false);
    assert.equal(await client.readRevocation("session", "session-1"), true);
    const authorityRows = store.auditRows().filter((row) =>
      row.tool === "internal_authority_switch" || row.tool === "internal_authority_revoke"
    );
    assert.equal(authorityRows.filter((row) => row.tool === "internal_authority_switch").length, 4);
    assert.equal(authorityRows.filter((row) => row.tool === "internal_authority_revoke").length, 2);
    assert.equal(new Set(authorityRows.map((row) => row.request_id)).has(disable.requestId), true);
    assert.equal(new Set(authorityRows.map((row) => row.request_id)).has(revoke.requestId), true);
    for (const row of authorityRows) {
      const evidence = JSON.parse(String(row.evidence_json)) as Record<string, unknown>;
      assert.equal("reason" in evidence, false);
      assert.match(String(evidence.reasonDigest), /^[a-f0-9]{64}$/u);
    }

    await client.setSwitch("global", true, false, "client-test");
    assert.equal(await client.readSwitch("global"), true);
    await client.revoke("edge", "edge-1", "client-test");
    assert.equal(await client.readRevocation("edge", "edge-1"), true);
    client.dispose();
    await assert.rejects(
      () => client.readSwitch("global"),
      (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "CANCELLED"
    );

    const stale = command("set_switch", 5, {
      switchName: "process" as SwitchName,
      disabled: true,
      expectedDisabled: true
    });
    const staleResponse = await sendCommand(socketPath, signAuthorityControlCommand(stale, authenticationKey));
    assert.equal(staleResponse.ok, false);
    if (!staleResponse.ok) assert.equal(staleResponse.result_class, "CONFLICT");
    assert.equal(store.isSwitchDisabled("process"), false);

    await server.close();
    store.close();
    store = new BrokerStore(databasePath);
    const reopenedServer = new AuthorityControlIpcServer({
      socketPath,
      store,
      authenticationKey,
      peerPolicy: currentProcessPeerPolicy(),
      now: () => NOW
    });
    try {
      await reopenedServer.listen();
      const reopenedClient = new AuthorityControlIpcClient({ socketPath, authenticationKey, now: () => NOW });
      assert.equal(await reopenedClient.readSwitch("global"), true);
      assert.equal(await reopenedClient.readSwitch("process"), false);
      assert.equal(await reopenedClient.readRevocation("session", "session-1"), true);
      assert.equal(await reopenedClient.readRevocation("edge", "edge-1"), true);
      const replayAfterRestart = await sendCommand(socketPath, signAuthorityControlCommand(enable, authenticationKey));
      assert.equal(replayAfterRestart.ok, false);
      if (!replayAfterRestart.ok) assert.equal(replayAfterRestart.result_class, "REPLAY_DENIED");
      reopenedClient.dispose();
    } finally {
      await reopenedServer.close();
    }
  } finally {
    await server.close().catch(() => undefined);
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("authority control IPC drops a denied peer before parsing or auditing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "acd-"));
  const socketPath = join(directory, "a.sock");
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const server = new AuthorityControlIpcServer({
    socketPath,
    store,
    authenticationKey: randomBytes(32),
    peerPolicy: deniedPeerPolicy(),
    now: () => NOW
  });
  try {
    await server.listen();
    await new Promise<void>((resolvePromise, reject) => {
      const socket = connect(socketPath);
      socket.once("error", (error: NodeJS.ErrnoException) => {
        if (error.code === "EPIPE" || error.code === "ECONNRESET") resolvePromise();
        else reject(error);
      });
      socket.once("close", () => resolvePromise());
      socket.on("connect", () => socket.write("not-json\n"));
    });
    assert.deepEqual(store.auditRows(), []);
    assert.equal(store.isSwitchDisabled("global"), false);
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("authority control IPC signs a stable expiry error for a structurally valid stale command", async () => {
  const directory = await mkdtemp(join(tmpdir(), "ace-"));
  const socketPath = join(directory, "a.sock");
  const databasePath = join(directory, "broker.sqlite");
  const authenticationKey = randomBytes(32);
  const store = new BrokerStore(databasePath);
  const server = new AuthorityControlIpcServer({
    socketPath,
    store,
    authenticationKey,
    peerCredentialVerifier: { verify: () => undefined },
    now: () => NOW
  });
  const expired = {
    ...command("set_switch", 90, {
      switchName: "process" as SwitchName,
      disabled: true,
      expectedDisabled: false
    }),
    timestampMs: NOW - 120_000,
    nonceExpiresAtMs: NOW - 60_000
  } satisfies UnsignedAuthorityControlCommand;
  try {
    await server.listen();
    const response = await sendCommand(socketPath, signAuthorityControlCommand(expired, authenticationKey));
    assert.equal(response.ok, false);
    if (!response.ok) {
      assert.equal(response.result_class, "AUTH_EXPIRED");
      assert.equal(authenticateAuthorityControlResponse(response, expired, authenticationKey).ok, false);
    }
    assert.equal(store.isSwitchDisabled("process"), false);
    assert.deepEqual(store.auditRows(), []);
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

function currentProcessPeerPolicy(): { expectedUid: number; expectedGid: number; allowedProcessIds: ReadonlySet<number> } {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  return { expectedUid: uid, expectedGid: gid, allowedProcessIds: new Set([process.pid]) };
}

function deniedPeerPolicy(): { expectedUid: number; allowedProcessIds: ReadonlySet<number> } {
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error("POSIX identity is unavailable");
  return { expectedUid: uid, allowedProcessIds: new Set([process.pid + 1]) };
}
