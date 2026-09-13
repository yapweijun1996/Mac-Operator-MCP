import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { connect } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";
import {
  AllowlistedPrivilegedHelper,
  BrokerStorePrivilegedHelperReplayGuard,
  InMemoryPrivilegedHelperReplayGuard,
  PrivilegedHelperIpcServer,
  authenticatePrivilegedHelperCommand,
  authenticatePrivilegedHelperResponse,
  signPrivilegedHelperCommand,
  validatePrivilegedHelperExecutionResult,
  type PrivilegedHelperResponse,
  type UnsignedPrivilegedHelperCommand
} from "./privileged-helper.js";

const NOW = 1_700_000_000_000;

function command(sequence: number, operation: UnsignedPrivilegedHelperCommand["operation"] = "service_control"): UnsignedPrivilegedHelperCommand {
  return {
    protocolVersion: "0.1",
    commandId: `priv-command:test-${sequence}`,
    requestId: `request:test-${sequence}`,
    nonce: `helper-nonce-${String(sequence).padStart(16, "0")}`,
    nonceExpiresAtMs: NOW + 30_000,
    timestampMs: NOW,
    expiresAtMs: NOW + 30_000,
    operation,
    targetRef: operation === "service_control" ? "service:system/com.example.test" : operation === "package_install" ? "package:example@1.2.3" : "host:local",
    payloadDigest: sha256(canonicalJson({ operation, sequence })),
    policyVersion: "policy-test-1",
    approvalId: `approval:test-${sequence}`,
    intentId: `intent:test-${sequence}`
  };
}

async function sendCommand(socketPath: string, payload: unknown): Promise<PrivilegedHelperResponse> {
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
        resolvePromise(JSON.parse(combined.subarray(0, newline).toString("utf8")) as PrivilegedHelperResponse);
      } catch (error) {
        reject(error);
      }
    });
    socket.on("close", () => {
      if (chunks.length === 0) reject(new Error("Privileged helper IPC closed without a response"));
    });
    socket.on("connect", () => socket.write(`${JSON.stringify(payload)}\n`));
  });
}

test("privileged helper command is signed, bounded, and excludes raw execution authority", () => {
  const key = randomBytes(32);
  const unsigned = command(1);
  const signed = signPrivilegedHelperCommand(unsigned, key);
  assert.deepEqual(authenticatePrivilegedHelperCommand(signed, key, NOW), unsigned);
  assert.throws(
    () => authenticatePrivilegedHelperCommand({ ...signed, operation: "power", targetRef: "host:local" }, key, NOW),
    (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "AUTH_INVALID"
  );
  assert.throws(
    () => authenticatePrivilegedHelperCommand({ ...signed, executable: "/bin/sh" }, key, NOW),
    (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "PRECONDITION_FAILED"
  );
  assert.throws(
    () => validatePrivilegedHelperExecutionResult({
      operation: "service_control", targetRef: "service:system/com.example.test", state: "completed", resultClass: "SUCCEEDED",
      evidence: {}, warnings: [], truncated: false, verification: { status: "failed", strategy: "allowlisted_postcondition" }
    }),
    (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "VERIFICATION_FAILED"
  );
  const sanitized = validatePrivilegedHelperExecutionResult({
    operation: "service_control", targetRef: "service:system/com.example.test", state: "completed", resultClass: "SUCCEEDED",
    evidence: { token: "sk-proj-1234567890123456", note: "password=super-secret-value" },
    warnings: ["secret=another-secret-value"], truncated: false,
    verification: { status: "verified", strategy: "allowlisted_postcondition", summary: "token=hidden-value" }
  });
  assert.equal(sanitized.evidence.token, "[REDACTED]");
  assert.equal(sanitized.evidence.note, "[REDACTED]");
  assert.equal(sanitized.warnings[0], "[REDACTED]");
  assert.equal(sanitized.verification.summary, "[REDACTED]");
});

test("privileged helper IPC authenticates the peer and command, rejects replay, and dispatches only allowlisted operations", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-"));
  const socketPath = join(directory, "helper.sock");
  const key = randomBytes(32);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const server = new PrivilegedHelperIpcServer({
    socketPath,
    authenticationKey: key,
    replayGuard: new BrokerStorePrivilegedHelperReplayGuard(store),
    peerCredentialVerifier: { verify: () => undefined },
    adapter: new AllowlistedPrivilegedHelper({
      service_control: async (request) => ({
        operation: request.operation,
        targetRef: request.targetRef,
        state: "completed",
        resultClass: "SUCCEEDED",
        evidence: { preState: "stopped", postState: "running" },
        warnings: [],
        truncated: false,
        verification: { status: "verified", strategy: "allowlisted_postcondition", summary: "state readback matched" }
      })
    }),
    now: () => NOW
  });
  try {
    await server.listen();
    const first = command(2);
    const firstSigned = signPrivilegedHelperCommand(first, key);
    const response = await sendCommand(socketPath, firstSigned);
    const verified = authenticatePrivilegedHelperResponse(response, first, key);
    assert.equal(verified.ok, true);
    if (verified.ok) {
      assert.equal(verified.result.resultClass, "SUCCEEDED");
      assert.equal(verified.result.verification.status, "verified");
    }
    assert.throws(
      () => authenticatePrivilegedHelperResponse(response, { ...first, targetRef: "service:system/com.example.other" }, key),
      (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "AUTH_INVALID"
    );

    const replay = await sendCommand(socketPath, firstSigned);
    const replayVerified = authenticatePrivilegedHelperResponse(replay, first, key);
    assert.equal(replayVerified.ok, false);
    if (!replayVerified.ok) assert.equal(replayVerified.resultClass, "REPLAY_DENIED");

    const deniedOperation = command(3, "package_install");
    const denied = await sendCommand(socketPath, signPrivilegedHelperCommand(deniedOperation, key));
    const deniedVerified = authenticatePrivilegedHelperResponse(denied, deniedOperation, key);
    assert.equal(deniedVerified.ok, false);
    if (!deniedVerified.ok) assert.equal(deniedVerified.resultClass, "PRIVILEGE_DENIED");

    const wrongKey = await sendCommand(socketPath, signPrivilegedHelperCommand(command(4), randomBytes(32)));
    assert.equal(wrongKey.ok, false);
    if (!wrongKey.ok) assert.equal(wrongKey.resultClass, "AUTH_INVALID");
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged helper replay admission survives BrokerStore reopen", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-replay-"));
  const databasePath = join(directory, "broker.sqlite");
  try {
    const firstStore = new BrokerStore(databasePath);
    const firstCommand = command(5);
    new BrokerStorePrivilegedHelperReplayGuard(firstStore).admit(firstCommand);
    firstStore.close();
    const reopened = new BrokerStore(databasePath);
    try {
      assert.throws(
        () => new BrokerStorePrivilegedHelperReplayGuard(reopened).admit(firstCommand),
        (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "REPLAY_DENIED"
      );
    } finally {
      reopened.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged helper rejects a denied peer before parsing", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-peer-"));
  const socketPath = join(directory, "helper.sock");
  const server = new PrivilegedHelperIpcServer({
    socketPath,
    authenticationKey: randomBytes(32),
    replayGuard: new InMemoryPrivilegedHelperReplayGuard(),
    peerCredentialVerifier: { verify: () => { throw new Error("denied"); } },
    adapter: new AllowlistedPrivilegedHelper({}),
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
  } finally {
    await server.close();
    await rm(directory, { recursive: true, force: true });
  }
});
