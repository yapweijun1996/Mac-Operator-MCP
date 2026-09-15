import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { connect } from "node:net";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, canonicalJson, CONTRACT_VERSION, sha256 } from "@mac-operator/contracts";
import { BrokerStore, validatePrivilegedHelperPayload } from "./persistence.js";
import {
  assertPrivilegedHelperCommandAuthority,
  AllowlistedPrivilegedHelper,
  BrokerPrivilegedHelperCommandFactory,
  BrokerStorePrivilegedHelperReplayGuard,
  InMemoryPrivilegedHelperReplayGuard,
  PrivilegedHelperIpcServer,
  authenticatePrivilegedHelperCommand,
  authenticatePrivilegedHelperResponse,
  authenticatePrivilegedHelperStatusResponse,
  executePrivilegedHelperCommand,
  readPrivilegedHelperStatus,
  signPrivilegedHelperCommand,
  signPrivilegedHelperStatusRequest,
  validateUnsignedPrivilegedHelperStatusRequest,
  validatePrivilegedHelperStatusReadback,
  validatePrivilegedHelperExecutionResult,
  type PrivilegedHelperResponse,
  type PrivilegedHelperStatusReadback,
  type PrivilegedHelperStatusResponse,
  type UnsignedPrivilegedHelperCommand
} from "./privileged-helper.js";

const NOW = 1_700_000_000_000;

function command(sequence: number, operation: UnsignedPrivilegedHelperCommand["operation"] = "service_control"): UnsignedPrivilegedHelperCommand {
  const payload = operation === "service_control"
    ? { operation: "service_control" as const, service_id: "system/com.example.test", action: "start" as const }
    : operation === "package_install"
      ? { operation: "package_install" as const, package_id: "example", version: "1.2.3" }
      : { operation: "power" as const, action: "reboot" as const };
  return {
    protocolVersion: "0.1",
    contractVersion: CONTRACT_VERSION,
    commandId: `priv-command:test-${sequence}`,
    requestId: `request:test-${sequence}`,
    nonce: `helper-nonce-${String(sequence).padStart(16, "0")}`,
    nonceExpiresAtMs: NOW + 30_000,
    timestampMs: NOW,
    expiresAtMs: NOW + 30_000,
    operation,
    targetRef: operation === "service_control" ? "service:system/com.example.test" : operation === "package_install" ? "package:example" : "host:local",
    payload,
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: "policy-test-1",
    approvalId: `approval:test-${sequence}`,
    intentId: `intent:test-${sequence}`
  };
}

async function sendCommand(socketPath: string, payload: unknown, suffix = ""): Promise<PrivilegedHelperResponse> {
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
    socket.on("connect", () => socket.write(`${JSON.stringify(payload)}\n${suffix}`));
  });
}

async function sendStatus(socketPath: string, payload: unknown, suffix = ""): Promise<PrivilegedHelperStatusResponse> {
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
        resolvePromise(JSON.parse(combined.subarray(0, newline).toString("utf8")) as PrivilegedHelperStatusResponse);
      } catch (error) {
        reject(error);
      }
    });
    socket.on("close", () => {
      if (chunks.length === 0) reject(new Error("Privileged helper status IPC closed without a response"));
    });
    socket.on("connect", () => socket.write(`${JSON.stringify(payload)}\n${suffix}`));
  });
}

function statusReadback(socketPath: string, brokerSocketPath: string, helperAuthoritySocketPath = "/Users/operator/run/helper-authority.sock"): PrivilegedHelperStatusReadback {
  return {
    component: "mac-operator-privileged-helper",
    state: "running",
    runtimeState: "running",
    nativeTransportRequired: true,
    adapterAvailable: false,
    helperSocketPath: socketPath,
    brokerSocketPath,
    helperAuthoritySocketPath,
    brokerPeerUid: 501,
    brokerPeerGid: 20,
    sourceRevision: "a".repeat(40),
    contractVersion: CONTRACT_VERSION,
    policyVersion: "policy-0.1",
    enabledCapabilities: []
  };
}

test("privileged helper command is signed, bounded, and excludes raw execution authority", () => {
  const key = randomBytes(32);
  const unsigned = command(1);
  const signed = signPrivilegedHelperCommand(unsigned, key);
  assert.deepEqual(authenticatePrivilegedHelperCommand(signed, key, NOW), unsigned);
  assert.throws(
    () => authenticatePrivilegedHelperCommand({ ...signed, operation: "power", targetRef: "host:local" }, key, NOW),
    (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "PRECONDITION_FAILED"
  );
  assert.throws(
    () => authenticatePrivilegedHelperCommand({ ...signed, executable: "/bin/sh" }, key, NOW),
    (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "PRECONDITION_FAILED"
  );
  assert.throws(
    () => authenticatePrivilegedHelperCommand({ ...signed, contractVersion: "9.9" }, key, NOW),
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
    evidence: {
      token: "sk-proj-1234567890123456",
      api_key: "api-secret",
      signing_key: "signing-secret",
      note: "password=super-secret-value"
    },
    warnings: ["secret=another-secret-value"], truncated: false,
    verification: { status: "verified", strategy: "allowlisted_postcondition", summary: "token=hidden-value" }
  });
  assert.equal(sanitized.evidence.token, "[REDACTED]");
  assert.equal(sanitized.evidence.api_key, "[REDACTED]");
  assert.equal(sanitized.evidence.signing_key, "[REDACTED]");
  assert.equal(sanitized.evidence.note, "[REDACTED]");
  assert.equal(sanitized.warnings[0], "[REDACTED]");
  assert.equal(sanitized.verification.summary, "[REDACTED]");
});

test("privileged helper parser rejects accessor command fields", () => {
  const key = randomBytes(32);
  const signed = signPrivilegedHelperCommand(command(0), key) as unknown as Record<string, unknown>;
  Object.defineProperty(signed, "operation", { enumerable: true, get: () => "service_control" });
  assert.throws(
    () => authenticatePrivilegedHelperCommand(signed, key, NOW),
    (error: unknown) => error instanceof Error && "errorClass" in error &&
      (error as { errorClass: string }).errorClass === "PRECONDITION_FAILED"
  );
  key.fill(0);
});

test("privileged helper status request boundary rejects accessors and inherited fields", () => {
  const valid = {
    protocolVersion: "0.1" as const,
    contractVersion: CONTRACT_VERSION,
    requestId: "request:status-boundary-1",
    nonce: "status-nonce-boundary-0001",
    timestampMs: NOW,
    expiresAtMs: NOW + 5_000,
    kind: "status" as const
  };
  validateUnsignedPrivilegedHelperStatusRequest(valid);

  const accessor = { ...valid } as Record<string, unknown>;
  Object.defineProperty(accessor, "kind", { enumerable: true, get: () => "status" });
  assert.throws(
    () => validateUnsignedPrivilegedHelperStatusRequest(accessor as never),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );

  const inherited = Object.create({ kind: "status" }) as Record<string, unknown>;
  Object.assign(inherited, { ...valid });
  delete inherited.kind;
  assert.throws(
    () => validateUnsignedPrivilegedHelperStatusRequest(inherited as never),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});

test("privileged helper status readback rejects accessors before key enumeration", () => {
  const status = statusReadback("/tmp/helper.sock", "/tmp/broker.sock");
  const accessor = { ...status } as Record<string, unknown>;
  Object.defineProperty(accessor, "runtimeState", { enumerable: true, get: () => "running" });
  assert.throws(
    () => validatePrivilegedHelperStatusReadback(accessor as never),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );

  const extraArrayProperty = { ...status, enabledCapabilities: [] as readonly [] };
  Object.defineProperty(extraArrayProperty.enabledCapabilities, "metadata", { enumerable: true, get: () => "injected" });
  assert.throws(
    () => validatePrivilegedHelperStatusReadback(extraArrayProperty),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );

  const inherited = Object.create({ component: status.component }) as Record<string, unknown>;
  Object.assign(inherited, status);
  delete inherited.component;
  assert.throws(
    () => validatePrivilegedHelperStatusReadback(inherited as never),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
});

test("privileged helper nested result and payload records reject non-data fields", () => {
  const verification = { status: "verified", strategy: "allowlisted_postcondition" } as Record<string, unknown>;
  Object.defineProperty(verification, "summary", { enumerable: true, get: () => "injected" });
  assert.throws(
    () => validatePrivilegedHelperExecutionResult({
      operation: "service_control", targetRef: "service:system/com.example.test", state: "completed", resultClass: "SUCCEEDED",
      evidence: {}, warnings: [], truncated: false, verification: verification as never
    }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );

  assert.throws(
    () => validatePrivilegedHelperExecutionResult({
      operation: "service_control", targetRef: "service:system/com.example.test", state: "completed", resultClass: "SUCCEEDED",
      evidence: {}, warnings: [], truncated: false, verification: { status: "verified", strategy: "allowlisted_postcondition" },
      extra: "must-be-rejected"
    } as never),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );

  assert.throws(
    () => validatePrivilegedHelperExecutionResult({
      operation: "service_control", targetRef: "service:system/com.example.test", state: "completed", resultClass: "SUCCEEDED",
      evidence: {}, warnings: [], truncated: false,
      verification: { status: "verified", strategy: "allowlisted_postcondition", extra: "must-be-rejected" }
    } as never),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );

  const payload = Object.create({ action: "start" }) as Record<string, unknown>;
  payload.operation = "service_control";
  payload.service_id = "system/com.example.test";
  assert.throws(
    () => validatePrivilegedHelperPayload(payload as never),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});

test("privileged helper IPC authenticates the peer and command, rejects replay, and dispatches only allowlisted operations", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-"));
  const socketPath = join(directory, "helper.sock");
  const key = randomBytes(32);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  let keyAvailable = true;
  const server = new PrivilegedHelperIpcServer({
    socketPath,
    authenticationKey: key,
    replayGuard: new BrokerStorePrivilegedHelperReplayGuard(store),
    keyAuthorityCheck: () => {
      if (!keyAvailable) throw new BrokerError("AUTH_EXPIRED", "Privileged helper key validity window ended");
    },
    authorizeCommand: () => undefined,
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

    const clientCommand = command(8);
    const clientResponse = await executePrivilegedHelperCommand(signPrivilegedHelperCommand(clientCommand, key), {
      socketPath,
      authenticationKey: key,
      now: () => NOW
    });
    assert.equal(clientResponse.ok, true);
    if (clientResponse.ok) assert.equal(clientResponse.result.resultClass, "SUCCEEDED");
    const clientReplay = await executePrivilegedHelperCommand(signPrivilegedHelperCommand(clientCommand, key), {
      socketPath,
      authenticationKey: key,
      now: () => NOW
    });
    assert.equal(clientReplay.ok, false);
    if (!clientReplay.ok) assert.equal(clientReplay.resultClass, "REPLAY_DENIED");

    assert.throws(
      () => authenticatePrivilegedHelperResponse(response, { ...first, targetRef: "service:system/com.example.other" }, key),
      (error: unknown) => error instanceof Error && "errorClass" in error && (error as { errorClass: string }).errorClass === "PRECONDITION_FAILED"
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

    const stale = {
      ...command(9),
      timestampMs: NOW - 120_000,
      nonceExpiresAtMs: NOW - 60_000,
      expiresAtMs: NOW - 60_000
    };
    const staleResponse = await sendCommand(socketPath, signPrivilegedHelperCommand(stale, key));
    assert.equal(staleResponse.ok, false);
    if (!staleResponse.ok) {
      assert.equal(staleResponse.resultClass, "AUTH_EXPIRED");
      const authenticated = authenticatePrivilegedHelperResponse(staleResponse, stale, key);
      assert.equal(authenticated.ok, false);
      if (!authenticated.ok) assert.equal(authenticated.resultClass, "AUTH_EXPIRED");
    }

    keyAvailable = false;
    const expired = await sendCommand(socketPath, signPrivilegedHelperCommand(command(7), key));
    assert.equal(expired.ok, false);
    if (!expired.ok) assert.equal(expired.resultClass, "AUTH_EXPIRED");
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged helper status readback is separately authenticated, replay-protected, and helper-owned", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-status-"));
  const socketPath = join(directory, "helper.sock");
  const brokerSocketPath = join(directory, "broker.sock");
  const key = randomBytes(32);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  let statusCalls = 0;
  const status = statusReadback(socketPath, brokerSocketPath);
  const server = new PrivilegedHelperIpcServer({
    socketPath,
    authenticationKey: key,
    replayGuard: new BrokerStorePrivilegedHelperReplayGuard(store),
    authorizeCommand: () => undefined,
    authorizeStatus: () => undefined,
    readStatus: () => {
      statusCalls += 1;
      return status;
    },
    peerCredentialVerifier: { verify: () => undefined },
    adapter: new AllowlistedPrivilegedHelper({}),
    now: () => NOW
  });
  try {
    await server.listen();
    const request = {
      protocolVersion: "0.1" as const,
      contractVersion: CONTRACT_VERSION,
      requestId: "request:status-test-1",
      nonce: "status-nonce-test-0001",
      timestampMs: NOW,
      expiresAtMs: NOW + 5_000,
      kind: "status" as const
    };
    const response = await sendStatus(socketPath, signPrivilegedHelperStatusRequest(request, key));
    const verified = authenticatePrivilegedHelperStatusResponse(response, request, key);
    assert.equal(verified.ok, true);
    if (verified.ok) assert.deepEqual(verified.status, status);
    assert.equal(statusCalls, 1);

    const replay = await sendStatus(socketPath, signPrivilegedHelperStatusRequest(request, key));
    assert.equal(replay.ok, false);
    if (!replay.ok) assert.equal(replay.resultClass, "REPLAY_DENIED");

    const expired = {
      ...request,
      requestId: "request:status-expired-1",
      nonce: "status-nonce-expired-1",
      timestampMs: NOW - 120_000,
      expiresAtMs: NOW - 60_000
    };
    const expiredResponse = await sendStatus(socketPath, signPrivilegedHelperStatusRequest(expired, key));
    assert.equal(expiredResponse.ok, false);
    if (!expiredResponse.ok) {
      assert.equal(expiredResponse.resultClass, "AUTH_EXPIRED");
      const authenticated = authenticatePrivilegedHelperStatusResponse(expiredResponse, expired, key);
      assert.equal(authenticated.ok, false);
      if (!authenticated.ok) assert.equal(authenticated.resultClass, "AUTH_EXPIRED");
    }
    assert.equal(statusCalls, 1);

    const clientStatus = await readPrivilegedHelperStatus({ socketPath, authenticationKey: key, now: () => NOW });
    assert.deepEqual(clientStatus, status);
    assert.equal(statusCalls, 2);
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged helper rejects trailing frames before replay admission or dispatch", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-framing-"));
  const socketPath = join(directory, "helper.sock");
  const brokerSocketPath = join(directory, "broker.sock");
  const key = randomBytes(32);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  let commandCalls = 0;
  let statusCalls = 0;
  const status = statusReadback(socketPath, brokerSocketPath);
  const server = new PrivilegedHelperIpcServer({
    socketPath,
    authenticationKey: key,
    replayGuard: new BrokerStorePrivilegedHelperReplayGuard(store),
    authorizeCommand: () => undefined,
    authorizeStatus: () => undefined,
    readStatus: () => {
      statusCalls += 1;
      return status;
    },
    peerCredentialVerifier: { verify: () => undefined },
    adapter: new AllowlistedPrivilegedHelper({
      service_control: async (request) => {
        commandCalls += 1;
        return {
          operation: request.operation,
          targetRef: request.targetRef,
          state: "completed",
          resultClass: "SUCCEEDED",
          evidence: {}, warnings: [], truncated: false,
          verification: { status: "verified", strategy: "allowlisted_postcondition" }
        };
      }
    }),
    now: () => NOW
  });
  try {
    await server.listen();
    const commandRequest = command(20);
    const trailingCommandResponse = await sendCommand(socketPath, signPrivilegedHelperCommand(commandRequest, key), "{}\n");
    const trailingCommand = authenticatePrivilegedHelperResponse(trailingCommandResponse, commandRequest, key);
    assert.equal(trailingCommand.ok, false);
    if (!trailingCommand.ok) assert.equal(trailingCommand.resultClass, "PRECONDITION_FAILED");
    assert.equal(commandCalls, 0);
    const cleanCommandResponse = await sendCommand(socketPath, signPrivilegedHelperCommand(commandRequest, key));
    assert.equal(cleanCommandResponse.ok, true);
    assert.equal(commandCalls, 1);

    const statusRequest = {
      protocolVersion: "0.1" as const,
      contractVersion: CONTRACT_VERSION,
      requestId: "request:status-framing-1",
      nonce: "status-nonce-framing-0001",
      timestampMs: NOW,
      expiresAtMs: NOW + 5_000,
      kind: "status" as const
    };
    const trailingStatusResponse = await sendStatus(socketPath, signPrivilegedHelperStatusRequest(statusRequest, key), "{}\n");
    const trailingStatus = authenticatePrivilegedHelperStatusResponse(trailingStatusResponse, statusRequest, key);
    assert.equal(trailingStatus.ok, false);
    if (!trailingStatus.ok) assert.equal(trailingStatus.resultClass, "PRECONDITION_FAILED");
    assert.equal(statusCalls, 0);
    const cleanStatusResponse = await sendStatus(socketPath, signPrivilegedHelperStatusRequest(statusRequest, key));
    assert.equal(cleanStatusResponse.ok, true);
    assert.equal(statusCalls, 1);
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

test("privileged helper does not publish success after active authority revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-revoke-"));
  const socketPath = join(directory, "helper.sock");
  const key = randomBytes(32);
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  let active = true;
  let calls = 0;
  const server = new PrivilegedHelperIpcServer({
    socketPath,
    authenticationKey: key,
    replayGuard: new BrokerStorePrivilegedHelperReplayGuard(store),
    authorizeCommand: () => {
      if (!active) throw new BrokerError("REVOKED", "Privileged helper authority was revoked");
    },
    peerCredentialVerifier: { verify: () => undefined },
    adapter: new AllowlistedPrivilegedHelper({
      service_control: async (request) => {
        calls += 1;
        active = false;
        return {
          operation: request.operation,
          targetRef: request.targetRef,
          state: "completed",
          resultClass: "SUCCEEDED",
          evidence: {}, warnings: [], truncated: false,
          verification: { status: "verified", strategy: "allowlisted_postcondition" }
        };
      }
    }),
    now: () => NOW
  });
  try {
    await server.listen();
    const request = command(6);
    const response = await sendCommand(socketPath, signPrivilegedHelperCommand(request, key));
    const verified = authenticatePrivilegedHelperResponse(response, request, key);
    assert.equal(calls, 1);
    assert.equal(verified.ok, false);
    if (!verified.ok) {
      assert.equal(verified.resultClass, "UNKNOWN_OUTCOME");
      assert.equal(verified.error.retryable, true);
    }
  } finally {
    await server.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("privileged helper polls the separate Broker authority before and after execution", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-authority-poll-"));
  const socketPath = join(directory, "helper.sock");
  const key = randomBytes(32);
  let polls = 0;
  let executions = 0;
  const server = new PrivilegedHelperIpcServer({
    socketPath,
    authenticationKey: key,
    replayGuard: new InMemoryPrivilegedHelperReplayGuard(),
    authorizeCommand: () => undefined,
    authorityPoller: {
      assertAuthorized: async () => {
        polls += 1;
        if (polls >= 2) throw new BrokerError("REVOKED", "Broker authority was revoked");
      }
    },
    authorityPollIntervalMs: 1,
    peerCredentialVerifier: { verify: () => undefined },
    adapter: new AllowlistedPrivilegedHelper({
      service_control: async (request) => {
        executions += 1;
        return {
          operation: request.operation,
          targetRef: request.targetRef,
          state: "completed",
          resultClass: "SUCCEEDED",
          evidence: {}, warnings: [], truncated: false,
          verification: { status: "verified", strategy: "allowlisted_postcondition" }
        };
      }
    }),
    now: () => NOW
  });
  try {
    await server.listen();
    const request = command(7);
    const response = await sendCommand(socketPath, signPrivilegedHelperCommand(request, key));
    const verified = authenticatePrivilegedHelperResponse(response, request, key);
    assert.equal(executions, 1);
    assert.equal(polls, 2);
    assert.equal(verified.ok, false);
    if (!verified.ok) {
      assert.equal(verified.resultClass, "UNKNOWN_OUTCOME");
      assert.equal(verified.error.retryable, true);
    }
  } finally {
    await server.close();
    key.fill(0);
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
    authorizeCommand: () => undefined,
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

test("Broker helper command factory binds a running approved Job without raw authority", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-factory-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  try {
    const identity = admitRunningPrivilegedJob(store, {
      requestId: "request-factory-service",
      jobId: "job:factory-service",
      tool: "mac_priv_service_control",
      targetRef: "service:system/com.example.factory",
      privilegedPayload: { operation: "service_control", service_id: "system/com.example.factory", action: "start" },
      payloadDigest: sha256(canonicalJson({ operation: "service_control", service_id: "system/com.example.factory", action: "start" }))
    });
    const authorized: UnsignedPrivilegedHelperCommand[] = [];
    const factory = new BrokerPrivilegedHelperCommandFactory({
      store,
      authenticationKey: key,
      authorizeCommand: (candidate) => authorized.push(candidate),
      now: () => NOW + 4,
      maxLifetimeMs: 20_000
    });
    const signed = factory.issue(identity);
    const unsigned = authenticatePrivilegedHelperCommand(signed, key, NOW + 4);
    assert.equal(unsigned.operation, "service_control");
    assert.equal(unsigned.contractVersion, CONTRACT_VERSION);
    assert.equal(unsigned.targetRef, "service:system/com.example.factory");
    assert.equal(unsigned.payloadDigest, identity.payloadDigest);
    assert.equal(unsigned.policyVersion, "policy-0.1");
    assert.equal(unsigned.approvalId, "approval:factory-service");
    assert.match(unsigned.intentId, /^intent:[a-f0-9]{48}$/u);
    assert.match(unsigned.commandId, /^priv-command:[a-f0-9]{48}$/u);
    assert.match(unsigned.requestId, /^request:[a-f0-9]{48}$/u);
    assert.match(unsigned.nonce, /^helper-nonce:[a-f0-9]{48}$/u);
    assert.equal(authorized.length, 1);
    const rawKeys = Object.keys(unsigned);
    assert.equal(rawKeys.includes("executable"), false);
    assert.equal(rawKeys.includes("args"), false);
    assert.equal(rawKeys.includes("payload"), true);

    const second = new BrokerPrivilegedHelperCommandFactory({
      store,
      authenticationKey: key,
      authorizeCommand: () => undefined,
      now: () => NOW + 4,
      maxLifetimeMs: 20_000
    }).issue(identity);
    assert.equal(second.commandId, signed.commandId);
    assert.equal(second.requestId, signed.requestId);
    assert.notEqual(second.nonce, signed.nonce);

    factory.dispose();
    assert.throws(
      () => factory.issue(identity),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
    );
    factory.dispose();
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Broker helper command factory fails closed on operation mismatch, queued work, and revocation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-factory-deny-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  try {
    const identity = admitRunningPrivilegedJob(store, {
      requestId: "request-factory-deny",
      jobId: "job:factory-deny",
      tool: "mac_priv_power",
      targetRef: "host:local",
      privilegedPayload: { operation: "power", action: "reboot", reason: "operator" },
      payloadDigest: sha256(canonicalJson({ operation: "power", action: "reboot", reason: "operator" }))
    });
    const factory = new BrokerPrivilegedHelperCommandFactory({
      store,
      authenticationKey: key,
      authorizeCommand: () => undefined,
      now: () => NOW + 4
    });
    assert.throws(
      () => factory.issue({ ...identity, operation: "service_control" }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );

    const queuedIdentity = admitApprovedPrivilegedJob(store, {
      requestId: "request-factory-queued",
      jobId: "job:factory-queued",
      tool: "mac_priv_power",
      targetRef: "host:local",
      privilegedPayload: { operation: "power", action: "shutdown" },
      payloadDigest: sha256(canonicalJson({ operation: "power", action: "shutdown" }))
    });
    const queuedFactory = new BrokerPrivilegedHelperCommandFactory({
      store,
      authenticationKey: key,
      authorizeCommand: () => undefined,
      now: () => NOW + 4
    });
    assert.throws(
      () => queuedFactory.issue(queuedIdentity),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
    );

    const originalApprovalRecord = store.approvalRecord.bind(store);
    const patchedStore = store as unknown as {
      approvalRecord: typeof store.approvalRecord;
    };
    patchedStore.approvalRecord = (approvalId) => {
      const approval = originalApprovalRecord(approvalId);
      return approval ? { ...approval, targetRef: "host:other" } : approval;
    };
    assert.throws(
      () => factory.issue(identity),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    patchedStore.approvalRecord = (approvalId) => {
      const approval = originalApprovalRecord(approvalId);
      return approval ? { ...approval, payloadDigest: "f".repeat(64) } : approval;
    };
    assert.throws(
      () => factory.issue(identity),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    patchedStore.approvalRecord = originalApprovalRecord;

    store.setSwitch("privileged", true, "TEST_KILL_SWITCH", NOW + 1);
    assert.throws(
      () => factory.issue(identity),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REVOKED"
    );
    store.setSwitch("privileged", false, "TEST_REENABLE", NOW + 2);
    store.revoke("session", "session-1", "TEST_REVOKED", NOW + 3);
    assert.throws(
      () => factory.issue(identity),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REVOKED"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Broker-backed helper authority rechecks active switches, revocation, and Job cancellation", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mops-helper-authority-gate-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  try {
    const identity = admitRunningPrivilegedJob(store, {
      requestId: "request-authority-gate",
      jobId: "job:authority-gate",
      tool: "mac_priv_service_control",
      targetRef: "service:system/com.example.authority",
      privilegedPayload: { operation: "service_control", service_id: "system/com.example.authority", action: "start" },
      payloadDigest: sha256(canonicalJson({ operation: "service_control", service_id: "system/com.example.authority", action: "start" }))
    });
    const factory = new BrokerPrivilegedHelperCommandFactory({
      store,
      authenticationKey: key,
      authorizeCommand: (command) => assertPrivilegedHelperCommandAuthority(store, command, NOW + 4),
      now: () => NOW + 4
    });
    const command = factory.issue(identity);
    assert.doesNotThrow(() => assertPrivilegedHelperCommandAuthority(store, command, NOW + 4));

    store.setSwitch("privileged", true, "TEST_KILL_SWITCH", NOW + 5);
    assert.throws(
      () => assertPrivilegedHelperCommandAuthority(store, command, NOW + 5),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REVOKED"
    );
    store.setSwitch("privileged", false, "TEST_REENABLE", NOW + 6);

    store.revoke("session", "session-1", "TEST_REVOKED", NOW + 7);
    assert.throws(
      () => assertPrivilegedHelperCommandAuthority(store, command, NOW + 7),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "REVOKED"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

type PrivilegedJobSetup = {
  requestId: string;
  jobId: string;
  tool: "mac_priv_service_control" | "mac_priv_package_install" | "mac_priv_power";
  targetRef: string;
  privilegedPayload: import("./persistence.js").PrivilegedHelperPayload;
  payloadDigest: string;
};

function admitRunningPrivilegedJob(store: BrokerStore, setup: PrivilegedJobSetup) {
  const identity = admitApprovedPrivilegedJob(store, setup);
  const runningRequest = store.markRequestRunning(setup.requestId, NOW + 4);
  const runningJob = store.startJob(setup.jobId, "principal-1", identity.jobRevision, NOW + 4);
  assert.equal(runningRequest.state, "RUNNING");
  assert.equal(runningJob.state, "running");
  return identity;
}

function admitApprovedPrivilegedJob(store: BrokerStore, setup: PrivilegedJobSetup) {
  const targetKind = setup.tool === "mac_priv_service_control" ? "service" : setup.tool === "mac_priv_package_install" ? "package" : "host";
  const approvalId = `approval:${setup.requestId.replace(/^request-/u, "")}`;
  store.admitRequest({
    requestId: setup.requestId,
    edgeId: "edge-1",
    nonce: `nonce-${setup.requestId}`,
    nonceExpiresAtMs: NOW + 60_000,
    principalId: "principal-1",
    sessionId: "session-1",
    tool: setup.tool,
    policyVersion: "policy-0.1",
    payloadDigest: setup.payloadDigest,
    mutation: true,
    receivedAtMs: NOW
  });
  store.recordRequestDecision({
    requestId: setup.requestId,
    principalId: "principal-1",
    tool: setup.tool,
    eventType: "decision",
    decision: "allow",
    resultClass: "AUTHORIZED",
    targetRef: setup.targetRef,
    policyVersion: "policy-0.1",
    evidence: {},
    timestampMs: NOW + 1
  });
  store.issueApproval({
    approvalId,
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool: setup.tool,
    contractVersion: "0.1",
    targetKind,
    targetRef: setup.targetRef,
    payloadDigest: setup.payloadDigest,
    policyVersion: "policy-0.1",
    approvalClass: "explicit_privileged_policy",
    unattended: false,
    issuedAtMs: NOW + 1,
    expiresAtMs: NOW + 60_000
  });
  store.recordRequestIntent({
    requestId: setup.requestId,
    principalId: "principal-1",
    tool: setup.tool,
    eventType: "intent",
    decision: "allow",
    resultClass: "INTENT_RECORDED",
    targetRef: setup.targetRef,
    policyVersion: "policy-0.1",
    evidence: {},
    timestampMs: NOW + 2
  }, {
    contractVersion: "0.1",
    targetKind,
    targetRef: setup.targetRef,
    payloadDigest: setup.payloadDigest,
    approvalClass: "explicit_privileged_policy",
    unattended: false
  });
  const created = store.createJob({
    jobId: setup.jobId,
    edgeId: "edge-1",
    edgeKeyId: "edge-1:edge-key-1",
    ownerPrincipalId: "principal-1",
    ownerSessionId: "session-1",
    tool: setup.tool,
    targetRef: setup.targetRef,
    policyVersion: "policy-0.1",
    payloadDigest: setup.payloadDigest,
    idempotencyKey: `idem-${setup.jobId.replace(/^job:/u, "")}`,
    createdAtMs: NOW + 2,
    privilegedPayload: setup.privilegedPayload
  });
  store.linkRequestJob(setup.requestId, setup.jobId, NOW + 3);
  return {
    ...setup,
    payloadDigest: setup.payloadDigest,
    jobRevision: created.job.revision,
    principalId: "principal-1",
    sessionId: "session-1"
  };
}
