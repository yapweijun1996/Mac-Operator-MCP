import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError, canonicalJson, CONTRACT_VERSION, sha256 } from "@mac-operator/contracts";
import { PrivilegedPowerAdapter } from "./privileged-power.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";
import type { UnsignedPrivilegedHelperCommand } from "./privileged-helper.js";

const NOW = 1_700_000_000_000;

function command(action: "reboot" | "shutdown" = "reboot", notBefore?: string, reason?: string): UnsignedPrivilegedHelperCommand {
  const payload = {
    operation: "power" as const,
    action,
    ...(notBefore === undefined ? {} : { not_before: notBefore }),
    ...(reason === undefined ? {} : { reason })
  };
  return {
    protocolVersion: "0.1",
    contractVersion: CONTRACT_VERSION,
    commandId: "priv-command:test-power-1",
    requestId: "request:test-power-1",
    nonce: "helper-nonce-test-power-1",
    nonceExpiresAtMs: NOW + 30_000,
    timestampMs: NOW,
    expiresAtMs: NOW + 30_000,
    operation: "power",
    targetRef: "host:local",
    payload,
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: "policy-test-1",
    approvalId: "approval:test-power-1",
    intentId: "intent:test-power-1"
  };
}

function success(): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout: "shutdown accepted\n",
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: 101,
    processGroupId: 101,
    terminationObserved: true
  };
}

function control(shouldCancel = false) {
  return { timeoutMs: 30_000, shouldCancel: () => shouldCancel };
}

test("privileged power adapter is disabled by default", () => {
  const adapter = new PrivilegedPowerAdapter();
  assert.equal(adapter.available, false);
  assert.deepEqual(adapter.enabledCapabilities, []);
});

test("privileged power adapter uses fixed reboot argv and reports accepted handoff", async () => {
  const requests: ProcessExecutionRequest[] = [];
  const adapter = new PrivilegedPowerAdapter({
    enabled: true,
    commandRunner: { run: async (request) => { requests.push(request); return success(); } },
    now: () => NOW
  });
  const result = await adapter.execute(command("reboot"), control());
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.state, "completed");
  assert.equal(result.verification.status, "verified");
  assert.equal(result.evidence.state, "accepted");
  assert.equal(result.evidence.connection_loss_expected, true);
  assert.deepEqual(requests.map((request) => ({ executable: request.executable, args: request.args, cwd: request.cwd, environment: request.environment })), [
    { executable: "/sbin/shutdown", args: ["-r", "now"], cwd: "/", environment: {} }
  ]);
});

test("privileged power adapter rounds a future lower-bound schedule upward and never forwards reason text", async () => {
  const requests: ProcessExecutionRequest[] = [];
  const notBefore = new Date(NOW + 125_000).toISOString();
  const payloadCommand = command("shutdown", notBefore, "operator requested maintenance");
  const adapter = new PrivilegedPowerAdapter({
    enabled: true,
    commandRunner: { run: async (request) => { requests.push(request); return success(); } },
    now: () => NOW
  });
  const result = await adapter.execute(payloadCommand, control());
  assert.equal(result.evidence.state, "scheduled");
  assert.deepEqual(requests[0]?.args, ["-h", "+3"]);
  assert.equal(requests[0]?.args.includes("operator requested maintenance"), false);
  assert.equal(result.evidence.scheduled_for, new Date(NOW + 180_000).toISOString());
});

test("privileged power adapter returns unknown when the handoff outcome cannot be resolved", async () => {
  const adapter = new PrivilegedPowerAdapter({
    enabled: true,
    commandRunner: {
      run: async () => ({ ...success(), resultClass: "UNKNOWN_OUTCOME" as const, state: "unknown" as const })
    },
    now: () => NOW
  });
  const result = await adapter.execute(command("shutdown"), control());
  assert.equal(result.resultClass, "UNKNOWN_OUTCOME");
  assert.equal(result.state, "unknown");
  assert.equal(result.verification.status, "unknown");
});

test("privileged power adapter rejects cancellation and past schedules before launch", async () => {
  let calls = 0;
  const adapter = new PrivilegedPowerAdapter({
    enabled: true,
    commandRunner: { run: async () => { calls += 1; return success(); } },
    now: () => NOW
  });
  await assert.rejects(
    () => adapter.execute(command("reboot"), control(true)),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
  await assert.rejects(
    () => adapter.execute(command("reboot", new Date(NOW - 1).toISOString()), control()),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  assert.equal(calls, 0);
});
