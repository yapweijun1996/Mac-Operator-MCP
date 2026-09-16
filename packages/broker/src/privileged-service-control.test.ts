import assert from "node:assert/strict";
import test from "node:test";
import { canonicalJson, CONTRACT_VERSION, sha256, BrokerError } from "@mac-operator/contracts";
import {
  PrivilegedServiceControlAdapter,
  type PrivilegedServiceControlCommandRunner
} from "./privileged-service-control.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";
import type { SafeServiceStatus, ServiceInspector } from "./service-inspector.js";
import type { UnsignedPrivilegedHelperCommand } from "./privileged-helper.js";

const NOW = 1_700_000_000_000;

function command(action: "start" | "stop" | "restart" | "enable" | "disable" = "start", expectedState?: "running" | "stopped" | "enabled" | "disabled"): UnsignedPrivilegedHelperCommand {
  const payload = {
    operation: "service_control" as const,
    service_id: "system/com.example.test",
    action,
    ...(expectedState === undefined ? {} : { expected_state: expectedState })
  };
  return {
    protocolVersion: "0.1",
    contractVersion: CONTRACT_VERSION,
    commandId: "priv-command:test-service-control-1",
    requestId: "request:test-service-control-1",
    nonce: "helper-nonce-test-service-control-1",
    nonceExpiresAtMs: NOW + 30_000,
    timestampMs: NOW,
    expiresAtMs: NOW + 30_000,
    operation: "service_control",
    targetRef: "service:system/com.example.test",
    payload,
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: "policy-test-1",
    approvalId: "approval:test-service-control-1",
    intentId: "intent:test-service-control-1"
  };
}

function status(state: SafeServiceStatus["state"]): SafeServiceStatus {
  return {
    serviceId: "system/com.example.test",
    loaded: state !== "unknown",
    running: state === "running",
    state,
    lastExitCode: null,
    pid: state === "running" ? 1234 : null,
    warnings: [],
    truncated: false
  };
}

function successfulProcessResult(): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
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

function adapterFixture(states: SafeServiceStatus["state"][], commands: ProcessExecutionRequest[] = []): PrivilegedServiceControlAdapter {
  const inspector: ServiceInspector = {
    inspect: async () => {
      const next = states.shift();
      if (next === undefined) throw new BrokerError("EXECUTION_FAILED", "fixture readback exhausted");
      return status(next);
    }
  };
  const commandRunner: PrivilegedServiceControlCommandRunner = {
    run: async (request) => {
      commands.push(request);
      return successfulProcessResult();
    }
  };
  return new PrivilegedServiceControlAdapter({ enabled: true, commandRunner, inspector, now: () => NOW });
}

test("privileged service-control adapter is disabled by default", () => {
  const adapter = new PrivilegedServiceControlAdapter();
  assert.equal(adapter.available, false);
  assert.deepEqual(adapter.enabledCapabilities, []);
});

test("privileged service-control adapter uses fixed argv and verifies the postcondition", async () => {
  const commands: ProcessExecutionRequest[] = [];
  const adapter = adapterFixture(["stopped", "running"], commands);
  const result = await adapter.execute(command("start", "running"), { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.verification.status, "verified");
  assert.deepEqual(result.evidence, { pre_state: "stopped", post_state: "running", idempotent: false });
  assert.equal(commands.length, 1);
  assert.deepEqual(commands[0]?.args, ["kickstart", "system/com.example.test"]);
  assert.equal(commands[0]?.executable, "/bin/launchctl");
  assert.equal(commands[0]?.cwd, "/");
  assert.deepEqual(commands[0]?.environment, {});
  assert.equal(commands[0]?.outputCapBytes, 128 * 1024);
});

test("privileged service-control adapter is idempotent when the requested state already holds", async () => {
  const commands: ProcessExecutionRequest[] = [];
  const adapter = adapterFixture(["running", "running"], commands);
  const result = await adapter.execute(command("start", "running"), { timeoutMs: 5_000, shouldCancel: () => false });
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.evidence.idempotent, true);
  assert.equal(commands.length, 0);
});

test("privileged service-control adapter never publishes an unverifiable state", async () => {
  const commands: ProcessExecutionRequest[] = [];
  const adapter = adapterFixture(["stopped", "failed"], commands);
  const result = await adapter.execute(command("start", "running"), { timeoutMs: 5_000, shouldCancel: () => false });
  assert.equal(result.resultClass, "VERIFICATION_FAILED");
  assert.equal(result.state, "failed");
  assert.equal(result.verification.status, "failed");
  assert.equal(commands.length, 1);
});

test("privileged service-control adapter rejects unsupported actions and cancellation before launch", async () => {
  const commands: ProcessExecutionRequest[] = [];
  const unsupported = adapterFixture(["stopped"], commands);
  await assert.rejects(
    () => unsupported.execute(command("enable"), { timeoutMs: 5_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNSUPPORTED_CAPABILITY"
  );
  assert.equal(commands.length, 0);

  const cancelled = adapterFixture(["stopped"], commands);
  await assert.rejects(
    () => cancelled.execute(command("start"), { timeoutMs: 5_000, shouldCancel: () => true }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
  assert.equal(commands.length, 0);
});

test("privileged service-control adapter requires a matching expected state", async () => {
  const adapter = adapterFixture(["stopped"]);
  await assert.rejects(
    () => adapter.execute(command("start", "stopped"), { timeoutMs: 5_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});
