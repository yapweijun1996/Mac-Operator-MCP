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

function adapterFixture(
  states: SafeServiceStatus["state"][],
  commands: ProcessExecutionRequest[] = [],
  enablementStates: ("enabled" | "disabled")[] = [],
  commandResult: ProcessExecutionResult = successfulProcessResult()
): PrivilegedServiceControlAdapter {
  const inspector: ServiceInspector = {
    inspect: async () => {
      const next = states.shift();
      if (next === undefined) throw new BrokerError("EXECUTION_FAILED", "fixture readback exhausted");
      return status(next);
    },
    inspectEnablement: async () => {
      const next = enablementStates.shift();
      if (next === undefined) throw new BrokerError("EXECUTION_FAILED", "fixture enablement readback exhausted");
      return next;
    }
  };
  const commandRunner: PrivilegedServiceControlCommandRunner = {
    run: async (request) => {
      commands.push(request);
      return commandResult;
    }
  };
  return new PrivilegedServiceControlAdapter({ enabled: true, commandRunner, inspector, now: () => NOW });
}

test("privileged service-control adapter is disabled by default", () => {
  const adapter = new PrivilegedServiceControlAdapter();
  assert.equal(adapter.available, false);
  assert.deepEqual(adapter.enabledCapabilities, []);
});

test("privileged service-control native wiring requires explicit fixed launchctl boundary acceptance", () => {
  const adapter = new PrivilegedServiceControlAdapter({
    enabled: true,
    systemPublishedExecutablePathAccepted: true
  });
  const runningAsRoot = typeof process.getuid === "function" && process.getuid() === 0;
  assert.equal(adapter.available, runningAsRoot && process.platform === "darwin");
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

test("privileged service-control adapter rejects missing enablement readback and cancellation before launch", async () => {
  const commands: ProcessExecutionRequest[] = [];
  const unsupported = new PrivilegedServiceControlAdapter({
    enabled: true,
    commandRunner: { run: async (request) => { commands.push(request); return successfulProcessResult(); } },
    inspector: { inspect: async () => status("stopped") }
  });
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

test("privileged service enablement uses fixed actions, idempotency, and verified readback", async () => {
  const commands: ProcessExecutionRequest[] = [];
  const enabling = adapterFixture([], commands, ["disabled", "enabled"]);
  const enabled = await enabling.execute(command("enable", "enabled"), { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(enabled.resultClass, "SUCCEEDED");
  assert.equal(enabled.verification.status, "verified");
  assert.deepEqual(enabled.evidence, { pre_state: "disabled", post_state: "enabled", idempotent: false });
  assert.deepEqual(commands[0]?.args, ["enable", "system/com.example.test"]);
  assert.equal(commands[0]?.executable, "/bin/launchctl");
  assert.deepEqual(commands[0]?.environment, {});

  const disabling = adapterFixture([], commands, ["enabled", "disabled"]);
  const disabled = await disabling.execute(command("disable", "disabled"), { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(disabled.resultClass, "SUCCEEDED");
  assert.deepEqual(disabled.evidence, { pre_state: "enabled", post_state: "disabled", idempotent: false });
  assert.deepEqual(commands[1]?.args, ["disable", "system/com.example.test"]);

  const alreadyDisabled = adapterFixture([], commands, ["disabled", "disabled"]);
  const unchanged = await alreadyDisabled.execute(command("disable", "disabled"), { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(unchanged.resultClass, "SUCCEEDED");
  assert.equal(unchanged.evidence.idempotent, true);
  assert.equal(commands.length, 2);
});

test("privileged service enablement refuses an unverifiable postcondition", async () => {
  const commands: ProcessExecutionRequest[] = [];
  const adapter = adapterFixture([], commands, ["disabled", "disabled"]);
  const result = await adapter.execute(command("enable", "enabled"), { timeoutMs: 10_000, shouldCancel: () => false });
  assert.equal(result.resultClass, "VERIFICATION_FAILED");
  assert.equal(result.verification.status, "failed");
  assert.deepEqual(commands[0]?.args, ["enable", "system/com.example.test"]);
});

test("privileged service mutations classify interrupted command outcomes as unknown", async () => {
  const interruptedResults: ProcessExecutionResult["resultClass"][] = ["CANCELLED", "TIMEOUT", "OUTPUT_LIMIT", "UNKNOWN_OUTCOME"];
  for (const resultClass of interruptedResults) {
    const commands: ProcessExecutionRequest[] = [];
    const result = { ...successfulProcessResult(), resultClass } as ProcessExecutionResult;
    const adapter = adapterFixture([], commands, ["disabled"], result);
    await assert.rejects(
      () => adapter.execute(command("enable", "enabled"), { timeoutMs: 10_000, shouldCancel: () => false }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME"
    );
    assert.equal(commands.length, 1);
  }
});

test("privileged service Job readback verifies enabled and disabled postconditions", async () => {
  const makeReadbackRequest = (action: "enable" | "disable", expected: "enabled" | "disabled") => {
    const value = command(action, expected);
    return {
      protocolVersion: value.protocolVersion,
      contractVersion: value.contractVersion,
      requestId: "request:readback-service-control-1",
      nonce: "readback-nonce-service-control-1",
      timestampMs: NOW,
      expiresAtMs: NOW + 30_000,
      kind: "job_readback" as const,
      jobId: "job:service-control-1",
      principalId: "principal-service-control-1",
      sessionId: "session-service-control-1",
      operation: "service_control" as const,
      targetRef: value.targetRef,
      payload: value.payload,
      payloadDigest: value.payloadDigest,
      policyVersion: value.policyVersion
    };
  };
  const enabling = adapterFixture([], [], ["enabled"]);
  const enabled = await enabling.readback(makeReadbackRequest("enable", "enabled"), { timeoutMs: 5_000, shouldCancel: () => false });
  assert.equal(enabled.postcondition, "matches");
  assert.equal(enabled.evidence.post_state, "enabled");

  const disabling = adapterFixture([], [], ["enabled"]);
  const disabled = await disabling.readback(makeReadbackRequest("disable", "disabled"), { timeoutMs: 5_000, shouldCancel: () => false });
  assert.equal(disabled.postcondition, "mismatch");
});

test("privileged service-control adapter requires a matching expected state", async () => {
  const adapter = adapterFixture(["stopped"]);
  await assert.rejects(
    () => adapter.execute(command("start", "stopped"), { timeoutMs: 5_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});
