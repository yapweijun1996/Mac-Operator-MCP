import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  LaunchdUserServiceReadbackObserver,
  UserServiceControlAdapter,
  type UserServiceBinding,
  type UserServiceControlCommandRunner,
  type UserServiceReadback,
  type UserServiceReadbackObserver
} from "./user-service-control.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";

const UID = typeof process.getuid === "function" && process.getuid() > 0 ? process.getuid() : 501;
const SERVICE_ID = `gui/${UID}/com.mac-operator.test`;
const SOURCE_REVISION = "0123456789abcdef";

const binding: UserServiceBinding = {
  serviceId: SERVICE_ID,
  sourceRevision: SOURCE_REVISION,
  plistPath: "/Users/operator/Library/LaunchAgents/com.mac-operator.test.plist",
  program: "/Users/operator/MacOperator/bin/node",
  arguments: ["/Users/operator/MacOperator/bin/node", "/Users/operator/MacOperator/service-entrypoint.js"]
};

function readback(state: "running" | "stopped" | "launching" | "waiting" | "loaded", sourceRevision = SOURCE_REVISION): UserServiceReadback {
  return {
    sourceRevision,
    launchd: {
      serviceId: SERVICE_ID,
      domain: `gui/${UID}`,
      label: "com.mac-operator.test",
      state,
      pid: state === "running" ? 4123 : null,
      program: binding.program,
      arguments: binding.arguments,
      plistPath: binding.plistPath,
      type: "LaunchAgent",
      lastExitCode: null,
      truncated: false
    }
  };
}

function successfulResult(): ProcessExecutionResult {
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

function failedResult(): ProcessExecutionResult {
  return { ...successfulResult(), state: "failed", resultClass: "EXECUTION_FAILED", exitCode: 1, stderr: "launchctl failed" };
}

function fixture(readbacks: UserServiceReadback[], results: ProcessExecutionResult[] = []) {
  const commands: ProcessExecutionRequest[] = [];
  const inspector: UserServiceReadbackObserver = {
    inspect: async () => {
      const next = readbacks.shift();
      if (next === undefined) throw new BrokerError("EXECUTION_FAILED", "readback fixture exhausted");
      return next;
    }
  };
  const commandRunner: UserServiceControlCommandRunner = {
    run: async (request) => {
      commands.push(request);
      return results.shift() ?? successfulResult();
    }
  };
  const adapter = new UserServiceControlAdapter({
    enabled: true,
    uid: UID,
    bindings: [binding],
    commandRunner,
    inspector,
    now: () => 1_700_000_000_000
  });
  return { adapter, commands };
}

function control() {
  return { timeoutMs: 5_000, shouldCancel: () => false };
}

test("user service-control candidate is disabled without host seams", async () => {
  const adapter = new UserServiceControlAdapter({ uid: UID, bindings: [binding] });
  assert.equal(adapter.available, false);
  assert.deepEqual(adapter.enabledCapabilities, []);
  await assert.rejects(
    () => adapter.execute({ serviceId: SERVICE_ID, action: "start" }, control()),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNSUPPORTED_CAPABILITY"
  );
});

test("user service-control native wiring requires explicit system-published boundary acceptance", () => {
  const adapter = new UserServiceControlAdapter({
    enabled: true,
    uid: UID,
    bindings: [binding],
    sourceRevisionReader: { read: async () => SOURCE_REVISION }
  });
  assert.equal(adapter.available, false);
  assert.deepEqual(adapter.enabledCapabilities, []);
});

test("user service-control rejects ambiguous native and injected command wiring", () => {
  assert.throws(
    () => new UserServiceControlAdapter({
      enabled: true,
      uid: UID,
      bindings: [binding],
      commandRunner: { run: async () => successfulResult() },
      descriptorSpawnAdapter: {
        mechanism: "darwin-descriptor-exec-v1",
        spawn: () => { throw new Error("unused"); }
      }
    }),
    /mutually exclusive/u
  );
});

test("user service-control host observer uses shared launchd parsing and source revision readback", async () => {
  const commands: ProcessExecutionRequest[] = [];
  const observer = new LaunchdUserServiceReadbackObserver(
    {
      run: async (request) => {
        commands.push(request);
        return {
          ...successfulResult(),
          stdout: `${SERVICE_ID} = {\n\ttype = LaunchAgent\n\tstate = not running\n\tpath = ${binding.plistPath}\n\tprogram = ${binding.program}\n\targuments = {\n\t${binding.program}\n\t${binding.arguments[1]}\n\t}\n\tlast exit code = 0\n}`
        };
      }
    },
    { read: async () => SOURCE_REVISION }
  );
  const result = await observer.inspect(SERVICE_ID, { timeoutMs: 1_000, shouldCancel: () => false });
  assert.equal(result.launchd.state, "stopped");
  assert.equal(result.sourceRevision, SOURCE_REVISION);
  assert.equal(commands[0]?.args[0], "print");
  assert.equal(typeof commands[0]?.shouldCancel, "function");
});

test("user service-control candidate captures a stable precondition and rejects a changed one", async () => {
  const captured = fixture([readback("stopped")]);
  const precondition = await captured.adapter.readPrecondition({ serviceId: SERVICE_ID, action: "start" }, control());
  assert.deepEqual(precondition, { state: "stopped", sourceRevision: SOURCE_REVISION });

  const changed = fixture([readback("stopped")]);
  await assert.rejects(
    () => changed.adapter.execute(
      { serviceId: SERVICE_ID, action: "start" },
      control(),
      { state: "running", sourceRevision: SOURCE_REVISION }
    ),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
  );
  assert.equal(changed.commands.length, 0);
});

test("user service-control candidate uses an exact user-domain target and fixed argv", async () => {
  const { adapter, commands } = fixture([readback("stopped"), readback("running")]);
  const result = await adapter.execute({ serviceId: SERVICE_ID, action: "start", expectedState: "running" }, control());
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.verification.status, "verified");
  assert.deepEqual(commands[0]?.args, ["kickstart", SERVICE_ID]);
  assert.equal(commands[0]?.executable, "/bin/launchctl");
  assert.equal(commands[0]?.cwd, "/");
  assert.deepEqual(commands[0]?.environment, {});
  assert.equal(commands[0]?.outputCapBytes, 128 * 1024);
});

test("user service-control candidate settles transient launchd post-state before verification", async () => {
  const { adapter, commands } = fixture([readback("stopped"), readback("launching"), readback("running")]);
  const result = await adapter.execute({ serviceId: SERVICE_ID, action: "start", expectedState: "running" }, control());
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.postState, "running");
  assert.equal(result.verification.status, "verified");
  assert.equal(commands.length, 1);
});

test("user service-control candidate is idempotent when the desired state already holds", async () => {
  const { adapter, commands } = fixture([readback("running"), readback("running")]);
  const result = await adapter.execute({ serviceId: SERVICE_ID, action: "start" }, control());
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.idempotent, true);
  assert.equal(commands.length, 0);
});

test("user service-control candidate restores the pre-state after a postcondition mismatch", async () => {
  const { adapter, commands } = fixture([readback("stopped"), readback("stopped"), readback("stopped")]);
  const result = await adapter.execute({ serviceId: SERVICE_ID, action: "start" }, control());
  assert.equal(result.resultClass, "VERIFICATION_FAILED");
  assert.equal(result.rollback.status, "verified");
  assert.deepEqual(commands.map((command) => command.args), [
    ["kickstart", SERVICE_ID],
    ["kill", "SIGTERM", SERVICE_ID]
  ]);
});

test("user service-control candidate reports unknown when rollback cannot be verified", async () => {
  const { adapter } = fixture(
    [readback("stopped"), readback("stopped")],
    [successfulResult(), failedResult()]
  );
  const result = await adapter.execute({ serviceId: SERVICE_ID, action: "start" }, control());
  assert.equal(result.resultClass, "UNKNOWN_OUTCOME");
  assert.equal(result.state, "unknown");
  assert.equal(result.verification.status, "unknown");
});

test("user service-control candidate restores the pre-state after an uncertain command result", async () => {
  const { adapter, commands } = fixture(
    [readback("stopped"), readback("running"), readback("stopped")],
    [failedResult(), successfulResult()]
  );
  const result = await adapter.execute({ serviceId: SERVICE_ID, action: "start" }, control());
  assert.equal(result.resultClass, "UNKNOWN_OUTCOME");
  assert.equal(result.rollback.status, "verified");
  assert.deepEqual(commands.map((command) => command.args), [
    ["kickstart", SERVICE_ID],
    ["kill", "SIGTERM", SERVICE_ID]
  ]);
});

test("user service-control candidate rejects system, root, unbound, and source-swapped targets", async () => {
  const { adapter } = fixture([readback("stopped")]);
  await assert.rejects(
    () => adapter.execute({ serviceId: "system/com.example.test", action: "start" }, control()),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  await assert.rejects(
    () => adapter.execute({ serviceId: `gui/${UID}/com.mac-operator.other`, action: "start" }, control()),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "TARGET_NOT_FOUND"
  );
  await assert.rejects(
    () => adapter.execute({ serviceId: "gui/0/com.mac-operator.root", action: "start" }, control()),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );

  const sourceSwap = fixture([readback("stopped", "fedcba9876543210")]);
  await assert.rejects(
    () => sourceSwap.adapter.execute({ serviceId: SERVICE_ID, action: "start" }, control()),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});

test("user service-control candidate rejects cancellation and unsupported actions before dispatch", async () => {
  const { adapter, commands } = fixture([readback("stopped")]);
  await assert.rejects(
    () => adapter.execute({ serviceId: SERVICE_ID, action: "enable" as never }, control()),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNSUPPORTED_CAPABILITY"
  );
  await assert.rejects(
    () => adapter.execute({ serviceId: SERVICE_ID, action: "start" }, { timeoutMs: 5_000, shouldCancel: () => true }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
  assert.equal(commands.length, 0);
});
