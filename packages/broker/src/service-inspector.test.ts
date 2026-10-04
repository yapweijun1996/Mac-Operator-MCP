import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { LaunchdServiceInspector, parseLaunchdEnablementStatus, validateServiceId } from "./service-inspector.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

test("launchd service inspector returns bounded status for an allowlisted system service", async () => {
  const inspector = new LaunchdServiceInspector();
  const status = await inspector.inspect("system/com.apple.logd", {
    timeoutMs: 5_000,
    shouldCancel: () => false
  });
  assert.equal(status.serviceId, "system/com.apple.logd");
  assert.equal(status.loaded, true);
  assert.ok(["loaded", "running", "stopped", "failed", "unknown"].includes(status.state));
  assert.equal(status.running, status.state === "running");
  assert.ok(status.pid === null || (Number.isSafeInteger(status.pid) && status.pid > 0 && status.pid <= 99_999_999));
  assert.ok(status.lastExitCode === null || Number.isSafeInteger(status.lastExitCode));
  assert.equal(status.truncated, false);
});

test("launchd service identifiers reject traversal and non-system domains", () => {
  assert.doesNotThrow(() => validateServiceId("system/com.apple.logd"));
  for (const serviceId of ["", "user/501/com.example", "system/../x", "system//x", "system/x\\y", "system/"]) {
    assert.throws(() => validateServiceId(serviceId), /system\/<launchd-label>/u);
  }
});

test("launchd service identifiers reject labels longer than the readback contract before execution", async () => {
  const serviceId = `system/${"a".repeat(129)}`;
  let invocations = 0;
  const executor = {
    async run(): Promise<ProcessExecutionResult> {
      invocations += 1;
      throw new Error("unexpected launchctl invocation");
    }
  } as never;
  await assert.rejects(
    new LaunchdServiceInspector(executor).inspect(serviceId, { timeoutMs: 5_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  assert.equal(invocations, 0);
});

test("launchd enablement readback parses exact system overrides and defaults absent entries to enabled", () => {
  const output = [
    "disabled services = {",
    '\t"com.example.enabled" => enabled',
    '\t"com.example.disabled" => disabled',
    "}"
  ].join("\n");
  assert.equal(parseLaunchdEnablementStatus("system/com.example.enabled", output), "enabled");
  assert.equal(parseLaunchdEnablementStatus("system/com.example.disabled", output), "disabled");
  assert.equal(parseLaunchdEnablementStatus("system/com.example.no-override", output), "enabled");
});

test("launchd enablement parser fails closed on malformed, duplicate, or non-system output", () => {
  const malformedOutputs = [
    "",
    "disabled services = {\n\tcom.example.disabled => disabled\n}",
    'disabled services = {\n\t"com.example.disabled" => disabled\n\t"com.example.disabled" => enabled\n}',
    'disabled services = {\n\t"com.example.disabled" => maybe\n}'
  ];
  for (const output of malformedOutputs) {
    assert.throws(
      () => parseLaunchdEnablementStatus("system/com.example.disabled", output),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
    );
  }
  assert.throws(
    () => parseLaunchdEnablementStatus("gui/501/com.example.disabled", "disabled services = {\n}\n"),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});

test("launchd service inspector reads enablement through fixed bounded launchctl argv", async () => {
  let request: { executable: string; args: readonly string[]; cwd: string; environment: Readonly<Record<string, string>>; timeoutMs: number; outputCapBytes: number } | undefined;
  const executor = {
    async run(value: typeof request): Promise<ProcessExecutionResult> {
      request = value;
      return {
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        signal: null,
        stdout: 'disabled services = {\n\t"com.example.disabled" => disabled\n}',
        stderr: "",
        truncated: false,
        durationMs: 1,
        processId: 1,
        processGroupId: 1,
        terminationObserved: true
      };
    }
  } as never;
  const state = await new LaunchdServiceInspector(executor).inspectEnablement("system/com.example.disabled", {
    timeoutMs: 10_000,
    shouldCancel: () => false
  });
  assert.equal(state, "disabled");
  assert.equal(request?.executable, "/bin/launchctl");
  assert.deepEqual(request?.args, ["print-disabled", "system"]);
  assert.equal(request?.cwd, "/");
  assert.deepEqual(request?.environment, {});
  assert.equal(request?.timeoutMs, 5_000);
  assert.equal(request?.outputCapBytes, 128 * 1024);
});

test("launchd service inspector accepts current host enablement readback", async () => {
  const state = await new LaunchdServiceInspector().inspectEnablement("system/com.apple.logd", {
    timeoutMs: 5_000,
    shouldCancel: () => false
  });
  assert.ok(state === "enabled" || state === "disabled");
});

test("launchd service inspector treats xpcproxy as loaded, not running", async () => {
  const serviceId = "system/com.apple.logd";
  const executor = {
    async run(): Promise<ProcessExecutionResult> {
      return {
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        signal: null,
        stdout: `${serviceId} = {\n\ttype = LaunchDaemon\n\tstate = xpcproxy\n\tpid = 4123\n\tlast exit code = (never exited)\n}`,
        stderr: "",
        truncated: false,
        durationMs: 1,
        processId: 1,
        processGroupId: 1,
        terminationObserved: true
      };
    }
  } as never;
  const status = await new LaunchdServiceInspector(executor).inspect(serviceId, {
    timeoutMs: 5_000,
    shouldCancel: () => false
  });
  assert.equal(status.state, "loaded");
  assert.equal(status.running, false);
  assert.equal(status.pid, 4123);
});

test("launchd service inspector rejects forged or conflicting readback fields", async () => {
  const serviceId = "system/com.apple.logd";
  const outputs = [
    `${serviceId} = {\n\ttype = LaunchDaemon\n\tstate = running\n\tstate = stopped\n\tpid = 4123\n}`,
    `${serviceId} = {\n\ttype = LaunchDaemon\n\tstate = running\n\tpid = 4123\n\t}\n\tstate = failed\n}`,
    "system/com.apple.other = {\n\ttype = LaunchDaemon\n\tstate = running\n\tpid = 4123\n}"
  ];
  for (const stdout of outputs) {
    const executor = {
      async run(): Promise<ProcessExecutionResult> {
        return {
          state: "completed",
          resultClass: "SUCCEEDED",
          exitCode: 0,
          signal: null,
          stdout,
          stderr: "",
          truncated: false,
          durationMs: 1,
          processId: 1,
          processGroupId: 1,
          terminationObserved: true
        };
      }
    } as never;
    await assert.rejects(
      new LaunchdServiceInspector(executor).inspect(serviceId, { timeoutMs: 5_000, shouldCancel: () => false }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
    );
  }
});

test("launchd service inspector rejects a system readback without LaunchDaemon identity", async () => {
  const serviceId = "system/com.apple.logd";
  const executor = {
    async run(): Promise<ProcessExecutionResult> {
      return {
        state: "completed",
        resultClass: "SUCCEEDED",
        exitCode: 0,
        signal: null,
        stdout: `${serviceId} = {\n\tstate = running\n\tpid = 4123\n}`,
        stderr: "",
        truncated: false,
        durationMs: 1,
        processId: 1,
        processGroupId: 1,
        terminationObserved: true
      };
    }
  } as never;
  await assert.rejects(
    new LaunchdServiceInspector(executor).inspect(serviceId, { timeoutMs: 5_000, shouldCancel: () => false }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "EXECUTION_FAILED"
  );
});
