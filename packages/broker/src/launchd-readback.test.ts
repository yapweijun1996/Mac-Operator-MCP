import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  LaunchdReadbackError,
  parseLaunchdJobReadback,
  readLaunchdJobReadback,
  validateLaunchdReadbackServiceId
} from "./launchd-readback.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";

test("launchd readback uses fixed argv, empty environment, and returns bounded metadata", async () => {
  const serviceId = "gui/501/com.mac-operator.broker";
  const executor = new FakeExecutor(success(`${serviceId} = {
\ttype = LaunchAgent
\tpath = /Users/operator/Library/LaunchAgents/com.mac-operator.broker.plist
\tstate = running
\tprogram = /Users/operator/Library/Application Support/MacOperator/bin/node
\targuments = {
\t/Users/operator/Library/Application Support/MacOperator/bin/node
\t/Users/operator/Library/Application Support/MacOperator/service-entrypoint.js
\t}
\tpid = 4123
\tlast exit code = (never exited)
}
`));
  const readback = await readLaunchdJobReadback(serviceId, { executor });
  assert.deepEqual(readback, {
    serviceId,
    domain: "gui/501",
    label: "com.mac-operator.broker",
    state: "running",
    pid: 4123,
    program: "/Users/operator/Library/Application Support/MacOperator/bin/node",
    arguments: [
      "/Users/operator/Library/Application Support/MacOperator/bin/node",
      "/Users/operator/Library/Application Support/MacOperator/service-entrypoint.js"
    ],
    plistPath: "/Users/operator/Library/LaunchAgents/com.mac-operator.broker.plist",
    type: "LaunchAgent",
    lastExitCode: null,
    truncated: false
  });
  assert.deepEqual(executor.commands[0], {
    executable: "/bin/launchctl",
    args: ["print", serviceId],
    cwd: "/",
    environment: {},
    timeoutMs: 5_000,
    outputCapBytes: 131_072
  });
});

test("launchd readback rejects identity, traversal, path, and state substitution", () => {
  assert.doesNotThrow(() => validateLaunchdReadbackServiceId("system/com.apple.logd"));
  assert.doesNotThrow(() => validateLaunchdReadbackServiceId("gui/501/com.mac-operator.broker"));
  for (const serviceId of ["", "system/../x", "system//x", "system/x\\y", "user/501/com.example", "gui/0/com.example"]) {
    assert.throws(() => validateLaunchdReadbackServiceId(serviceId), (error: unknown) =>
      error instanceof LaunchdReadbackError && error.code === "INVALID_SERVICE"
    );
  }
  const serviceId = "system/com.apple.logd";
  assert.throws(
    () => parseLaunchdJobReadback(serviceId, "system/com.apple.other = {\n\tstate = running\n}"),
    (error: unknown) => error instanceof LaunchdReadbackError && error.code === "MALFORMED_READBACK"
  );
  assert.throws(
    () => parseLaunchdJobReadback(serviceId, `${serviceId} = {\n\tstate = running\n\tprogram = relative\n}`),
    (error: unknown) => error instanceof LaunchdReadbackError && error.code === "MALFORMED_READBACK"
  );
  assert.throws(
    () => parseLaunchdJobReadback(serviceId, `${serviceId} = {\n\tstate = running\n\tprogram = /tmp/../private\n}`),
    (error: unknown) => error instanceof LaunchdReadbackError && error.code === "MALFORMED_READBACK"
  );
  assert.throws(
    () => parseLaunchdJobReadback(serviceId, `${serviceId} = {\n\tstate = attacker-controlled\n}`),
    (error: unknown) => error instanceof LaunchdReadbackError && error.code === "MALFORMED_READBACK"
  );
  assert.throws(
    () => parseLaunchdJobReadback(serviceId, `${serviceId} = {\n\ttype = LaunchAgent\n\tstate = running\n}`),
    (error: unknown) => error instanceof LaunchdReadbackError && error.code === "MALFORMED_READBACK"
  );
  const guiServiceId = "gui/501/com.mac-operator.broker";
  assert.throws(
    () => parseLaunchdJobReadback(guiServiceId, `${guiServiceId} = {\n\ttype = LaunchAgent\n\tstate = running\n\tprogram = /bin/node\n\targuments = {\n\t/bin/sh\n\t}\n}`),
    (error: unknown) => error instanceof LaunchdReadbackError && error.code === "MALFORMED_READBACK"
  );
});

test("launchd readback rejects duplicate singleton fields and argument blocks", () => {
  const serviceId = "gui/501/com.mac-operator.broker";
  const duplicateState = `${serviceId} = {\n\ttype = LaunchAgent\n\tstate = running\n\tstate = stopped\n}`;
  assert.throws(
    () => parseLaunchdJobReadback(serviceId, duplicateState),
    (error: unknown) => error instanceof LaunchdReadbackError && error.code === "MALFORMED_READBACK"
  );
  const duplicateProgram = `${serviceId} = {\n\ttype = LaunchAgent\n\tstate = running\n\tprogram = /bin/node\n\tprogram = /bin/sh\n}`;
  assert.throws(
    () => parseLaunchdJobReadback(serviceId, duplicateProgram),
    (error: unknown) => error instanceof LaunchdReadbackError && error.code === "MALFORMED_READBACK"
  );
  const duplicateArguments = `${serviceId} = {\n\ttype = LaunchAgent\n\tstate = running\n\targuments = {\n\t/bin/node\n\t}\n\targuments = {\n\t/bin/node\n\t}\n}`;
  assert.throws(
    () => parseLaunchdJobReadback(serviceId, duplicateArguments),
    (error: unknown) => error instanceof LaunchdReadbackError && error.code === "MALFORMED_READBACK"
  );
});

test("launchd readback does not treat an argument value as a service field", () => {
  const serviceId = "gui/501/com.mac-operator.broker";
  const readback = parseLaunchdJobReadback(serviceId, `${serviceId} = {\n\ttype = LaunchAgent\n\tstate = running\n\tprogram = /bin/node\n\targuments = {\n\t/bin/node\n\tstate = running\n\t}\n\tpid = 4123\n}`);
  assert.equal(readback.state, "running");
  assert.deepEqual(readback.arguments, ["/bin/node", "state = running"]);
});

test("launchd readback normalizes macOS xpcproxy bootstrap state without claiming running", () => {
  const serviceId = "gui/501/com.mac-operator.broker";
  const readback = parseLaunchdJobReadback(serviceId, `${serviceId} = {\n\ttype = LaunchAgent\n\tstate = xpcproxy\n\tprogram = /bin/sleep\n\targuments = {\n\t/bin/sleep\n\t30\n\t}\n\tpid = 4123\n}`);
  assert.equal(readback.state, "launching");
  assert.equal(readback.pid, 4123);
  assert.equal(readback.type, "LaunchAgent");
  assert.deepEqual(readback.arguments, ["/bin/sleep", "30"]);
});

test("launchd readback normalizes the macOS not-running state to stopped", () => {
  const serviceId = "gui/501/com.mac-operator.test";
  const readback = parseLaunchdJobReadback(serviceId, `${serviceId} = {\n\ttype = LaunchAgent\n\tstate = not running\n}`);
  assert.equal(readback.state, "stopped");
});

test("launchd readback preserves stable Broker cancellation errors from its executor", async () => {
  await assert.rejects(
    () => readLaunchdJobReadback("gui/501/com.mac-operator.test", {
      executor: { run: async () => { throw new BrokerError("CANCELLED", "cancelled"); } }
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
});

test("launchd readback smoke reads an existing system service on macOS", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("launchd readback is a macOS host boundary");
    return;
  }
  const readback = await readLaunchdJobReadback("system/com.apple.logd");
  assert.equal(readback.serviceId, "system/com.apple.logd");
  assert.equal(readback.domain, "system");
  assert.equal(readback.label, "com.apple.logd");
  assert.ok(["running", "stopped", "waiting", "launching", "loaded", "failed", "unknown"].includes(readback.state));
  assert.ok(readback.pid === null || (Number.isSafeInteger(readback.pid) && readback.pid > 0));
  assert.ok(readback.program === null || readback.program.startsWith("/"));
  assert.ok(readback.arguments === null || readback.arguments.length > 0);
  assert.ok(readback.plistPath === null || readback.plistPath.startsWith("/"));
});

class FakeExecutor {
  readonly commands: ProcessExecutionRequest[] = [];

  constructor(private readonly result: ProcessExecutionResult) {}

  async run(command: ProcessExecutionRequest): Promise<ProcessExecutionResult> {
    this.commands.push(command);
    return this.result;
  }
}

function success(stdout: string): ProcessExecutionResult {
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
