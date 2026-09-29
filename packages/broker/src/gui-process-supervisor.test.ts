import assert from "node:assert/strict";
import test from "node:test";
import { GuiProcessSupervisor, guiApplicationExecutable, guiLauncherExecutable } from "./gui-process-supervisor.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";

test("GUI transport keeps input off argv and preserves cancellation and execution limits", async () => {
  let received: ProcessExecutionRequest | undefined;
  const result = { resultClass: "CANCELLED" } as ProcessExecutionResult;
  const supervisor = new GuiProcessSupervisor({ run: async (request) => { received = request; return result; } });
  const shouldCancel = () => true;
  const request: ProcessExecutionRequest = {
    executable: guiApplicationExecutable, args: ["type", "visual", "com.google.Chrome", "Test"],
    stdin: '{"text":"test text"}', cwd: "/", timeoutMs: 1234, outputCapBytes: 5678, shouldCancel
  };
  assert.equal(await supervisor.run(request), result);
  assert.equal(received?.executable, guiLauncherExecutable);
  assert.deepEqual(received?.args, []);
  assert.deepEqual(JSON.parse(received?.stdin ?? ""), { args: request.args, stdin: request.stdin });
  assert.equal(received?.shouldCancel, shouldCancel);
  assert.equal(received?.timeoutMs, 1234);
  assert.equal(received?.outputCapBytes, 5678);
});

test("non-GUI executables retain the exact original request", async () => {
  const request: ProcessExecutionRequest = { executable: "/usr/bin/osascript", args: [], cwd: "/", timeoutMs: 1000, outputCapBytes: 1024 };
  const supervisor = new GuiProcessSupervisor({ run: async (actual) => {
    assert.equal(actual, request);
    return {} as ProcessExecutionResult;
  } });
  await supervisor.run(request);
});

test("GUI launcher respects the production root-ownership gate", { skip: process.platform !== "darwin" || process.env.MOP_REAL_GUI_TRANSPORT !== "1" }, async () => {
  const { ProcessSupervisor } = await import("./process-supervisor.js");
  const blocked = new GuiProcessSupervisor(new ProcessSupervisor({ requireRootOwnedExecutable: true }));
  const request: ProcessExecutionRequest = {
    executable: guiApplicationExecutable, args: ["permission"], cwd: "/", timeoutMs: 10000, outputCapBytes: 4096
  };
  await assert.rejects(blocked.run(request), /Executable is not root-owned/u);
  const allowed = new GuiProcessSupervisor(new ProcessSupervisor({
    requireRootOwnedExecutable: true, trustedUserOwnedExecutablePaths: [guiLauncherExecutable]
  }));
  const result = await allowed.run(request);
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.terminationObserved, true);
  assert.equal(JSON.parse(result.stdout).status, "ok");
});
