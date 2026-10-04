import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import { ContainerTaskRunner, type ContainerTaskRunnerOptions } from "./container-task-runner.js";
import {
  type ContainerCreateOptions, type ContainerTaskHandle, type ContainerEngineControl,
  type ContainerExecOptions, type ContainerExecResult, type ContainerEngineInfo
} from "./container-engine.js";
import { type CodexControllerRun, type CodexControllerResult, type CodexDynamicTool } from "./codex-controller.js";
import { createWorkspaceArchive, type ContainerSnapshot, type SnapshotFile } from "./container-snapshot.js";
import { type ContainerTaskJobMetadata } from "./container-job-metadata.js";
import { type ResolvedTaskProfile } from "./task-profile.js";
import { TASK_PHASE_KEYS, validateTaskExecutionResult, type TaskExecutionControl, type TaskExecutionResult, type TaskIsolationProof } from "./task-runner.js";

const IMAGE = `sha256:${"a".repeat(64)}`;
const ENGINE = "engine-unit-test";
const CID = "b".repeat(64);
const PROOF: TaskIsolationProof = {
  schemaVersion: "0.1", sandboxMechanism: "docker-container", sandboxProfile: "container-task-v1",
  filesystem: "enforced", network: "enforced", credentials: "isolated", persistence: "isolated",
  credentialIsolation: "docker-container-no-host-credentials-v1", processTree: "owned", processTreePolicy: "owned_group",
  evidenceRef: "docs/container-host-unit-test", containerImage: { imageId: IMAGE, engineId: ENGINE }
};
const COMMANDS = [
  { name: "test", projectRoot: "/unit/project", executable: "/usr/local/bin/node", args: ["--test"], kind: "test" as const },
  { name: "build", projectRoot: "/unit/project", executable: "/usr/local/bin/node", args: ["build.mjs"], kind: "build" as const }
];
const file = (path: string, content: string): SnapshotFile => ({ path, content: Buffer.from(content), sha256: sha256(content) });
const INPUT = [file("src/main.js", "export const value = 1;\n")];
const OUTPUT = [file("src/main.js", "export const value = 2;\n")];
function snapshot(root: string, readonlyWorkspace = false): ContainerSnapshot {
  return { root, files: INPUT, excluded: [".git", ".env"], archive: createWorkspaceArchive(INPUT, ["src"], readonlyWorkspace) };
}
function profile(cwd = "/unit/worktree", agent?: "readonly" | "workspace-write" | "test-only"): ResolvedTaskProfile {
  return { profile: "test", cwd, process: { executable: "/usr/local/bin/node", args: ["--test"], cwd, timeoutMs: 1000, outputCapBytes: 8192 },
    filesystemRoots: [cwd], networkPolicy: "none", networkAllowlist: [], credentialPolicy: "none", processTreePolicy: "owned_group",
    sandboxProfile: "container-task-v1", verificationStrategy: "exit_status_and_declared_task_verification",
    containerExecution: { imageId: IMAGE, engineId: ENGINE, projectRoot: "/unit/project", taskId: "task-unit", owner: "person@example.org", readonlyWorkspace: agent !== "workspace-write" && agent !== undefined,
      ...(agent === undefined ? {} : { agent: { task: "Update the isolated source and validate it.", executionProfile: agent, allowedPaths: ["src"] } }) } };
}
function control(events: string[] = [], callback?: TaskExecutionControl["onContainerCreated"]): TaskExecutionControl {
  return { timeoutMs: 1000, shouldCancel: () => false, onWorkspaceImport: () => {}, onContainerCreated: metadata => { events.push("persist"); callback?.(metadata); } };
}
function complete(output = "Task completed"): CodexControllerResult {
  return { status: "completed", output, toolCalls: [], reasonCodes: [], durationMs: 1 };
}
function errorClass(code: string): (error: unknown) => boolean {
  return error => error instanceof BrokerError && error.errorClass === code;
}
class FakeEngine {
  readonly events: string[] = [];
  readonly calls: Array<{ handle: ContainerTaskHandle; command: readonly string[]; signal?: AbortSignal }> = [];
  created: ContainerTaskHandle[] = [];
  result: ContainerExecResult = { exitCode: 0, stdout: "tests passed", stderr: "", truncated: false };
  failKill = false;
  absent = false;
  changedEngine = false;
  createsUnknown = false;
  uploaded?: Buffer;
  onExec?: (options: ContainerExecOptions, request: ContainerEngineControl) => Promise<ContainerExecResult>;
  async info(): Promise<ContainerEngineInfo> {
    this.events.push("info");
    return { id: this.changedEngine ? "different-engine" : ENGINE, serverVersion: "29", osType: "linux", architecture: "aarch64", securityOptions: [], cgroupVersion: "2" };
  }
  async inspectImage(): Promise<{ id: string; repoDigests: string[]; os: "linux"; architecture: string }> {
    this.events.push("image"); return { id: IMAGE, repoDigests: [], os: "linux", architecture: "arm64" };
  }
  async create(value: ContainerCreateOptions): Promise<ContainerTaskHandle> {
    this.events.push("create");
    if (this.createsUnknown) throw new BrokerError("UNKNOWN_OUTCOME", "Creation response was lost");
    const handle = Object.freeze({ id: this.created.length ? "c".repeat(64) : CID, imageId: IMAGE, engineId: ENGINE, taskId: value.taskId,
      owner: value.owner, nonce: value.nonce, readonlyWorkspace: value.readonlyWorkspace ?? false, maxRuntimeMs: value.maxRuntimeMs,
      memoryBytes: 512 * 1024 * 1024, nanoCpus: 1_000_000_000, pidsLimit: 128 });
    this.created.push(handle); return handle;
  }
  async start(handle: ContainerTaskHandle): Promise<{ id: string; running: boolean; status: string; exitCode: number; processId: number }> {
    this.events.push("start"); return { id: handle.id, running: true, status: "running", exitCode: 0, processId: 100 };
  }
  async inspect(handle: ContainerTaskHandle): Promise<{ id: string; running: boolean; status: string; exitCode: number; processId: number }> {
    return { id: handle.id, running: true, status: "running", exitCode: 0, processId: 100 };
  }
  async uploadArchive(_handle: ContainerTaskHandle, archive: Buffer): Promise<void> { this.events.push("upload"); this.uploaded = archive; }
  async downloadArchive(): Promise<Buffer> { this.events.push("download"); return createWorkspaceArchive(OUTPUT, ["src"]); }
  async exec(handle: ContainerTaskHandle, options: ContainerExecOptions, request: ContainerEngineControl = {}): Promise<ContainerExecResult> {
    this.events.push("exec"); this.calls.push({ handle, command: options.command, ...(request.signal ? { signal: request.signal } : {}) });
    return this.onExec ? this.onExec(options, request) : this.result;
  }
  async kill(handle: ContainerTaskHandle): Promise<{ id: string; running: boolean; status: string; exitCode: number; processId: number }> {
    this.events.push("kill");
    if (this.absent) throw new BrokerError("TARGET_NOT_FOUND", "Exact container is absent");
    if (this.failKill) throw new BrokerError("UNKNOWN_OUTCOME", "Stop is unverified");
    return { id: handle.id, running: false, status: "exited", exitCode: 137, processId: 0 };
  }
  async remove(): Promise<{ removed: true }> { this.events.push("remove"); return { removed: true }; }
}
function runner(engine = new FakeEngine(), options: Partial<ContainerTaskRunnerOptions> = {}): ContainerTaskRunner {
  return new ContainerTaskRunner({ engine, imageId: IMAGE, engineId: ENGINE, enabled: true, hostEvidenceAccepted: true,
    isolationProof: PROOF, registeredCommands: COMMANDS, snapshotProvider: snapshot, ...options });
}
async function waiting(_options: ContainerExecOptions, request: ContainerEngineControl): Promise<ContainerExecResult> {
  return new Promise((_resolve, reject) => {
    if (request.signal?.aborted) reject(new BrokerError("CANCELLED", "Cancelled"));
    else request.signal?.addEventListener("abort", () => reject(new BrokerError("CANCELLED", "Cancelled")), { once: true });
  });
}

/** The runner's own result must survive the Broker's validator, and its phases can never add up to more than the whole run. */
function assertPhaseTiming(result: TaskExecutionResult): Record<string, number> {
  assert.deepEqual(validateTaskExecutionResult(result), result);
  const phaseMs = result.phaseMs as Record<string, number>;
  assert.ok(phaseMs);
  for (const [phase, ms] of Object.entries(phaseMs)) {
    assert.ok((TASK_PHASE_KEYS as readonly string[]).includes(phase), phase);
    assert.ok(Number.isSafeInteger(ms) && ms >= 0, `${phase}: ${ms}`);
  }
  assert.ok(Object.values(phaseMs).reduce((sum, ms) => sum + ms, 0) <= result.durationMs);
  return phaseMs;
}
/**
 * A runner whose Engine, snapshot, controller and import steps each move a mocked wall clock by a fixed amount, so every phase
 * has an exact expected duration: create 3, start 5, snapshot 4, upload 7, exec 11, download 13, kill 2.
 */
function timedRunner(t: TestContext, engine: FakeEngine, options: Partial<ContainerTaskRunnerOptions> = {}): { task: ContainerTaskRunner; advance: (ms: number) => void } {
  let now = 1_000_000;
  t.mock.method(Date, "now", () => now);
  const advance = (ms: number): void => { now += ms; };
  const slow = <A extends unknown[], R>(operation: (...args: A) => Promise<R>, ms: number) => async (...args: A): Promise<R> => { advance(ms); return operation(...args); };
  engine.create = slow(engine.create.bind(engine), 3);
  engine.start = slow(engine.start.bind(engine), 5);
  engine.uploadArchive = slow(engine.uploadArchive.bind(engine), 7);
  engine.exec = slow(engine.exec.bind(engine), 11);
  engine.downloadArchive = slow(engine.downloadArchive.bind(engine), 13);
  engine.kill = slow(engine.kill.bind(engine), 2);
  return { advance, task: runner(engine, { snapshotProvider: (root, readonlyWorkspace) => { advance(4); return snapshot(root, readonlyWorkspace); }, ...options }) };
}

test("Container runner requires explicit accepted image/Engine evidence and never runs by default", async () => {
  assert.equal(new ContainerTaskRunner().available, false);
  for (const options of [{ enabled: false }, { hostEvidenceAccepted: false }, { imageId: `sha256:${"d".repeat(64)}` }, { engineId: "other" }]) {
    const engine = new FakeEngine(); const task = runner(engine, options);
    assert.equal(task.publicEnablement, "unavailable");
    await assert.rejects(task.run(profile(), control()), errorClass("POLICY_DENIED"));
    assert.deepEqual(engine.events, []);
  }
});

test("Container runner durably records exact identity before starting and passes only registered guest argv", async () => {
  const engine = new FakeEngine(); let persisted: Omit<ContainerTaskJobMetadata, "taskDescriptorDigest"> | undefined;
  const task = runner(engine);
  const result = await task.run(profile(), control(engine.events, metadata => { persisted = metadata; }));
  assert.equal(result.state, "completed"); assert.equal(result.containerCleanupVerified, true);
  assert.deepEqual(engine.events, ["info", "image", "create", "persist", "start", "upload", "exec", "info", "kill", "remove"]);
  assert.ok(persisted); assert.equal(persisted.containerId, CID); assert.match(persisted.nonce, /^[a-f0-9]{64}$/u);
  assert.equal(persisted.owner, "person@example.org"); assert.ok(persisted.deadlineAtMs > persisted.recordedAtMs);
  assert.ok(Object.isFrozen(persisted)); assert.deepEqual(engine.calls[0]!.command, ["/usr/local/bin/node", "--test"]);
  assert.deepEqual(result.changedPaths, []); assert.ok(engine.uploaded);
});

for (const callback of [() => { throw new Error("Persistence is unavailable"); }, () => Promise.resolve()]) {
  test(`Container runner fails closed before start when ownership persistence ${callback.toString().includes("throw") ? "throws" : "is asynchronous"}`, async () => {
    const engine = new FakeEngine(); const task = runner(engine);
    const result = await task.run(profile(), { timeoutMs: 1000, shouldCancel: () => false, onContainerCreated: callback });
    assert.equal(result.state, "unknown"); assert.equal(result.containerCleanupVerified, true);
    assert.ok(!engine.events.includes("start")); assert.ok(engine.events.includes("remove"));
  });
}

for (const mutate of [
  (p: ResolvedTaskProfile) => { p.process.args = ["-e", "process.exit(0)"]; },
  (p: ResolvedTaskProfile) => { p.networkPolicy = "allowlist"; p.networkAllowlist = ["tcp://localhost:1"]; },
  (p: ResolvedTaskProfile) => { p.filesystemRoots = [p.cwd, "/Users/example"]; },
  (p: ResolvedTaskProfile) => { p.process.environment = { OPENAI_API_KEY: "configured" }; },
  (p: ResolvedTaskProfile) => { p.containerExecution!.imageId = `sha256:${"d".repeat(64)}`; },
  (p: ResolvedTaskProfile) => { p.process.cwd = "/outside"; },
  (p: ResolvedTaskProfile) => { p.cwd = "/unit/../outside"; p.process.cwd = p.cwd; p.filesystemRoots = [p.cwd]; }
]) {
  test("Container runner rejects command, network, filesystem and image authority mismatches without creation", async () => {
    const engine = new FakeEngine(); const task = runner(engine); const p = profile(); mutate(p);
    await assert.rejects(async () => task.run(p, control()), errorClass("POLICY_DENIED")); assert.deepEqual(engine.events, []);
  });
}

test("Container registry rejects shell and sudo and caller cannot substitute an executable", async () => {
  for (const executable of ["/bin/sh", "/usr/bin/sudo", "/usr/bin/env", "node"]) {
    assert.throws(() => runner(new FakeEngine(), { registeredCommands: [{ name: "test", executable, args: [] }] }), errorClass("POLICY_DENIED"));
  }
  const engine = new FakeEngine(); const p = profile(); p.process.executable = "/bin/sh";
  await assert.rejects(async () => runner(engine).run(p, control()), errorClass("POLICY_DENIED")); assert.deepEqual(engine.events, []);
});

test("Ordinary validation source writes are ephemeral and a failed exit retains bounded evidence", async () => {
  const engine = new FakeEngine(); let imports = 0;
  const task = runner(engine, { importChanges: () => { imports++; return []; } });
  const success = await task.run(profile(), control());
  assert.equal(success.state, "completed"); assert.equal(imports, 0); assert.ok(!engine.events.includes("download"));
  engine.result = { exitCode: 3, stdout: "one test failed", stderr: "assertion failed", truncated: false };
  const failure = await task.run(profile(), control());
  assert.equal(failure.state, "failed"); assert.equal(failure.exitCode, 3); assert.equal(failure.stdout, "one test failed");
  assert.equal(failure.containerCleanupVerified, true); assert.equal(imports, 0);
});

test("Readonly snapshot and staging failures identify their trusted phase without forwarding backend messages", async () => {
  const backendMessage = "Private backend trace must not be forwarded: token=synthetic-backend-credential /Users/fixture/.ssh/private.key";
  for (const phase of ["snapshot", "stage"] as const) {
    const engine = new FakeEngine();
    let controllerCalls = 0;
    let imports = 0;
    const fail = () => { throw new BrokerError("VERIFICATION_FAILED", backendMessage); };
    if (phase === "stage") engine.uploadArchive = async () => fail();
    const task = runner(engine, {
      ...(phase === "snapshot" ? { snapshotProvider: fail } : {}),
      controller: { run: async () => { controllerCalls++; return complete(); } },
      importChanges: () => { imports++; return []; }
    });
    const result = await task.run(profile(undefined, "readonly"), control());
    assert.equal(result.state, "failed");
    assert.equal(result.resultClass, "EXECUTION_FAILED");
    assert.equal(result.stderr, `Container task failed a validation or execution check [VERIFICATION_FAILED/${phase}]`);
    assert.equal(result.stdout, "");
    assert.ok(!JSON.stringify(result).includes(backendMessage));
    assert.ok(!JSON.stringify(result).includes("Private backend trace"));
    assert.ok(!JSON.stringify(result).includes("synthetic-backend-credential"));
    assert.ok(!JSON.stringify(result).includes(".ssh"));
    assert.equal(controllerCalls, 0);
    assert.equal(imports, 0);
    assert.equal(result.containerCleanupVerified, true);
    assert.ok(engine.events.includes("remove"));
    assert.ok(!engine.events.includes("exec"));
  }
});

test("Registered command failure diagnostics disclose the fixed error class and phase only", async () => {
  const engine = new FakeEngine();
  engine.onExec = async () => { throw new BrokerError("POLICY_DENIED", "backend-private-details password=synthetic-command-credential"); };
  const result = await runner(engine).run(profile(), control());
  assert.equal(result.state, "failed");
  assert.equal(result.stderr, "Container task failed a validation or execution check [POLICY_DENIED/command]");
  assert.equal(result.stdout, "");
  assert.ok(!JSON.stringify(result).includes("backend-private-details"));
  assert.ok(!JSON.stringify(result).includes("synthetic-command-credential"));
  assert.equal(result.containerCleanupVerified, true);
  assert.ok(engine.events.includes("remove"));
});

test("Staging diagnostics classify only fixed Engine failures and exact HTTP status messages", async () => {
  for (const [message, diagnostic] of [
    ["Container Engine response transport failed", "ENGINE_RESPONSE_TRANSPORT"],
    ["Container Engine response ended unexpectedly", "ENGINE_RESPONSE_ABORTED"],
    ["Container Engine request transport failed", "ENGINE_REQUEST_TRANSPORT"],
    ["Container Engine request transport failed (ECONNRESET)", "ENGINE_REQUEST_ECONNRESET"],
    ["Container Engine request transport failed (EMFILE)", "ENGINE_REQUEST_EMFILE"],
    ["Container Engine request transport failed (EPIPE/exec-start)", "ENGINE_REQUEST_EPIPE/exec-start"],
    ["Container Engine operation failed with status 500", "ENGINE_HTTP_500"],
    ["constructor", ""],
    ["toString", ""],
    ["Container Engine operation failed with status 500 token=synthetic-private-value", ""]
  ]) {
    const engine = new FakeEngine();
    engine.uploadArchive = async () => { throw new BrokerError("EXECUTION_FAILED", message!); };
    const result = await runner(engine).run(profile(), control());
    assert.equal(result.stderr, `Container task failed a validation or execution check [EXECUTION_FAILED/stage${diagnostic ? `/${diagnostic}` : ""}]`);
    assert.ok(!JSON.stringify(result).includes("synthetic-private-value"));
    assert.equal(result.containerCleanupVerified, true);
  }
});

test("Unclassified backend exceptions retain UNKNOWN and never expose an exception message", async () => {
  const engine = new FakeEngine();
  engine.uploadArchive = async () => { throw new Error("private-engine-exception api_key=synthetic-opaque-credential"); };
  const result = await runner(engine).run(profile(), control());
  assert.equal(result.state, "unknown");
  assert.equal(result.resultClass, "UNKNOWN_OUTCOME");
  assert.equal(result.stderr, "Container task outcome could not be verified");
  assert.equal(result.stdout, "");
  assert.ok(!JSON.stringify(result).includes("private-engine-exception"));
  assert.ok(!JSON.stringify(result).includes("synthetic-opaque-credential"));
  assert.equal(result.containerCleanupVerified, true);
  assert.ok(engine.events.includes("remove"));
});

test("Workspace-write coding imports only a validated archive and rechecks cancellation immediately before each host write", async () => {
  const engine = new FakeEngine(); let cancelled = false; let writes = 0;
  const task = runner(engine, { controller: { run: async () => complete() }, importChanges: (input, output, paths, hooks) => {
    assert.equal(input.root, "/unit/worktree"); assert.deepEqual(paths, ["src"]); assert.equal(output[0]!.content.toString(), OUTPUT[0]!.content.toString());
    hooks!.beforeWrite!(); writes++; hooks!.onChangedPath!("src/main.js"); cancelled = true; hooks!.beforeWrite!(); writes++; return ["src/main.js"];
  } });
  const result = await task.run(profile(undefined, "workspace-write"), { ...control(), shouldCancel: () => cancelled });
  assert.equal(result.state, "cancelled"); assert.equal(writes, 1); assert.deepEqual(result.changedPaths, ["src/main.js"]);
  assert.equal(result.containerCleanupVerified, true); assert.ok(engine.events.includes("download"));
});

test("Workspace-write coding succeeds after bounded safe import and readonly coding never downloads or imports", async () => {
  const engine = new FakeEngine(); let imports = 0;
  const task = runner(engine, { controller: { run: async () => complete() }, importChanges: (_input, _output, _paths, hooks) => {
    hooks!.beforeWrite!(); imports++; hooks!.onChangedPath!("src/main.js"); return ["src/main.js"];
  } });
  const write = await task.run(profile(undefined, "workspace-write"), control());
  assert.equal(write.state, "completed"); assert.deepEqual(write.changedPaths, ["src/main.js"]); assert.equal(imports, 1);
  engine.events.length = 0;
  const read = await task.run(profile(undefined, "readonly"), control());
  assert.equal(read.state, "completed"); assert.equal(imports, 1); assert.ok(!engine.events.includes("download"));
});

for (const mode of ["timeout", "cancel"] as const) {
  test(`Container runner ${mode} stops and removes its owned container and never imports`, async () => {
    const engine = new FakeEngine(); engine.onExec = waiting; let cancelled = false;
    const p = profile(); p.process.timeoutMs = mode === "timeout" ? 40 : 1000;
    const task = runner(engine); const pending = task.run(p, { ...control(), shouldCancel: () => cancelled });
    if (mode === "cancel") setTimeout(() => { cancelled = true; }, 30);
    const result = await pending;
    assert.equal(result.state, mode === "timeout" ? "timed_out" : "cancelled"); assert.equal(result.containerCleanupVerified, true);
    if (mode === "timeout") assert.match(result.stderr, /^Container task exceeded its deadline of 40 ms in phase "[a-z]+"; it covers Engine checks, container start, workspace staging and the command/u);
    assert.ok(engine.events.includes("remove")); assert.ok(!engine.events.includes("download"));
    const phaseMs = assertPhaseTiming(result);
    assert.ok("command" in phaseMs && "cleanup" in phaseMs, JSON.stringify(phaseMs));
  });
}

test("Unverified cleanup and unknown creation preserve UNKNOWN rather than reporting success", async () => {
  const engine = new FakeEngine(); engine.failKill = true;
  const result = await runner(engine).run(profile(), control());
  assert.equal(result.state, "unknown"); assert.equal(result.containerCleanupVerified, false); assert.ok(!engine.events.includes("remove"));
  const uncertain = new FakeEngine(); uncertain.createsUnknown = true;
  const unknown = await runner(uncertain).run(profile(), control());
  assert.equal(unknown.state, "unknown"); assert.equal(unknown.containerCleanupVerified, false); assert.ok(!uncertain.events.includes("start"));
});

function metadata(): ContainerTaskJobMetadata {
  return { schemaVersion: "0.1", containerId: CID, imageId: IMAGE, engineId: ENGINE, taskId: "task-recovered", owner: "owner",
    nonce: "c".repeat(64), taskDescriptorDigest: "d".repeat(64), recordedAtMs: 100, deadlineAtMs: 200, readonlyWorkspace: true,
    maxRuntimeMs: 100, memoryBytes: 512 * 1024 * 1024, nanoCpus: 1_000_000_000, pidsLimit: 128 };
}

test("Restart recovery stops only persisted exact authority and never replays task code", async () => {
  const engine = new FakeEngine(); const task = runner(engine);
  assert.equal(await task.recoverContainerTask(metadata()), true); assert.deepEqual(engine.events, ["info", "kill", "remove"]);
  engine.events.length = 0;
  assert.equal(await task.recoverContainerTask({ ...metadata(), imageId: `sha256:${"e".repeat(64)}` }), false);
  assert.deepEqual(engine.events, []);
  await assert.rejects(task.recoverContainerTask({ ...metadata(), containerId: "named-container" }), errorClass("PRECONDITION_FAILED"));
  engine.absent = true;
  assert.equal(await task.recoverContainerTask(metadata()), true);
  assert.ok(!(engine.events as string[]).includes("exec")); assert.ok(!(engine.events as string[]).includes("start"));
  engine.changedEngine = true;
  assert.equal(await task.recoverContainerTask(metadata()), false);
});

test("Concurrent tasks own separate containers while the same worktree is locked", async () => {
  const engine = new FakeEngine(); engine.onExec = waiting;
  const task = runner(engine); const first = task.run(profile("/unit/a"), control());
  await assert.rejects(task.run(profile("/unit/a"), control()), errorClass("CONFLICT"));
  const second = task.run(profile("/unit/b"), control());
  await assert.rejects(task.run(profile("/unit/c"), control()), errorClass("CONFLICT"));
  await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(engine.created.length, 2); assert.notEqual(engine.created[0]!.id, engine.created[1]!.id);
  assert.notEqual(engine.created[0]!.nonce, engine.created[1]!.nonce);
  await task.close();
  assert.equal((await first).state, "cancelled"); assert.equal((await second).state, "cancelled");
  await assert.rejects(task.run(profile(), control()), errorClass("POLICY_DENIED"));
});

test("Shutdown refuses to claim drained ownership if a task container cannot be stopped", async () => {
  const engine = new FakeEngine(); engine.onExec = waiting; engine.failKill = true;
  const task = runner(engine); const pending = task.run(profile(), control());
  await new Promise(resolve => setTimeout(resolve, 10));
  await assert.rejects(task.close(), errorClass("UNKNOWN_OUTCOME")); assert.equal((await pending).state, "unknown");
});

async function withTools(mode: "readonly" | "workspace-write" | "test-only", action: (tools: CodexDynamicTool[], request: CodexControllerRun, engine: FakeEngine) => Promise<void>): Promise<void> {
  const engine = new FakeEngine(); engine.onExec = async options => {
    if (options.command[1] === "-e") {
      new Function(options.command[2]!);
      const args = JSON.parse(options.command[3]!) as { op: string; path: string };
      return { exitCode: 0, stdout: JSON.stringify(args.op === "read" ? { path: args.path, content: "safe source" } : args.op === "list" ?
        { entries: [{ path: "src/main.js", type: "file" }, { path: ".ssh/key", type: "file" }, { path: ".git/config", type: "file" }, { path: "outside.js", type: "file" }] } : { path: args.path, writtenBytes: 12 }), stderr: "", truncated: false };
    }
    return engine.result;
  };
  const task = runner(engine, { controller: { run: async request => { await action(request.dynamicTools, request, engine); return complete(); } }, importChanges: () => [] });
  const result = await task.run(profile(undefined, mode), control());
  assert.equal(result.state, "completed"); assert.equal(result.containerCleanupVerified, true);
}
const context = (mode: "readonly" | "workspace-write" | "test-only") => ({ signal: new AbortController().signal, executionProfile: mode });

test("Readonly coding receives only source read/list capabilities and rejects traversal, secrets and scope escapes before exec", async () => {
  await withTools("readonly", async (tools, request, engine) => {
    assert.deepEqual(tools.map(t => t.name), ["list_files", "read_file"]); assert.equal(request.executionProfile, "readonly");
    const read = tools.find(t => t.name === "read_file")!;
    for (const path of ["../host", "/Users/owner/.ssh/key", "src/.env", "src/.git/config", "other/main.js", "src/../main.js"]) {
      await assert.rejects(Promise.resolve().then(() => read.handler({ path }, context("readonly"))), errorClass("POLICY_DENIED"));
    }
    assert.equal(engine.calls.length, 0);
    const content = await read.handler({ path: "src/main.js" }, context("readonly")); assert.deepEqual(content, { path: "src/main.js", content: "safe source" });
    const listing = await tools[0]!.handler({ path: "" }, context("readonly")); assert.deepEqual(listing, { entries: [{ path: "src/main.js", type: "file" }] });
    assert.ok(engine.calls.every(call => call.command[0] === "/usr/local/bin/node"));
    const script = engine.calls[0]!.command[2]!;
    assert.ok(script.includes("C.O_NOFOLLOW")); assert.ok(script.includes("/proc/self/fd/"));
    assert.ok(script.includes(String.raw`/[\x00-\x1f\\]/`));
  });
});

test("Workspace-write coding receives fixed file tools and only approved validation names", async () => {
  await withTools("workspace-write", async (tools, _request, engine) => {
    assert.deepEqual(tools.map(t => t.name), ["list_files", "read_file", "write_file", "edit_file", "run_registered_command"]);
    const write = tools.find(t => t.name === "write_file")!;
    await write.handler({ path: "src/new/nested.js", content: "safe code" }, context("workspace-write"));
    const call = engine.calls.at(-1)!; assert.ok(call.command[2]!.includes("openDir(parts,q.op==='write')"));
    const command = tools.find(t => t.name === "run_registered_command")!;
    await assert.rejects(Promise.resolve().then(() => command.handler({ name: "sudo" }, context("workspace-write"))), errorClass("POLICY_DENIED"));
    await command.handler({ name: "test" }, context("workspace-write")); assert.deepEqual(engine.calls.at(-1)!.command, ["/usr/local/bin/node", "--test"]);
  });
});

test("Test-only coding cannot write and cannot invoke a registered build command", async () => {
  await withTools("test-only", async tools => {
    assert.deepEqual(tools.map(t => t.name), ["list_files", "read_file", "run_registered_command"]);
    const command = tools.at(-1)!;
    await assert.rejects(Promise.resolve().then(() => command.handler({ name: "build" }, context("test-only"))), errorClass("POLICY_DENIED"));
    await command.handler({ name: "test" }, context("test-only"));
  });
});

test("Coding timeout fences late callbacks before any engine access or host import", async () => {
  const engine = new FakeEngine(); let late: CodexDynamicTool | undefined; let imports = 0;
  const task = runner(engine, { controller: { run: async request => { late = request.dynamicTools.find(t => t.name === "write_file"); return new Promise(() => {}); } }, importChanges: () => { imports++; return []; } });
  const p = profile(undefined, "workspace-write"); p.process.timeoutMs = 30;
  const result = await task.run(p, control()); assert.equal(result.state, "timed_out"); assert.equal(result.containerCleanupVerified, true); assert.equal(imports, 0);
  assert.ok(late); const count = engine.calls.length;
  await assert.rejects(Promise.resolve().then(() => late!.handler({ path: "src/late.js", content: "late" }, context("workspace-write"))), errorClass("TIMEOUT"));
  assert.equal(engine.calls.length, count);
});

test("Coding readonly flag cannot be used to misrepresent writable source and output remains bounded", async () => {
  const engine = new FakeEngine(); const task = runner(engine, { controller: { run: async () => complete("x".repeat(20_000)) } });
  const bad = profile(undefined, "workspace-write"); bad.containerExecution!.readonlyWorkspace = true;
  await assert.rejects(async () => task.run(bad, control()), errorClass("POLICY_DENIED")); assert.deepEqual(engine.events, []);
  const result = await task.run(profile(undefined, "readonly"), control());
  assert.ok(Buffer.byteLength(result.stdout) <= 8192); assert.equal(result.truncated, true);
});

test("Workspace imports persist intent before mutation and verified audit after readback", async () => {
  const engine = new FakeEngine(); const events: string[] = [];
  const task = runner(engine, { controller: { run: async () => complete() }, importChanges: (_snapshot, _files, _paths, hooks) => {
    hooks!.beforeWrite!(); hooks!.onWriteIntent!("src/main.js"); events.push("write"); hooks!.onChangedPath!("src/main.js"); return ["src/main.js"];
  } });
  const result = await task.run(profile(undefined, "workspace-write"), { ...control(), onWorkspaceImport: (path, phase) => { events.push(`${phase}:${path}`); } });
  assert.equal(result.state, "completed"); assert.deepEqual(events, ["intent:src/main.js", "write", "verified:src/main.js"]);
});

test("Workspace import audit failure preserves partial paths and never starts a mutation without persisted intent", async () => {
  const engine = new FakeEngine(); let writes = 0;
  const task = runner(engine, { controller: { run: async () => complete() }, importChanges: (_snapshot, _files, _paths, hooks) => {
    hooks!.onWriteIntent!("src/main.js"); writes++; hooks!.onChangedPath!("src/main.js"); return ["src/main.js"];
  } });
  const p = profile(undefined, "workspace-write");
  const blocked = await task.run(p, { ...control(), onWorkspaceImport: () => { throw new BrokerError("AUDIT_UNAVAILABLE", "Cannot persist intent"); } });
  assert.equal(blocked.state, "unknown"); assert.equal(writes, 0);
  const partial = await task.run(p, { ...control(), onWorkspaceImport: (_path, phase) => { if (phase === "verified") throw new BrokerError("AUDIT_UNAVAILABLE", "Cannot persist readback"); } });
  assert.equal(partial.state, "unknown"); assert.equal(writes, 1); assert.deepEqual(partial.changedPaths, ["src/main.js"]);
  await assert.rejects(async () => task.run(p, { timeoutMs: 1000, shouldCancel: () => false, onContainerCreated: () => {} }), errorClass("POLICY_DENIED"));
});

test("Coding commands remain bound to the authorized project and absent project authority exposes no commands", async () => {
  const engine = new FakeEngine(); let observed: string[] = [];
  const task = runner(engine, { registeredCommands: [...COMMANDS, { name: "foreign", projectRoot: "/unit/foreign", executable: "/usr/local/bin/node", args: ["foreign.js"] }],
    controller: { run: async request => {
      observed = request.dynamicTools.map(t => t.name);
      const command = request.dynamicTools.find(t => t.name === "run_registered_command");
      if (command) await assert.rejects(Promise.resolve().then(() => command.handler({ name: "foreign" }, context("workspace-write"))), errorClass("POLICY_DENIED"));
      return complete();
    } }, importChanges: () => [] });
  assert.equal((await task.run(profile(undefined, "workspace-write"), control())).state, "completed"); assert.ok(observed.includes("run_registered_command"));
  const noProject = profile(undefined, "workspace-write"); delete noProject.containerExecution!.projectRoot;
  assert.equal((await task.run(noProject, control())).state, "completed"); assert.ok(!observed.includes("run_registered_command"));
  const ordinary = profile(); ordinary.containerExecution!.projectRoot = "/unit/foreign";
  await assert.rejects(async () => task.run(ordinary, control()), errorClass("POLICY_DENIED"));
});

test("Trusted snapshot exclusions are canonical, unique and frozen before task admission", async () => {
  for (const paths of [["../data"], ["/absolute/data"], ["data/../media"], ["data", "data"], [".git"], ["data/"], ["data\\media"], Array.from({ length: 65 }, (_item, index) => `data${index}`)]) {
    assert.throws(() => runner(new FakeEngine(), { snapshotExcludedPaths: paths }), errorClass("POLICY_DENIED"));
  }
  const paths = ["portal/data", "portal/uploads"];
  let captured: readonly string[] = [];
  const task = runner(new FakeEngine(), { snapshotExcludedPaths: paths, snapshotProvider: (root, readonlyWorkspace, exclusions) => {
    captured = exclusions ?? []; assert.ok(Object.isFrozen(captured)); return snapshot(root, readonlyWorkspace);
  } });
  paths.push("src");
  assert.equal((await task.run(profile(), control())).state, "completed");
  assert.deepEqual(captured, ["portal/data", "portal/uploads"]);
});

test("Dynamic source tools cannot read or revive an excluded subtree and listings hide excluded entries", async () => {
  const engine = new FakeEngine();
  engine.onExec = async options => {
    const query = JSON.parse(options.command[3]!);
    return { exitCode: 0, stdout: JSON.stringify(query.op === "list" ? { entries: [
      { path: "src/main.js", type: "file" }, { path: "src/private", type: "directory" }, { path: "src/private/source.js", type: "file" }
    ] } : { path: query.path, content: "safe source" }), stderr: "", truncated: false };
  };
  const task = runner(engine, { snapshotExcludedPaths: ["src/private"], controller: { run: async request => {
    const tool = (name: string) => request.dynamicTools.find(t => t.name === name)!;
    for (const name of ["read_file", "write_file", "list_files"]) {
      for (const path of ["src/private", "src/private/source.js"]) {
        await assert.rejects(Promise.resolve().then(() => tool(name).handler({ path, content: "safe" }, context("workspace-write"))), errorClass("POLICY_DENIED"));
      }
    }
    assert.equal(engine.calls.length, 0);
    const listing = await tool("list_files").handler({ path: "src" }, context("workspace-write"));
    assert.deepEqual(listing, { entries: [{ path: "src/main.js", type: "file" }] });
    return complete();
  } }, importChanges: () => [] });
  assert.equal((await task.run(profile(undefined, "workspace-write"), control())).state, "completed");
});

test("Excluded output paths are rejected before any host import even when a registered task recreated them", async () => {
  const engine = new FakeEngine(); let imports = 0;
  const task = runner(engine, { snapshotExcludedPaths: ["src/private"], controller: { run: async () => complete() },
    parseArchive: () => [OUTPUT[0]!, file("src/private/new.js", "regular source")],
    importChanges: () => { imports++; return ["src/main.js"]; }
  });
  const result = await task.run(profile(undefined, "workspace-write"), control());
  assert.equal(result.state, "failed"); assert.equal(result.containerCleanupVerified, true); assert.equal(imports, 0); assert.deepEqual(result.changedPaths, []);
});

test("Container runner reports per-phase timing for a registered command and the Broker validator accepts it unchanged", async t => {
  const { task } = timedRunner(t, new FakeEngine());
  const result = await task.run(profile(), control());
  assert.equal(result.state, "completed");
  assert.deepEqual(assertPhaseTiming(result), { prepare: 3, start: 5, snapshot: 4, stage: 7, command: 11, cleanup: 2 });
  assert.equal(result.durationMs, 3 + 5 + 4 + 7 + 11 + 2);
});

test("Container runner times export and import and books the coding controller run as the command phase", async t => {
  let advance = (_ms: number): void => {};
  const timed = timedRunner(t, new FakeEngine(), { controller: { run: async () => { advance(9); return complete(); } },
    importChanges: () => { advance(6); return ["src/main.js"]; } });
  advance = timed.advance;
  const { task } = timed;
  const written = await task.run(profile(undefined, "workspace-write"), control());
  assert.equal(written.state, "completed");
  assert.deepEqual(assertPhaseTiming(written), { prepare: 3, start: 5, snapshot: 4, stage: 7, command: 9, export: 13, import: 6, cleanup: 2 });
  const read = await task.run(profile(undefined, "readonly"), control());
  assert.deepEqual(assertPhaseTiming(read), { prepare: 3, start: 5, snapshot: 4, stage: 7, command: 9, cleanup: 2 });
});

test("Container runner keeps the timing of the phase that failed and still times cleanup", async t => {
  const engine = new FakeEngine();
  const { task, advance } = timedRunner(t, engine);
  const upload = engine.uploadArchive;
  engine.uploadArchive = async (...args) => { await upload(...args); advance(20); throw new BrokerError("EXECUTION_FAILED", "Container Engine response transport failed"); };
  const failed = await task.run(profile(), control());
  assert.equal(failed.state, "failed");
  assert.deepEqual(assertPhaseTiming(failed), { prepare: 3, start: 5, snapshot: 4, stage: 27, cleanup: 2 });
});

test("Container runner times a teardown it could not verify", async t => {
  const engine = new FakeEngine(); engine.failKill = true;
  const { task } = timedRunner(t, engine);
  const result = await task.run(profile(), control());
  assert.equal(result.state, "unknown"); assert.equal(result.containerCleanupVerified, false);
  assert.deepEqual(assertPhaseTiming(result), { prepare: 3, start: 5, snapshot: 4, stage: 7, command: 11, cleanup: 2 });
});

test("Container runner has no cleanup timing when no container was ever created", async t => {
  const engine = new FakeEngine(); engine.createsUnknown = true;
  const { task } = timedRunner(t, engine);
  const result = await task.run(profile(), control());
  assert.equal(result.state, "unknown");
  assert.deepEqual(assertPhaseTiming(result), { prepare: 3 });
});
