import assert from "node:assert/strict";
import { execFile, fork, type ChildProcess, type ForkOptions } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { BrokerError, canonicalJson, sha256 } from "@mac-operator/contracts";
import { DockerContainerEngine, type ContainerTaskHandle } from "./container-engine.js";
import { type ContainerTaskJobMetadata } from "./container-job-metadata.js";
import { ContainerTaskProfileRegistry, type ApprovedContainerTask } from "./container-task-profile.js";
import { ContainerTaskRunner } from "./container-task-runner.js";
import { ManagedWorktrees } from "./managed-worktrees.js";
import { loadNativePeerAdapter, parsePeerCredentials, parsePeerProcessIdentity, type PeerCredentialPolicy } from "./peer-credentials.js";
import { BrokerStore, type JobLease } from "./persistence.js";
import { SAFE_GIT_ENVIRONMENT } from "./git-inspector.js";
import { freezeResolvedTaskProfile, type ResolvedTaskProfile } from "./task-profile.js";
import { type TaskIsolationProof } from "./task-runner.js";

const OWNER = "physical-validation-owner";
const DEFAULT_ENGINE = "f8fbb9ed-402f-4ff7-b672-fc10a3401347";
const execFileAsync = promisify(execFile);
const delay = (ms: number): Promise<void> => new Promise(resolve => setTimeout(resolve, ms));
const failure = (code: string) => (error: unknown): boolean => error instanceof BrokerError && error.errorClass === code;

export interface PhysicalContainerValidationOptions { imageId: string; socketPath: string; engineId?: string; evidencePath?: string; }
export interface PhysicalContainerEvidence {
  schemaVersion: "0.1";
  mechanism: "docker-container";
  imageId: string;
  engineId: string;
  nodeVersion: string;
  durationMs: number;
  checks: Array<{ name: string; status: "pass" }>;
}

interface FixtureConfiguration {
  root: string; projectRoot: string; stateRoot: string; worktreeRoot: string;
  imageId: string; engineId: string; socketPath: string; manifestSha256: string; crashWorktree: string;
}

/** Independently exercise the real host boundary; this does not enable any live MCP tool. */
export async function runPhysicalContainerValidation(options: PhysicalContainerValidationOptions): Promise<PhysicalContainerEvidence> {
  assert.equal(process.platform, "darwin", "Physical verification requires the actual macOS host");
  assert.match(options.imageId, /^sha256:[a-f0-9]{64}$/u);
  const engineId = options.engineId ?? DEFAULT_ENGINE;
  assert.match(engineId, /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u);
  const started = Date.now();
  const root = await realpath(await mkdtemp(join(tmpdir(), "mac-operator-physical-")));
  const projectRoot = join(root, "project");
  const stateRoot = join(root, "state");
  const worktreeRoot = join(root, "worktrees");
  const checks: PhysicalContainerEvidence["checks"] = [];
  const handles: ContainerTaskHandle[] = [];
  const detachedStarted = new Set<string>();
  let store: BrokerStore | undefined;
  let worktrees: ManagedWorktrees | undefined;
  let runner: ContainerTaskRunner | undefined;
  let worker: ChildProcess | undefined;
  const engine = await physicalEngine(options.socketPath);
  try {
    assert.equal((await engine.info()).id, engineId);
    assert.equal((await engine.inspectImage(options.imageId)).id, options.imageId);
    await Promise.all([projectRoot, stateRoot, worktreeRoot].map(path => mkdir(path, { mode: 0o700 })));
    await writeFile(join(root, "host-marker.txt"), "PUBLIC HOST FIXTURE\n", { mode: 0o600 });
    const scripts = fixtureScripts(join(root, "host-marker.txt"));
    const manifest = JSON.stringify({ name: "physical-container-fixture", private: true, type: "module",
      scripts: Object.fromEntries(Object.keys(scripts).map(name => [name, `node ${name}.mjs`])) }) + "\n";
    await Promise.all(Object.entries(scripts).map(([name, content]) => writeFile(join(projectRoot, `${name}.mjs`), content, { mode: 0o600 })));
    await writeFile(join(projectRoot, "package.json"), manifest, { mode: 0o600 });
    await writeFile(join(projectRoot, "public.txt"), "PUBLIC WORKSPACE FIXTURE\n", { mode: 0o600 });
    await git(projectRoot, ["init", "--initial-branch=main"]);
    await git(projectRoot, ["add", "--", "package.json", "public.txt", ...Object.keys(scripts).map(name => `${name}.mjs`)]);
    await git(projectRoot, ["-c", "user.name=Physical Validation", "-c", "user.email=physical@example.invalid", "commit", "-m", "Create synthetic container validation fixture"]);
    const before = await primaryState(projectRoot);
    worktrees = new ManagedWorktrees(stateRoot, worktreeRoot);
    const create = async (taskId: string): Promise<string> => (await worktrees!.create({ projectRoot, branchName: `codex/${taskId}`,
      baseRef: "main", taskId, idempotencyKey: taskId, owner: OWNER }, { timeoutMs: 10_000, shouldCancel: () => false }, () => undefined)).record.worktree;
    const first = await create("physical-first");
    const second = await create("physical-second");
    const crashWorktree = await create("physical-crash");
    await mkdir(join(first, ".ssh"), { mode: 0o700 });
    await writeFile(join(first, ".ssh", "id_rsa"), "PUBLIC INNOCUOUS FIXTURE\n", { mode: 0o600 });
    await writeFile(join(first, ".env"), "PUBLIC_FIXTURE=present\n", { mode: 0o600 });
    await symlink(join(root, "host-marker.txt"), join(first, "host-link"));
    const config: FixtureConfiguration = { root, projectRoot, stateRoot, worktreeRoot, imageId: options.imageId, engineId,
      socketPath: options.socketPath, manifestSha256: sha256(manifest), crashWorktree };
    const registry = physicalRegistry(config, engine, worktrees, scripts);
    runner = physicalRunner(config, engine, registry, owned => { detachedStarted.add(owned.id); });
    store = new BrokerStore(join(root, "ledger.sqlite"), { runtimeFence: true });
    const execute = async (name: string, cwd = first, taskId = "physical-first", changes?: { readonly?: boolean; timeout?: number; cancel?: boolean }) => {
      let profile = await registry.resolve({ profile: `physical.${name}`, cwd, taskId,
        ...(changes?.timeout === undefined ? {} : { maxRuntimeMs: changes.timeout }) });
      if (changes?.readonly) profile = freezeResolvedTaskProfile({ ...profile, containerExecution: { ...profile.containerExecution!, readonlyWorkspace: true } });
      const result = await durableRun(store!, runner!, profile, handles, changes?.cancel ?? false, undefined,
        containerId => detachedStarted.has(containerId));
      if (name === "sleep") assert.ok(detachedStarted.has(result.metadata.containerId), "Actual detached child did not start before cancellation/deadline");
      return result;
    };

    const boundary = await execute("boundary");
    assert.equal(boundary.result.state, "completed", boundary.result.stderr);
    const observed = JSON.parse(boundary.result.stdout) as { nodeVersion: string };
    assert.match(observed.nodeVersion, /^v\d+\.\d+\.\d+$/u);
    await absent(engine, boundary.metadata);
    for (const name of ["host_filesystem_not_mounted", "secret_and_symlink_inputs_filtered", "nonroot_zero_capabilities_no_sudo_or_socket",
      "network_none_enforced", "untrusted_uid_cannot_stop_deadline_pid1", "root_filesystem_readonly"]) checks.push({ name, status: "pass" });

    const readonly = await execute("readonly", first, "physical-first", { readonly: true });
    assert.equal(readonly.result.state, "completed", readonly.result.stderr);
    assert.equal(readonly.result.stdout.trim(), "readonly-enforced");
    await absent(engine, readonly.metadata);
    checks.push({ name: "readonly_workspace_rejects_write_chmod_and_chown", status: "pass" });

    const good = await execute("good");
    assert.equal(good.result.state, "completed"); assert.equal(good.result.exitCode, 0);
    const bad = await execute("bad");
    assert.equal(bad.result.state, "failed"); assert.equal(bad.result.exitCode, 7);
    await absent(engine, good.metadata); await absent(engine, bad.metadata);
    checks.push({ name: "registered_tests_success_and_failure_observed", status: "pass" });
    const output = await execute("output");
    assert.equal(output.result.resultClass, "OUTPUT_LIMIT"); assert.equal(output.result.containerCleanupVerified, true);
    assert.ok(Buffer.byteLength(output.result.stdout + output.result.stderr) <= 1024);
    await absent(engine, output.metadata);
    checks.push({ name: "output_limit_terminates_and_removes_exact_container", status: "pass" });

    const timeout = await execute("sleep", first, "physical-first", { timeout: 5000 });
    assert.equal(timeout.result.state, "timed_out", timeout.result.stderr);
    assert.equal(timeout.result.containerCleanupVerified, true); await absent(engine, timeout.metadata);
    assert.ok(timeout.result.durationMs < 15_000);
    checks.push({ name: "timeout_kills_detached_descendants_and_removes_container", status: "pass" });
    const cancelled = await execute("sleep", first, "physical-first", { cancel: true });
    assert.equal(cancelled.result.state, "cancelled", cancelled.result.stderr);
    assert.equal(cancelled.job.state, "cancelled"); await absent(engine, cancelled.metadata);
    checks.push({ name: "durable_cancellation_kills_and_removes_container", status: "pass" });

    const concurrent = await Promise.all([execute("isolation"), execute("isolation", second, "physical-second")]);
    assert.ok(concurrent.every(value => value.result.state === "completed" && value.result.stdout.trim() === "isolated"),
      canonicalJson(concurrent.map(value => ({ state: value.result.state, resultClass: value.result.resultClass,
        stdout: value.result.stdout, stderr: value.result.stderr, exitCode: value.result.exitCode, durationMs: value.result.durationMs }))));
    assert.notEqual(concurrent[0]!.metadata.containerId, concurrent[1]!.metadata.containerId);
    assert.notEqual(concurrent[0]!.metadata.nonce, concurrent[1]!.metadata.nonce);
    await Promise.all(concurrent.map(value => absent(engine, value.metadata)));
    checks.push({ name: "concurrent_worktrees_have_distinct_container_and_filesystem_identity", status: "pass" });

    await assert.rejects(registry.resolve({ profile: "physical.good", cwd: first, taskId: "physical-first", args: ["; sudo anything"] }), failure("PRECONDITION_FAILED"));
    await assert.rejects(registry.resolve({ profile: "physical.good", cwd: projectRoot, taskId: "physical-first" }), failure("POLICY_DENIED"));
    const valid = await registry.resolve({ profile: "physical.good", cwd: first, taskId: "physical-first" });
    const beforeMalformed = handles.length;
    await assert.rejects(async () => runner!.run({ ...valid, process: { ...valid.process, args: ["-e", "process.exit(0)"] } },
      { timeoutMs: 1000, shouldCancel: () => false, onContainerCreated: () => assert.fail("Malformed request created a container") }), failure("POLICY_DENIED"));
    assert.equal(handles.length, beforeMalformed);
    checks.push({ name: "malformed_commands_and_primary_checkout_execution_denied", status: "pass" });
    assert.ok(store.auditRows().some(row => row.result_class === "CONTAINER_OWNERSHIP_RECORDED"));
    checks.push({ name: "container_identity_audited_before_start", status: "pass" });

    store.close(); store = undefined;
    await worktrees.close(); worktrees = undefined;
    await writeFile(join(root, "fixture.json"), JSON.stringify(config), { mode: 0o600 });
    const workerOptions: ForkOptions & { shell: false } = { shell: false, cwd: root, execArgv: [], stdio: ["ignore", "pipe", "pipe", "ipc"],
      env: { PATH: "/usr/bin:/bin", LANG: "C.UTF-8" } };
    worker = fork(fileURLToPath(import.meta.url), ["--physical-crash-worker", root], workerOptions);
    const exit = new Promise<void>(resolve => worker!.once("exit", () => resolve()));
    const actualStarted = workerStarted(worker);
    void actualStarted.catch(() => undefined);
    const metadata = await workerMetadata(worker);
    const crashHandle = handle(metadata); handles.push(crashHandle);
    await actualStarted;
    assert.equal((await engine.inspect(crashHandle)).running, true);
    assert.equal(worker.kill("SIGKILL"), true); await exit; worker = undefined;
    store = new BrokerStore(join(root, "ledger.sqlite"), { runtimeFence: true });
    const unknown = store.listUnresolvedTaskContainers().find(job => job.containerMetadata?.containerId === metadata.containerId);
    assert.ok(unknown); assert.equal(unknown.state, "unknown"); assert.equal(unknown.cancelRequested, true);
    assert.deepEqual(unknown.containerMetadata, metadata);
    await waitFor(async () => !(await engine.inspect(crashHandle)).running,
      Math.max(1, metadata.deadlineAtMs - Date.now()) + 2500, "Owned PID1 deadline did not stop descendants after Broker death");
    assert.equal((await engine.inspect(crashHandle)).exitCode, 124);
    checks.push({ name: "broker_crash_retains_unknown_identity_and_independent_deadline_stops_cgroup", status: "pass" });
    assert.equal(await runner.recoverContainerTask(metadata), true);
    const recovered = store.reconcileUnknownContainerTask(unknown.jobId, OWNER, unknown.revision, metadata,
      { state: "cancelled", finishedAtMs: Date.now(), containerCleanupVerified: true });
    assert.equal(recovered.state, "cancelled"); assert.equal(recovered.containerMetadata, undefined);
    assert.equal(store.listUnresolvedTaskContainers().length, 0); await absent(engine, metadata);
    checks.push({ name: "restart_recovers_exact_container_without_execution_replay", status: "pass" });
    assert.equal(await primaryState(projectRoot), before);
    assert.equal((await readFile(join(first, "public.txt"), "utf8")), "PUBLIC WORKSPACE FIXTURE\n");
    assert.equal((await readFile(join(second, "public.txt"), "utf8")), "PUBLIC WORKSPACE FIXTURE\n");
    checks.push({ name: "primary_repository_and_host_worktree_content_unchanged", status: "pass" });
    const evidence: PhysicalContainerEvidence = { schemaVersion: "0.1", mechanism: "docker-container", imageId: options.imageId,
      engineId, nodeVersion: observed.nodeVersion, durationMs: Date.now() - started, checks };
    if (options.evidencePath !== undefined) await writeFile(options.evidencePath, JSON.stringify(evidence, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    return evidence;
  } finally {
    if (worker && worker.exitCode === null && worker.signalCode === null) {
      const child = worker; const exited = new Promise<void>(resolve => child.once("exit", () => resolve())); child.kill("SIGKILL"); await exited;
    }
    await runner?.close();
    for (const owned of handles) {
      try { await engine.inspect(owned); await engine.kill(owned); await engine.remove(owned); }
      catch (error) { if (!failure("TARGET_NOT_FOUND")(error)) throw error; }
    }
    store?.close(); await worktrees?.close();
    await rm(root, { recursive: true, force: true });
  }
}

async function physicalEngine(socketPath: string): Promise<DockerContainerEngine> {
  const socket = createConnection({ path: socketPath });
  try {
    await new Promise<void>((resolve, reject) => { socket.once("connect", resolve); socket.once("error", reject); });
    const native = loadNativePeerAdapter();
    const fd = (socket as Socket & { _handle?: { fd?: number } })._handle?.fd;
    assert.ok(Number.isSafeInteger(fd));
    const peer = parsePeerCredentials(native.getPeerCredentials(fd!));
    assert.equal(peer.uid, process.getuid!());
    const policy: PeerCredentialPolicy = { expectedUid: peer.uid, expectedGid: peer.gid,
      allowedProcessIdentity: parsePeerProcessIdentity(native.getProcessIdentity(peer.pid)) };
    return new DockerContainerEngine({ socketPath, peerPolicy: policy });
  } finally { socket.destroy(); }
}

function physicalRegistry(config: FixtureConfiguration, engine: DockerContainerEngine, worktrees: ManagedWorktrees,
  scripts = fixtureScripts(join(config.root, "host-marker.txt"))): ContainerTaskProfileRegistry {
  const entries: ApprovedContainerTask[] = Object.keys(scripts).map(name => ({ profile: `physical.${name}`, projectRoot: config.projectRoot,
    manifestPath: "package.json", manifestSha256: config.manifestSha256, scriptName: name, scriptValue: `node ${name}.mjs`,
    command: ["/usr/local/bin/node", `${name}.mjs`], timeoutMs: name === "crash" ? 8000 : 30_000, outputCapBytes: name === "output" ? 1024 : 8192 }));
  return new ContainerTaskProfileRegistry({ imageId: config.imageId, engineId: config.engineId, entries,
    validateWorkspace: async (cwd, project, task) => { assert.equal(project, config.projectRoot); worktrees.require(cwd, project, OWNER, task); return { owner: OWNER, isWorktree: true }; },
    validateRuntime: async (image, id, command) => (await engine.info()).id === id && (await engine.inspectImage(image)).id === image && command[0] === "/usr/local/bin/node" });
}

function physicalRunner(config: FixtureConfiguration, engine: DockerContainerEngine, registry: ContainerTaskProfileRegistry,
  onDetached?: (owned: ContainerTaskHandle) => void): ContainerTaskRunner {
  const proof: TaskIsolationProof = { schemaVersion: "0.1", sandboxMechanism: "docker-container", sandboxProfile: "docker-container",
    filesystem: "enforced", network: "enforced", credentials: "isolated", persistence: "isolated",
    credentialIsolation: "docker-container-no-host-credentials-v1", processTree: "owned", processTreePolicy: "owned_group",
    evidenceRef: "physical-validation-harness-not-live-activation", containerImage: { imageId: config.imageId, engineId: config.engineId } };
  // Delay delivery of a real, verified exec response to exercise the crash window
  // while a detached child remains alive. No Engine response is fabricated.
  const observedEngine = {
    info: engine.info.bind(engine), inspectImage: engine.inspectImage.bind(engine), create: engine.create.bind(engine),
    start: engine.start.bind(engine), inspect: engine.inspect.bind(engine), uploadArchive: engine.uploadArchive.bind(engine),
    downloadArchive: engine.downloadArchive.bind(engine), kill: engine.kill.bind(engine), remove: engine.remove.bind(engine),
    exec: async (...args: Parameters<DockerContainerEngine["exec"]>) => {
      const result = await engine.exec(...args);
      if (!["sleep.mjs", "crash.mjs"].includes(args[1].command[1] ?? "")) return result;
      assert.equal(result.exitCode, 0, result.stderr);
      const observed = JSON.parse(result.stdout) as { detachedPid: number; processGroup: number; session: number; heartbeat: boolean };
      assert.ok(Number.isSafeInteger(observed.detachedPid) && observed.detachedPid > 1);
      assert.equal(observed.processGroup, observed.detachedPid); assert.equal(observed.session, observed.detachedPid);
      assert.equal(observed.heartbeat, true); onDetached?.(args[0]);
      const signal = args[2]?.signal; assert.ok(signal);
      await new Promise<never>((_resolve, reject) => {
        const abort = (): void => reject(new BrokerError("CANCELLED", "Physical probe acknowledgement interrupted"));
        if (signal.aborted) abort(); else signal.addEventListener("abort", abort, { once: true });
      });
      return result;
    }
  };
  return new ContainerTaskRunner({ engine: observedEngine, imageId: config.imageId, engineId: config.engineId, enabled: true, hostEvidenceAccepted: true, isolationProof: proof,
    registeredCommands: registry.names().map(name => ({ name, executable: "/usr/local/bin/node", args: [`${name.slice("physical.".length)}.mjs`], kind: "test" })) });
}

async function durableRun(store: BrokerStore, runner: ContainerTaskRunner, profile: ResolvedTaskProfile,
  handles: ContainerTaskHandle[], cancel: boolean, notify?: (metadata: ContainerTaskJobMetadata) => void,
  detachedHasStarted?: (containerId: string) => boolean) {
  const jobId = `job:physical-${randomUUID()}`;
  const created = Date.now();
  const lease: JobLease = { ownerId: `broker:physical-${process.pid}`, token: `lease:${randomUUID()}`, expiresAtMs: created + 120_000 };
  const digest = sha256(canonicalJson(profile));
  store.createJob({ jobId, ownerPrincipalId: OWNER, ownerSessionId: "physical-validation-session", tool: "mac_task_run", targetRef: `task_profile:${profile.profile}`,
    policyVersion: "policy-physical-validation", payloadDigest: digest, idempotencyKey: randomUUID(), createdAtMs: created });
  let job = store.startJob(jobId, OWNER, 0, Date.now(), lease);
  let metadata: ContainerTaskJobMetadata | undefined;
  let cancelAt = Number.POSITIVE_INFINITY;
  let cancellationArmed = false;
  const result = await runner.run(profile, { timeoutMs: profile.process.timeoutMs, shouldCancel: () => {
    if (cancel && detachedHasStarted && metadata && !cancellationArmed && detachedHasStarted(metadata.containerId)) {
      cancelAt = Date.now() + 100; cancellationArmed = true;
    }
    if (Date.now() < cancelAt) return false;
    if (!job.cancelRequested) job = store.requestJobCancellation(jobId, OWNER, "TASK_CANCELLED", Date.now()).job;
    return true;
  }, onContainerCreated: value => {
    metadata = { ...value, taskDescriptorDigest: digest };
    job = store.recordJobContainerOwnership(jobId, OWNER, job.revision, metadata, lease, Date.now());
    handles.push(handle(metadata)); notify?.(metadata); if (cancel && !detachedHasStarted) cancelAt = Date.now() + 1200;
  } });
  assert.ok(metadata, result.stderr); assert.equal(result.containerCleanupVerified, true, result.stderr);
  const state = result.state === "timed_out" ? "failed" : result.state;
  job = store.finishJob(jobId, OWNER, job.revision, { state,
    resultClass: state === "completed" ? "success" : state === "cancelled" ? "denied" : state === "unknown" ? "unknown" : "failed",
    finishedAtMs: Date.now(), exitCode: result.exitCode, stdout: result.stdout, stderr: result.stderr, truncated: result.truncated, containerCleanupVerified: true }, lease, Date.now());
  return { result, metadata, job };
}

function handle(metadata: ContainerTaskJobMetadata): ContainerTaskHandle {
  return { id: metadata.containerId, imageId: metadata.imageId, engineId: metadata.engineId, taskId: metadata.taskId, owner: metadata.owner,
    nonce: metadata.nonce, maxRuntimeMs: metadata.maxRuntimeMs, readonlyWorkspace: metadata.readonlyWorkspace,
    memoryBytes: metadata.memoryBytes, nanoCpus: metadata.nanoCpus, pidsLimit: metadata.pidsLimit };
}
async function absent(engine: DockerContainerEngine, metadata: ContainerTaskJobMetadata): Promise<void> { await assert.rejects(engine.inspect(handle(metadata)), failure("TARGET_NOT_FOUND")); }
async function git(cwd: string, args: string[]): Promise<string> {
  return (await execFileAsync("/usr/bin/git", ["-c", "core.hooksPath=/dev/null", ...args], { shell: false, cwd, env: { ...SAFE_GIT_ENVIRONMENT, PATH: "/usr/bin:/bin" }, timeout: 10_000, maxBuffer: 262_144 })).stdout;
}
async function primaryState(root: string): Promise<string> {
  return canonicalJson({ head: await git(root, ["rev-parse", "HEAD"]), status: await git(root, ["status", "--porcelain=v1", "--untracked-files=all"]), public: sha256(await readFile(join(root, "public.txt"))) });
}
async function waitFor(check: () => Promise<boolean>, ms: number, message: string): Promise<void> {
  const deadline = Date.now() + ms;
  do { if (await check()) return; await delay(100); } while (Date.now() < deadline);
  assert.fail(message);
}
function workerMetadata(child: ChildProcess): Promise<ContainerTaskJobMetadata> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Crash worker did not persist container identity")), 10_000);
    child.once("message", value => { clearTimeout(timer); resolve(value as ContainerTaskJobMetadata); });
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("exit", () => { clearTimeout(timer); reject(new Error("Crash worker exited before container admission")); });
  });
}
function workerStarted(child: ChildProcess): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("Crash task never produced actual execution evidence")), 6000);
    const listener = (value: unknown): void => {
      if (value !== null && typeof value === "object" && (value as { type?: unknown }).type === "task-started") {
        clearTimeout(timer); child.off("message", listener); resolve();
      }
    };
    child.on("message", listener);
    child.once("exit", () => { clearTimeout(timer); child.off("message", listener); reject(new Error("Crash worker exited before task execution")); });
  });
}

function fixtureScripts(hostMarker: string): Record<string, string> {
  return {
    boundary: `import assert from 'node:assert/strict';import fs from 'node:fs';import net from 'node:net';import {spawnSync} from 'node:child_process';
assert.equal(process.getuid(),65532);assert.equal(process.getgid(),65532);
for(const p of [${JSON.stringify(hostMarker)},'.git','.env','.ssh/id_rsa','host-link','/home/agent/.ssh/id_rsa','/var/run/docker.sock','/usr/bin/sudo'])assert.equal(fs.existsSync(p),false,p);
for(const k of ['OPENAI_API_KEY','ANTHROPIC_API_KEY','SSH_AUTH_SOCK','AWS_ACCESS_KEY_ID'])assert.equal(process.env[k],undefined);
const status=fs.readFileSync('/proc/self/status','utf8');assert.match(status,/NoNewPrivs:\\s+1/);
for(const name of ['CapEff','CapPrm','CapInh','CapAmb'])assert.match(status,new RegExp(name+':\\\\s+0+\\\\n'));
const elevation=spawnSync('/usr/bin/su',['-c','id -u'],{input:'',encoding:'utf8',timeout:1200});assert.notEqual(elevation.status,0);assert.notEqual(elevation.stdout?.trim(),'0');
assert.equal(fs.readFileSync('/proc/net/route','utf8').trim().split('\\n').length,1);
assert.match(fs.readFileSync('/proc/1/status','utf8'),/Uid:\\s+65533\\s+65533\\s+65533\\s+65533/);
assert.throws(()=>process.kill(1,'SIGSTOP'),e=>e.code==='EPERM');assert.throws(()=>fs.writeFileSync('/etc/physical-marker','public'),e=>['EROFS','EACCES','EPERM'].includes(e.code));
await new Promise((resolve,reject)=>{const s=net.createConnection({host:'1.1.1.1',port:443});s.once('connect',()=>{s.destroy();reject(new Error('Network escaped'));});s.once('error',()=>resolve());s.setTimeout(500,()=>{s.destroy();resolve();});});
console.log(JSON.stringify({nodeVersion:process.version}));\n`,
    readonly: `import assert from 'node:assert/strict';import fs from 'node:fs';for(const op of [()=>fs.writeFileSync('public.txt','changed'),()=>fs.chmodSync('public.txt',0o600),()=>fs.chownSync('public.txt',65532,65532),()=>fs.writeFileSync('new.txt','public')])assert.throws(op,e=>['EPERM','EACCES','EROFS'].includes(e.code));console.log('readonly-enforced');\n`,
    good: "console.log('test passed');\n",
    bad: "console.error('synthetic expected failure');process.exit(7);\n",
    output: "process.stdout.write('x'.repeat(4096));\n",
    sleep: detachedFixture(),
    isolation: "import fs from 'node:fs';import assert from 'node:assert/strict';const value=String(process.pid);fs.writeFileSync('isolated.txt',value);await new Promise(r=>setTimeout(r,300));assert.equal(fs.readFileSync('isolated.txt','utf8'),value);console.log('isolated');\n",
    crash: detachedFixture()
  };
}
function detachedFixture(): string {
  return "import fs from 'node:fs';import assert from 'node:assert/strict';import {spawn} from 'node:child_process';" +
    "const c=spawn(process.execPath,['-e',\"const fs=require('node:fs');setInterval(()=>fs.writeFileSync('/workspace/heartbeat.txt','public'),100)\"],{detached:true,stdio:'ignore'});" +
    "await new Promise((r,j)=>{c.once('spawn',r);c.once('error',j);});c.unref();" +
    "for(let i=0;i<20&&!fs.existsSync('heartbeat.txt');i++)await new Promise(r=>setTimeout(r,50));assert.ok(fs.existsSync('heartbeat.txt'));" +
    "const stat=fs.readFileSync('/proc/'+c.pid+'/stat','utf8');const fields=stat.slice(stat.lastIndexOf(')')+2).split(' ');" +
    "console.log(JSON.stringify({detachedPid:c.pid,processGroup:Number(fields[2]),session:Number(fields[3]),heartbeat:true}));\n";
}

async function crashWorker(rootArgument: string): Promise<void> {
  const root = await realpath(rootArgument);
  assert.equal(rootArgument, root); assert.match(basename(root), /^mac-operator-physical-/u);
  const config = JSON.parse(await readFile(join(root, "fixture.json"), "utf8")) as FixtureConfiguration;
  assert.equal(config.root, root); assert.equal(config.projectRoot, join(root, "project"));
  assert.equal(config.stateRoot, join(root, "state")); assert.equal(config.worktreeRoot, join(root, "worktrees"));
  const engine = await physicalEngine(config.socketPath);
  const worktrees = new ManagedWorktrees(config.stateRoot, config.worktreeRoot);
  const registry = physicalRegistry(config, engine, worktrees);
  const runner = physicalRunner(config, engine, registry, () => { process.send?.({ type: "task-started" }); });
  const store = new BrokerStore(join(root, "ledger.sqlite"), { runtimeFence: true });
  try {
    const profile = await registry.resolve({ profile: "physical.crash", cwd: config.crashWorktree, taskId: "physical-crash" });
    await durableRun(store, runner, profile, [], false, metadata => { process.send?.(metadata); });
  } finally { await runner.close(); store.close(); await worktrees.close(); }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href && process.argv[2] === "--physical-crash-worker") {
  await crashWorker(process.argv[3]!);
}
