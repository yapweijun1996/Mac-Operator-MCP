import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, realpath, rm, symlink, unlink } from "node:fs/promises";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { createWorkspaceArchive, parseWorkspaceArchive } from "./container-snapshot.js";
import { sha256 } from "@mac-operator/contracts";
import {
  DockerContainerEngine, CONTAINER_LABELS,
  type ContainerEngineOptions, type ContainerTaskHandle
} from "./container-engine.js";

const CONTAINER_ID = "a".repeat(64);
const EXEC_ID = "b".repeat(64);
const IMAGE = `sha256:${"c".repeat(64)}`;
const ENGINE = "engine-local-identity";
const TASK = { image: IMAGE, taskId: "task-1", owner: "operator-1", nonce: "nonce-1", maxRuntimeMs: 30_000 };

type JsonRecord = Record<string, any>;
interface FakeEngine {
  engine: DockerContainerEngine;
  socket: string;
  directory: string;
  options: ContainerEngineOptions;
  requests: Array<{ method: string; path: string; body: JsonRecord | Buffer }>;
  createConfig: JsonRecord | undefined;
  execConfig: JsonRecord | undefined;
  inspectMutation: ((value: JsonRecord) => void) | undefined;
  output: Buffer;
  outputStatus: number;
  execExitCode: number;
  execInspectionMutation: ((value: JsonRecord) => void) | undefined;
  delayRoute: string | undefined;
  responseOverride: ((req: IncomingMessage, res: ServerResponse) => boolean) | undefined;
  verifiedConnections: number;
  close(): Promise<void>;
}

function multiplex(stream: number, value: string): Buffer {
  const content = Buffer.from(value);
  const header = Buffer.alloc(8);
  header[0] = stream;
  header.writeUInt32BE(content.length, 4);
  return Buffer.concat([header, content]);
}

async function fixture(overrides: Partial<ContainerEngineOptions> = {}): Promise<FakeEngine> {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mop-engine-")));
  await chmod(directory, 0o700);
  const socket = join(directory, "engine.sock");
  let running = false;
  let deleted = false;
  const workspaceFiles = new Map<string, Buffer>();
  const result = {
    directory, socket, requests: [], createConfig: undefined, execConfig: undefined, inspectMutation: undefined,
    output: Buffer.concat([multiplex(1, "test passed\n"), multiplex(2, "warning\n")]), outputStatus: 200,
    delayRoute: undefined, responseOverride: undefined, verifiedConnections: 0, execExitCode: 0, execInspectionMutation: undefined
  } as unknown as FakeEngine;
  const json = (res: ServerResponse, status: number, value: unknown): void => {
    res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(value));
  };
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    const bytes = Buffer.concat(chunks);
    const path = req.url ?? "";
    const body = bytes.length === 0 ? {} : req.headers["content-type"] === "application/x-tar" ? bytes : JSON.parse(bytes.toString("utf8"));
    result.requests.push({ method: req.method ?? "", path, body });
    if (result.delayRoute === path || result.responseOverride?.(req, res)) return;
    if (path === "/v1.47/info") return json(res, 200, { ID: ENGINE, ServerVersion: "29.0", OSType: "linux", Architecture: "aarch64", SecurityOptions: ["name=seccomp,profile=builtin", "name=cgroupns"], CgroupVersion: "2" });
    if (path === "/v1.47/version") return json(res, 200, { Version: "29.0", ApiVersion: "1.53", Os: "linux", Arch: "arm64" });
    if (path.startsWith("/v1.47/images/")) return json(res, 200, { Id: IMAGE, RepoDigests: [`node@${IMAGE}`], Os: "linux", Architecture: "arm64" });
    if (path === "/v1.47/containers/create") { result.createConfig = body as JsonRecord; return json(res, 201, { Id: CONTAINER_ID, Warnings: [] }); }
    if (path === `/v1.47/containers/${CONTAINER_ID}/json`) {
      if (deleted) return json(res, 404, { message: "absent" });
      const raw = { Id: CONTAINER_ID, Image: IMAGE, Config: structuredClone(result.createConfig!), HostConfig: structuredClone(result.createConfig?.HostConfig),
        State: { Running: running, Status: running ? "running" : "created", ExitCode: 0, Pid: running ? 100 : 0 }, Mounts: [], NetworkSettings: { Networks: { none: {} } } };
      delete raw.Config.HostConfig;
      result.inspectMutation?.(raw);
      return json(res, 200, raw);
    }
    if (path.endsWith("/start") && path.includes("/containers/")) { running = true; res.writeHead(204); return res.end(); }
    if (path.endsWith("/kill?signal=SIGKILL")) { running = false; res.writeHead(204); return res.end(); }
    if (req.method === "DELETE" && path.endsWith("?force=false&v=false")) { deleted = true; res.writeHead(204); return res.end(); }
    if (path.endsWith("/exec") && path.includes("/containers/")) {
      result.execConfig = body as JsonRecord;
      if (result.execConfig.Cmd[2]?.includes("STAGING_DENIED")) {
        const stage = JSON.parse(result.execConfig.Cmd[3]);
        if (stage.op === "begin") workspaceFiles.clear();
        if (stage.op === "chunks") for (const chunk of stage.chunks) {
          const before = workspaceFiles.get(chunk.path) ?? Buffer.alloc(0);
          workspaceFiles.set(chunk.path, Buffer.concat([before, Buffer.from(chunk.data, "base64")]));
        }
      }
      return json(res, 201, { Id: EXEC_ID });
    }
    if (path === `/v1.47/exec/${EXEC_ID}/start`) {
      const staging = result.execConfig?.Cmd[2]?.includes("STAGING_DENIED");
      const exporting = result.execConfig?.Cmd[2]?.includes("EXPORT_DENIED");
      let exported: unknown;
      if (exporting) {
        const query = JSON.parse(result.execConfig!.Cmd[3]);
        if (query.op === "index") {
          const directories = [...new Set([...workspaceFiles.keys()].flatMap(path => path.split("/").slice(0, -1).map((_p, i) => path.split("/").slice(0, i + 1).join("/"))))];
          exported = { directories, files: [...workspaceFiles.entries()].map(([path, content]) => ({ path, size: content.length, dev: "1", ino: "1", mtime: "1", ctime: "1" })) };
        } else if (query.op === "hashes") exported = { files: query.files.map((file: JsonRecord) => ({ path: file.path, sha256: sha256(workspaceFiles.get(file.path)!) })) };
        else exported = { data: workspaceFiles.get(query.file.path)!.subarray(query.offset, query.offset + query.length).toString("base64"), sha256: sha256(workspaceFiles.get(query.file.path)!) };
      }
      res.writeHead(staging || exporting ? 200 : result.outputStatus, { "Content-Type": "application/vnd.docker.raw-stream" });
      return res.end(staging ? multiplex(1, "STAGED") : exporting ? multiplex(1, JSON.stringify(exported)) : result.output);
    }
    if (path === `/v1.47/exec/${EXEC_ID}/json`) {
      const staging = result.execConfig?.Cmd[2]?.includes("STAGING_DENIED");
      const exporting = result.execConfig?.Cmd[2]?.includes("EXPORT_DENIED");
      const raw = { ID: EXEC_ID, ContainerID: CONTAINER_ID, Running: false, ExitCode: staging || exporting ? 0 : result.execExitCode, ProcessConfig: { user: result.execConfig?.User, privileged: false, tty: false } };
      result.execInspectionMutation?.(raw);
      return json(res, 200, raw);
    }
    json(res, 404, { message: "unexpected route" });
  });
  await new Promise<void>((resolvePromise, reject) => { server.once("error", reject); server.listen(socket, resolvePromise); });
  await chmod(socket, 0o600);
  result.options = { socketPath: socket,
    peerPolicy: { expectedUid: process.getuid!(), expectedGid: process.getgid!(), allowedProcessIdentity: { pid: process.pid, startTimeMicros: 1 } },
    peerVerifier: { verify: () => { result.verifiedConnections += 1; return { uid: process.getuid!(), gid: process.getgid!(), pid: process.pid }; } },
    ...overrides };
  result.engine = new DockerContainerEngine(result.options);
  result.close = async (): Promise<void> => { server.closeAllConnections(); await new Promise<void>((resolvePromise) => server.close(() => resolvePromise())); await rm(directory, { recursive: true, force: true }); };
  return result;
}

async function running(f: FakeEngine, readonlyWorkspace = false): Promise<ContainerTaskHandle> {
  const handle = await f.engine.create({ ...TASK, readonlyWorkspace });
  await f.engine.start(handle);
  await f.engine.uploadArchive(handle, createWorkspaceArchive([]));
  return handle;
}

test("Container Engine pins identity, ignores ambient contexts and creates the fixed isolated configuration", async () => {
  const f = await fixture();
  try {
    const handle = await f.engine.create(TASK);
    assert.equal(Object.isFrozen(handle), true);
    assert.equal(handle.id, CONTAINER_ID);
    assert.equal(handle.engineId, ENGINE);
    assert.equal((await f.engine.version()).os, "linux");
    const config = f.createConfig!;
    assert.equal(config.Image, IMAGE);
    assert.equal(config.User, "65533:65533");
    assert.deepEqual(config.Entrypoint, ["/usr/local/bin/node"]);
    assert.match(config.Cmd[1], /setTimeout/u);
    assert.equal(config.Cmd[2], "30000");
    assert.equal(config.Labels[CONTAINER_LABELS.nonce], TASK.nonce);
    assert.equal(config.HostConfig.ReadonlyRootfs, true);
    assert.equal(config.HostConfig.NetworkMode, "none");
    assert.deepEqual(config.HostConfig.CapDrop, ["ALL"]);
    assert.deepEqual(config.HostConfig.SecurityOpt, ["no-new-privileges:true"]);
    assert.equal(config.HostConfig.Privileged, false);
    assert.deepEqual(config.HostConfig.Binds, []);
    assert.deepEqual(config.HostConfig.Mounts, []);
    assert.deepEqual(config.HostConfig.Devices, []);
    assert.deepEqual(config.HostConfig.DeviceRequests, []);
    assert.equal(config.HostConfig.IpcMode, "private");
    assert.equal(config.HostConfig.CgroupnsMode, "private");
    assert.equal(config.HostConfig.PidMode, "");
    assert.equal(config.HostConfig.MemorySwap, config.HostConfig.Memory);
    assert.equal(config.HostConfig.PidsLimit, 128);
    assert.match(config.HostConfig.Tmpfs["/workspace"], /uid=65532,gid=65532,mode=0700/u);
    assert.equal(f.verifiedConnections, f.requests.length);
    f.inspectMutation = raw => { raw.Config.Env.reverse(); };
    assert.equal((await f.engine.inspect(handle)).id, CONTAINER_ID);
    const source = await import("node:fs/promises").then(fs => fs.readFile(new URL("./container-engine.js", import.meta.url), "utf8"));
    assert.doesNotMatch(source, /process\.env|DOCKER_HOST|child_process/u);
  } finally { await f.close(); }
});

test("Container Engine discloses only a fixed transport errno after an authenticated peer resets", async () => {
  const f = await fixture();
  try {
    f.responseOverride = (req) => { req.socket.destroy(); return true; };
    await assert.rejects(f.engine.version(), error => error instanceof Error && error.message === "Container Engine request transport failed (ECONNRESET)");
    assert.equal(f.verifiedConnections, 1);
  } finally { await f.close(); }
});

test("Container Engine readonly workspace uses root ownership and executes all tasks under a separate nonroot user", async () => {
  const f = await fixture();
  try {
    const handle = await running(f, true);
    assert.match(f.createConfig!.HostConfig.Tmpfs["/workspace"], /uid=0,gid=0,mode=0555/u);
    const result = await f.engine.exec(handle, { command: ["/usr/local/bin/node", "--version"], timeoutMs: 2_000, outputCapBytes: 1024 });
    assert.deepEqual(result, { exitCode: 0, stdout: "test passed\n", stderr: "warning\n", truncated: false });
    assert.equal(f.execConfig!.User, "65532:65532");
    assert.notEqual(f.execConfig!.User, f.createConfig!.User);
    assert.equal(f.execConfig!.Privileged, false);
    assert.equal(f.execConfig!.AttachStdin, false);
    assert.equal(f.execConfig!.Tty, false);
    assert.equal(f.execConfig!.WorkingDir, "/workspace");
    await assert.rejects(f.engine.exec(handle, { command: ["/usr/local/bin/node"], timeoutMs: 100, outputCapBytes: 1024, user: "0" } as never), /malformed/u);
  } finally { await f.close(); }
});

test("Container Engine archive transfer remains workspace-only and removal requires verified stop and absence", async () => {
  const f = await fixture();
  try {
    const handle = await f.engine.create(TASK);
    await f.engine.start(handle);
    await f.engine.uploadArchive(handle, createWorkspaceArchive([{ path: "src/example.js", content: Buffer.from("safe source") }], ["src"]));
    const exported = parseWorkspaceArchive(await f.engine.downloadArchive(handle), false);
    assert.deepEqual(exported.map(file => [file.path, file.content.toString()]), [["src/example.js", "safe source"]]);
    await assert.rejects(f.engine.remove(handle), /stopped/u);
    assert.equal((await f.engine.kill(handle)).running, false);
    assert.deepEqual(await f.engine.remove(handle), { removed: true });
    assert.ok(f.requests.some(req => req.method === "DELETE" && req.path.endsWith(`${CONTAINER_ID}?force=false&v=false`)));
    assert.ok(!f.requests.some(req => req.method === "PUT"));
    assert.ok(f.requests.some(req => req.path.endsWith("/exec") && (req.body as JsonRecord).Cmd[2]?.includes("STAGING_DENIED")));
  } finally { await f.close(); }
});

for (const [name, mutate] of [
  ["owner label", (raw: JsonRecord) => { raw.Config.Labels[CONTAINER_LABELS.owner] = "other"; }],
  ["nonce label", (raw: JsonRecord) => { raw.Config.Labels[CONTAINER_LABELS.nonce] = "other"; }],
  ["image", (raw: JsonRecord) => { raw.Image = `sha256:${"d".repeat(64)}`; }],
  ["ID", (raw: JsonRecord) => { raw.Id = "short"; }],
  ["privilege", (raw: JsonRecord) => { raw.HostConfig.Privileged = true; }],
  ["network", (raw: JsonRecord) => { raw.HostConfig.NetworkMode = "host"; }],
  ["host PID namespace", (raw: JsonRecord) => { raw.HostConfig.PidMode = "host"; }],
  ["attached bridge", (raw: JsonRecord) => { raw.NetworkSettings.Networks.bridge = {}; }],
  ["capabilities", (raw: JsonRecord) => { raw.HostConfig.CapAdd = ["SYS_ADMIN"]; }],
  ["writable root", (raw: JsonRecord) => { raw.HostConfig.ReadonlyRootfs = false; }],
  ["host bind", (raw: JsonRecord) => { raw.Mounts = [{ Type: "bind", Destination: "/workspace", RW: true }]; }],
  ["extra tmpfs", (raw: JsonRecord) => { raw.HostConfig.Tmpfs["/secrets"] = "rw"; }],
  ["PID1 user", (raw: JsonRecord) => { raw.Config.User = "65532:65532"; }],
  ["PID1 timer", (raw: JsonRecord) => { raw.Config.Cmd = ["-e", "while(true){}"];}],
  ["credential environment", (raw: JsonRecord) => { raw.Config.Env.push("TOKEN=secret"); }],
  ["duplicate environment", (raw: JsonRecord) => { raw.Config.Env[1] = raw.Config.Env[0]; }]
] as const) {
  test(`Container Engine rejects unexpected ${name} before a container mutation`, async () => {
    const f = await fixture();
    try {
      const handle = await f.engine.create(TASK);
      f.inspectMutation = mutate;
      const before = f.requests.filter(req => req.method !== "GET").length;
      await assert.rejects(f.engine.start(handle), /configuration|mount|network attachment/u);
      await assert.rejects(f.engine.remove(handle), /configuration|mount|network attachment/u);
      assert.equal(f.requests.filter(req => req.method !== "GET").length, before);
    } finally { await f.close(); }
  });
}

test("Container Engine rejects malformed creation, unpinned images and name-based container authority without HTTP", async () => {
  const f = await fixture();
  try {
    for (const input of [{ ...TASK, image: "node:latest" }, { ...TASK, maxRuntimeMs: 0 }, { ...TASK, privileged: true }, { ...TASK, memoryBytes: 16 }, { ...TASK, nonce: "../escape" }]) {
      await assert.rejects(f.engine.create(input as never), /pinned|bounded|malformed/u);
    }
    const handle = { id: "friendly-name", imageId: IMAGE, engineId: ENGINE, taskId: TASK.taskId, owner: TASK.owner, nonce: TASK.nonce, maxRuntimeMs: 1000, readonlyWorkspace: false, memoryBytes: 512 * 1024 * 1024, nanoCpus: 1_000_000_000, pidsLimit: 128 };
    await assert.rejects(f.engine.remove(handle), /full container ID/u);
    assert.equal(f.requests.length, 0);
  } finally { await f.close(); }
});

for (const [name, output] of [
  ["invalid stream", multiplex(0, "stdin")],
  ["nonzero reserved bits", (() => { const frame = multiplex(1, "hi"); frame[1] = 1; return frame; })()],
  ["short header", Buffer.alloc(7)],
  ["truncated payload", multiplex(1, "hello").subarray(0, 10)],
  ["excess output", multiplex(1, "x".repeat(2048))]
] as const) {
  test(`Container Engine ${name} stops the complete task container`, async () => {
    const f = await fixture();
    try {
      const handle = await running(f);
      f.output = output;
      await assert.rejects(f.engine.exec(handle, { command: ["/usr/local/bin/node", "--version"], timeoutMs: 2000, outputCapBytes: 1024 }), /framing|incomplete|bounded/u);
      assert.ok(f.requests.some(req => req.path.endsWith("/kill?signal=SIGKILL")));
      assert.equal((await f.engine.inspect(handle)).running, false);
    } finally { await f.close(); }
  });
}

test("Container Engine request timeout, response cap and cancellation are bounded", async () => {
  const f = await fixture({ requestTimeoutMs: 30, maxResponseBytes: 512 });
  try {
    f.delayRoute = "/v1.47/version";
    await assert.rejects(f.engine.version(), /deadline/u);
    const controller = new AbortController();
    const pending = f.engine.version({ signal: controller.signal });
    controller.abort();
    await assert.rejects(pending, /cancelled/u);
    f.delayRoute = undefined;
    f.responseOverride = (req, res) => { if (req.url?.endsWith("/version")) { res.end("x".repeat(1024)); return true; } return false; };
    await assert.rejects(f.engine.version(), /bounded size/u);
  } finally { await f.close(); }
});

test("Container Engine task timeout and external cancellation kill with a fresh un-aborted control", async () => {
  for (const cancel of [false, true]) {
    const f = await fixture();
    try {
      const handle = await running(f);
      f.delayRoute = `/v1.47/exec/${EXEC_ID}/start`;
      const controller = new AbortController();
      const pending = f.engine.exec(handle, { command: ["/usr/local/bin/node", "--version"], timeoutMs: cancel ? 2000 : 80, outputCapBytes: 1024 }, { signal: controller.signal });
      if (cancel) setTimeout(() => controller.abort(), 40);
      await assert.rejects(pending, /deadline or cancellation/u);
      assert.equal((await f.engine.inspect(handle)).running, false);
      assert.ok(f.requests.some(req => req.path.endsWith("/kill?signal=SIGKILL")));
    } finally { await f.close(); }
  }
});

test("Container Engine peer rejection sends no HTTP request", async () => {
  const f = await fixture({ peerVerifier: { verify: () => { throw new Error("unexpected peer"); } } });
  try { await assert.rejects(f.engine.info(), /peer identity/u); assert.equal(f.requests.length, 0); }
  finally { await f.close(); }
});

test("Container Engine rejects symlink socket, writable parents and replaced socket inode", async () => {
  const f = await fixture();
  try {
    const alias = join(f.directory, "alias.sock");
    await symlink(f.socket, alias);
    assert.throws(() => new DockerContainerEngine({ ...f.options, socketPath: alias }), /startup/u);
    await chmod(f.directory, 0o777);
    assert.throws(() => new DockerContainerEngine(f.options), /unsafe/u);
    await chmod(f.directory, 0o700);
    const before = await lstat(f.socket);
    await unlink(f.socket);
    const replacement = createServer();
    await new Promise<void>(resolvePromise => replacement.listen(f.socket, resolvePromise));
    await chmod(f.socket, 0o600);
    assert.notEqual((await lstat(f.socket)).ino, before.ino);
    await assert.rejects(f.engine.info(), /unsafe/u);
    replacement.closeAllConnections();
    await new Promise<void>(resolvePromise => replacement.close(() => resolvePromise()));
  } finally { await f.close(); }
});


test("Container Engine preserves a verified nonzero task exit", async () => {
  const f = await fixture();
  try {
    const handle = await running(f);
    f.execExitCode = 1;
    const result = await f.engine.exec(handle, { command: ["/usr/local/bin/node", "-e", "process.exit(1)"], timeoutMs: 2000, outputCapBytes: 1024 });
    assert.equal(result.exitCode, 1);
    assert.equal(f.requests.some(req => req.path.endsWith("/kill?signal=SIGKILL")), false);
  } finally { await f.close(); }
});

for (const [name, mutate] of [
  ["wrong user", (raw: JsonRecord) => { raw.ProcessConfig.user = "65533:65533"; }],
  ["privileged exec", (raw: JsonRecord) => { raw.ProcessConfig.privileged = true; }],
  ["different container", (raw: JsonRecord) => { raw.ContainerID = "d".repeat(64); }]
] as const) {
  test(`Container Engine rejects ${name} exit inspection and stops only the owned container`, async () => {
    const f = await fixture();
    try {
      const handle = await running(f);
      f.execInspectionMutation = mutate;
      await assert.rejects(f.engine.exec(handle, { command: ["/usr/local/bin/node", "--version"], timeoutMs: 2000, outputCapBytes: 1024 }), /exec identity/u);
      assert.ok(f.requests.some(req => req.path === `/v1.47/containers/${CONTAINER_ID}/kill?signal=SIGKILL`));
      assert.equal(f.requests.some(req => req.path.includes("d".repeat(64))), false);
    } finally { await f.close(); }
  });
}

test("Container Engine cleanup with an uncertain stopped-state readback stays UNKNOWN", async () => {
  const f = await fixture();
  try {
    const handle = await running(f);
    f.output = Buffer.alloc(7);
    f.inspectMutation = raw => { raw.State.Running = true; raw.State.Status = "running"; raw.State.Pid = 100; };
    await assert.rejects(f.engine.exec(handle, { command: ["/usr/local/bin/node", "--version"], timeoutMs: 2000, outputCapBytes: 1024 }), error =>
      error instanceof Error && "errorClass" in error && error.errorClass === "UNKNOWN_OUTCOME");
  } finally { await f.close(); }
});

test("Container Engine refuses a peer verifier that returns another UID or PID", async () => {
  const f = await fixture({ peerVerifier: { verify: () => ({ uid: process.getuid!(), gid: process.getgid!(), pid: process.pid + 1 }) } });
  try { await assert.rejects(f.engine.info(), /peer identity/u); assert.equal(f.requests.length, 0); }
  finally { await f.close(); }
});

test("Container Engine snapshots task material before asynchronous Engine inspection", async () => {
  const f = await fixture();
  try {
    const input = { ...TASK, memoryBytes: 512 * 1024 * 1024 };
    f.responseOverride = (req, res) => {
      if (req.url !== "/v1.47/info") return false;
      input.nonce = "replaced";
      input.memoryBytes = 0;
      res.end(JSON.stringify({ ID: ENGINE, ServerVersion: "29.0", OSType: "linux", Architecture: "aarch64", SecurityOptions: ["name=seccomp,profile=builtin", "name=cgroupns"], CgroupVersion: "2" }));
      return true;
    };
    const handle = await f.engine.create(input);
    assert.equal(handle.nonce, TASK.nonce);
    assert.equal(f.createConfig!.HostConfig.Memory, 512 * 1024 * 1024);
  } finally { await f.close(); }
});

test("Container Engine snapshots caller-owned handles and command arrays before admission awaits", async () => {
  const f = await fixture();
  try {
    const original = await running(f);
    const handle = { ...original };
    const command = ["/usr/local/bin/node", "--version"];
    const input = { command, timeoutMs: 2000, outputCapBytes: 1024 };
    f.responseOverride = (req, res) => {
      if (req.url !== "/v1.47/info") return false;
      handle.id = "d".repeat(64);
      handle.owner = "different";
      command[0] = "/bin/changed";
      input.timeoutMs = 1;
      res.end(JSON.stringify({ ID: ENGINE, ServerVersion: "29.0", OSType: "linux", Architecture: "aarch64", SecurityOptions: ["name=seccomp,profile=builtin", "name=cgroupns"], CgroupVersion: "2" }));
      return true;
    };
    const result = await f.engine.exec(handle, input);
    assert.equal(result.exitCode, 0);
    assert.deepEqual(f.execConfig!.Cmd, ["/usr/local/bin/node", "--version"]);
    assert.equal(f.requests.some(req => req.path.includes("d".repeat(64))), false);
  } finally { await f.close(); }
});


test("Container Engine accepts post-start cgroup v2 OOM null normalization and still rejects enabled OOM override", async () => {
  const f = await fixture();
  try {
    const handle = await running(f);
    f.inspectMutation = raw => { raw.HostConfig.OomKillDisable = null; };
    assert.equal((await f.engine.inspect(handle)).running, true);
    f.inspectMutation = raw => { raw.HostConfig.OomKillDisable = true; };
    await assert.rejects(f.engine.inspect(handle), /configuration/u);
    f.inspectMutation = raw => { raw.HostConfig.OomKillDisable = null; };
    await f.engine.kill(handle);
    await f.engine.remove(handle);
  } finally { await f.close(); }
});

test("Workspace staging is once-only, precedes normal execution and never allows caller-selected root execution", async () => {
  const f = await fixture();
  try {
    const handle = await f.engine.create({ ...TASK, readonlyWorkspace: true });
    await f.engine.start(handle);
    await assert.rejects(f.engine.exec(handle, { command: ["/usr/local/bin/node", "--version"], timeoutMs: 1000, outputCapBytes: 1024 }), /staged workspace/u);
    await f.engine.uploadArchive(handle, createWorkspaceArchive([{ path: "src/folder/source.js", content: Buffer.from("export const value = 1;\n") }], ["src", "src/folder"], true));
    const staging = f.requests.filter(r => r.path.endsWith("/exec")).map(r => r.body as JsonRecord);
    assert.equal(staging.length, 3);
    assert.ok(staging.every(value => value.User === "0:0" && value.Privileged === false && value.Cmd[0] === "/usr/local/bin/node"));
    assert.ok(staging.every(value => value.Cmd[2].includes("STAGING_DENIED") && value.Cmd[2].includes("C.O_NOFOLLOW")));
    for (const value of staging) new Function(value.Cmd[2]);
    assert.ok(staging[2]!.Cmd[2].includes("fs.fchmodSync(file,0o444)"));
    assert.ok(staging[2]!.Cmd[2].includes("fs.fchmodSync(dir,0o555)"));
    assert.equal(f.createConfig!.HostConfig.ReadonlyRootfs, true);
    await assert.rejects(f.engine.uploadArchive(handle, createWorkspaceArchive([])), /exactly once/u);
    await f.engine.exec(handle, { command: ["/usr/local/bin/node", "--version"], timeoutMs: 1000, outputCapBytes: 1024 });
    assert.equal(f.execConfig!.User, "65532:65532");
    await assert.rejects(f.engine.exec(handle, { command: ["/usr/local/bin/node"], user: "0:0", timeoutMs: 1000, outputCapBytes: 1024 } as never), /malformed/u);
    await assert.rejects(f.engine.uploadArchive(handle, createWorkspaceArchive([])), /exactly once/u);
  } finally { await f.close(); }
});

test("Writable staging uses only the task UID and splits large data into bounded fixed-script arguments", async () => {
  const f = await fixture();
  try {
    const handle = await f.engine.create(TASK); await f.engine.start(handle);
    const content = Buffer.from("regular source line\n".repeat(20_000));
    await f.engine.uploadArchive(handle, createWorkspaceArchive([{ path: "source.js", content }]));
    const configs = f.requests.filter(r => r.path.endsWith("/exec")).map(r => r.body as JsonRecord);
    assert.ok(configs.length > 10);
    assert.ok(configs.every(config => config.User === "65532:65532"));
    assert.ok(configs.every(config => Buffer.byteLength(config.Cmd[3]) < 48 * 1024));
    const chunks = configs.filter(c => JSON.parse(c.Cmd[3]).op === "chunks").flatMap(c => JSON.parse(c.Cmd[3]).chunks);
    assert.equal(Buffer.concat(chunks.map(chunk => Buffer.from(chunk.data, "base64"))).compare(content), 0);
    assert.equal(chunks.at(-1).final, true);
    assert.ok(!f.requests.some(r => r.method === "PUT"));
  } finally { await f.close(); }
});

test("Staging rejects malformed archives without guest exec and a failed trusted stager fences and stops the container", async () => {
  const f = await fixture();
  try {
    const handle = await f.engine.create(TASK); await f.engine.start(handle);
    await assert.rejects(f.engine.uploadArchive(handle, Buffer.alloc(1024, 1)), /Archive|archive/u);
    assert.ok(!f.requests.some(r => r.path.endsWith("/exec")));
    f.responseOverride = (req, res) => {
      if (req.url === `/v1.47/exec/${EXEC_ID}/start`) { res.writeHead(200); res.end(multiplex(2, "STAGING_DENIED")); return true; }
      return false;
    };
    await assert.rejects(f.engine.uploadArchive(handle, createWorkspaceArchive([])), /staging/u);
    assert.equal((await f.engine.inspect(handle)).running, false);
    await assert.rejects(f.engine.exec(handle, { command: ["/usr/local/bin/node"], timeoutMs: 1000, outputCapBytes: 1024 }), /staged workspace/u);
  } finally { await f.close(); }
});

test("Guest export reads real staged source in bounded chunks, pins hashes and permanently fences task exec", async () => {
  const f = await fixture();
  try {
    const handle = await f.engine.create(TASK); await f.engine.start(handle);
    const content = Buffer.from("source line\n".repeat(60_000));
    await f.engine.uploadArchive(handle, createWorkspaceArchive([{ path: "workspace/src/file.js", content }], ["workspace", "workspace/src"]));
    const archive = await f.engine.downloadArchive(handle);
    const files = parseWorkspaceArchive(archive, false);
    assert.equal(files[0]!.path, "workspace/src/file.js"); assert.equal(files[0]!.content.compare(content), 0);
    const configs = f.requests.filter(r => r.path.endsWith("/exec") && (r.body as JsonRecord).Cmd[2].includes("EXPORT_DENIED")).map(r => r.body as JsonRecord);
    assert.ok(configs.length >= 5); assert.ok(configs.every(c => c.User === "65532:65532" && c.Privileged === false));
    for (const config of configs) new Function(config.Cmd[2]);
    const script = configs[0]!.Cmd[2];
    assert.ok(script.includes("process.kill(-1,'SIGKILL')")); assert.ok(script.includes("uid[1]!=='65533'")); assert.ok(script.includes("C.O_NOFOLLOW"));
    assert.ok(!f.requests.some(r => r.path.includes("/archive?")));
    await assert.rejects(f.engine.exec(handle, { command: ["/usr/local/bin/node"], timeoutMs: 1000, outputCapBytes: 1024 }), /staged workspace/u);
    await f.engine.kill(handle); await f.engine.remove(handle);
  } finally { await f.close(); }
});

for (const invalid of ["secret", "hash"] as const) {
  test(`Guest export rejects ${invalid} evidence and stops before any unverified import`, async () => {
    const f = await fixture();
    try {
      const handle = await running(f);
      f.responseOverride = (req, res) => {
        if (req.url !== `/v1.47/exec/${EXEC_ID}/start` || !f.execConfig!.Cmd[2].includes("EXPORT_DENIED")) return false;
        const q = JSON.parse(f.execConfig!.Cmd[3]);
        if (q.op === "index") {
          const path = invalid === "secret" ? ".env" : "source.js";
          res.writeHead(200); res.end(multiplex(1, JSON.stringify({ directories: [], files: [{ path, size: 1, dev: "1", ino: "1", mtime: "1", ctime: "1" }] }))); return true;
        }
        if (q.op === "hashes") { res.writeHead(200); res.end(multiplex(1, JSON.stringify({ files: [{ path: "source.js", sha256: "d".repeat(64) }] }))); return true; }
        res.writeHead(200); res.end(multiplex(1, JSON.stringify({ data: Buffer.from("x").toString("base64"), sha256: "e".repeat(64) }))); return true;
      };
      await assert.rejects(f.engine.downloadArchive(handle), /invalid|forbidden/u);
      assert.equal((await f.engine.inspect(handle)).running, false);
      const ops = f.requests.filter(r => r.path.endsWith("/exec") && (r.body as JsonRecord).Cmd[2].includes("EXPORT_DENIED")).map(r => JSON.parse((r.body as JsonRecord).Cmd[3]).op);
      if (invalid === "secret") assert.deepEqual(ops, ["index"]);
    } finally { await f.close(); }
  });
}

test("Guest export cannot race an in-flight task execution", async () => {
  const f = await fixture();
  try {
    const handle = await running(f); f.delayRoute = `/v1.47/exec/${EXEC_ID}/start`;
    const cancelled = new AbortController();
    const task = f.engine.exec(handle, { command: ["/usr/local/bin/node"], timeoutMs: 500, outputCapBytes: 1024 }, { signal: cancelled.signal });
    await assert.rejects(f.engine.downloadArchive(handle), /exclusive ownership/u);
    cancelled.abort(); await assert.rejects(task, /cancellation/u);
    assert.equal((await f.engine.inspect(handle)).running, false);
  } finally { await f.close(); }
});
