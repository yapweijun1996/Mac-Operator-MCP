import assert from "node:assert/strict";
import { spawn, type ChildProcess } from "node:child_process";
import { chmod, constants, copyFile, lstat, mkdir, mkdtemp, realpath, rename, rm, symlink, unlink } from "node:fs/promises";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import {
  DockerContainerEngine,
  type ContainerEngineOptions, type ContainerEngineRevalidationEvent
} from "./container-engine.js";
import { captureContainerEnginePeer, type ContainerEnginePeerIdentity } from "./container-engine-peer.js";

const ENGINE = "engine-local-identity";
const APPROVED_EXECUTABLE = "/Applications/Engine.app/Contents/MacOS/engine-daemon";
const UID = process.getuid!();
const GID = process.getgid!();

interface Daemon { requests: string[]; close(): Promise<void>; }

async function serve(socket: string, engineId = ENGINE, status = 200): Promise<Daemon> {
  const requests: string[] = [];
  const server = createServer((req, res) => {
    requests.push(req.url ?? "");
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ID: engineId, ServerVersion: "29.0", OSType: "linux", Architecture: "aarch64",
      SecurityOptions: ["name=seccomp,profile=builtin", "name=cgroupns"], CgroupVersion: "2" }));
  });
  await new Promise<void>((ok, fail) => { server.once("error", fail); server.listen(socket, ok); });
  await chmod(socket, 0o600);
  return { requests, close: async () => { server.closeAllConnections(); await new Promise<void>(done => server.close(() => done())); } };
}

interface Fixture {
  engine: DockerContainerEngine;
  directory: string;
  socket: string;
  daemon: Daemon;
  /** What the (stubbed) native probe reports about whoever owns the socket right now. */
  peer: ContainerEnginePeerIdentity;
  /** When set, the connect-time verifier reports this PID instead of the probe's. */
  verifierPid: number | undefined;
  events: ContainerEngineRevalidationEvent[];
  probes: number;
  restart(engineId?: string): Promise<Daemon>;
  close(): Promise<void>;
}

async function fixture(options: { revalidation?: boolean; cooldownMs?: number; probe?: (f: Fixture) => Promise<void> } = {}): Promise<Fixture> {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mop-revalidate-")));
  await chmod(directory, 0o700);
  const socket = join(directory, "engine.sock");
  const f = { directory, socket, events: [], probes: 0,
    peer: { uid: UID, gid: GID, pid: 1000, startTimeMicros: 10, executable: APPROVED_EXECUTABLE } } as unknown as Fixture;
  f.daemon = await serve(socket);
  const engineOptions: ContainerEngineOptions = {
    socketPath: socket,
    peerPolicy: { expectedUid: UID, expectedGid: GID, allowedProcessIdentity: { pid: 1000, startTimeMicros: 10 } },
    peerVerifier: { verify: () => ({ uid: f.peer.uid, gid: f.peer.gid, pid: f.verifierPid ?? f.peer.pid }) },
    ...(options.revalidation === false ? {} : { revalidation: { approvedEngineId: ENGINE, peerExecutable: APPROVED_EXECUTABLE,
      failureCooldownMs: options.cooldownMs ?? 0, onRevalidation: event => f.events.push(event),
      capturePeer: async () => { f.probes++; await options.probe?.(f); return { ...f.peer }; } } })
  };
  f.engine = new DockerContainerEngine(engineOptions);
  f.restart = async (engineId = ENGINE) => {
    await f.daemon.close();
    try { await unlink(socket); } catch { /* closed servers already removed their socket */ }
    f.daemon = await serve(socket, engineId);
    return f.daemon;
  };
  f.close = async () => { await f.daemon.close(); await rm(directory, { recursive: true, force: true }); };
  return f;
}

const inode = async (path: string): Promise<number> => (await lstat(path)).ino;

test("an engine restart is revalidated once and then served from the new socket and daemon", async () => {
  const f = await fixture();
  try {
    assert.equal((await f.engine.info()).id, ENGINE);
    const before = await inode(f.socket);
    await f.restart();
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20 };
    assert.notEqual(await inode(f.socket), before);
    assert.equal((await f.engine.info()).id, ENGINE);
    assert.equal(f.probes, 1);
    assert.equal(f.events.length, 1);
    assert.deepEqual({ outcome: f.events[0]!.outcome, reason: f.events[0]!.reason, engineId: f.events[0]!.engineId }, { outcome: "accepted", reason: "ENGINE_RESTART_REVALIDATED", engineId: ENGINE });
    assert.deepEqual(f.events[0]!.previous.pid, 1000);
    assert.deepEqual(f.events[0]!.current, { inode: await inode(f.socket), pid: 2000 });
    // The new pins are in force: no further revalidation, and the old daemon identity is no longer accepted.
    await f.engine.info();
    assert.equal(f.probes, 1);
    f.peer = { ...f.peer, pid: 1000, startTimeMicros: 10 };
    await assert.rejects(f.engine.info(), /peer identity/u);
  } finally { await f.close(); }
});

test("without opt-in a restarted engine stays denied and receives no request", async () => {
  const f = await fixture({ revalidation: false });
  try {
    await f.engine.info();
    const replacement = await f.restart();
    await assert.rejects(f.engine.info(), /unsafe/u);
    assert.equal(replacement.requests.length, 0);
    assert.equal(f.probes, 0);
  } finally { await f.close(); }
});

test("a replacement socket served by a different executable is denied without sending any request", async () => {
  const f = await fixture();
  try {
    await f.engine.info();
    const attacker = await f.restart();
    f.peer = { ...f.peer, pid: 3000, startTimeMicros: 30, executable: "/tmp/attacker/engine-daemon" };
    await assert.rejects(f.engine.info(), /executable differs/u);
    assert.equal(attacker.requests.length, 0);
    assert.equal(f.events.at(-1)?.reason, "ENGINE_EXECUTABLE_CHANGED");
    assert.equal(f.events.at(-1)?.outcome, "refused");
    // A refusal keeps the previous pins: the real daemon identity is still the only one that could ever be accepted.
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20, executable: APPROVED_EXECUTABLE };
    assert.equal((await f.engine.info()).id, ENGINE);
  } finally { await f.close(); }
});

test("a replacement whose peer is another user or group is denied without sending any request", async () => {
  for (const peer of [{ uid: UID + 1 }, { gid: GID + 1 }]) {
    const f = await fixture();
    try {
      await f.engine.info();
      const attacker = await f.restart();
      f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20, ...peer };
      await assert.rejects(f.engine.info(), /peer owner differs/u);
      assert.equal(attacker.requests.length, 0);
      assert.equal(f.events.at(-1)?.reason, "ENGINE_PEER_OWNER_MISMATCH");
    } finally { await f.close(); }
  }
});

test("a native probe that cannot identify the peer denies the replacement", async () => {
  const f = await fixture({ probe: async () => { throw new Error("no peer"); } });
  try {
    await f.engine.info();
    const attacker = await f.restart();
    await assert.rejects(f.engine.info(), /peer identity verification failed/u);
    assert.equal(attacker.requests.length, 0);
    assert.equal(f.events.at(-1)?.reason, "ENGINE_PEER_UNVERIFIED");
  } finally { await f.close(); }
});

test("a replacement socket with unsafe permissions, a symlink or an unsafe parent is denied", async () => {
  const f = await fixture();
  try {
    await f.engine.info();
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20 };

    const loose = await f.restart();
    await chmod(f.socket, 0o666);
    await assert.rejects(f.engine.info(), /unsafe/u);
    assert.equal(loose.requests.length, 0);
    assert.equal(f.events.at(-1)?.reason, "ENGINE_SOCKET_UNSAFE");

    const real = await f.restart();
    const hidden = join(f.directory, "hidden.sock");
    await rename(f.socket, hidden);
    await symlink(hidden, f.socket);
    await assert.rejects(f.engine.info(), /unsafe/u);
    assert.equal(real.requests.length, 0);
    await unlink(f.socket);
    await rename(hidden, f.socket);

    await chmod(f.directory, 0o777);
    await assert.rejects(f.engine.info(), /unsafe/u);
    await chmod(f.directory, 0o700);
    assert.equal(real.requests.length, 0);
    assert.equal(f.probes, 0, "structural failures are refused before the daemon is even contacted");
  } finally { await f.close(); }
});

test("a replacement that reports another engine identity is denied and the previous pins survive", async () => {
  const f = await fixture();
  try {
    await f.engine.info();
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20 };
    await f.restart("some-other-engine");
    await assert.rejects(f.engine.info(), /identity changed/u);
    assert.equal(f.events.at(-1)?.reason, "ENGINE_IDENTITY_CHANGED");
    // The rejected engine ID was not remembered, so the genuine engine can still be revalidated afterwards.
    await f.restart(ENGINE);
    assert.equal((await f.engine.info()).id, ENGINE);
  } finally { await f.close(); }
});

test("the operator-approved engine identity is enforced even when the engine was never queried before the restart", async () => {
  const f = await fixture();
  try {
    await f.restart("some-other-engine");
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20 };
    await assert.rejects(f.engine.info(), /identity changed/u);
    await f.restart(ENGINE);
    assert.equal((await f.engine.info()).id, ENGINE, "a rejected engine ID must not stay cached");
  } finally { await f.close(); }
});

test("a daemon that answers with an error is reported as unavailable and can be revalidated once it is ready", async () => {
  const f = await fixture();
  try {
    await f.engine.info();
    await f.daemon.close();
    await rm(f.socket, { force: true });
    f.daemon = await serve(f.socket, ENGINE, 503);
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20 };
    await assert.rejects(f.engine.info(), /not ready to be revalidated/u);
    assert.equal(f.events.at(-1)?.reason, "ENGINE_UNAVAILABLE");
    await f.restart();
    assert.equal((await f.engine.info()).id, ENGINE);
    assert.equal(f.events.at(-1)?.outcome, "accepted");
  } finally { await f.close(); }
});

test("a peer that fails the connect-time check on the candidate pins receives nothing and is refused", async () => {
  const f = await fixture();
  try {
    await f.engine.info();
    const replacement = await f.restart();
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20 };
    f.verifierPid = 4000;
    await assert.rejects(f.engine.info(), /peer identity verification failed/u);
    assert.equal(f.events.at(-1)?.reason, "ENGINE_PEER_UNVERIFIED");
    assert.equal(replacement.requests.length, 0);
    f.verifierPid = undefined;
    assert.equal((await f.engine.info()).id, ENGINE);
  } finally { await f.close(); }
});

test("a socket swapped again while the daemon is being identified is denied", async () => {
  let swapped: Daemon | undefined;
  const f = await fixture({ probe: async (self) => {
    await self.daemon.close();
    try { await unlink(self.socket); } catch { /* already removed */ }
    swapped = await serve(self.socket);
    self.daemon = swapped;
  } });
  try {
    await f.engine.info();
    const first = await f.restart();
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20 };
    await assert.rejects(f.engine.info(), /unsafe/u);
    assert.equal(first.requests.length, 0);
    assert.equal(swapped?.requests.length, 0);
    assert.equal(f.events.at(-1)?.reason, "ENGINE_SOCKET_REPLACED");
  } finally { await f.close(); }
});

test("an active task blocks revalidation, and a completed one is fenced once the restart is accepted", async () => {
  const f = await fixture();
  try {
    await f.engine.info();
    const workspaces = (f.engine as unknown as { workspaces: Map<string, { phase: string; activeExecutions: number }> }).workspaces;
    const attacker = await f.restart();
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20 };
    workspaces.set("running", { phase: "executing", activeExecutions: 1 });
    await assert.rejects(f.engine.info(), /task was active/u);
    assert.equal(f.events.at(-1)?.reason, "ENGINE_TASK_ACTIVE");
    assert.equal(attacker.requests.length, 0);
    workspaces.set("running", { phase: "staging", activeExecutions: 0 });
    await assert.rejects(f.engine.info(), /task was active/u);
    workspaces.set("running", { phase: "executing", activeExecutions: 0 });
    workspaces.set("idle", { phase: "ready", activeExecutions: 0 });
    await f.engine.info();
    assert.deepEqual([...workspaces.values()].map(workspace => workspace.phase), ["blocked", "blocked"]);
    assert.equal(f.events.at(-1)?.fencedWorkspaces, 2);
  } finally { await f.close(); }
});

test("concurrent requests during a restart share one revalidation and none bypasses it", async () => {
  const f = await fixture();
  try {
    await f.engine.info();
    const replacement = await f.restart();
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20 };
    const results = await Promise.all([f.engine.info(), f.engine.info(), f.engine.info(), f.engine.info()]);
    assert.ok(results.every(result => result.id === ENGINE));
    assert.equal(f.probes, 1);
    assert.equal(f.events.filter(event => event.outcome === "accepted").length, 1);
    assert.equal(replacement.requests.length, 5, "one verification probe plus the four callers");
  } finally { await f.close(); }
});

test("a refused attempt is not retried inside the cooldown, and the cooldown does not extend itself", async () => {
  const f = await fixture({ cooldownMs: 250 });
  try {
    await f.engine.info();
    await f.restart();
    f.peer = { ...f.peer, pid: 2000, startTimeMicros: 20, executable: "/tmp/other" };
    await assert.rejects(f.engine.info(), /executable differs/u);
    f.peer = { ...f.peer, executable: APPROVED_EXECUTABLE };
    await assert.rejects(f.engine.info(), /moments ago/u);
    assert.equal(f.probes, 1);
    await new Promise<void>(done => setTimeout(done, 300));
    assert.equal((await f.engine.info()).id, ENGINE);
  } finally { await f.close(); }
});

test("revalidation configuration is validated and the probe seam is unavailable in production", async () => {
  const f = await fixture({ revalidation: false });
  try {
    const base = { socketPath: f.socket, peerPolicy: { expectedUid: UID, expectedGid: GID, allowedProcessIdentity: { pid: 1000, startTimeMicros: 10 } } };
    const capturePeer = async (): Promise<ContainerEnginePeerIdentity> => f.peer;
    for (const revalidation of [
      { approvedEngineId: "", peerExecutable: APPROVED_EXECUTABLE },
      { approvedEngineId: ENGINE, peerExecutable: "relative/engine" },
      { approvedEngineId: ENGINE, peerExecutable: APPROVED_EXECUTABLE, extra: true },
      { approvedEngineId: ENGINE, peerExecutable: APPROVED_EXECUTABLE, failureCooldownMs: -1 },
      { approvedEngineId: ENGINE, peerExecutable: APPROVED_EXECUTABLE, capturePeer }
    ]) {
      assert.throws(() => new DockerContainerEngine({ ...base, revalidation } as ContainerEngineOptions), /revalidation|bounded range/u);
    }
  } finally { await f.close(); }
});

// Real processes, real kernel peer credentials, real socket recreation. The daemon is a stand-in HTTP server run by
// the node binary, so the executable continuity and PID/start-time pinning are exercised by the native adapter.
const DAEMON_SCRIPT = `const h=require("http"),fs=require("fs");const sock=process.argv[1];
const s=h.createServer((q,r)=>{console.log("REQ "+q.url);r.setHeader("content-type","application/json");
r.end(JSON.stringify({ID:"${ENGINE}",ServerVersion:"29.0",OSType:"linux",Architecture:"aarch64",SecurityOptions:["name=seccomp,profile=builtin","name=cgroupns"],CgroupVersion:"2"}))});
s.listen(sock,()=>{fs.chmodSync(sock,0o600);console.log("READY")});process.on("SIGTERM",()=>{s.close();process.exit(0)});`;

interface RealDaemon { child: ChildProcess; requests: () => number; stop(): Promise<void>; }

async function spawnDaemon(executable: string, socket: string): Promise<RealDaemon> {
  const child = spawn(executable, ["-e", DAEMON_SCRIPT, socket], { stdio: ["ignore", "pipe", "ignore"] });
  let requests = 0;
  await new Promise<void>((ok, fail) => {
    child.once("error", fail);
    child.once("exit", code => fail(new Error(`daemon exited early (${code})`)));
    child.stdout!.on("data", chunk => {
      const text = String(chunk);
      requests += (text.match(/REQ /gu) ?? []).length;
      if (text.includes("READY")) ok();
    });
  });
  return { child, requests: () => requests, stop: async () => {
    if (child.exitCode !== null || child.signalCode !== null) return;
    child.kill("SIGTERM");
    await new Promise<void>(done => child.once("exit", () => done()));
  } };
}

test("real host: a restarted daemon process is revalidated, an impostor executable is not", { skip: process.platform !== "darwin" }, async () => {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mop-native-revalidate-")));
  await chmod(directory, 0o700);
  const socket = join(directory, "engine.sock");
  const impostorBinary = join(directory, "impostor", "bin", "node");
  const daemons: RealDaemon[] = [];
  try {
    // A byte-identical copy at another path; shared-library node builds resolve libnode through ../lib.
    await mkdir(dirname(impostorBinary), { recursive: true });
    await copyFile(process.execPath, impostorBinary, constants.COPYFILE_FICLONE);
    await chmod(impostorBinary, 0o755);
    await symlink(join(dirname(await realpath(process.execPath)), "..", "lib"), join(directory, "impostor", "lib"));
    const first = await spawnDaemon(process.execPath, socket);
    daemons.push(first);
    const pinned = await captureContainerEnginePeer(socket, UID);
    assert.equal(pinned.pid, first.child.pid);
    assert.ok(pinned.executable, "the kernel reports the daemon executable");
    const events: ContainerEngineRevalidationEvent[] = [];
    const engine = new DockerContainerEngine({ socketPath: socket,
      peerPolicy: { expectedUid: pinned.uid, expectedGid: pinned.gid, allowedProcessIdentity: { pid: pinned.pid, startTimeMicros: pinned.startTimeMicros } },
      revalidation: { approvedEngineId: ENGINE, peerExecutable: pinned.executable!, failureCooldownMs: 0, onRevalidation: event => events.push(event) } });
    assert.equal((await engine.info()).id, ENGINE);
    const firstInode = await inode(socket);

    // Legitimate restart: new process, new socket inode, same executable.
    await first.stop();
    await rm(socket, { force: true });
    const second = await spawnDaemon(process.execPath, socket);
    daemons.push(second);
    assert.notEqual(await inode(socket), firstInode);
    assert.equal((await engine.info()).id, ENGINE);
    assert.equal(events.at(-1)?.outcome, "accepted");
    assert.equal(events.at(-1)?.current?.pid, second.child.pid);

    // Impostor: same user, same uid/gid, even a valid /info answer — but not the approved executable file.
    await second.stop();
    await rm(socket, { force: true });
    const impostor = await spawnDaemon(impostorBinary, socket);
    daemons.push(impostor);
    await assert.rejects(engine.info(), /executable differs|peer identity/u);
    assert.equal(impostor.requests(), 0, "no request may reach the impostor");
    assert.equal(events.at(-1)?.reason, "ENGINE_EXECUTABLE_CHANGED");
    await impostor.stop();
  } finally {
    await Promise.all(daemons.map(daemon => daemon.stop()));
    await rm(directory, { recursive: true, force: true });
  }
});
