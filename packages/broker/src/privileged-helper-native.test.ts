import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, readFile, rm, stat, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { InMemoryPrivilegedHelperReplayGuard, FailClosedPrivilegedHelper, PrivilegedHelperIpcServer } from "./privileged-helper.js";
import { capturePeerProcessIdentity } from "./peer-credentials.js";

const CHILD_SCRIPT = [
  'import { createConnection } from "node:net";',
  'import { stat, writeFile } from "node:fs/promises";',
  'const [socketPath, readyPath, resultPath, holdPath] = process.argv.slice(1);',
  'const deadline = Date.now() + 5000;',
  'while (true) { try { await stat(readyPath); break; } catch { if (Date.now() >= deadline) process.exit(2); await new Promise((resolve) => setTimeout(resolve, 10)); } }',
  'const socket = createConnection(socketPath);',
  'let output = "";',
  'socket.setEncoding("utf8");',
  'socket.on("data", (chunk) => { output += chunk; });',
  'socket.on("error", () => {});',
  'socket.on("close", async () => { await writeFile(resultPath, output, { mode: 0o600 }); if (holdPath) { while (true) { try { await stat(holdPath); await new Promise((resolve) => setTimeout(resolve, 20)); } catch { break; } } } });',
  'socket.on("connect", () => socket.end("not-json\\n"));'
].join("\n");

test("privileged helper native IPC accepts the bound Broker process and drops a spawned caller spoof", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("macOS native peer credentials are required");
    return;
  }
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined || uid < 1) throw new Error("POSIX identity is unavailable");
  const directory = await mkdtemp(join(tmpdir(), "mac-helper-native-peer-"));
  const socketPath = join(directory, "helper.sock");
  const authorizedReady = join(directory, "authorized.ready");
  const authorizedResult = join(directory, "authorized.result");
  const authorizedHold = join(directory, "authorized.hold");
  const attackerReady = join(directory, "attacker.ready");
  const attackerResult = join(directory, "attacker.result");
  let authorized: ChildProcess | undefined;
  let attacker: ChildProcess | undefined;
  let server: PrivilegedHelperIpcServer | undefined;
  try {
    authorized = spawn(process.execPath, ["--input-type=module", "-e", CHILD_SCRIPT, socketPath, authorizedReady, authorizedResult, authorizedHold], {
      cwd: "/",
      env: { PATH: process.env.PATH ?? "" },
      stdio: "ignore"
    });
    if (authorized.pid === undefined) throw new Error("Authorized helper peer fixture did not expose a PID");
    const authorizedIdentity = await waitForProcessIdentity(authorized.pid);
    server = new PrivilegedHelperIpcServer({
      socketPath,
      authenticationKey: randomBytes(32),
      replayGuard: new InMemoryPrivilegedHelperReplayGuard(),
      authorizeCommand: () => undefined,
      adapter: new FailClosedPrivilegedHelper(),
      peerPolicy: {
        expectedUid: uid,
        expectedGid: gid,
        allowedProcessIdentity: authorizedIdentity
      }
    });
    await writeFile(authorizedHold, "hold\n", { mode: 0o600 });
    await server.listen();
    await writeFile(authorizedReady, "ready\n", { mode: 0o600 });
    const authorizedOutput = await waitForFileText(authorizedResult);
    const authorizedResponse = JSON.parse(authorizedOutput) as { ok: boolean; resultClass: string };
    assert.equal(authorizedResponse.ok, false);
    assert.equal(authorizedResponse.resultClass, "PRECONDITION_FAILED");

    attacker = spawn(process.execPath, ["--input-type=module", "-e", CHILD_SCRIPT, socketPath, attackerReady, attackerResult], {
      cwd: "/",
      env: { PATH: process.env.PATH ?? "" },
      stdio: "ignore"
    });
    await writeFile(attackerReady, "ready\n", { mode: 0o600 });
    const attackerOutput = await waitForFileText(attackerResult, false);
    assert.equal(attackerOutput, "");
  } finally {
    await unlink(authorizedHold).catch(() => undefined);
    if (authorized && authorized.exitCode === null) authorized.kill("SIGKILL");
    if (attacker && attacker.exitCode === null) attacker.kill("SIGKILL");
    await server?.close().catch(() => undefined);
    await rm(directory, { recursive: true, force: true });
  }
});

async function waitForProcessIdentity(pid: number): Promise<ReturnType<typeof capturePeerProcessIdentity>> {
  const deadline = Date.now() + 2_000;
  while (Date.now() < deadline) {
    try { return capturePeerProcessIdentity(pid); }
    catch { await new Promise((resolve) => setTimeout(resolve, 10)); }
  }
  throw new Error("Helper peer process identity was unavailable");
}

async function waitForFileText(path: string, requireNonEmpty = true): Promise<string> {
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      const value = await readFile(path, "utf8");
      if (!requireNonEmpty || value.length > 0) return value;
    } catch {
      // The result file can exist while the child is still flushing its bytes.
    }
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for ${path}`);
}
