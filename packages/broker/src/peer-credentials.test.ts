import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { createConnection, createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { MacOsPeerCredentialVerifier } from "./peer-credentials.js";

test("macOS peer credentials bind an accepted UDS connection to uid, gid, and pid", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-peer-"));
  const socketPath = join(directory, "peer.sock");
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  const verifier = new MacOsPeerCredentialVerifier({
    expectedUid: uid,
    expectedGid: gid,
    allowedProcessIds: new Set([process.pid])
  });
  const observed = new Promise<void>((resolve, reject) => {
    const server = createServer((socket) => {
      try {
        assert.deepEqual(verifier.verify(socket), { uid, gid, pid: process.pid });
        socket.end();
        server.close((error) => error ? reject(error) : resolve());
      } catch (error) {
        reject(error);
      }
    });
    server.once("error", reject);
    server.listen(socketPath, () => createConnection(socketPath));
  });
  try {
    await observed;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("macOS peer credential policy rejects an unlisted process identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-peer-deny-"));
  const socketPath = join(directory, "peer.sock");
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error("POSIX identity is unavailable");
  const verifier = new MacOsPeerCredentialVerifier({
    expectedUid: uid,
    allowedProcessIds: new Set([process.pid + 1])
  });
  const observed = new Promise<void>((resolve, reject) => {
    const server = createServer((socket) => {
      try {
        assert.throws(() => verifier.verify(socket), /process is not authorized/u);
        socket.end();
        server.close((error) => error ? reject(error) : resolve());
      } catch (error) {
        reject(error);
      }
    });
    server.once("error", reject);
    server.listen(socketPath, () => createConnection(socketPath));
  });
  try {
    await observed;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
