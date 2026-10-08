import assert from "node:assert/strict";
import { chown, lstat, mkdtemp, rm, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { MacOsNativePeerIpcServer } from "./native-peer-ipc-server.js";
import { loadNativePeerAdapter } from "./peer-credentials.js";

test("native listener fixes inherited parent GID before strict owner-only IPC readback", async (t) => {
  const uid = process.geteuid!();
  const gid = process.getegid!();
  const directory = await mkdtemp(join(tmpdir(), "mops-native-gid-"));
  const socketPath = join(directory, "peer.sock");
  const native = loadNativePeerAdapter();
  const server = new MacOsNativePeerIpcServer({
    socketPath,
    peerPolicy: { expectedUid: uid, expectedGid: gid, allowedProcessIds: new Set([process.pid]) },
    onSocket: (socket) => socket.destroy()
  });
  let descriptor: number | undefined;
  try {
    if ((await lstat(directory)).gid === gid) {
      const parentGid = process.getgroups!().find((group) => group !== gid);
      if (parentGid === undefined) {
        t.skip("A different inherited or supplementary parent GID is required");
        return;
      }
      // An owner can assign a supplementary group without root privileges.
      await chown(directory, uid, parentGid);
    }
    const parent = await lstat(directory);
    assert.equal(parent.uid, uid);
    assert.notEqual(parent.gid, gid);
    assert.equal(parent.mode & 0o777, 0o700);

    descriptor = native.createUnixListener(socketPath, 16);
    const socket = await lstat(socketPath);
    assert.equal(socket.isSocket(), true);
    assert.equal(socket.uid, uid);
    assert.equal(socket.gid, gid);
    assert.equal(socket.mode & 0o7777, 0o600);
    native.closeUnixDescriptor(descriptor);
    descriptor = undefined;
    await unlink(socketPath);

    await server.listen();
    assert.equal((await lstat(socketPath)).gid, gid);
    assert.equal((await lstat(socketPath)).mode & 0o7777, 0o600);
    await server.close();
    await assert.rejects(lstat(socketPath), { code: "ENOENT" });
    assert.equal((await lstat(directory)).gid, parent.gid);
  } finally {
    if (descriptor !== undefined) native.closeUnixDescriptor(descriptor);
    await server.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("native listener preserves explicit group access and exact-user ACL metadata", async (t) => {
  const uid = process.geteuid!();
  const gid = process.getegid!();
  if (uid === 0) {
    t.skip("The exact-user ACL fixture requires a non-root peer UID");
    return;
  }
  const directory = await mkdtemp(join(tmpdir(), "mops-native-access-"));
  const socketPath = join(directory, "peer.sock");
  const native = loadNativePeerAdapter();
  let descriptor: number | undefined;
  try {
    descriptor = native.createUnixListener(socketPath, 16, gid);
    const groupSocket = await lstat(socketPath);
    assert.equal(groupSocket.uid, uid);
    assert.equal(groupSocket.gid, gid);
    assert.equal(groupSocket.mode & 0o7777, 0o620);
    native.closeUnixDescriptor(descriptor);
    descriptor = undefined;
    await unlink(socketPath);

    descriptor = native.createUnixListener(socketPath, 16, undefined, uid);
    const aclSocket = await lstat(socketPath);
    assert.equal(aclSocket.uid, uid);
    assert.equal(aclSocket.gid, gid);
    assert.equal(aclSocket.mode & 0o7777, 0o600);
    assert.equal(native.getUnixSocketAclPeerUid(socketPath), uid);
  } finally {
    if (descriptor !== undefined) native.closeUnixDescriptor(descriptor);
    await rm(directory, { recursive: true, force: true });
  }
});
