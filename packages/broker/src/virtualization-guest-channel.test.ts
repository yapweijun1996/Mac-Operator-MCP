import assert from "node:assert/strict";
import { chmod, mkdtemp, rm, symlink } from "node:fs/promises";
import { createServer, type Server, type Socket } from "node:net";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { MacOsVirtualizationGuestChannel, validateVirtualizationGuestSocketTarget } from "./virtualization-guest-channel.js";

const darwinOnly = { skip: process.platform !== "darwin" || process.getuid?.() === undefined };

test("guest channel authenticates the native peer and exchanges one bounded frame", darwinOnly, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-channel-"));
  const socketPath = join(directory, "adapter.sock");
  let server: Server | undefined;
  const uid = process.getuid?.();
  assert.notEqual(uid, undefined);
  try {
    server = await startServer(socketPath, (socket) => readRequest(socket, (request) => {
      assert.equal(request.toString("utf8"), "guest-request");
      socket.end(encodeFrame(Buffer.from("guest-response", "utf8")));
    }));
    const channel = new MacOsVirtualizationGuestChannel({
      socketPath,
      peerPolicy: { expectedUid: uid! },
      maxFrameBytes: 1_024
    });
    try {
      const response = await channel.exchange(Buffer.from("guest-request", "utf8"), new AbortController().signal);
      assert.equal(Buffer.from(response).toString("utf8"), "guest-response");
    } finally {
      channel.close();
    }
  } finally {
    await closeServer(server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("guest channel rejects peer substitution before accepting a response", darwinOnly, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-channel-peer-"));
  const socketPath = join(directory, "adapter.sock");
  let server: Server | undefined;
  const uid = process.getuid?.();
  assert.notEqual(uid, undefined);
  try {
    server = await startServer(socketPath, (socket) => socket.end(encodeFrame(Buffer.from("unexpected", "utf8"))));
    const channel = new MacOsVirtualizationGuestChannel({
      socketPath,
      peerPolicy: { expectedUid: uid! + 1 }
    });
    await assert.rejects(
      () => channel.exchange(Buffer.from("guest-request", "utf8"), new AbortController().signal),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUTH_INVALID"
    );
    channel.close();
  } finally {
    await closeServer(server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("guest channel maps cancellation, oversized, and trailing responses safely", darwinOnly, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-channel-bounds-"));
  const socketPath = join(directory, "adapter.sock");
  const uid = process.getuid?.();
  assert.notEqual(uid, undefined);
  let server: Server | undefined;
  try {
    server = await startServer(socketPath, (socket) => readRequest(socket, () => undefined));
    const channel = new MacOsVirtualizationGuestChannel({
      socketPath,
      peerPolicy: { expectedUid: uid! },
      timeoutMs: 2_000,
      maxFrameBytes: 256
    });
    const abortController = new AbortController();
    const cancelled = channel.exchange(Buffer.from("guest-request", "utf8"), abortController.signal);
    setTimeout(() => abortController.abort(), 10);
    await assert.rejects(
      () => cancelled,
      (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
    );
    channel.close();
    await closeServer(server);

    server = await startServer(socketPath, (socket) => readRequest(socket, () => {
      socket.end(encodeFrame(Buffer.alloc(257)));
    }));
    const oversizedChannel = new MacOsVirtualizationGuestChannel({
      socketPath,
      peerPolicy: { expectedUid: uid! },
      maxFrameBytes: 256
    });
    await assert.rejects(
      () => oversizedChannel.exchange(Buffer.from("guest-request", "utf8"), new AbortController().signal),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "OUTPUT_LIMIT"
    );
    oversizedChannel.close();
    await closeServer(server);

    server = await startServer(socketPath, (socket) => readRequest(socket, () => {
      socket.end(Buffer.concat([encodeFrame(Buffer.from("ok", "utf8")), Buffer.from("trailing", "utf8")]));
    }));
    const trailingChannel = new MacOsVirtualizationGuestChannel({
      socketPath,
      peerPolicy: { expectedUid: uid! },
      maxFrameBytes: 256
    });
    await assert.rejects(
      () => trailingChannel.exchange(Buffer.from("guest-request", "utf8"), new AbortController().signal),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
    );
    trailingChannel.close();
  } finally {
    await closeServer(server);
    await rm(directory, { recursive: true, force: true });
  }
});

test("guest channel target validation rejects a symlinked socket", darwinOnly, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-channel-path-"));
  const socketPath = join(directory, "adapter.sock");
  const aliasPath = join(directory, "adapter-alias.sock");
  let server: Server | undefined;
  try {
    server = await startServer(socketPath, () => undefined);
    await symlink(socketPath, aliasPath);
    await assert.rejects(
      () => validateVirtualizationGuestSocketTarget(aliasPath),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    await closeServer(server);
    await rm(directory, { recursive: true, force: true });
  }
});

async function startServer(socketPath: string, onConnection: (socket: Socket) => void): Promise<Server> {
  const server = createServer(onConnection);
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(socketPath, () => resolve());
  });
  await chmod(socketPath, 0o600);
  return server;
}

async function closeServer(server: Server | undefined): Promise<void> {
  if (server === undefined) return;
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

function readRequest(socket: Socket, onRequest: (request: Buffer) => void): void {
  let buffer = Buffer.alloc(0);
  socket.on("data", (chunk: Buffer) => {
    buffer = Buffer.concat([buffer, chunk]);
    if (buffer.byteLength < 4) return;
    const length = buffer.readUInt32BE(0);
    if (length < 1 || buffer.byteLength < length + 4) return;
    onRequest(buffer.subarray(4, length + 4));
  });
}

function encodeFrame(payload: Buffer): Buffer {
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(payload.byteLength, 0);
  return Buffer.concat([header, payload]);
}
