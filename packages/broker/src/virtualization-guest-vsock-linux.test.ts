import assert from "node:assert/strict";
import test from "node:test";
import type { VirtualizationGuestStream } from "./virtualization-guest-bootstrap.js";
import {
  createLinuxGuestVsockConnectionSource,
  type LinuxGuestVsockBinding
} from "./virtualization-guest-vsock-linux.js";

class FakeBinding implements LinuxGuestVsockBinding {
  readonly accepted: unknown[] = [];
  readonly closedConnections: unknown[] = [];
  readonly readChunks: Array<Buffer | null> = [];
  readonly written: Buffer[] = [];
  listenerClosed = false;
  listenerOptions: [number, number] | undefined;
  acceptPromise: Promise<unknown | null> | undefined;

  createGuestVsockListener(port: number, backlog: number): unknown {
    this.listenerOptions = [port, backlog];
    return { listener: true };
  }

  async acceptGuestVsockConnection(): Promise<unknown | null> {
    if (this.acceptPromise !== undefined) return this.acceptPromise;
    return this.accepted.shift() ?? null;
  }

  async readGuestVsockChunk(): Promise<Buffer | null> {
    return this.readChunks.shift() ?? null;
  }

  async writeGuestVsockChunk(_connection: unknown, frame: Buffer): Promise<void> {
    this.written.push(Buffer.from(frame));
  }

  closeGuestVsockConnection(connection: unknown): void {
    this.closedConnections.push(connection);
  }

  closeGuestVsockListener(): void {
    this.listenerClosed = true;
  }
}

test("Linux guest vsock source creates one bounded startup listener and adapts streams", async () => {
  const binding = new FakeBinding();
  binding.accepted.push({ connection: 1 });
  binding.readChunks.push(Buffer.from("request-frame"), null);
  const source = createLinuxGuestVsockConnectionSource({ port: 38_765, maxConnections: 2, binding });
  assert.deepEqual(binding.listenerOptions, [38_765, 2]);

  const stream = await source.accept(new AbortController().signal) as VirtualizationGuestStream;
  const received: Buffer[] = [];
  for await (const chunk of stream.readable) received.push(Buffer.from(chunk));
  assert.deepEqual(Buffer.concat(received), Buffer.from("request-frame"));
  await stream.write(Buffer.from("response-frame"));
  assert.deepEqual(binding.written, [Buffer.from("response-frame")]);
  stream.close();
  assert.deepEqual(binding.closedConnections, [{ connection: 1 }]);

  await source.close();
  assert.equal(binding.listenerClosed, true);
});

test("Linux guest vsock source closes a connection accepted after cancellation", async () => {
  const binding = new FakeBinding();
  let resolveAccept: ((value: unknown | null) => void) | undefined;
  binding.acceptPromise = new Promise((resolve) => { resolveAccept = resolve; });
  const source = createLinuxGuestVsockConnectionSource({ port: 38_765, binding });
  const controller = new AbortController();
  const pending = source.accept(controller.signal);
  controller.abort();
  await assert.rejects(pending, /cancelled/u);

  resolveAccept?.({ connection: "late" });
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(binding.closedConnections, [{ connection: "late" }]);
  await source.close();
});

test("Linux guest vsock source rejects invalid startup budgets", () => {
  const binding = new FakeBinding();
  assert.throws(() => createLinuxGuestVsockConnectionSource({ port: 0, binding }), /options are invalid/u);
  assert.throws(() => createLinuxGuestVsockConnectionSource({ port: 38_765, maxConnections: 9, binding }), /options are invalid/u);
});
