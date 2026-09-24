import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  InMemoryVirtualizationGuestReplayGuard,
  createVirtualizationGuestRequest,
  virtualizationGuestRequestDigest,
  type UnsignedVirtualizationGuestRequest,
  type UnsignedVirtualizationGuestResponse
} from "./virtualization-guest-transport.js";
import { VirtualizationGuestAgent } from "./virtualization-guest-agent.js";
import {
  VirtualizationGuestBootstrap,
  type VirtualizationGuestConnectionSource,
  type VirtualizationGuestStream
} from "./virtualization-guest-bootstrap.js";

const guestIdentity = { imageSha256: "a".repeat(64), runtimeVersion: "test-generic-efi-vz-1" } as const;
const now = 1_800_000_000_000;

function requestFrame(): Uint8Array {
  const key = Buffer.alloc(32, 0x61);
  const request = createVirtualizationGuestRequest({
    guestIdentity,
    sandboxProfile: "guest-task-v1",
    profileDigest: "b".repeat(64),
    taskDigest: "c".repeat(64),
    processTreePolicy: "single_process",
    timeoutMs: 1_000,
    outputCapBytes: 1_024,
    requestId: "request:guest-bootstrap-0123456789",
    nonce: "guest-nonce-bootstrap-0123456789",
    timestampMs: now,
    expiresAtMs: now + 30_000
  }, key, { now });
  key.fill(0);
  return Buffer.from(JSON.stringify(request), "utf8");
}

function response(request: UnsignedVirtualizationGuestRequest): UnsignedVirtualizationGuestResponse {
  return {
    schemaVersion: "0.1",
    protocolVersion: "0.1",
    contractVersion: "0.1",
    kind: "virtualization_guest_task_result",
    requestId: request.requestId,
    nonce: request.nonce,
    guestIdentity,
    requestDigest: virtualizationGuestRequestDigest(request),
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    stdout: "guest-bootstrap-ok",
    stderr: "",
    truncated: false,
    durationMs: 2,
    outputPolicy: "broker-redacted-v1",
    verification: { status: "verified", summary: "guest response verified" }
  };
}

class TestStream implements VirtualizationGuestStream {
  readonly readable: AsyncIterable<Uint8Array>;
  written: Uint8Array | undefined;
  closed = false;
  private resolveClosed!: () => void;
  readonly closedPromise = new Promise<void>((resolve) => { this.resolveClosed = resolve; });

  constructor(...chunks: Uint8Array[]) {
    this.readable = (async function* () {
      for (const chunk of chunks) yield chunk;
    })();
  }

  async write(frame: Uint8Array): Promise<void> {
    this.written = new Uint8Array(frame);
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.resolveClosed();
  }
}

class TestSource implements VirtualizationGuestConnectionSource {
  private readonly streams: VirtualizationGuestStream[];
  closed = false;

  constructor(...streams: VirtualizationGuestStream[]) {
    this.streams = [...streams];
  }

  async accept(): Promise<VirtualizationGuestStream | null> {
    return this.streams.shift() ?? null;
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const stream of this.streams) stream.close();
  }
}

class HangingStream implements VirtualizationGuestStream {
  readonly readable: AsyncIterable<Uint8Array>;
  closed = false;
  private readonly release: () => void;

  constructor() {
    let resolveRelease!: () => void;
    const gate = new Promise<void>((resolve) => { resolveRelease = resolve; });
    this.release = resolveRelease;
    this.readable = (async function* () {
      await gate;
    })();
  }

  async write(): Promise<void> { return undefined; }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.release();
  }
}

function agent(): VirtualizationGuestAgent {
  const key = Buffer.alloc(32, 0x61);
  return new VirtualizationGuestAgent({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    expectedGuestIdentity: guestIdentity,
    expectedSandboxProfile: "guest-task-v1",
    expectedProfileDigest: "b".repeat(64),
    now: () => now,
    execute: async (request) => response(request)
  });
}

test("guest bootstrap is disabled without accepting connections", async () => {
  const source = new TestSource();
  const bootstrap = new VirtualizationGuestBootstrap({ enabled: false, agent: agent(), source });
  await assert.rejects(bootstrap.start(), (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED");
  assert.equal(bootstrap.readback().state, "disabled");
  assert.equal(source.closed, false);
  await bootstrap.close();
  assert.equal(bootstrap.readback().state, "closed");
});

test("guest bootstrap serves one bounded authenticated frame per connection", async () => {
  const stream = new TestStream(encodeFrame(requestFrame()));
  const source = new TestSource(stream);
  const bootstrap = new VirtualizationGuestBootstrap({ enabled: true, agent: agent(), source });
  await bootstrap.start();
  await stream.closedPromise;
  assert.equal(stream.closed, true);
  assert.ok(stream.written);
  const responseFrame = Buffer.from(stream.written!);
  assert.equal(responseFrame.readUInt32BE(0), responseFrame.byteLength - 4);
  const parsed = JSON.parse(responseFrame.subarray(4).toString("utf8")) as { stdout?: string };
  assert.equal(parsed.stdout, "guest-bootstrap-ok");
  assert.equal(bootstrap.readback().completedConnections, 1);
  await bootstrap.close();
  assert.equal(bootstrap.readback().state, "closed");
});

test("guest bootstrap rejects trailing and oversized request frames", async () => {
  const trailing = new TestStream(Buffer.concat([Buffer.from(encodeFrame(requestFrame())), Buffer.from([1])]));
  const oversized = new TestStream(Buffer.from([0, 0, 0x10, 0x01, 1]));
  const source = new TestSource(trailing, oversized);
  const bootstrap = new VirtualizationGuestBootstrap({
    enabled: true,
    agent: agent(),
    source,
    maxFrameBytes: 4_096
  });
  await bootstrap.start();
  await Promise.all([trailing.closedPromise, oversized.closedPromise]);
  assert.equal(bootstrap.readback().completedConnections, 0);
  assert.equal(bootstrap.readback().rejectedConnections, 2);
  await bootstrap.close();
});

test("guest bootstrap bounds concurrency and closes active streams", async () => {
  const hanging = new HangingStream();
  const rejected = new TestStream(encodeFrame(requestFrame()));
  const bootstrap = new VirtualizationGuestBootstrap({
    enabled: true,
    agent: agent(),
    source: new TestSource(hanging, rejected),
    maxConnections: 1,
    connectionTimeoutMs: 100
  });
  await bootstrap.start();
  await rejected.closedPromise;
  assert.equal(bootstrap.readback().rejectedConnections, 1);
  await bootstrap.close();
  assert.equal(hanging.closed, true);
  assert.equal(bootstrap.readback().state, "closed");
});

test("guest bootstrap propagates shutdown cancellation into the guest agent", async () => {
  const stream = new TestStream(encodeFrame(requestFrame()));
  let startedResolve!: () => void;
  const started = new Promise<void>((resolve) => { startedResolve = resolve; });
  let aborted = false;
  const key = Buffer.alloc(32, 0x61);
  const agent = new VirtualizationGuestAgent({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    expectedGuestIdentity: guestIdentity,
    expectedSandboxProfile: "guest-task-v1",
    expectedProfileDigest: "b".repeat(64),
    now: () => now,
    execute: async (_request, signal) => {
      startedResolve();
      await new Promise<void>((_resolve, reject) => {
        signal?.addEventListener("abort", () => {
          aborted = true;
          reject(new BrokerError("CANCELLED", "guest callback cancelled"));
        }, { once: true });
      });
      throw new BrokerError("CANCELLED", "guest callback cancelled");
    }
  });
  const bootstrap = new VirtualizationGuestBootstrap({ enabled: true, agent, source: new TestSource(stream) });
  await bootstrap.start();
  await started;
  await bootstrap.close();
  assert.equal(aborted, true);
  assert.equal(bootstrap.readback().state, "closed");
});

test("guest bootstrap aborts guest execution when the connection deadline expires", async () => {
  const stream = new TestStream(encodeFrame(requestFrame()));
  let startedResolve!: () => void;
  const started = new Promise<void>((resolve) => { startedResolve = resolve; });
  let aborted = false;
  const key = Buffer.alloc(32, 0x61);
  const agent = new VirtualizationGuestAgent({
    authenticationKey: key,
    replayGuard: new InMemoryVirtualizationGuestReplayGuard({ now: () => now }),
    expectedGuestIdentity: guestIdentity,
    expectedSandboxProfile: "guest-task-v1",
    expectedProfileDigest: "b".repeat(64),
    now: () => now,
    execute: async (_request, signal) => {
      startedResolve();
      await new Promise<void>((_resolve, reject) => {
        signal?.addEventListener("abort", () => {
          aborted = true;
          reject(new BrokerError("CANCELLED", "guest callback cancelled"));
        }, { once: true });
      });
      throw new BrokerError("CANCELLED", "guest callback cancelled");
    }
  });
  const bootstrap = new VirtualizationGuestBootstrap({
    enabled: true,
    agent,
    source: new TestSource(stream),
    connectionTimeoutMs: 25
  });
  await bootstrap.start();
  await started;
  await stream.closedPromise;
  assert.equal(aborted, true);
  assert.equal(bootstrap.readback().completedConnections, 0);
  assert.equal(bootstrap.readback().rejectedConnections, 1);
  await bootstrap.close();
});

function encodeFrame(frame: Uint8Array): Uint8Array {
  const header = Buffer.alloc(4);
  header.writeUInt32BE(frame.byteLength, 0);
  return Buffer.concat([header, Buffer.from(frame)]);
}
