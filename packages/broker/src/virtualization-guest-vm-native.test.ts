import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { lstat, mkdtemp, readFile, realpath, rm, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  createNativeVirtualizationGuestVm,
  loadNativeVirtualizationGuestVmBinding,
  NativeVirtualizationGuestChannel,
  createNativeVirtualizationGuestConnectionSource,
  parseStatusResult,
  parseTransitionResult,
  type NativeVirtualizationGuestVmBinding,
  validateNativeVirtualizationGuestVmAdapterPath
} from "./virtualization-guest-vm-native.js";
import { loadVirtualizationGuestImage } from "./virtualization-guest-image.js";

const require = createRequire(import.meta.url);

test("native Virtualization guest lifecycle artifact exposes handle-bound operations", () => {
  const native = loadNativeVirtualizationGuestVmBinding();
  assert.equal(native.nativeNodeVersion, process.versions.node);
  assert.equal(typeof native.createGuestVm, "function");
  assert.equal(typeof native.startGuestVm, "function");
  assert.equal(typeof native.stopGuestVm, "function");
  assert.equal(typeof native.statusGuestVm, "function");
  assert.equal(typeof native.closeGuestVm, "function");
  assert.equal(typeof native.listenGuestPort, "function");
  assert.equal(typeof native.removeGuestPort, "function");
  assert.equal(typeof native.acceptGuestConnection, "function");
  assert.equal(typeof native.readGuestConnectionChunk, "function");
  assert.equal(typeof native.writeGuestConnectionChunk, "function");
  assert.equal(typeof native.closeGuestConnection, "function");
  validateNativeVirtualizationGuestVmAdapterPath(require.resolve("./virtualization_guest_lifecycle.node"));
});

test("native Virtualization guest close cannot resurrect a retained handle or dispatch through a null queue", async () => {
  const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
  const source = await readFile(join(repositoryRoot, "packages/broker/native/virtualization_guest_lifecycle.cc"), "utf8");
  assert.match(source, /std::atomic<uint64_t> magic/u);
  assert.match(source, /active_connections/u);
  assert.match(source, /CloseActiveVirtioConnections\(handle\);\s*\[handle\.machine stopWithCompletionHandler/u);
  assert.doesNotMatch(source, /operation->handle->magic\s*=\s*kHandleMagic/u);
  assert.match(source, /handle\.machine = nil;\s*\/\/ Keep the serial queue alive until the external handle finalizer runs\./u);
  assert.match(source, /IsSystemPublishedImage\(resolved_path, path_stat\)/u);
  assert.match(source, /current_uid == 0/u);
  assert.match(source, /initWithURL:url readOnly:YES/u);
});

test("native Virtualization guest lifecycle remains disabled without explicit host gates", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-vz-lifecycle-disabled-"));
  const imagePath = join(directory, "guest.raw");
  const image = Buffer.alloc(512, 0x41);
  await writeFile(imagePath, image, { mode: 0o600 });
  try {
    const stat = await lstat(imagePath);
    const loadedImage = await loadVirtualizationGuestImage({
      path: await realpath(imagePath),
      expectedSha256: createHash("sha256").update(image).digest("hex"),
      runtimeVersion: "macos-26.2-vz-1"
    });
    const adapter = await createNativeVirtualizationGuestVm({
      image: loadedImage,
      enabled: false,
      hostEvidenceAccepted: false
    });
    assert.equal(adapter.available, false);
    assert.equal(adapter.guestIdentity, null);
    await assert.rejects(
      adapter.start({ guestIdentity: loadedImage.guestIdentity, signal: new AbortController().signal }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    assert.equal(stat.isFile(), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native Virtualization guest lifecycle creation fails closed without a valid entitled VM configuration", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-vz-lifecycle-create-"));
  const imagePath = join(directory, "guest.raw");
  const bytes = Buffer.alloc(1024 * 1024, 0);
  await writeFile(imagePath, bytes, { mode: 0o600 });
  try {
    const image = await loadVirtualizationGuestImage({
      path: await realpath(imagePath),
      expectedSha256: createHash("sha256").update(bytes).digest("hex"),
      runtimeVersion: "macos-26.2-vz-1"
    });
    let adapter: Awaited<ReturnType<typeof createNativeVirtualizationGuestVm>> | undefined;
    try {
      adapter = await createNativeVirtualizationGuestVm({ image, enabled: true, hostEvidenceAccepted: true });
    } catch (error) {
      assert.ok(error instanceof BrokerError || error instanceof Error);
      assert.match(String(error), /Virtualization guest VM|native adapter|configuration|unavailable/u);
    }
    if (adapter !== undefined) {
      try {
        const status = await adapter.status({ guestIdentity: image.guestIdentity, signal: new AbortController().signal });
        assert.ok(["stopped", "unknown"].includes(status.state));
      } finally {
        await adapter.close?.();
      }
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native Virtualization guest lifecycle rejects broker-owned images before native loading", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-vz-lifecycle-publication-"));
  const imagePath = join(directory, "guest.raw");
  const bytes = Buffer.alloc(1024, 0x42);
  await writeFile(imagePath, bytes, { mode: 0o600 });
  try {
    const image = await loadVirtualizationGuestImage({
      path: await realpath(imagePath),
      expectedSha256: createHash("sha256").update(bytes).digest("hex"),
      runtimeVersion: "macos-26.2-vz-1"
    });
    await assert.rejects(
      () => createNativeVirtualizationGuestVm({ image, enabled: true, hostEvidenceAccepted: true }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED" &&
        error.message.includes("system-published")
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native Virtualization guest VM results reject unstable authority fields", () => {
  const guestIdentity = { imageSha256: "a".repeat(64), runtimeVersion: "macos-26.2-vz-1" };
  const running = { bootId: "boot-12345678", guestIdentity, state: "running" as const };
  assert.deepEqual(parseTransitionResult(running, "running", guestIdentity), running);
  assert.throws(
    () => parseTransitionResult({ ...running, extra: true }, "running", guestIdentity),
    /malformed result|identity is invalid/u
  );
  const accessor = { ...running } as Record<string, unknown>;
  Object.defineProperty(accessor, "state", { enumerable: true, get: () => "running" });
  assert.throws(() => parseTransitionResult(accessor, "running", guestIdentity), /malformed result|identity is invalid/u);

  const stopped = { bootId: null, guestIdentity, state: "stopped" as const };
  assert.deepEqual(parseStatusResult(stopped, guestIdentity), stopped);
  assert.throws(() => parseStatusResult({ ...stopped, extra: true }, guestIdentity), /result is malformed/u);
});

test("native virtio guest channel enforces bounded frames and forwards only handle-bound calls", async () => {
  const calls: Array<{ handle: unknown; port: number; frame: Buffer; cap: number; timeout: number }> = [];
  const native = {
    exchangeGuestFrame: async (handle: unknown, port: number, frame: Buffer, cap: number, timeout: number): Promise<Buffer> => {
      calls.push({ handle, port, frame, cap, timeout });
      return Buffer.from("guest-response", "utf8");
    }
  } as unknown as NativeVirtualizationGuestVmBinding;
  const handle = { privateHandle: true };
  const channel = new NativeVirtualizationGuestChannel(native, handle, {
    port: 1024,
    maxFrameBytes: 1_024,
    timeoutMs: 2_000
  });
  const response = await channel.exchange(new Uint8Array([1, 2, 3]), new AbortController().signal);
  assert.equal(Buffer.from(response).toString("utf8"), "guest-response");
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.handle, handle);
  assert.equal(calls[0]?.port, 1024);
  assert.deepEqual(calls[0]?.frame, Buffer.from([1, 2, 3]));
  assert.equal(calls[0]?.cap, 1_024);
  assert.equal(calls[0]?.timeout, 2_000);

  await assert.rejects(
    channel.exchange(new Uint8Array(1_025), new AbortController().signal),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "OUTPUT_LIMIT"
  );
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    channel.exchange(new Uint8Array([1]), controller.signal),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
});

test("native virtio guest listener adapts bounded connections into the bootstrap source", async () => {
  const calls: string[] = [];
  const writes: Buffer[] = [];
  const chunks: Array<Buffer | null> = [Buffer.from([1, 2, 3]), null];
  const accepted: Array<unknown | null> = [null, { nativeConnection: true }];
  const native = {
    listenGuestPort: (_handle: unknown, port: number, maxConnections: number): void => {
      calls.push(`listen:${port}:${maxConnections}`);
    },
    removeGuestPort: (_handle: unknown, port: number): void => {
      calls.push(`remove:${port}`);
    },
    acceptGuestConnection: async (): Promise<unknown | null> => accepted.shift() ?? null,
    readGuestConnectionChunk: async (): Promise<Buffer | null> => chunks.shift() ?? null,
    writeGuestConnectionChunk: async (_connection: unknown, frame: Buffer): Promise<void> => {
      writes.push(frame);
    },
    closeGuestConnection: (): void => {
      calls.push("close");
    }
  } as unknown as NativeVirtualizationGuestVmBinding;
  const source = createNativeVirtualizationGuestConnectionSource(native, { privateHandle: true }, {
    port: 38_765,
    maxConnections: 2,
    maxChunkBytes: 256,
    ioTimeoutMs: 500
  });
  const stream = await source.accept(new AbortController().signal);
  assert.ok(stream);
  const received: Uint8Array[] = [];
  for await (const chunk of stream.readable) received.push(chunk);
  assert.deepEqual([...received[0]!], [1, 2, 3]);
  await stream.write(new Uint8Array([9, 8]));
  await stream.close();
  await source.close();
  assert.deepEqual(calls, ["listen:38765:2", "close", "remove:38765"]);
  assert.deepEqual(writes, [Buffer.from([9, 8])]);
});

test("native virtio guest listener closes a connection that arrives after accept cancellation", async () => {
  let resolveAccept!: (value: unknown) => void;
  let closed = 0;
  const native = {
    listenGuestPort: (): void => undefined,
    removeGuestPort: (): void => undefined,
    acceptGuestConnection: (): Promise<unknown> => new Promise((resolve) => { resolveAccept = resolve; }),
    readGuestConnectionChunk: async (): Promise<null> => null,
    writeGuestConnectionChunk: async (): Promise<void> => undefined,
    closeGuestConnection: (): void => { closed += 1; }
  } as unknown as NativeVirtualizationGuestVmBinding;
  const source = createNativeVirtualizationGuestConnectionSource(native, { privateHandle: true }, {
    port: 38_765,
    maxChunkBytes: 256,
    ioTimeoutMs: 500
  });
  const controller = new AbortController();
  const pending = source.accept(controller.signal);
  controller.abort();
  await assert.rejects(
    pending,
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
  resolveAccept({ lateConnection: true });
  await new Promise<void>((resolve) => setImmediate(resolve));
  assert.equal(closed, 1);
  await source.close();
});
