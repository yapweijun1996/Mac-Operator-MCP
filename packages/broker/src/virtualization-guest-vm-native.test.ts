import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { lstat, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  createNativeVirtualizationGuestVm,
  loadNativeVirtualizationGuestVmBinding,
  NativeVirtualizationGuestChannel,
  type NativeVirtualizationGuestVmBinding,
  validateNativeVirtualizationGuestVmAdapterPath
} from "./virtualization-guest-vm-native.js";
import { loadVirtualizationGuestImage } from "./virtualization-guest-image.js";

const require = createRequire(import.meta.url);

test("native Virtualization guest lifecycle artifact exposes handle-bound operations", () => {
  const native = loadNativeVirtualizationGuestVmBinding();
  assert.equal(typeof native.createGuestVm, "function");
  assert.equal(typeof native.startGuestVm, "function");
  assert.equal(typeof native.stopGuestVm, "function");
  assert.equal(typeof native.statusGuestVm, "function");
  assert.equal(typeof native.closeGuestVm, "function");
  validateNativeVirtualizationGuestVmAdapterPath(require.resolve("./virtualization_guest_lifecycle.node"));
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
