import assert from "node:assert/strict";
import { canonicalJson, sha256 } from "@mac-operator/contracts";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { provisionAuthenticationKey } from "./credentials.js";
import {
  createVirtualizationGuestRuntime,
  DEFAULT_VIRTUALIZATION_GUEST_PORT,
  type VirtualizationGuestVmFactory
} from "./virtualization-guest-startup.js";
import type { VirtualizationGuestVmAdapter } from "./virtualization-guest-lifecycle.js";
import type { VirtualizationGuestIdentity, VirtualizationGuestAttestation } from "./virtualization-guest-attestation.js";

test("virtualization guest startup stays disabled without both host gates", async () => {
  let factoryCalled = false;
  const runtime = await createVirtualizationGuestRuntime({
    image: {
      path: "/Users/operator/guest.img",
      expectedSha256: "a".repeat(64),
      runtimeVersion: "macos-26.2-vz-1"
    },
    enabled: false,
    hostEvidenceAccepted: true,
    vmFactory: async () => {
      factoryCalled = true;
      throw new Error("native adapter must not load while disabled");
    }
  });
  try {
    assert.equal(runtime.available, false);
    assert.equal(runtime.readback().state, "disabled");
    assert.equal(factoryCalled, false);
    await assert.rejects(runtime.start(), /not enabled/u);
  } finally {
    await runtime.close();
  }
});

test("virtualization guest startup requires complete authority before native creation", async () => {
  await assert.rejects(
    createVirtualizationGuestRuntime({
      image: {
        path: "/Users/operator/guest.img",
        expectedSha256: "b".repeat(64),
        runtimeVersion: "macos-26.2-vz-1"
      },
      enabled: true,
      hostEvidenceAccepted: true
    }),
    (error: unknown) => error instanceof Error && error.message.includes("authority is incomplete")
  );
});

test("enabled startup binds one image, port, lifecycle, and authenticated transport", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("native VM lifecycle availability is a macOS boundary");
    return;
  }
  const root = await mkdtemp(join(tmpdir(), "mops-guest-startup-"));
  const imagePath = join(root, "guest.img");
  const keyPath = join(root, "guest.key");
  const imageBytes = Buffer.from("synthetic guest image\n", "utf8");
  await writeFile(imagePath, imageBytes, { mode: 0o600 });
  await provisionAuthenticationKey(keyPath);
  const guestIdentity: VirtualizationGuestIdentity = {
    imageSha256: sha256(imageBytes),
    runtimeVersion: "macos-26.2-vz-1"
  };
  const unsigned = {
    schemaVersion: "0.1" as const,
    guestIdentity,
    sandboxProfile: "guest-default",
    filesystem: "guest-private" as const,
    network: "profile-bound" as const,
    credentials: "host-credentials-unavailable" as const,
    processTree: "guest-owned" as const,
    processTreePolicy: "single_process" as const,
    evidenceRef: "evidence:test-guest-startup"
  };
  const attestation: VirtualizationGuestAttestation = {
    ...unsigned,
    attestationDigest: sha256(canonicalJson(unsigned))
  };
  const proof = {
    schemaVersion: "0.1" as const,
    sandboxMechanism: "virtualization" as const,
    sandboxProfile: "guest-default",
    filesystem: "enforced" as const,
    network: "enforced" as const,
    credentials: "isolated" as const,
    credentialIsolation: "virtualization-no-host-credentials-v1" as const,
    processTree: "owned" as const,
    processTreePolicy: "single_process" as const,
    evidenceRef: "evidence:test-guest-startup",
    virtualizationGuest: guestIdentity
  };
  let state: "stopped" | "running" = "stopped";
  let bootId = "boot-test-12345678";
  let channelPort: number | undefined;
  let listenerPort: number | undefined;
  let listenerClosed = false;
  const adapter: VirtualizationGuestVmAdapter & {
    createChannel(options: { port: number }): { exchange: (frame: Uint8Array, signal: AbortSignal) => Promise<Uint8Array> };
    createConnectionSource(options: { port: number }): { accept(signal: AbortSignal): Promise<null>; close(): Promise<void> };
  } = {
    available: true,
    guestIdentity,
    async start() { state = "running"; return { state: "running", guestIdentity, bootId }; },
    async stop(input) { assert.equal(input.bootId, bootId); state = "stopped"; return { state: "stopped", guestIdentity, bootId }; },
    async status() { return { state, guestIdentity, bootId: state === "running" ? bootId : null }; },
    createChannel(options) {
      channelPort = options.port;
      return { exchange: async () => new Uint8Array([123, 125]) };
    },
    createConnectionSource(options: { port: number }) {
      listenerPort = options.port;
      return {
        accept: async () => null,
        close: async () => { listenerClosed = true; }
      };
    },
    async close() { state = "stopped"; }
  };
  const vmFactory: VirtualizationGuestVmFactory = async (options) => {
    assert.equal(options.image.guestIdentity.imageSha256, guestIdentity.imageSha256);
    return adapter as never;
  };
  const runtime = await createVirtualizationGuestRuntime({
    image: { path: imagePath, expectedSha256: guestIdentity.imageSha256, runtimeVersion: guestIdentity.runtimeVersion },
    authenticationKeyPath: keyPath,
    replayGuard: { admit: () => undefined },
    isolationProof: proof,
    attestation,
    enabled: true,
    hostEvidenceAccepted: true,
    connectionSource: { port: 38_766, maxConnections: 2, maxChunkBytes: 256, ioTimeoutMs: 500 },
    vmFactory
  });
  try {
    assert.equal(runtime.available, true);
    assert.equal(channelPort, DEFAULT_VIRTUALIZATION_GUEST_PORT);
    assert.equal(listenerPort, 38_766);
    assert.ok(runtime.connectionSource);
    await runtime.start();
    assert.equal(runtime.readback().state, "running");
    assert.equal((await runtime.recover()).state, "running");
    await runtime.stop();
    assert.equal(runtime.readback().state, "stopped");
  } finally {
    await runtime.close();
    assert.equal(listenerClosed, true);
    await rm(root, { recursive: true, force: true });
  }
});
