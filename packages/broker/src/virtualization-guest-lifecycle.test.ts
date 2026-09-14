import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  VirtualizationGuestVmLifecycle,
  type VirtualizationGuestVmAdapter,
  type VirtualizationGuestVmStartResult,
  type VirtualizationGuestVmStopResult,
  type VirtualizationGuestVmStatusResult
} from "./virtualization-guest-lifecycle.js";

const guestIdentity = { imageSha256: "a".repeat(64), runtimeVersion: "macos-26.2-vz-1" } as const;
const bootId = "boot-0123456789abcdef";

function adapterFixture(options: {
  available?: boolean;
  start?: () => Promise<VirtualizationGuestVmStartResult>;
  stop?: () => Promise<VirtualizationGuestVmStopResult>;
  status?: () => Promise<VirtualizationGuestVmStatusResult>;
} = {}): VirtualizationGuestVmAdapter {
  return {
    available: options.available ?? true,
    guestIdentity,
    start: options.start ?? (async () => ({ state: "running", guestIdentity, bootId })),
    stop: options.stop ?? (async () => ({ state: "stopped", guestIdentity, bootId })),
    status: options.status ?? (async () => ({ state: "stopped", guestIdentity, bootId: null }))
  };
}

function enabledLifecycle(adapter: VirtualizationGuestVmAdapter = adapterFixture()): VirtualizationGuestVmLifecycle {
  return new VirtualizationGuestVmLifecycle({
    enabled: true,
    hostEvidenceAccepted: true,
    expectedGuestIdentity: guestIdentity,
    adapter,
    startTimeoutMs: 100,
    stopTimeoutMs: 100
  });
}

test("VM lifecycle is disabled unless explicit host gates and identity match", async () => {
  const lifecycle = new VirtualizationGuestVmLifecycle({
    expectedGuestIdentity: guestIdentity,
    adapter: adapterFixture()
  });
  assert.equal(lifecycle.available, false);
  assert.equal(lifecycle.state, "disabled");
  await assert.rejects(
    lifecycle.start(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("VM lifecycle serializes idempotent start and identity-bound stop", async () => {
  let starts = 0;
  let stops = 0;
  const lifecycle = enabledLifecycle(adapterFixture({
    start: async () => {
      starts += 1;
      return { state: "running", guestIdentity, bootId };
    },
    stop: async (/* ignored */) => {
      stops += 1;
      return { state: "stopped", guestIdentity, bootId };
    }
  }));
  const first = await lifecycle.start();
  const second = await lifecycle.start();
  assert.deepEqual(second, first);
  assert.equal(starts, 1);
  assert.equal(lifecycle.state, "running");
  assert.equal(lifecycle.bootId, bootId);
  const stopped = await lifecycle.stop();
  assert.equal(stopped.bootId, bootId);
  assert.equal(stops, 1);
  assert.equal(lifecycle.state, "stopped");
  const idempotentStop = await lifecycle.stop();
  assert.equal(idempotentStop.state, "stopped");
  assert.equal(stops, 1);
});

test("VM lifecycle keeps failed start and status identity mismatches unknown", async () => {
  const failedStart = enabledLifecycle(adapterFixture({
    start: async () => ({ state: "running", guestIdentity: { ...guestIdentity, imageSha256: "b".repeat(64) }, bootId })
  }));
  await assert.rejects(
    failedStart.start(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.equal(failedStart.state, "unknown");
  await assert.rejects(
    failedStart.start(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME"
  );

  const badStatus = enabledLifecycle(adapterFixture({
    status: async () => ({ state: "running", guestIdentity: { ...guestIdentity, runtimeVersion: "other" }, bootId })
  }));
  await assert.rejects(
    badStatus.status(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.equal(badStatus.state, "unknown");
});

test("VM lifecycle maps timeout and cancellation to unknown recovery state", async () => {
  const never = new Promise<VirtualizationGuestVmStartResult>(() => undefined);
  const timedOut = new VirtualizationGuestVmLifecycle({
    enabled: true,
    hostEvidenceAccepted: true,
    expectedGuestIdentity: guestIdentity,
    adapter: adapterFixture({ start: async () => never }),
    startTimeoutMs: 10,
    stopTimeoutMs: 100
  });
  await assert.rejects(
    timedOut.start(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "TIMEOUT" && error.retryable === true
  );
  assert.equal(timedOut.state, "unknown");

  const cancelled = enabledLifecycle(adapterFixture({ start: async () => never }));
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    cancelled.start(controller.signal),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
  assert.equal(cancelled.state, "stopped");
});

test("VM lifecycle close drains a running adapter and rejects new work", async () => {
  let closed = 0;
  let stopped = 0;
  const adapter = adapterFixture({
    stop: async () => {
      stopped += 1;
      return { state: "stopped", guestIdentity, bootId };
    }
  });
  adapter.close = async () => { closed += 1; };
  const lifecycle = enabledLifecycle(adapter);
  await lifecycle.start();
  await lifecycle.close();
  assert.equal(stopped, 1);
  assert.equal(closed, 1);
  assert.equal(lifecycle.state, "closed");
  await assert.rejects(
    lifecycle.start(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("VM lifecycle does not close over an unconfirmed stop", async () => {
  let stopAttempts = 0;
  let closeAttempts = 0;
  let failStop = true;
  const adapter = adapterFixture({
    stop: async () => {
      stopAttempts += 1;
      if (failStop) throw new Error("stop unavailable");
      return { state: "stopped", guestIdentity, bootId };
    },
    status: async () => ({ state: "running", guestIdentity, bootId })
  });
  adapter.close = async () => { closeAttempts += 1; };
  const lifecycle = enabledLifecycle(adapter);
  await lifecycle.start();
  await assert.rejects(
    lifecycle.close(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME"
  );
  assert.equal(lifecycle.state, "unknown");
  assert.equal(closeAttempts, 0);
  await lifecycle.status();
  failStop = false;
  await lifecycle.close();
  assert.equal(lifecycle.state, "closed");
  assert.equal(stopAttempts, 2);
});
