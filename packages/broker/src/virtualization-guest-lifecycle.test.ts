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

const guestIdentity = { imageSha256: "a".repeat(64), runtimeVersion: "test-generic-efi-vz-1" } as const;
const bootId = "boot-0123456789abcdef";

function adapterFixture(options: {
  available?: boolean;
  prepareTaskInstance?: () => Promise<{ state: "stopped"; guestIdentity: typeof guestIdentity; instanceId: string }>;
  start?: () => Promise<VirtualizationGuestVmStartResult>;
  stop?: () => Promise<VirtualizationGuestVmStopResult>;
  status?: () => Promise<VirtualizationGuestVmStatusResult>;
} = {}): VirtualizationGuestVmAdapter {
  let taskInstanceNumber = 0;
  return {
    available: options.available ?? true,
    guestIdentity,
    taskInstanceIsolation: "fresh-vm-object-per-task-v1",
    prepareTaskInstance: options.prepareTaskInstance ?? (async () => ({
      state: "stopped",
      guestIdentity,
      instanceId: `vm-test-${String(++taskInstanceNumber).padStart(8, "0")}`
    })),
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

test("VM lifecycle freezes its expected guest identity authority", () => {
  const source = { ...guestIdentity };
  const lifecycle = new VirtualizationGuestVmLifecycle({
    enabled: true,
    hostEvidenceAccepted: true,
    expectedGuestIdentity: source,
    adapter: adapterFixture()
  });
  assert.equal(Object.isFrozen(lifecycle.expectedGuestIdentity), true);
  assert.throws(
    () => { (lifecycle.expectedGuestIdentity as { imageSha256: string }).imageSha256 = "b".repeat(64); },
    TypeError
  );
  source.imageSha256 = "b".repeat(64);
  assert.equal(lifecycle.expectedGuestIdentity.imageSha256, "a".repeat(64));
});

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
  await assert.rejects(
    lifecycle.runTask(async () => undefined),
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

test("VM lifecycle gives each task an exclusive start-run-stop cycle", async () => {
  const events: string[] = [];
  let bootNumber = 0;
  let instanceNumber = 0;
  let activeBootId: string | undefined;
  const lifecycle = enabledLifecycle(adapterFixture({
    prepareTaskInstance: async () => {
      instanceNumber += 1;
      const instanceId = `vm-instance-${String(instanceNumber).padStart(8, "0")}`;
      events.push(`reset:${instanceId}`);
      return { state: "stopped", guestIdentity, instanceId };
    },
    start: async () => {
      bootNumber += 1;
      activeBootId = `boot-${String(bootNumber).padStart(16, "0")}`;
      events.push(`start:${activeBootId}`);
      return { state: "running", guestIdentity, bootId: activeBootId };
    },
    stop: async () => {
      assert.ok(activeBootId);
      events.push(`stop:${activeBootId}`);
      const stoppedBootId = activeBootId;
      activeBootId = undefined;
      return { state: "stopped", guestIdentity, bootId: stoppedBootId };
    }
  }));

  const first = lifecycle.runTask(async () => {
    events.push("task:one");
    events.push("result-journaled:one");
    return "one";
  });
  const second = lifecycle.runTask(async () => {
    events.push("task:two");
    events.push("result-journaled:two");
    return "two";
  });
  assert.deepEqual(await Promise.all([first, second]), ["one", "two"]);
  assert.deepEqual(events, [
    "reset:vm-instance-00000001",
    "start:boot-0000000000000001",
    "task:one",
    "result-journaled:one",
    "stop:boot-0000000000000001",
    "reset:vm-instance-00000002",
    "start:boot-0000000000000002",
    "task:two",
    "result-journaled:two",
    "stop:boot-0000000000000002"
  ]);
  assert.equal(lifecycle.state, "stopped");
});

test("VM lifecycle replaces an already-running runtime VM before task dispatch", async () => {
  const events: string[] = [];
  let instanceNumber = 0;
  const lifecycle = enabledLifecycle(adapterFixture({
    prepareTaskInstance: async () => {
      instanceNumber += 1;
      events.push(`reset:${instanceNumber}`);
      return { state: "stopped", guestIdentity, instanceId: `vm-instance-${String(instanceNumber).padStart(8, "0")}` };
    },
    start: async () => {
      events.push("start");
      return { state: "running", guestIdentity, bootId };
    },
    stop: async () => {
      events.push("stop");
      return { state: "stopped", guestIdentity, bootId };
    }
  }));
  await lifecycle.start();
  await lifecycle.runTask(async () => { events.push("task"); });
  assert.deepEqual(events, ["start", "stop", "reset:1", "start", "task", "stop"]);
});

test("VM lifecycle rejects a reused task VM instance identity before dispatch", async () => {
  let tasks = 0;
  const lifecycle = enabledLifecycle(adapterFixture({
    prepareTaskInstance: async () => ({
      state: "stopped",
      guestIdentity,
      instanceId: "vm-instance-reused"
    })
  }));
  await lifecycle.runTask(async () => { tasks += 1; });
  await assert.rejects(
    lifecycle.runTask(async () => { tasks += 1; }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.equal(tasks, 1);
  assert.equal(lifecycle.state, "unknown");
});

test("VM lifecycle requires an explicit fresh-instance adapter capability", () => {
  const adapter = adapterFixture();
  (adapter as { taskInstanceIsolation?: string }).taskInstanceIsolation = "reboot-same-vm-object-v1";
  assert.throws(
    () => new VirtualizationGuestVmLifecycle({
      enabled: true,
      hostEvidenceAccepted: true,
      expectedGuestIdentity: guestIdentity,
      adapter
    }),
    /options are invalid/u
  );
});

test("VM lifecycle stops after task failure and fences later tasks when hard-stop is unknown", async () => {
  let stopFails = true;
  let taskCalls = 0;
  const lifecycle = enabledLifecycle(adapterFixture({
    stop: async () => {
      if (stopFails) throw new Error("synthetic hard-stop failure");
      return { state: "stopped", guestIdentity, bootId };
    }
  }));

  await assert.rejects(
    lifecycle.runTask(async () => {
      taskCalls += 1;
      throw new Error("synthetic task failure");
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME"
  );
  assert.equal(lifecycle.state, "unknown");
  await assert.rejects(
    lifecycle.runTask(async () => { taskCalls += 1; }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME"
  );
  assert.equal(taskCalls, 1);

  stopFails = false;
  await lifecycle.status();
  await assert.rejects(lifecycle.runTask(async () => { throw new Error("task failure"); }), /task failure/u);
  assert.equal(lifecycle.state, "stopped");
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

test("VM lifecycle fences a timed-out native operation until it settles", async () => {
  let releaseStart: (() => void) | undefined;
  let startCalls = 0;
  const delayedStart = new Promise<VirtualizationGuestVmStartResult>((resolve) => {
    releaseStart = () => resolve({ state: "running", guestIdentity, bootId });
  });
  const lifecycle = new VirtualizationGuestVmLifecycle({
    enabled: true,
    hostEvidenceAccepted: true,
    expectedGuestIdentity: guestIdentity,
    adapter: adapterFixture({
      start: async () => {
        startCalls += 1;
        return delayedStart;
      },
      status: async () => ({ state: "stopped", guestIdentity, bootId: null })
    }),
    startTimeoutMs: 10,
    stopTimeoutMs: 100
  });

  await assert.rejects(
    lifecycle.start(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "TIMEOUT"
  );
  await assert.rejects(
    lifecycle.status(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "UNKNOWN_OUTCOME" && error.retryable === true
  );
  assert.equal(startCalls, 1);

  releaseStart?.();
  await new Promise((resolve) => setImmediate(resolve));
  const recovered = await lifecycle.status();
  assert.equal(recovered.state, "stopped");
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
