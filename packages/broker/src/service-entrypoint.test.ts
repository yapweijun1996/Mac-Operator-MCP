import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import test from "node:test";
import { BrokerServiceEntrypoint } from "./service-entrypoint.js";
import { LocalBrokerRuntime, type RuntimeChannel } from "./runtime.js";

function metadata() {
  return {
    component: "mac-operator-broker" as const,
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1",
    policyVersion: "0.1"
  };
}

test("Broker service entrypoint exposes native-required readback and handles termination", async () => {
  const events: string[] = [];
  const runtime = new LocalBrokerRuntime({ brokerChannel: channel(events) });
  const service = new BrokerServiceEntrypoint(runtime, metadata(), ["mac.control.read"]);
  const signals = new EventEmitter();
  const run = service.runUntilSignal(signals);
  await waitFor(() => service.state === "running");
  assert.deepEqual(service.readback(), {
    ...metadata(),
    state: "running",
    runtimeState: "running",
    nativeTransportRequired: true,
    enabledCapabilities: ["mac.control.read"]
  });
  signals.emit("SIGTERM");
  await run;
  assert.equal(service.state, "stopped");
  assert.deepEqual(events, ["listen", "close"]);
});

test("Broker service entrypoint can bind a non-sensitive audit summary to host readback", async () => {
  const runtime = new LocalBrokerRuntime({ brokerChannel: channel([]) });
  const audit = {
    format: "mac-operator-audit-integrity-v1" as const,
    eventCount: 3,
    tailSequence: 3,
    tailHash: "a".repeat(64),
    keyedAnchor: "verified" as const
  };
  const service = new BrokerServiceEntrypoint(runtime, metadata(), [], () => audit);
  await service.start();
  try {
    assert.deepEqual(service.readback().audit, audit);
  } finally {
    await service.stop();
  }
});

test("Broker service entrypoint fails closed when startup fails", async () => {
  const runtime = new LocalBrokerRuntime({
    brokerChannel: {
      async listen() { throw new Error("native transport unavailable"); },
      async close() {}
    }
  });
  const service = new BrokerServiceEntrypoint(runtime, metadata());
  await assert.rejects(service.start(), /native transport unavailable/u);
  assert.equal(service.state, "failed");
  assert.equal(runtime.state, "stopped");
  await service.stop();
  assert.equal(service.state, "stopped");
});

test("Broker service serializes stop behind an in-flight start", async () => {
  const events: string[] = [];
  let releaseStart!: () => void;
  const startGate = new Promise<void>((resolve) => { releaseStart = resolve; });
  let runtimeState: import("./runtime.js").LocalBrokerRuntimeState = "stopped";
  const runtime = {
    get state() { return runtimeState; },
    async start() {
      events.push("start");
      await startGate;
      runtimeState = "running";
    },
    async close() {
      events.push("close");
      runtimeState = "stopped";
    }
  } as unknown as LocalBrokerRuntime;
  const service = new BrokerServiceEntrypoint(runtime, metadata());

  const starting = service.start();
  await waitFor(() => events.includes("start"));
  const stopping = service.stop();
  assert.equal(service.state, "starting");
  releaseStart();
  await Promise.all([starting, stopping]);
  assert.equal(service.state, "stopped");
  assert.deepEqual(events, ["start", "close"]);
});

function channel(events: string[]): RuntimeChannel {
  return {
    async listen() { events.push("listen"); },
    async close() { events.push("close"); }
  };
}

async function waitFor(predicate: () => boolean): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  throw new Error("condition was not reached");
}
