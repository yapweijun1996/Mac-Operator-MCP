import assert from "node:assert/strict";
import test from "node:test";
import { LocalBrokerRuntime, type RuntimeChannel } from "./runtime.js";

test("local Broker runtime starts Broker IPC before operator channels and closes in reverse order", async () => {
  const events: string[] = [];
  const broker = channel("broker", events);
  const signer = channel("signer", events);
  const approval = channel("approval", events);
  const runtime = new LocalBrokerRuntime({ brokerChannel: broker, operatorChannels: [signer, approval] });

  assert.equal(runtime.state, "stopped");
  await runtime.start();
  assert.equal(runtime.state, "running");
  assert.deepEqual(events, ["broker:listen", "signer:listen", "approval:listen"]);

  await runtime.close();
  assert.equal(runtime.state, "stopped");
  assert.deepEqual(events, [
    "broker:listen", "signer:listen", "approval:listen",
    "approval:close", "signer:close", "broker:close"
  ]);
  await runtime.close();
  assert.deepEqual(events, [
    "broker:listen", "signer:listen", "approval:listen",
    "approval:close", "signer:close", "broker:close"
  ]);
});

test("local Broker runtime closes owned resources after transport channels", async () => {
  const events: string[] = [];
  const runtime = new LocalBrokerRuntime({
    brokerChannel: channel("broker", events),
    closeResources: async () => { events.push("resources:close"); }
  });
  await runtime.start();
  await runtime.close();
  assert.deepEqual(events, ["broker:listen", "broker:close", "resources:close"]);
});

test("local Broker runtime rolls back a partial startup and remains restartable", async () => {
  const events: string[] = [];
  const broker = channel("broker", events);
  const failingSigner = channel("signer", events, new Error("operator channel unavailable"));
  const runtime = new LocalBrokerRuntime({ brokerChannel: broker, operatorChannels: [failingSigner] });

  await assert.rejects(runtime.start(), /operator channel unavailable/u);
  assert.equal(runtime.state, "stopped");
  assert.deepEqual(events, ["broker:listen", "signer:listen", "broker:close"]);
  await assert.rejects(runtime.start(), /operator channel unavailable/u);
  assert.equal(runtime.state, "stopped");
  assert.deepEqual(events, [
    "broker:listen", "signer:listen", "broker:close",
    "broker:listen", "signer:listen", "broker:close"
  ]);
});

test("local Broker runtime serializes concurrent lifecycle operations", async () => {
  const events: string[] = [];
  const runtime = new LocalBrokerRuntime({ brokerChannel: channel("broker", events) });

  const firstStart = runtime.start();
  const secondStart = runtime.start();
  await firstStart;
  await assert.rejects(secondStart, /Broker runtime cannot start from running/u);
  assert.equal(runtime.state, "running");

  const close = runtime.close();
  const secondClose = runtime.close();
  await close;
  await secondClose;
  assert.equal(runtime.state, "stopped");
  assert.deepEqual(events, ["broker:listen", "broker:close"]);
});

test("local Broker runtime rejects duplicate channels", () => {
  const broker = channel("broker", []);
  assert.throws(
    () => new LocalBrokerRuntime({ brokerChannel: broker, operatorChannels: [broker] }),
    /channels must be unique/u
  );
});

test("local Broker runtime retains a failed cleanup for explicit recovery", async () => {
  const events: string[] = [];
  let cleanupFailure = true;
  const broker = channel("broker", events, undefined, () => cleanupFailure);
  const failingSigner = channel("signer", events, new Error("operator channel unavailable"));
  const runtime = new LocalBrokerRuntime({ brokerChannel: broker, operatorChannels: [failingSigner] });

  await assert.rejects(runtime.start(), /startup failed and cleanup also failed/u);
  assert.equal(runtime.state, "failed");
  assert.deepEqual(events, ["broker:listen", "signer:listen", "broker:close"]);
  await assert.rejects(runtime.start(), /Broker runtime cannot start from failed/u);

  cleanupFailure = false;
  await runtime.close();
  assert.equal(runtime.state, "stopped");
  assert.deepEqual(events, [
    "broker:listen", "signer:listen", "broker:close",
    "broker:close"
  ]);
});

function channel(name: string, events: string[], listenError?: Error, closeError?: () => boolean): RuntimeChannel {
  return {
    async listen() {
      events.push(`${name}:listen`);
      if (listenError) throw listenError;
    },
    async close() {
      events.push(`${name}:close`);
      if (closeError?.()) throw new Error(`${name} close failed`);
    }
  };
}
