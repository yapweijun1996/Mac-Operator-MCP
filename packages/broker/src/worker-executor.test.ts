import assert from "node:assert/strict";
import { Worker } from "node:worker_threads";
import test from "node:test";
import { BoundedWorkerExecutor } from "./worker-executor.js";

test("bounded worker executor returns a structured result", async () => {
  const executor = new BoundedWorkerExecutor<{ value: number }, number>(
    (command) => new Worker(
      `const { parentPort, workerData } = require("node:worker_threads"); parentPort.postMessage({ ok: true, value: workerData.value });`,
      { eval: true, workerData: command, env: {}, argv: [], execArgv: [] }
    ),
    1
  );
  assert.equal(await executor.run({ value: 42 }, 1_000, () => false), 42);
});

test("bounded worker executor rejects excess concurrency", async () => {
  const executor = slowExecutor(1);
  const first = executor.run({ delayMs: 100 }, 1_000, () => false);
  await assert.rejects(executor.run({ delayMs: 1 }, 1_000, () => false), (error: unknown) =>
    hasErrorClass(error, "CONFLICT"));
  assert.equal(await first, "done");
});

test("bounded worker executor enforces deadline and active cancellation", async () => {
  const timeoutExecutor = slowExecutor(1);
  await assert.rejects(timeoutExecutor.run({ delayMs: 1_000 }, 20, () => false), (error: unknown) =>
    hasErrorClass(error, "TIMEOUT"));

  const cancellationExecutor = slowExecutor(1);
  let cancelled = false;
  const cancellation = cancellationExecutor.run({ delayMs: 1_000 }, 2_000, () => cancelled);
  setTimeout(() => { cancelled = true; }, 10);
  await assert.rejects(cancellation, (error: unknown) => hasErrorClass(error, "CANCELLED"));
});

test("bounded worker executor releases capacity after an abrupt worker exit", async () => {
  let crash = true;
  const executor = new BoundedWorkerExecutor<Record<string, never>, string>(
    () => new Worker(
      crash
        ? "throw new Error('test-only worker crash');"
        : "const { parentPort } = require('node:worker_threads'); parentPort.postMessage({ ok: true, value: 'recovered' });",
      { eval: true, env: {}, argv: [], execArgv: [] }
    ),
    1
  );
  await assert.rejects(executor.run({}, 1_000, () => false), (error: unknown) =>
    hasErrorClass(error, "EXECUTION_FAILED"));
  await waitFor(() => executor.activeCount() === 0, 2_000);
  crash = false;
  assert.equal(await executor.run({}, 1_000, () => false), "recovered");
});

test("bounded worker executor closes active workers and rejects new work", async () => {
  const executor = slowExecutor(1);
  const active = executor.run({ delayMs: 10_000 }, 20_000, () => false);
  const closing = executor.close();
  await assert.rejects(active, (error: unknown) => hasErrorClass(error, "EXECUTION_FAILED"));
  await closing;
  assert.equal(executor.activeCount(), 0);
  await assert.rejects(
    executor.run({ delayMs: 1 }, 1_000, () => false),
    (error: unknown) => hasErrorClass(error, "CANCELLED")
  );
  await executor.close();
});

test("bounded worker executor releases cancelled capacity before accepting new work", async () => {
  const executor = slowExecutor(1);
  let cancelled = false;
  const cancellation = executor.run({ delayMs: 1_000 }, 2_000, () => cancelled);
  cancelled = true;
  await assert.rejects(cancellation, (error: unknown) => hasErrorClass(error, "CANCELLED"));
  assert.equal(executor.activeCount(), 1);
  await waitFor(() => executor.activeCount() === 0, 2_000);
  assert.equal(await executor.run({ delayMs: 1 }, 1_000, () => false), "done");
});

test("worker environment can be reduced independently from the Broker environment", async () => {
  process.env.MAC_OPERATOR_TEST_SECRET = "must-not-cross";
  try {
    const executor = new BoundedWorkerExecutor<Record<string, never>, boolean>(
      () => new Worker(
        `const { parentPort } = require("node:worker_threads"); parentPort.postMessage({ ok: true, value: process.env.MAC_OPERATOR_TEST_SECRET === undefined });`,
        { eval: true, env: {}, argv: [], execArgv: [] }
      ),
      1
    );
    assert.equal(await executor.run({}, 1_000, () => false), true);
  } finally {
    delete process.env.MAC_OPERATOR_TEST_SECRET;
  }
});

function slowExecutor(maxConcurrent: number) {
  return new BoundedWorkerExecutor<{ delayMs: number }, string>(
    (command) => new Worker(
      `const { parentPort, workerData } = require("node:worker_threads"); setTimeout(() => parentPort.postMessage({ ok: true, value: "done" }), workerData.delayMs);`,
      { eval: true, workerData: command, env: {}, argv: [], execArgv: [] }
    ),
    maxConcurrent
  );
}

function hasErrorClass(error: unknown, expected: string): boolean {
  return error !== null && typeof error === "object" && "errorClass" in error &&
    (error as { errorClass: unknown }).errorClass === expected;
}

async function waitFor(predicate: () => boolean, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error("condition was not met before the deadline");
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}
