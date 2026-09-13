import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { sha256 } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import {
  captureLaunchdEdgeProcessIdentity,
  createMacOsNativeBrokerRuntimeForLaunchdEdge,
  createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig,
  NativeRuntimeStartupError,
  parseLaunchdEdgeProcessReadback
} from "./native-runtime-startup.js";
import { BrokerStore } from "./persistence.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { EdgeAuthenticationKeyManager, writeEdgeAuthenticationKeyConfig, type EdgeAuthenticationKeyConfig } from "./edge-keyring-config.js";

test("launchd Edge identity capture binds a running per-user service to native process identity", async () => {
  const uid = process.getuid?.();
  if (uid === undefined || uid < 1) throw new Error("POSIX non-root identity is unavailable");
  const serviceId = `gui/${uid}/com.mac-operator.edge`;
  const executor = new FakeLaunchdExecutor(success(`
${serviceId} = {
\tstate = running
\tpid = ${process.pid}
}
`));
  const identity = await captureLaunchdEdgeProcessIdentity({ edgeServiceId: serviceId, expectedUid: uid, commandExecutor: executor });
  assert.equal(identity.pid, process.pid);
  assert.ok(identity.startTimeMicros > 0);
  assert.deepEqual(executor.commands[0]?.args, ["print", serviceId]);
  assert.equal(executor.commands[0]?.environment && Object.keys(executor.commands[0].environment).length, 0);
});

test("launchd Edge identity capture rejects wrong domains, stopped services, and malformed identities", async () => {
  const uid = process.getuid?.();
  if (uid === undefined || uid < 1) throw new Error("POSIX non-root identity is unavailable");
  await assert.rejects(
    captureLaunchdEdgeProcessIdentity({
      edgeServiceId: `system/com.mac-operator.edge`,
      expectedUid: uid,
      commandExecutor: new FakeLaunchdExecutor(success(""))
    }),
    (error: unknown) => error instanceof NativeRuntimeStartupError && error.code === "INVALID_EDGE_SERVICE"
  );
  const serviceId = `gui/${uid}/com.mac-operator.edge`;
  await assert.rejects(
    captureLaunchdEdgeProcessIdentity({
      edgeServiceId: serviceId,
      expectedUid: uid,
      commandExecutor: new FakeLaunchdExecutor(success(`${serviceId} = {\n\tstate = not running\n}`))
    }),
    (error: unknown) => error instanceof NativeRuntimeStartupError && error.code === "EDGE_PROCESS_NOT_RUNNING"
  );
  assert.throws(
    () => parseLaunchdEdgeProcessReadback(serviceId, success(`gui/${uid}/com.mac-operator.other = {\n\tstate = running\n\tpid = 1\n}`)),
    (error: unknown) => error instanceof NativeRuntimeStartupError && error.code === "EDGE_SERVICE_UNAVAILABLE"
  );
});

test("launchd Edge startup assembly wires captured identity into the native runtime", async () => {
  const uid = process.getuid?.();
  if (uid === undefined || uid < 1) throw new Error("POSIX non-root identity is unavailable");
  const root = await mkdtemp(join(tmpdir(), "mac-operator-startup-"));
  const store = new BrokerStore(join(root, "broker.sqlite"));
  const now = Date.now();
  const broker = new Broker({
    store,
    policy: createDefaultPolicy("edge-1"),
    edgeAuthenticationKeys: new EdgeKeyring([{
      edgeId: "edge-1",
      keyId: "edge-key-1",
      key: randomBytes(32),
      notBeforeMs: now - 1_000,
      expiresAtMs: now + 60_000
    }]),
    now: () => now
  });
  try {
    const serviceId = `gui/${uid}/com.mac-operator.edge`;
    const { runtime } = await createMacOsNativeBrokerRuntimeForLaunchdEdge({
      socketPath: join(root, "broker.sock"),
      broker,
      edgeId: "edge-1",
      edgeServiceId: serviceId,
      expectedEdgeUid: uid,
      commandExecutor: new FakeLaunchdExecutor(success(`${serviceId} = {\n\tstate = running\n\tpid = ${process.pid}\n}`))
    });
    assert.equal(runtime.state, "stopped");
    await runtime.start();
    assert.equal(runtime.state, "running");
    await runtime.close();
    assert.equal(runtime.state, "stopped");
  } finally {
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("launchd Edge startup restores the active key config before Broker construction", async () => {
  const uid = process.getuid?.();
  if (uid === undefined || uid < 1) throw new Error("POSIX non-root identity is unavailable");
  const root = await mkdtemp(join(tmpdir(), "mac-operator-startup-key-config-"));
  const store = new BrokerStore(join(root, "broker.sqlite"));
  const keyPath = join(root, "edge.key");
  const configPath = join(root, "edge-keys.json");
  const now = Date.now();
  try {
    await provisionAuthenticationKey(keyPath);
    const key = await loadAuthenticationKey(keyPath);
    const config: EdgeAuthenticationKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        edgeId: "edge-1",
        keyId: "edge-key-1",
        keySource: "file",
        path: keyPath,
        keyDigest: sha256(key),
        notBeforeMs: now - 1_000,
        expiresAtMs: now + 60_000
      }]
    };
    await writeEdgeAuthenticationKeyConfig(configPath, config);
    const manager = new EdgeAuthenticationKeyManager(configPath, store, () => now);
    await manager.activate();
    let constructedKeyring: EdgeKeyring | undefined;
    const serviceId = `gui/${uid}/com.mac-operator.edge`;
    const { runtime } = await createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig({
      socketPath: join(root, "broker.sock"),
      edgeId: "edge-1",
      edgeServiceId: serviceId,
      expectedEdgeUid: uid,
      edgeKeyConfigPath: configPath,
      edgeKeyStore: store,
      commandExecutor: new FakeLaunchdExecutor(success(`${serviceId} = {\n\tstate = running\n\tpid = ${process.pid}\n}`)),
      createBroker: (edgeAuthenticationKeys) => {
        constructedKeyring = edgeAuthenticationKeys;
        return new Broker({
          store,
          policy: createDefaultPolicy("edge-1"),
          edgeAuthenticationKeys,
          now: () => now
        });
      }
    });
    assert.equal(constructedKeyring?.keyByIdentity("edge-1", "edge-key-1")?.toString("hex"), key.toString("hex"));
    await runtime.start();
    await runtime.close();
  } finally {
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("launchd Edge startup refuses an unactivated key config before launchctl readback", async () => {
  const uid = process.getuid?.();
  if (uid === undefined || uid < 1) throw new Error("POSIX non-root identity is unavailable");
  const root = await mkdtemp(join(tmpdir(), "mac-operator-startup-key-config-deny-"));
  const store = new BrokerStore(join(root, "broker.sqlite"));
  const keyPath = join(root, "edge.key");
  const configPath = join(root, "edge-keys.json");
  const now = Date.now();
  try {
    await provisionAuthenticationKey(keyPath);
    const key = await loadAuthenticationKey(keyPath);
    const config: EdgeAuthenticationKeyConfig = {
      schemaVersion: "0.1", revision: 1, keys: [{
        edgeId: "edge-1", keyId: "edge-key-1", keySource: "file", path: keyPath,
        keyDigest: sha256(key),
        notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
      }]
    };
    await writeEdgeAuthenticationKeyConfig(configPath, config);
    let launchctlCalled = false;
    await assert.rejects(
      createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig({
        socketPath: join(root, "broker.sock"), edgeId: "edge-1",
        edgeServiceId: `gui/${uid}/com.mac-operator.edge`, expectedEdgeUid: uid,
        edgeKeyConfigPath: configPath, edgeKeyStore: store,
        commandExecutor: {
          async run(): Promise<ProcessExecutionResult> {
            launchctlCalled = true;
            return success("");
          }
        },
        createBroker: (edgeAuthenticationKeys) => new Broker({ store, policy: createDefaultPolicy("edge-1"), edgeAuthenticationKeys, now: () => now })
      }),
      /does not match persisted activation/u
    );
    assert.equal(launchctlCalled, false);

    const manager = new EdgeAuthenticationKeyManager(configPath, store, () => now);
    await manager.activate();
    await writeEdgeAuthenticationKeyConfig(configPath, {
      ...config,
      revision: 2,
      keys: [{ ...config.keys[0]!, edgeId: "edge-other" }]
    });
    await manager.activate(1);
    launchctlCalled = false;
    await assert.rejects(
      createMacOsNativeBrokerRuntimeForLaunchdEdgeFromActiveKeyConfig({
        socketPath: join(root, "broker-mismatch.sock"), edgeId: "edge-1",
        edgeServiceId: `gui/${uid}/com.mac-operator.edge`, expectedEdgeUid: uid,
        edgeKeyConfigPath: configPath, edgeKeyStore: store,
        commandExecutor: {
          async run(): Promise<ProcessExecutionResult> {
            launchctlCalled = true;
            return success("");
          }
        },
        createBroker: (edgeAuthenticationKeys) => new Broker({ store, policy: createDefaultPolicy("edge-1"), edgeAuthenticationKeys, now: () => now })
      }),
      (error: unknown) => error instanceof NativeRuntimeStartupError && error.code === "EDGE_KEY_CONFIG_UNAVAILABLE"
    );
    assert.equal(launchctlCalled, false);
  } finally {
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});

function success(stdout: string): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout,
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: 1,
    processGroupId: 1,
    terminationObserved: true
  };
}

class FakeLaunchdExecutor {
  readonly commands: ProcessExecutionRequest[] = [];

  constructor(private readonly result: ProcessExecutionResult) {}

  async run(command: ProcessExecutionRequest): Promise<ProcessExecutionResult> {
    this.commands.push(command);
    return this.result;
  }
}
