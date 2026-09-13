import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { sha256 } from "@mac-operator/contracts";
import {
  captureLaunchdBrokerProcessIdentity,
  createPrivilegedHelperRuntimeForLaunchdBroker,
  createPrivilegedHelperRuntimeFromActiveKeyConfig,
  PrivilegedHelperStartupError
} from "./privileged-helper-runtime.js";
import { FailClosedPrivilegedHelper } from "./privileged-helper.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { BrokerStore } from "./persistence.js";
import { PrivilegedHelperKeyManager, writePrivilegedHelperKeyConfig, type PrivilegedHelperKeyConfig } from "./privileged-helper-keyring.js";
import { capturePeerProcessIdentity } from "./peer-credentials.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";

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
    processId: process.pid,
    processGroupId: process.pid,
    terminationObserved: true
  };
}

test("privileged helper startup restores an activated key and owns a separate native runtime", async () => {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || uid < 1 || gid === undefined) throw new Error("POSIX non-root identity is unavailable");
  const root = await mkdtemp(join(tmpdir(), "mac-operator-helper-runtime-"));
  const keyPath = join(root, "helper.key");
  const configPath = join(root, "helper-keys.json");
  const brokerSocketPath = join(root, "broker.sock");
  const helperSocketPath = join(root, "helper.sock");
  const store = new BrokerStore(join(root, "broker.sqlite"));
  const now = Date.now();
  let manager: PrivilegedHelperKeyManager | undefined;
  try {
    const provisioned = await provisionAuthenticationKey(keyPath);
    const key = await loadAuthenticationKey(keyPath);
    const config: PrivilegedHelperKeyConfig = {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        keyId: "helper-key-1",
        keySource: "file",
        path: keyPath,
        keyDigest: sha256(key),
        notBeforeMs: now - 1_000,
        expiresAtMs: now + 60_000
      }]
    };
    await writePrivilegedHelperKeyConfig(configPath, config);
    manager = new PrivilegedHelperKeyManager(configPath, store, () => now);
    await manager.activate();
    manager.dispose();

    const brokerServiceId = `gui/${uid}/com.mac-operator.broker`;
    const runtime = await createPrivilegedHelperRuntimeForLaunchdBroker({
      helperKeyConfigPath: configPath,
      helperKeyStore: store,
      socketPath: helperSocketPath,
      brokerSocketPath,
      brokerServiceId,
      expectedBrokerUid: uid,
      expectedBrokerGid: gid,
      commandExecutor: {
        async run(command): Promise<ProcessExecutionResult> {
          assert.deepEqual(command.args, ["print", brokerServiceId]);
          return success(`${brokerServiceId} = {\n\tstate = running\n\tpid = ${process.pid}\n}`);
        }
      },
      replayGuard: { admit: () => undefined },
      adapter: new FailClosedPrivilegedHelper(),
      authorizeCommand: () => undefined
    });
    assert.equal(runtime.state, "stopped");
    await runtime.start();
    assert.equal(runtime.state, "running");
    await runtime.close();
    assert.equal(runtime.state, "stopped");
    assert.equal(provisioned.digest, config.keys[0].keyDigest);
  } finally {
    manager?.dispose();
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("privileged helper caller capture binds the exact Broker LaunchAgent and rejects smuggled services", async () => {
  const uid = process.getuid?.();
  if (uid === undefined || uid < 1) throw new Error("POSIX non-root identity is unavailable");
  const serviceId = `gui/${uid}/com.mac-operator.broker`;
  const identity = await captureLaunchdBrokerProcessIdentity({
    brokerServiceId: serviceId,
    expectedBrokerUid: uid,
    commandExecutor: { async run(): Promise<ProcessExecutionResult> { return success(`${serviceId} = {\n\tstate = running\n\tpid = ${process.pid}\n}`); } }
  });
  assert.equal(identity.pid, process.pid);
  assert.ok(identity.startTimeMicros > 0);
  await assert.rejects(
    captureLaunchdBrokerProcessIdentity({
      brokerServiceId: `gui/${uid}/com.mac-operator.attacker`,
      expectedBrokerUid: uid,
      commandExecutor: { async run(): Promise<ProcessExecutionResult> { return success(""); } }
    }),
    (error: unknown) => error instanceof PrivilegedHelperStartupError && error.code === "INVALID_HELPER_SERVICE"
  );
  await assert.rejects(
    captureLaunchdBrokerProcessIdentity({
      brokerServiceId: serviceId,
      expectedBrokerUid: uid,
      commandExecutor: { async run(): Promise<ProcessExecutionResult> { return success(`${serviceId} = {\n\tstate = not running\n}`); } }
    }),
    (error: unknown) => error instanceof PrivilegedHelperStartupError && error.code === "HELPER_PROCESS_NOT_RUNNING"
  );
});

test("privileged helper startup fails closed before key restore for invalid boundary inputs", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-helper-runtime-deny-"));
  const store = new BrokerStore(join(root, "broker.sqlite"));
  try {
    await assert.rejects(
      createPrivilegedHelperRuntimeFromActiveKeyConfig({
        helperKeyConfigPath: join(root, "missing.json"),
        helperKeyStore: store,
        socketPath: join(root, "same.sock"),
        brokerSocketPath: join(root, "same.sock"),
        peerPolicy: { expectedUid: process.getuid?.() ?? 1, allowedProcessIdentity: capturePeerProcessIdentity(process.pid) },
        replayGuard: { admit: () => undefined },
        adapter: new FailClosedPrivilegedHelper(),
        authorizeCommand: () => undefined
      }),
      (error: unknown) => error instanceof PrivilegedHelperStartupError && error.code === "HELPER_SOCKET_INVALID"
    );
    await assert.rejects(
      createPrivilegedHelperRuntimeFromActiveKeyConfig({
        helperKeyConfigPath: join(root, "missing.json"),
        helperKeyStore: store,
        socketPath: join(root, "helper.sock"),
        brokerSocketPath: join(root, "broker.sock"),
        peerPolicy: { expectedUid: process.getuid?.() ?? 1 },
        replayGuard: { admit: () => undefined },
        adapter: new FailClosedPrivilegedHelper(),
        authorizeCommand: () => undefined
      }),
      (error: unknown) => error instanceof PrivilegedHelperStartupError && error.code === "HELPER_PEER_POLICY_INVALID"
    );
  } finally {
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});
