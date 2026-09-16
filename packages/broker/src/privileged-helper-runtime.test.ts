import assert from "node:assert/strict";
import { access, mkdtemp, rm } from "node:fs/promises";
import { connect } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, CONTRACT_VERSION, sha256 } from "@mac-operator/contracts";
import {
  captureLaunchdBrokerProcessIdentity,
  createPrivilegedHelperRuntimeFromKeyMaterial,
  createPrivilegedHelperRuntimeForLaunchdBroker,
  createPrivilegedHelperRuntimeFromActiveKeyConfig,
  PrivilegedHelperRuntime,
  PrivilegedHelperStartupError
} from "./privileged-helper-runtime.js";
import {
  AllowlistedPrivilegedHelper,
  authenticatePrivilegedHelperResponse,
  FailClosedPrivilegedHelper,
  signPrivilegedHelperCommand,
  type PrivilegedHelperIpcServer,
  type UnsignedPrivilegedHelperCommand
} from "./privileged-helper.js";
import { createPrivilegedServiceControlHelper } from "./privileged-service-control.js";
import type { SafeServiceStatus, ServiceInspector } from "./service-inspector.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { BrokerStore } from "./persistence.js";
import { PrivilegedHelperKeyManager, writePrivilegedHelperKeyConfig, type PrivilegedHelperKeyConfig } from "./privileged-helper-keyring.js";
import { capturePeerProcessIdentity } from "./peer-credentials.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";
import { PrivilegedHelperAuthorityIpcServer } from "./privileged-helper-authority-ipc.js";

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
          return success(`${brokerServiceId} = {\n\ttype = LaunchAgent\n\tstate = running\n\tpid = ${process.pid}\n}`);
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

test("privileged helper runtime auto-wires and disposes the Broker authority poller", async () => {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || uid < 1 || gid === undefined) throw new Error("POSIX non-root identity is unavailable");
  const root = await mkdtemp(join(tmpdir(), "mops-rt-"));
  const keyPath = join(root, "helper.key");
  const configPath = join(root, "helper-keys.json");
  const helperSocketPath = join(root, "helper.sock");
  const brokerSocketPath = join(root, "broker.sock");
  const authoritySocketPath = join(root, "authority.sock");
  const store = new BrokerStore(join(root, "broker.sqlite"));
  const now = Date.now();
  const peerPolicy = { expectedUid: uid, expectedGid: gid, allowedProcessIdentity: capturePeerProcessIdentity(process.pid) };
  let authority: PrivilegedHelperAuthorityIpcServer | undefined;
  let runtime: Awaited<ReturnType<typeof createPrivilegedHelperRuntimeFromActiveKeyConfig>> | undefined;
  try {
    const provisioned = await provisionAuthenticationKey(keyPath);
    const key = await loadAuthenticationKey(keyPath);
    await writePrivilegedHelperKeyConfig(configPath, {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        keyId: "helper-key-1", keySource: "file", path: keyPath,
        keyDigest: provisioned.digest, notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
      }]
    });
    const manager = new PrivilegedHelperKeyManager(configPath, store, () => now);
    await manager.activate();
    manager.dispose();

    authority = new PrivilegedHelperAuthorityIpcServer({
      socketPath: authoritySocketPath,
      authenticationKey: key,
      replayGuard: { admit: () => undefined },
      authorizeCommand: () => undefined,
      peerPolicy,
      now: () => now
    });
    await authority.listen();
    runtime = await createPrivilegedHelperRuntimeFromActiveKeyConfig({
      helperKeyConfigPath: configPath,
      helperKeyStore: store,
      socketPath: helperSocketPath,
      brokerSocketPath,
      authoritySocketPath,
      peerPolicy,
      replayGuard: { admit: () => undefined },
      adapter: new AllowlistedPrivilegedHelper({
        service_control: async (command, control) => {
          assert.equal(control.shouldCancel(), false);
          return {
            operation: command.operation,
            targetRef: command.targetRef,
            state: "completed",
            resultClass: "SUCCEEDED",
            evidence: {}, warnings: [], truncated: false,
            verification: { status: "verified", strategy: "allowlisted_postcondition" }
          };
        }
      }),
      authorizeCommand: () => undefined
    });
    await runtime.start();
    const payload = { operation: "service_control" as const, service_id: "system/com.example.test", action: "start" as const };
    const unsigned: UnsignedPrivilegedHelperCommand = {
      protocolVersion: "0.1",
      contractVersion: CONTRACT_VERSION,
      commandId: "priv-command:runtime-authority-0001",
      requestId: "request:runtime-authority-0001",
      nonce: "helper-nonce-runtime-authority-0001",
      nonceExpiresAtMs: now + 30_000,
      timestampMs: now,
      expiresAtMs: now + 30_000,
      operation: "service_control",
      targetRef: "service:system/com.example.test",
      payload,
      payloadDigest: sha256(canonicalJson(payload)),
      policyVersion: "policy-test-1",
      approvalId: "approval:runtime-authority-0001",
      intentId: "intent:runtime-authority-0001"
    };
    const response = await sendHelperCommand(helperSocketPath, signPrivilegedHelperCommand(unsigned, key));
    const verified = authenticatePrivilegedHelperResponse(response, unsigned, key);
    assert.equal(verified.ok, true);
    await runtime.close();
    assert.equal(runtime.state, "stopped");
    key.fill(0);
  } finally {
    await runtime?.close().catch(() => undefined);
    await authority?.close().catch(() => undefined);
    store.close();
    await rm(root, { recursive: true, force: true });
  }
});

test("privileged helper runtime disposes its authority poller on startup failure and unopened close", async () => {
  let startupCloses = 0;
  let startupDisposals = 0;
  const startupServer = {
    listen: async () => { throw new Error("listener startup failed"); },
    close: async () => { startupCloses += 1; }
  } as unknown as PrivilegedHelperIpcServer;
  const startupPoller = {
    assertAuthorized: async () => undefined,
    dispose: () => { startupDisposals += 1; }
  };
  const startupRuntime = new PrivilegedHelperRuntime(startupServer, startupPoller);
  await assert.rejects(startupRuntime.start(), /listener startup failed/);
  assert.equal(startupRuntime.state, "stopped");
  assert.equal(startupCloses, 1);
  assert.equal(startupDisposals, 1);
  await startupRuntime.close();
  assert.equal(startupDisposals, 1);
  await assert.rejects(startupRuntime.start(), /cannot restart after authority poller disposal/);

  let cleanupDisposals = 0;
  const cleanupServer = {
    listen: async () => { throw new Error("listener startup failed"); },
    close: async () => { throw new Error("listener cleanup failed"); }
  } as unknown as PrivilegedHelperIpcServer;
  const cleanupPoller = {
    assertAuthorized: async () => undefined,
    dispose: () => { cleanupDisposals += 1; }
  };
  const cleanupRuntime = new PrivilegedHelperRuntime(cleanupServer, cleanupPoller);
  await assert.rejects(
    cleanupRuntime.start(),
    (error: unknown) => error instanceof AggregateError && error.message === "Privileged helper startup failed and cleanup also failed"
  );
  assert.equal(cleanupRuntime.state, "failed");
  assert.equal(cleanupDisposals, 1);

  let unopenedDisposals = 0;
  const unopenedServer = {
    listen: async () => undefined,
    close: async () => undefined
  } as unknown as PrivilegedHelperIpcServer;
  const unopenedPoller = {
    assertAuthorized: async () => undefined,
    dispose: () => { unopenedDisposals += 1; }
  };
  const unopenedRuntime = new PrivilegedHelperRuntime(unopenedServer, unopenedPoller);
  await unopenedRuntime.close();
  await unopenedRuntime.close();
  assert.equal(unopenedRuntime.state, "stopped");
  assert.equal(unopenedDisposals, 1);
  await assert.rejects(unopenedRuntime.start(), /cannot restart after authority poller disposal/);
});

test("root-helper key-material startup does not require BrokerStore access", async () => {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || uid < 1 || gid === undefined) throw new Error("POSIX non-root identity is unavailable");
  const root = await mkdtemp(join(tmpdir(), "mops-root-helper-material-"));
  const keyPath = join(root, "helper.key");
  const configPath = join(root, "helper-keys.json");
  const helperSocketPath = join(root, "helper.sock");
  const brokerSocketPath = join(root, "broker.sock");
  const authoritySocketPath = join(root, "authority.sock");
  const now = Date.now();
  const peerPolicy = { expectedUid: uid, expectedGid: gid, allowedProcessIdentity: capturePeerProcessIdentity(process.pid) };
  let authority: PrivilegedHelperAuthorityIpcServer | undefined;
  let runtime: Awaited<ReturnType<typeof createPrivilegedHelperRuntimeFromKeyMaterial>> | undefined;
  try {
    const provisioned = await provisionAuthenticationKey(keyPath);
    const key = await loadAuthenticationKey(keyPath);
    await writePrivilegedHelperKeyConfig(configPath, {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        keyId: "helper-key-root-material", keySource: "file", path: keyPath,
        keyDigest: provisioned.digest, notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
      }]
    });
    authority = new PrivilegedHelperAuthorityIpcServer({
      socketPath: authoritySocketPath,
      authenticationKey: key,
      replayGuard: { admit: () => undefined },
      authorizeCommand: () => undefined,
      peerPolicy,
      now: () => now
    });
    await authority.listen();
    runtime = await createPrivilegedHelperRuntimeFromKeyMaterial({
      helperKeyConfigPath: configPath,
      socketPath: helperSocketPath,
      brokerSocketPath,
      authoritySocketPath,
      peerPolicy,
      replayGuard: { admit: () => undefined },
      adapter: new AllowlistedPrivilegedHelper({
        service_control: async (command) => ({
          operation: command.operation,
          targetRef: command.targetRef,
          state: "completed",
          resultClass: "SUCCEEDED",
          evidence: {}, warnings: [], truncated: false,
          verification: { status: "verified", strategy: "allowlisted_postcondition" }
        })
      }),
      authorizeCommand: () => undefined,
      serverOptions: { now: () => now }
    });
    await runtime.start();
    const payload = { operation: "service_control" as const, service_id: "system/com.example.test", action: "start" as const };
    const unsigned: UnsignedPrivilegedHelperCommand = {
      protocolVersion: "0.1",
      contractVersion: CONTRACT_VERSION,
      commandId: "priv-command:root-material-0001",
      requestId: "request:root-material-0001",
      nonce: "helper-nonce-root-material-0001",
      nonceExpiresAtMs: now + 30_000,
      timestampMs: now,
      expiresAtMs: now + 30_000,
      operation: "service_control",
      targetRef: "service:system/com.example.test",
      payload,
      payloadDigest: sha256(canonicalJson(payload)),
      policyVersion: "policy-test-1",
      approvalId: "approval:root-material-0001",
      intentId: "intent:root-material-0001"
    };
    const response = await sendHelperCommand(helperSocketPath, signPrivilegedHelperCommand(unsigned, key));
    assert.equal(authenticatePrivilegedHelperResponse(response, unsigned, key).ok, true);
    await assert.rejects(access(join(root, "broker.sqlite")));
    key.fill(0);
  } finally {
    await runtime?.close().catch(() => undefined);
    await authority?.close().catch(() => undefined);
    await rm(root, { recursive: true, force: true });
  }
});

test("root-helper runtime dispatches the fixed service-control adapter through authenticated IPC", async () => {
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || uid < 1 || gid === undefined) throw new Error("POSIX non-root identity is unavailable");
  const root = await mkdtemp(join(tmpdir(), "mops-root-helper-service-control-"));
  const keyPath = join(root, "helper.key");
  const configPath = join(root, "helper-keys.json");
  const helperSocketPath = join(root, "helper.sock");
  const brokerSocketPath = join(root, "broker.sock");
  const authoritySocketPath = join(root, "authority.sock");
  const now = Date.now();
  const peerPolicy = { expectedUid: uid, expectedGid: gid, allowedProcessIdentity: capturePeerProcessIdentity(process.pid) };
  const commandRequests: ProcessExecutionRequest[] = [];
  const states: SafeServiceStatus["state"][] = ["stopped", "running"];
  const inspector: ServiceInspector = {
    inspect: async () => {
      const state = states.shift();
      if (state === undefined) throw new Error("service-control readback fixture exhausted");
      return {
        serviceId: "system/com.example.test",
        loaded: state !== "unknown",
        running: state === "running",
        state,
        lastExitCode: null,
        pid: state === "running" ? 1234 : null,
        warnings: [],
        truncated: false
      };
    }
  };
  const helperAdapter = createPrivilegedServiceControlHelper({
    enabled: true,
    commandRunner: {
      run: async (request) => {
        commandRequests.push(request);
        return success("");
      }
    },
    inspector,
    now: () => now
  });
  assert.equal(helperAdapter.available, true);
  assert.deepEqual(helperAdapter.enabledCapabilities, ["mac_priv_service_control"]);
  let key: Buffer | undefined;
  let authority: PrivilegedHelperAuthorityIpcServer | undefined;
  let runtime: Awaited<ReturnType<typeof createPrivilegedHelperRuntimeFromKeyMaterial>> | undefined;
  try {
    const provisioned = await provisionAuthenticationKey(keyPath);
    key = await loadAuthenticationKey(keyPath);
    await writePrivilegedHelperKeyConfig(configPath, {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        keyId: "helper-key-service-control", keySource: "file", path: keyPath,
        keyDigest: provisioned.digest, notBeforeMs: now - 1_000, expiresAtMs: now + 60_000
      }]
    });
    authority = new PrivilegedHelperAuthorityIpcServer({
      socketPath: authoritySocketPath,
      authenticationKey: key,
      replayGuard: { admit: () => undefined },
      authorizeCommand: () => undefined,
      peerPolicy,
      now: () => now
    });
    await authority.listen();
    runtime = await createPrivilegedHelperRuntimeFromKeyMaterial({
      helperKeyConfigPath: configPath,
      socketPath: helperSocketPath,
      brokerSocketPath,
      authoritySocketPath,
      peerPolicy,
      replayGuard: { admit: () => undefined },
      adapter: helperAdapter,
      authorizeCommand: () => undefined,
      serverOptions: { now: () => now }
    });
    await runtime.start();
    const payload = {
      operation: "service_control" as const,
      service_id: "system/com.example.test",
      action: "start" as const,
      expected_state: "running" as const
    };
    const unsigned: UnsignedPrivilegedHelperCommand = {
      protocolVersion: "0.1",
      contractVersion: CONTRACT_VERSION,
      commandId: "priv-command:runtime-service-control-0001",
      requestId: "request:runtime-service-control-0001",
      nonce: "helper-nonce-runtime-service-control-0001",
      nonceExpiresAtMs: now + 30_000,
      timestampMs: now,
      expiresAtMs: now + 30_000,
      operation: "service_control",
      targetRef: "service:system/com.example.test",
      payload,
      payloadDigest: sha256(canonicalJson(payload)),
      policyVersion: "policy-test-1",
      approvalId: "approval:runtime-service-control-0001",
      intentId: "intent:runtime-service-control-0001"
    };
    const response = await sendHelperCommand(helperSocketPath, signPrivilegedHelperCommand(unsigned, key));
    const verified = authenticatePrivilegedHelperResponse(response, unsigned, key);
    assert.equal(verified.ok, true);
    if (verified.ok) {
      assert.equal(verified.result.resultClass, "SUCCEEDED");
      assert.deepEqual(verified.result.evidence, { pre_state: "stopped", post_state: "running", idempotent: false });
    }
    assert.equal(commandRequests.length, 1);
    assert.deepEqual(commandRequests[0]?.args, ["kickstart", "system/com.example.test"]);
    assert.deepEqual(commandRequests[0]?.environment, {});
  } finally {
    await runtime?.close().catch(() => undefined);
    await authority?.close().catch(() => undefined);
    key?.fill(0);
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
    commandExecutor: { async run(): Promise<ProcessExecutionResult> { return success(`${serviceId} = {\n\ttype = LaunchAgent\n\tstate = running\n\tpid = ${process.pid}\n}`); } }
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
      commandExecutor: { async run(): Promise<ProcessExecutionResult> { return success(`${serviceId} = {\n\ttype = LaunchAgent\n\tstate = not running\n}`); } }
    }),
    (error: unknown) => error instanceof PrivilegedHelperStartupError && error.code === "HELPER_PROCESS_NOT_RUNNING"
  );
  await assert.rejects(
    captureLaunchdBrokerProcessIdentity({
      brokerServiceId: serviceId,
      expectedBrokerUid: uid,
      commandExecutor: { async run(): Promise<ProcessExecutionResult> { return success(`${serviceId} = {\n\tstate = running\n\tpid = 1\n}`); } }
    }),
    (error: unknown) => error instanceof PrivilegedHelperStartupError && error.code === "HELPER_SERVICE_UNAVAILABLE"
  );
  await assert.rejects(
    captureLaunchdBrokerProcessIdentity({
      brokerServiceId: serviceId,
      expectedBrokerUid: uid,
      commandExecutor: { async run(): Promise<ProcessExecutionResult> { return success(`${serviceId} = {\n\ttype = LaunchAgent\n\tstate = running\n\tstate = stopped\n\tpid = ${process.pid}\n}`); } }
    }),
    (error: unknown) => error instanceof PrivilegedHelperStartupError && error.code === "HELPER_SERVICE_UNAVAILABLE"
  );
  await assert.rejects(
    captureLaunchdBrokerProcessIdentity({
      brokerServiceId: serviceId,
      expectedBrokerUid: uid,
      commandExecutor: { async run(): Promise<ProcessExecutionResult> { return success(`${serviceId} = {\n\ttype = LaunchAgent\n\tstate = running\n\tpid = 0\n}`); } }
    }),
    (error: unknown) => error instanceof PrivilegedHelperStartupError && error.code === "HELPER_PROCESS_NOT_RUNNING"
  );
});

test("privileged helper caller capture retries only the xpcproxy bootstrap state", async () => {
  const uid = process.getuid?.();
  if (uid === undefined || uid < 1) throw new Error("POSIX non-root identity is unavailable");
  const serviceId = `gui/${uid}/com.mac-operator.broker`;
  const commands: ProcessExecutionRequest[] = [];
  const executor = {
    async run(command: ProcessExecutionRequest): Promise<ProcessExecutionResult> {
      commands.push(command);
      const state = commands.length === 1 ? "xpcproxy" : "running";
      return success(`${serviceId} = {\n\ttype = LaunchAgent\n\tstate = ${state}\n\tpid = ${process.pid}\n}`);
    }
  };
  const identity = await captureLaunchdBrokerProcessIdentity({ brokerServiceId: serviceId, expectedBrokerUid: uid, commandExecutor: executor });
  assert.equal(identity.pid, process.pid);
  assert.equal(commands.length, 2);
  assert.equal(commands[0]?.timeoutMs, 5_000);
  assert.ok((commands[1]?.timeoutMs ?? 0) > 0);
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
    await assert.rejects(
      createPrivilegedHelperRuntimeFromActiveKeyConfig({
        helperKeyConfigPath: join(root, "missing.json"),
        helperKeyStore: store,
        socketPath: join(root, "helper.sock"),
        brokerSocketPath: join(root, "broker.sock"),
        peerPolicy: { expectedUid: 0, allowedProcessIdentity: capturePeerProcessIdentity(process.pid) },
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

async function sendHelperCommand(socketPath: string, payload: unknown): Promise<import("./privileged-helper.js").PrivilegedHelperResponse> {
  return new Promise((resolvePromise, reject) => {
    const socket = connect(socketPath);
    const chunks: Buffer[] = [];
    let settled = false;
    const fail = (error: unknown) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      reject(error);
    };
    socket.once("error", fail);
    socket.on("data", (chunk) => {
      chunks.push(chunk);
      const combined = Buffer.concat(chunks);
      const newline = combined.indexOf(0x0a);
      if (newline === -1) return;
      settled = true;
      socket.destroy();
      try { resolvePromise(JSON.parse(combined.subarray(0, newline).toString("utf8"))); }
      catch (error) { reject(error); }
    });
    socket.on("close", () => {
      if (!settled) fail(new Error("Privileged helper runtime closed without a response"));
    });
    socket.once("connect", () => socket.write(`${JSON.stringify(payload)}\n`));
  });
}
