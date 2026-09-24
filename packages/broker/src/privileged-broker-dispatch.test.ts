import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, canonicalJson, sha256, signRequest, type Scope, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import {
  assertPrivilegedHelperReadbackAuthority,
  BrokerPrivilegedHelperCommandFactory,
  BrokerStorePrivilegedHelperReplayGuard,
  executePrivilegedHelperCommand,
  PrivilegedHelperIpcServer
} from "./privileged-helper.js";
import { createPrivilegedHelperAdapter } from "./privileged-helper-adapters.js";
import { createPrivilegedHelperReadbackClient, PrivilegedHelperJobExecutor } from "./privileged-helper-executor.js";
import type { ProcessExecutionResult } from "./process-supervisor.js";
import type { BrokerPolicy } from "./policy.js";

const NOW = 1_700_000_000_000;

function successfulProcessResult(): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout: "",
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: 42,
    processGroupId: 42,
    terminationObserved: true
  };
}

function keyring(key: Buffer): EdgeKeyring {
  return new EdgeKeyring([{
    edgeId: "edge-1",
    keyId: "edge-key-1",
    key,
    notBeforeMs: 0,
    expiresAtMs: Number.MAX_SAFE_INTEGER
  }]);
}

function request(key: Buffer, scopes: readonly Scope[]): ReturnType<typeof signRequest> {
  const unsigned: UnsignedBrokerRequest = {
    protocolVersion: "0.1",
    requestId: "request-privileged-dispatch",
    contractVersion: "0.1",
    tool: "mac_priv_service_control",
    arguments: { service_id: "system/com.example.test", action: "start", expected_state: "running" },
    principal: {
      principalId: "principal-1",
      sessionId: "session-privileged",
      issuer: "test-issuer",
      audience: "mac-operator-broker",
      scopes: [...scopes],
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000,
      edgeId: "edge-1"
    },
    timestampMs: NOW,
    nonce: "nonce-privileged-dispatch",
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-1"
  };
  return signRequest(unsigned, key);
}

function enabledPolicy(): BrokerPolicy {
  const base = createDefaultPolicy("edge-1", false, ["mac.priv.service"]);
  const tool = base.tools.get("mac_priv_service_control");
  assert.ok(tool);
  return {
    ...base,
    targetRules: [
      ...base.targetRules,
      {
        ruleId: "privileged-service-allow",
        effect: "allow",
        principalId: "principal-1",
        scope: "mac.priv.service",
        target: { kind: "service", reference: "system/com.example.test" }
      }
    ],
    tools: new Map(base.tools).set("mac_priv_service_control", { ...tool, implemented: true, enabled: true })
  };
}

function enabledPolicyFor(toolName: string, scope: Scope, targetKind: "package" | "host", targetReference: string): BrokerPolicy {
  const base = createDefaultPolicy("edge-1", false, [scope, "mac.job.read"]);
  const tool = base.tools.get(toolName);
  assert.ok(tool);
  const jobStatusTool = base.tools.get("mac_job_status");
  assert.ok(jobStatusTool);
  return {
    ...base,
    targetRules: [
      ...base.targetRules,
      { ruleId: `privileged-${toolName}-allow`, effect: "allow", principalId: "principal-1", scope, target: { kind: targetKind, reference: targetReference } }
    ],
    tools: new Map(base.tools)
      .set(toolName, { ...tool, implemented: true, enabled: true })
      .set("mac_job_status", { ...jobStatusTool, implemented: true, enabled: true })
  };
}

function requestFor(
  key: Buffer,
  tool: string,
  argumentsValue: Readonly<Record<string, unknown>>,
  scope: Scope,
  requestId: string,
  sessionId: string,
  nonce: string
): ReturnType<typeof signRequest> {
  return signRequest({
    protocolVersion: "0.1",
    requestId,
    contractVersion: "0.1",
    tool,
    arguments: argumentsValue,
    principal: {
      principalId: "principal-1",
      sessionId,
      issuer: "test-issuer",
      audience: "mac-operator-broker",
      scopes: [scope],
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000,
      edgeId: "edge-1"
    },
    timestampMs: NOW,
    nonce,
    policyAudience: "mac-operator-broker",
    policyVersion: "policy-0.1",
    authenticationKeyId: "edge-key-1"
  }, key);
}

test("Broker dispatches an approved privileged Job through the helper boundary", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-privileged-dispatch-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  const helperKey = randomBytes(32);
  const input = request(edgeKey, ["mac.priv.service"]);
  const payload = {
    operation: "service_control" as const,
    service_id: "system/com.example.test",
    action: "start" as const,
    expected_state: "running" as const
  };
  store.issueApproval({
    approvalId: "approval:privileged-dispatch",
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool: input.tool,
    contractVersion: input.contractVersion,
    targetKind: "service",
    targetRef: "service:system/com.example.test",
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: input.policyVersion,
    approvalClass: "explicit_privileged_policy",
    unattended: false,
    issuedAtMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000
  });
  const commandFactory = new BrokerPrivilegedHelperCommandFactory({
    store,
    authenticationKey: helperKey,
    authorizeCommand: () => undefined,
    now: () => NOW
  });
  const executor = new PrivilegedHelperJobExecutor({
    store,
    enabled: true,
    enabledOperations: ["service_control"],
    commandFactory,
    commandClient: async (command) => ({
      ok: true as const,
      commandId: command.commandId,
      requestId: command.requestId,
      result: {
        operation: "service_control" as const,
        targetRef: command.targetRef,
        state: "completed" as const,
        resultClass: "SUCCEEDED" as const,
        evidence: { pre_state: "stopped", post_state: "running" },
        warnings: [],
        truncated: false,
        verification: { status: "verified" as const, strategy: "allowlisted_postcondition" as const }
      },
      responseProof: ""
    }),
    now: () => NOW
  });
  const broker = new Broker({ store, policy: enabledPolicy(), edgeAuthenticationKeys: keyring(edgeKey), privilegedHelperExecutor: executor, now: () => NOW });
  try {
    const result = await broker.handle(input);
    assert.equal(result.ok, true, JSON.stringify(result));
    if (result.ok) {
      const requestRecord = store.requestRecord(input.requestId);
      const jobId = requestRecord?.jobId;
      assert.ok(jobId);
      assert.equal(result.tool, "mac_priv_service_control");
      assert.deepEqual(result.data, {
        service_id: "system/com.example.test",
        action: "start",
        pre_state: "stopped",
        post_state: "running",
        verification_status: "verified",
        job_id: jobId
      });
    }
    assert.equal(store.requestRecord(input.requestId)?.state, "SUCCEEDED");
    const jobId = store.requestRecord(input.requestId)?.jobId;
    assert.ok(jobId);
    assert.equal(store.ownedJob(jobId, "principal-1")?.state, "completed");
  } finally {
    commandFactory.dispose();
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Broker refuses privileged admission when the helper boundary is disabled", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-privileged-disabled-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  const input = request(edgeKey, ["mac.priv.service"]);
  const payload = {
    operation: "service_control" as const,
    service_id: "system/com.example.test",
    action: "start" as const,
    expected_state: "running" as const
  };
  store.issueApproval({
    approvalId: "approval:privileged-disabled",
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool: input.tool,
    contractVersion: input.contractVersion,
    targetKind: "service",
    targetRef: "service:system/com.example.test",
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: input.policyVersion,
    approvalClass: "explicit_privileged_policy",
    unattended: false,
    issuedAtMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000
  });
  const broker = new Broker({ store, policy: enabledPolicy(), edgeAuthenticationKeys: keyring(edgeKey), now: () => NOW });
  try {
    const result = await broker.handle(input);
    assert.equal(result.ok, false);
    if (!result.ok) assert.equal(result.result_class, "POLICY_DENIED");
    assert.equal(store.requestRecord(input.requestId)?.jobId, null);
  } finally {
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("Broker maps package-install and power helper readbacks to their tool contracts", async () => {
  const cases = [
    {
      tool: "mac_priv_package_install",
      scope: "mac.priv.package" as const,
      args: { package_id: "example", version: "1.2.3", source_profile: "approved" },
      payload: { operation: "package_install" as const, package_id: "example", version: "1.2.3", source_profile: "approved" },
      targetKind: "package" as const,
      targetReference: "example",
      targetRef: "package:example",
      evidence: { installed_version: "1.2.3", artifact_id: "artifact:example", already_installed: false, matched_version: true, state: "installed" },
      expected: { package_id: "example", requested_version: "1.2.3", installed_version: "1.2.3", artifact_id: "artifact:example", precondition: { already_installed: false, matched_version: false }, state: "installed" }
    },
    {
      tool: "mac_priv_power",
      scope: "mac.priv.power" as const,
      args: { action: "reboot", reason: "operator" },
      payload: { operation: "power" as const, action: "reboot", reason: "operator" },
      targetKind: "host" as const,
      targetReference: "local",
      targetRef: "host:local",
      evidence: { state: "scheduled", scheduled_for: null, handoff_id: "handoff:reboot", connection_loss_expected: true },
      expected: { action: "reboot", state: "accepted", scheduled_for: null, connection_loss_expected: true }
    }
  ] as const;
  for (const [index, testCase] of cases.entries()) {
    const directory = await mkdtemp(join(tmpdir(), `mac-operator-privileged-${index}-`));
    const store = new BrokerStore(join(directory, "broker.sqlite"));
    const edgeKey = randomBytes(32);
    const helperKey = randomBytes(32);
    const input = requestFor(edgeKey, testCase.tool, testCase.args, testCase.scope, `request-privileged-${index}`, `session-privileged-${index}`, `nonce-privileged-${index}-unique`);
    store.issueApproval({
      approvalId: `approval:privileged-${index}`,
      approverPrincipalId: "operator-1",
      requestingPrincipalId: "principal-1",
      tool: input.tool,
      contractVersion: input.contractVersion,
      targetKind: testCase.targetKind,
      targetRef: testCase.targetRef,
      payloadDigest: sha256(canonicalJson(testCase.payload)),
      policyVersion: input.policyVersion,
      approvalClass: "explicit_privileged_policy",
      unattended: false,
      issuedAtMs: NOW - 1_000,
      expiresAtMs: NOW + 60_000
    });
    const commandFactory = new BrokerPrivilegedHelperCommandFactory({ store, authenticationKey: helperKey, authorizeCommand: () => undefined, now: () => NOW });
    let packageInstalled = false;
    const packageRuns: Array<{ executable: string; args: readonly string[] }> = [];
    const powerRuns: Array<{ executable: string; args: readonly string[] }> = [];
    const helper = createPrivilegedHelperAdapter({
      packageInstall: {
        enabled: true,
        catalog: [{
          packageId: "example",
          version: "1.2.3",
          artifactId: "artifact:example",
          artifactPath: "/private/var/db/mac-operator/packages/example-1.2.3.pkg",
          artifactSha256: "a".repeat(64),
          sourceProfile: "approved"
        }],
        commandRunner: {
          run: async (run) => {
            packageRuns.push(run);
            packageInstalled = true;
            return successfulProcessResult();
          }
        },
        artifactVerifier: { verify: async () => undefined },
        receiptReader: {
          read: async () => packageInstalled ? { packageId: "example", version: "1.2.3" } : undefined
        },
        now: () => NOW
      },
      power: {
        enabled: true,
        commandRunner: {
          run: async (run) => {
            powerRuns.push(run);
            return successfulProcessResult();
          }
        },
        now: () => NOW
      }
    });
    const socketPath = join(directory, "helper.sock");
    const server = new PrivilegedHelperIpcServer({
      socketPath,
      authenticationKey: helperKey,
      replayGuard: new BrokerStorePrivilegedHelperReplayGuard(store),
      authorizeCommand: () => undefined,
      peerCredentialVerifier: { verify: () => undefined },
      adapter: helper,
      now: () => NOW
    });
    const executor = new PrivilegedHelperJobExecutor({
      store,
      enabled: true,
      enabledOperations: [testCase.payload.operation],
      commandFactory,
      commandClient: async (command, timeoutMs) => executePrivilegedHelperCommand(command, {
        socketPath,
        authenticationKey: helperKey,
        now: () => NOW,
        timeoutMs
      }),
      now: () => NOW,
      leaseDurationMs: 120_000
    });
    const broker = new Broker({
      store,
      policy: enabledPolicyFor(testCase.tool, testCase.scope, testCase.targetKind, testCase.targetReference),
      edgeAuthenticationKeys: keyring(edgeKey),
      privilegedHelperExecutor: executor,
      now: () => NOW
    });
    try {
      await server.listen();
      const result = await broker.handle(input);
      assert.equal(result.ok, true, JSON.stringify(result));
      if (result.ok) {
        const jobId = store.requestRecord(input.requestId)?.jobId;
        assert.ok(jobId);
        if (testCase.payload.operation === "package_install") {
          assert.deepEqual(result.data, { ...testCase.expected, job_id: jobId });
        } else {
          const data = result.data as Record<string, unknown>;
          assert.deepEqual({
            action: data.action,
            state: data.state,
            scheduled_for: data.scheduled_for,
            connection_loss_expected: data.connection_loss_expected,
            job_id: data.job_id
          }, { ...testCase.expected, job_id: jobId });
          assert.match(String(data.handoff_id), /^power:[a-f0-9]{48}$/u);
        }
      }
      if (testCase.payload.operation === "package_install") {
        assert.equal(packageRuns.length, 1);
        assert.equal(packageRuns[0]?.executable, "/usr/sbin/installer");
        assert.deepEqual(packageRuns[0]?.args, ["-pkg", "/private/var/db/mac-operator/packages/example-1.2.3.pkg", "-target", "/"]);
        assert.deepEqual(powerRuns, []);
      } else {
        assert.equal(powerRuns.length, 1);
        assert.equal(powerRuns[0]?.executable, "/sbin/shutdown");
        assert.deepEqual(powerRuns[0]?.args, ["-r", "now"]);
        assert.deepEqual(packageRuns, []);
      }
    } finally {
      await server.close();
      commandFactory.dispose();
      await broker.close();
      store.close();
      await rm(directory, { recursive: true, force: true });
    }
  }
});

type RecoveryMode = "unknown" | "cancel" | "revoke";

async function runActualPrivilegedRecoveryCase(mode: RecoveryMode): Promise<void> {
  const operation = mode === "revoke" ? "power" as const : "package_install" as const;
  const tool = operation === "package_install" ? "mac_priv_package_install" : "mac_priv_power";
  const scope = operation === "package_install" ? "mac.priv.package" as const : "mac.priv.power" as const;
  const targetKind = operation === "package_install" ? "package" as const : "host" as const;
  const targetReference = operation === "package_install" ? "example" : "local";
  const targetRef = `${targetKind}:${targetReference}`;
  const argumentsValue = operation === "package_install"
    ? { package_id: "example", version: "1.2.3", source_profile: "approved" }
    : { action: "reboot", reason: "recovery-test" };
  const payload = operation === "package_install"
    ? { operation, package_id: "example", version: "1.2.3", source_profile: "approved" }
    : { operation, action: "reboot", reason: "recovery-test" };
  const requestId = `request-privileged-recovery-${mode}`;
  const directory = await mkdtemp(join(tmpdir(), `mops-pr-${mode}-`));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const edgeKey = randomBytes(32);
  const helperKey = randomBytes(32);
  const input = requestFor(edgeKey, tool, argumentsValue, scope, requestId, `session-${mode}`, `nonce-${mode}-unique`);
  let active = true;
  let commandRuns = 0;
  let packageInstalled = false;
  store.issueApproval({
    approvalId: `approval:${mode}`,
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "principal-1",
    tool: input.tool,
    contractVersion: input.contractVersion,
    targetKind,
    targetRef,
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: input.policyVersion,
    approvalClass: "explicit_privileged_policy",
    unattended: false,
    issuedAtMs: NOW - 1_000,
    expiresAtMs: NOW + 60_000
  });

  const packageInstall = {
    enabled: true,
    catalog: [{
      packageId: "example",
      version: "1.2.3",
      artifactId: "artifact:example",
      artifactPath: "/private/var/db/mac-operator/packages/example-1.2.3.pkg",
      artifactSha256: "a".repeat(64),
      sourceProfile: "approved"
    }],
    commandRunner: {
      run: async () => {
        commandRuns += 1;
        if (mode === "cancel") {
          const jobId = store.requestRecord(requestId)?.jobId;
          assert.ok(jobId);
          store.requestJobCancellation(jobId, "principal-1", "TEST_CANCEL_AFTER_DISPATCH", NOW);
          packageInstalled = true;
        }
        return mode === "unknown"
          ? { ...successfulProcessResult(), state: "unknown" as const, resultClass: "UNKNOWN_OUTCOME" as const }
          : successfulProcessResult();
      }
    },
    artifactVerifier: { verify: async () => undefined },
    receiptReader: { read: async () => packageInstalled ? { packageId: "example", version: "1.2.3" } : undefined },
    now: () => NOW
  };
  const power = {
    enabled: true,
    commandRunner: {
      run: async () => {
        commandRuns += 1;
        active = false;
        return successfulProcessResult();
      }
    },
    now: () => NOW
  };
  const helper = operation === "package_install"
    ? createPrivilegedHelperAdapter({ packageInstall })
    : createPrivilegedHelperAdapter({ power });
  const commandFactory = new BrokerPrivilegedHelperCommandFactory({
    store,
    authenticationKey: helperKey,
    authorizeCommand: () => undefined,
    now: () => NOW
  });
  const socketPath = join(directory, "helper.sock");
  const server = new PrivilegedHelperIpcServer({
    socketPath,
    authenticationKey: helperKey,
    replayGuard: new BrokerStorePrivilegedHelperReplayGuard(store),
    authorizeCommand: () => {
      if (!active) throw new BrokerError("REVOKED", "Privileged helper authority was revoked");
    },
    authorizeReadback: (readback) => {
      if (!active) throw new BrokerError("REVOKED", "Privileged helper readback authority was revoked");
      assertPrivilegedHelperReadbackAuthority(store, readback);
    },
    peerCredentialVerifier: { verify: () => undefined },
    adapter: helper,
    now: () => NOW
  });
  const executor = new PrivilegedHelperJobExecutor({
    store,
    enabled: true,
    enabledOperations: [operation],
    commandFactory,
    commandClient: async (command, timeoutMs) => executePrivilegedHelperCommand(command, {
      socketPath,
      authenticationKey: helperKey,
      now: () => NOW,
      timeoutMs
    }),
    readbackClient: createPrivilegedHelperReadbackClient((timeoutMs) => ({
      socketPath,
      authenticationKey: helperKey,
      now: () => NOW,
      timeoutMs
    })),
    now: () => NOW,
    leaseDurationMs: 120_000
  });
  const broker = new Broker({
    store,
    policy: enabledPolicyFor(tool, scope, targetKind, targetReference),
    edgeAuthenticationKeys: keyring(edgeKey),
    privilegedHelperExecutor: executor,
    now: () => NOW
  });
  try {
    await server.listen();
    const result = await broker.handle(input);
    assert.equal(result.ok, false, JSON.stringify(result));
    if (!result.ok) assert.equal(result.result_class, "UNKNOWN_OUTCOME");
    const jobId = store.requestRecord(requestId)?.jobId;
    assert.ok(jobId);
    const job = store.ownedJob(jobId, "principal-1");
    assert.equal(job?.state, "unknown");
    assert.equal(job?.resultClass, "unknown");
    assert.equal(commandRuns, 1);
    if (mode === "cancel") assert.equal(job?.cancelRequested, true);
    const status = await broker.handle(requestFor(
      edgeKey,
      "mac_job_status",
      { job_id: jobId, tail_bytes: 128 },
      "mac.job.read",
      `request-privileged-recovery-status-${mode}`,
      `session-${mode}`,
      `nonce-privileged-recovery-status-${mode}-unique`
    ));
    assert.equal(status.ok, true, JSON.stringify(status));
    if (status.ok) {
      const data = status.data as Record<string, unknown>;
      assert.equal(data.state, "unknown");
      assert.equal(data.result_class, "unknown");
      const expectedPostcondition = mode === "cancel" ? "matches" : mode === "unknown" ? "mismatch" : "unavailable";
      assert.deepEqual(data.recovery, {
        postcondition: expectedPostcondition,
        resolution: "remains_unknown",
        observed_at: new Date(NOW).toISOString()
      });
    }
  } finally {
    await server.close();
    commandFactory.dispose();
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
}

test("Broker persists UNKNOWN_OUTCOME for an unresolved package adapter over authenticated helper IPC", async () => {
  await runActualPrivilegedRecoveryCase("unknown");
});

test("Broker preserves UNKNOWN after package dispatch is cancelled through the Job ledger", async () => {
  await runActualPrivilegedRecoveryCase("cancel");
});

test("Broker persists UNKNOWN when helper authority is revoked after a power adapter handoff", async () => {
  await runActualPrivilegedRecoveryCase("revoke");
});
