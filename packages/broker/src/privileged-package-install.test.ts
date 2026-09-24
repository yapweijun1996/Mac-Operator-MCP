import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError, canonicalJson, CONTRACT_VERSION, sha256 } from "@mac-operator/contracts";
import {
  PrivilegedPackageInstallAdapter,
  type ApprovedPackageArtifact,
  type InstalledPackageReadback
} from "./privileged-package-install.js";
import type { ProcessExecutionRequest, ProcessExecutionResult } from "./process-supervisor.js";
import type { UnsignedPrivilegedHelperCommand } from "./privileged-helper.js";

const NOW = 1_700_000_000_000;
const ARTIFACT: ApprovedPackageArtifact = {
  packageId: "com.example.tool",
  version: "1.2.3",
  artifactId: "artifact:com.example.tool:1.2.3",
  artifactPath: "/Library/MacOperator/approved/com.example.tool-1.2.3.pkg",
  artifactSha256: "a".repeat(64),
  sourceProfile: "stable"
};

function command(version?: string, sourceProfile?: string): UnsignedPrivilegedHelperCommand {
  const payload = {
    operation: "package_install" as const,
    package_id: ARTIFACT.packageId,
    ...(version === undefined ? {} : { version }),
    ...(sourceProfile === undefined ? {} : { source_profile: sourceProfile })
  };
  return {
    protocolVersion: "0.1",
    contractVersion: CONTRACT_VERSION,
    commandId: "priv-command:test-package-install-1",
    requestId: "request:test-package-install-1",
    nonce: "helper-nonce-test-package-install-1",
    nonceExpiresAtMs: NOW + 30_000,
    timestampMs: NOW,
    expiresAtMs: NOW + 30_000,
    operation: "package_install",
    targetRef: `package:${ARTIFACT.packageId}`,
    payload,
    payloadDigest: sha256(canonicalJson(payload)),
    policyVersion: "policy-test-1",
    approvalId: "approval:test-package-install-1",
    intentId: "intent:test-package-install-1"
  };
}

function success(): ProcessExecutionResult {
  return {
    state: "completed",
    resultClass: "SUCCEEDED",
    exitCode: 0,
    signal: null,
    stdout: "installer: package accepted\n",
    stderr: "",
    truncated: false,
    durationMs: 1,
    processId: 100,
    processGroupId: 100,
    terminationObserved: true
  };
}

function control(shouldCancel = false) {
  return { timeoutMs: 60_000, shouldCancel: () => shouldCancel };
}

function fixture(readbacks: readonly (InstalledPackageReadback | undefined)[], requests: ProcessExecutionRequest[], verifications: string[]) {
  let index = 0;
  return new PrivilegedPackageInstallAdapter({
    enabled: true,
    catalog: [ARTIFACT],
    commandRunner: { run: async (request) => { requests.push(request); return success(); } },
    artifactVerifier: { verify: async (artifact) => { verifications.push(artifact.artifactId); } },
    receiptReader: { read: async () => readbacks[index++] },
    now: () => NOW
  });
}

test("privileged package-install adapter is disabled without explicit enablement", () => {
  const adapter = new PrivilegedPackageInstallAdapter({ catalog: [ARTIFACT] });
  assert.equal(adapter.available, false);
  assert.deepEqual(adapter.enabledCapabilities, []);
});

test("privileged package-install adapter returns an idempotent verified readback without invoking installer", async () => {
  const requests: ProcessExecutionRequest[] = [];
  const verifications: string[] = [];
  const adapter = fixture([
    { packageId: ARTIFACT.packageId, version: ARTIFACT.version },
    { packageId: ARTIFACT.packageId, version: ARTIFACT.version }
  ], requests, verifications);
  const result = await adapter.execute(command(ARTIFACT.version), control());
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.verification.status, "verified");
  assert.deepEqual(result.evidence, {
    installed_version: ARTIFACT.version,
    artifact_id: ARTIFACT.artifactId,
    already_installed: true,
    matched_version: true,
    state: "already_installed"
  });
  assert.equal(requests.length, 0);
  assert.deepEqual(verifications, [ARTIFACT.artifactId]);
});

test("privileged package-install adapter resolves only catalog entries and uses fixed installer argv", async () => {
  const requests: ProcessExecutionRequest[] = [];
  const verifications: string[] = [];
  const adapter = fixture([
    undefined,
    { packageId: ARTIFACT.packageId, version: ARTIFACT.version }
  ], requests, verifications);
  const result = await adapter.execute(command(), control());
  assert.equal(result.resultClass, "SUCCEEDED");
  assert.equal(result.verification.status, "verified");
  assert.deepEqual(requests.map((request) => ({ executable: request.executable, args: request.args, cwd: request.cwd, environment: request.environment })), [
    { executable: "/usr/sbin/installer", args: ["-pkg", ARTIFACT.artifactPath, "-target", "/"], cwd: "/", environment: {} }
  ]);
  assert.deepEqual(verifications, [ARTIFACT.artifactId, ARTIFACT.artifactId]);
});

test("privileged package-install adapter rejects ambiguous or unknown catalog selections", async () => {
  const second = { ...ARTIFACT, version: "2.0.0", artifactId: "artifact:com.example.tool:2.0.0" };
  const adapter = new PrivilegedPackageInstallAdapter({
    enabled: true,
    catalog: [ARTIFACT, second],
    commandRunner: { run: async () => success() },
    artifactVerifier: { verify: async () => undefined },
    receiptReader: { read: async () => undefined },
    now: () => NOW
  });
  await assert.rejects(
    () => adapter.execute(command(), control()),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CONFLICT"
  );
  await assert.rejects(
    () => adapter.execute(command("9.9.9"), control()),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "TARGET_NOT_FOUND"
  );
});

test("privileged package-install adapter stops before any command when cancelled", async () => {
  let calls = 0;
  const adapter = new PrivilegedPackageInstallAdapter({
    enabled: true,
    catalog: [ARTIFACT],
    commandRunner: { run: async () => { calls += 1; return success(); } },
    artifactVerifier: { verify: async () => undefined },
    receiptReader: { read: async () => undefined },
    now: () => NOW
  });
  await assert.rejects(
    () => adapter.execute(command(), control(true)),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "CANCELLED"
  );
  assert.equal(calls, 0);
});
