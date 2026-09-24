import assert from "node:assert/strict";
import test from "node:test";
import { CONTRACT_VERSION } from "@mac-operator/contracts";
import {
  createPrivilegedHelperRuntimeFromDescriptor,
  parsePrivilegedHelperRuntimeDescriptor,
  validatePrivilegedHelperRuntimeDescriptor,
  type PrivilegedHelperRuntimeDescriptor,
  type PrivilegedHelperRuntimeLaunchOptions
} from "./privileged-helper-main.js";
import type { PrivilegedHelperRuntime } from "./privileged-helper-runtime.js";

const HELPER_ROOT = "/Library/Application Support/MacOperator/PrivilegedHelper";
const DESCRIPTOR: PrivilegedHelperRuntimeDescriptor = {
  schemaVersion: "0.1",
  helperRoot: HELPER_ROOT,
  helperKeyConfigPath: `${HELPER_ROOT}/config/helper-keys.json`,
  helperSocketPath: `${HELPER_ROOT}/run/helper.sock`,
  brokerSocketPath: "/Users/operator/Library/Application Support/MacOperator/run/broker.sock",
  helperAuthoritySocketPath: "/Users/operator/Library/Application Support/MacOperator/run/helper-authority.sock",
  brokerPeer: { uid: 501, gid: 20 },
  sourceRevision: "a".repeat(40),
  contractVersion: CONTRACT_VERSION,
  policyVersion: "policy-2026-09-23",
  capabilities: {
    serviceControl: { enabled: false, systemPublishedExecutablePathAccepted: false },
    packageInstall: { enabled: false, systemPublishedExecutablePathAccepted: false, catalog: [] },
    power: { enabled: false, systemPublishedExecutablePathAccepted: false }
  }
};

test("privileged helper runtime descriptor binds separate socket ownership domains", () => {
  const descriptor = validatePrivilegedHelperRuntimeDescriptor(DESCRIPTOR);
  assert.deepEqual(descriptor.brokerPeer, { uid: 501, gid: 20 });
  assert.equal(descriptor.helperRoot, HELPER_ROOT);
  assert.deepEqual(descriptor.capabilities.packageInstall.catalog, []);

  assert.throws(() => validatePrivilegedHelperRuntimeDescriptor({
    ...DESCRIPTOR,
    brokerSocketPath: `${HELPER_ROOT}/run/broker.sock`
  }), /Broker-owned sockets must remain outside/u);
  assert.throws(() => validatePrivilegedHelperRuntimeDescriptor({
    ...DESCRIPTOR,
    helperAuthoritySocketPath: DESCRIPTOR.brokerSocketPath
  }), /sockets must be distinct/u);
  assert.throws(() => validatePrivilegedHelperRuntimeDescriptor({
    ...DESCRIPTOR,
    helperKeyConfigPath: `${HELPER_ROOT}/../outside/helper-keys.json`
  }), /canonical absolute path/u);
});

test("embedded runtime descriptor parser rejects duplicate fields and malformed UTF-8", () => {
  const encoded = Buffer.from(JSON.stringify(DESCRIPTOR));
  const duplicateKey = Buffer.from(
    encoded.toString("utf8").replace('"schemaVersion":"0.1"', '"schemaVersion":"0.1","schemaVersion":"0.1"'),
    "utf8"
  );
  assert.throws(() => parsePrivilegedHelperRuntimeDescriptor(duplicateKey), /duplicate key/u);
  assert.throws(() => parsePrivilegedHelperRuntimeDescriptor(Buffer.from([0xc3, 0x28])), /valid UTF-8/u);
  assert.deepEqual(parsePrivilegedHelperRuntimeDescriptor(encoded), validatePrivilegedHelperRuntimeDescriptor(DESCRIPTOR));
});

test("privileged helper runtime descriptor fails closed on capability and ABI drift", () => {
  assert.throws(() => validatePrivilegedHelperRuntimeDescriptor({
    ...DESCRIPTOR,
    unsupportedMode: "shell"
  }), /unsupported or missing fields/u);
  assert.throws(() => validatePrivilegedHelperRuntimeDescriptor({
    ...DESCRIPTOR,
    brokerPeer: { uid: 0, gid: 0 }
  }), /brokerPeer.uid/u);
  assert.throws(() => validatePrivilegedHelperRuntimeDescriptor({
    ...DESCRIPTOR,
    sourceRevision: "not-a-commit"
  }), /sourceRevision/u);
  assert.throws(() => validatePrivilegedHelperRuntimeDescriptor({
    ...DESCRIPTOR,
    contractVersion: "future-contract"
  }), /does not match this helper/u);
  assert.throws(() => validatePrivilegedHelperRuntimeDescriptor({
    ...DESCRIPTOR,
    capabilities: {
      ...DESCRIPTOR.capabilities,
      serviceControl: { enabled: true, systemPublishedExecutablePathAccepted: false }
    }
  }), /explicit acceptance/u);
  assert.throws(() => validatePrivilegedHelperRuntimeDescriptor({
    ...DESCRIPTOR,
    capabilities: {
      ...DESCRIPTOR.capabilities,
      packageInstall: { enabled: true, systemPublishedExecutablePathAccepted: true, catalog: [] }
    }
  }), /non-empty approved catalog/u);
});

test("privileged helper package catalog accepts only immutable approved artifact identities", () => {
  const descriptor = {
    ...DESCRIPTOR,
    capabilities: {
      ...DESCRIPTOR.capabilities,
      packageInstall: {
        enabled: true,
        systemPublishedExecutablePathAccepted: true,
        catalog: [{
          packageId: "com.example.tool",
          version: "1.2.3",
          artifactId: "tool-1.2.3",
          artifactPath: "/Library/Application Support/MacOperator/Packages/tool.pkg",
          artifactSha256: "b".repeat(64),
          sourceProfile: "approved-channel"
        }]
      }
    }
  };
  const parsed = validatePrivilegedHelperRuntimeDescriptor(descriptor);
  assert.equal(parsed.capabilities.packageInstall.catalog.length, 1);
  assert.equal(parsed.capabilities.packageInstall.catalog[0]?.artifactSha256, "b".repeat(64));

  assert.throws(() => validatePrivilegedHelperRuntimeDescriptor({
    ...descriptor,
    capabilities: {
      ...descriptor.capabilities,
      packageInstall: {
        ...descriptor.capabilities.packageInstall,
        catalog: [{ ...descriptor.capabilities.packageInstall.catalog[0], artifactSha256: "mutable" }]
      }
    }
  }), /artifactSha256/u);
});

test("production runtime factory captures the exact Broker LaunchAgent and reports the signed projection", async () => {
  let captured: PrivilegedHelperRuntimeLaunchOptions | undefined;
  let peerIdentityLossReported = false;
  const fakeRuntime = {
    state: "stopped",
    async start() {},
    async close() {}
  } as unknown as PrivilegedHelperRuntime;
  const runtime = await createPrivilegedHelperRuntimeFromDescriptor(DESCRIPTOR, {
    platform: "darwin",
    effectiveUid: 0,
    executablePath: `${HELPER_ROOT}/MacOperatorPrivilegedHelper.app/Contents/MacOS/mac-operator-privileged-helper`,
    onPeerIdentityLost: () => { peerIdentityLossReported = true; },
    createRuntime: async (options) => {
      captured = options;
      return fakeRuntime;
    }
  });

  assert.equal(runtime, fakeRuntime);
  assert.equal(captured?.brokerServiceId, "gui/501/com.mac-operator.broker");
  assert.equal(captured?.expectedBrokerUid, 501);
  assert.equal(captured?.expectedBrokerGid, 20);
  assert.equal(captured?.keychainTrustedExecutablePath, `${HELPER_ROOT}/MacOperatorPrivilegedHelper.app/Contents/MacOS/mac-operator-privileged-helper`);
  assert.equal(captured?.authorizeCommand !== undefined, true);
  assert.equal(captured?.authorizeStatus !== undefined, true);
  assert.equal(typeof captured?.serverOptions?.onPeerIdentityLost, "function");
  captured?.serverOptions?.onPeerIdentityLost?.({ pid: 1234, startTimeMicros: 5678 });
  assert.equal(peerIdentityLossReported, true);
  assert.deepEqual(captured?.readStatus?.(), {
    component: "mac-operator-privileged-helper",
    state: "running",
    runtimeState: "running",
    nativeTransportRequired: true,
    adapterAvailable: false,
    helperSocketPath: DESCRIPTOR.helperSocketPath,
    brokerSocketPath: DESCRIPTOR.brokerSocketPath,
    helperAuthoritySocketPath: DESCRIPTOR.helperAuthoritySocketPath,
    brokerPeerUid: 501,
    brokerPeerGid: 20,
    sourceRevision: DESCRIPTOR.sourceRevision,
    contractVersion: CONTRACT_VERSION,
    policyVersion: DESCRIPTOR.policyVersion,
    enabledCapabilities: []
  });
});

test("production runtime factory rejects non-root, non-macOS, and non-canonical executables before construction", async () => {
  let factoryCalled = false;
  const host = {
    platform: "darwin",
    effectiveUid: 501,
    executablePath: "/Applications/Helper.app/Contents/MacOS/helper",
    createRuntime: async () => {
      factoryCalled = true;
      throw new Error("runtime factory must not be called");
    }
  };
  await assert.rejects(createPrivilegedHelperRuntimeFromDescriptor(DESCRIPTOR, host), /requires the root service identity/u);
  await assert.rejects(createPrivilegedHelperRuntimeFromDescriptor(DESCRIPTOR, { ...host, effectiveUid: 0, platform: "linux" }), /requires macOS/u);
  await assert.rejects(createPrivilegedHelperRuntimeFromDescriptor(DESCRIPTOR, { ...host, effectiveUid: 0, executablePath: "relative-helper" }), /canonical absolute path/u);
  assert.equal(factoryCalled, false);
});
