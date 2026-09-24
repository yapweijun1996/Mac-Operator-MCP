import assert from "node:assert/strict";
import test from "node:test";
import { NativeAppSandboxTaskExecutor } from "./app-sandbox-task-executor.js";
import { validateAppSandboxHelperReleaseEvidence } from "./app-sandbox-helper-release.js";

const helperPath = "/tmp/AppSandboxHelper.app/Contents/MacOS/app_sandbox_helper";
const helperContentSha256 = "a".repeat(64);
const teamIdentifier = "ABCDE12345";
const cdHash = "b".repeat(40);

function options(overrides: Partial<ConstructorParameters<typeof NativeAppSandboxTaskExecutor>[0]> = {}) {
  return {
    helperPath,
    containerRoot: "/tmp/mac-operator-app-sandbox-container",
    attestationKeyId: "app-sandbox-test-key",
    attestationPublicKey: Buffer.alloc(32),
    ...overrides
  };
}

test("NativeAppSandboxTaskExecutor remains unavailable without both independent gates", async () => {
  const executor = new NativeAppSandboxTaskExecutor(options({ enabled: true, hostEvidenceAccepted: false }));
  assert.equal(executor.available, false);
  await assert.rejects(
    executor.run({} as never, { timeoutMs: 1_000, shouldCancel: () => false }),
    (error: unknown) => (error as { errorClass?: string }).errorClass === "POLICY_DENIED"
  );
  await executor.close();
});

test("NativeAppSandboxTaskExecutor remains unavailable without helper content evidence", async () => {
  const executor = new NativeAppSandboxTaskExecutor(options({ enabled: true, hostEvidenceAccepted: true }));
  assert.equal(executor.available, false);
  assert.equal(executor.capability.helperContentIdentity, "unproven");
  await executor.close();
});

test("NativeAppSandboxTaskExecutor rejects non-canonical helper paths", () => {
  assert.throws(
    () => new NativeAppSandboxTaskExecutor(options({ helperPath: "/tmp/../tmp/AppSandboxHelper" })),
    /options are invalid/
  );
});

test("NativeAppSandboxTaskExecutor rejects malformed helper content evidence", () => {
  assert.throws(
    () => new NativeAppSandboxTaskExecutor(options({ expectedHelperContentSha256: "not-a-digest" })),
    /options are invalid/
  );
});

test("NativeAppSandboxTaskExecutor requires complete release evidence in production mode", () => {
  assert.throws(
    () => new NativeAppSandboxTaskExecutor(options({
      enabled: true,
      hostEvidenceAccepted: true,
      releaseMode: "production",
      expectedHelperContentSha256: helperContentSha256
    })),
    /Developer ID release evidence/u
  );
});

test("NativeAppSandboxTaskExecutor exposes development probe mode without claiming production provenance", () => {
  const executor = new NativeAppSandboxTaskExecutor(options({
    enabled: true,
    hostEvidenceAccepted: true,
    releaseMode: "development-probe",
    expectedHelperContentSha256: helperContentSha256
  }));
  assert.equal(executor.available, true);
  assert.equal(executor.capability.helperReleaseMode, "development-probe");
  assert.equal(executor.capability.productionRelease, "unproven");
});

test("App Sandbox helper release evidence binds the bundle, Developer ID, and notarization", () => {
  const evidence = {
    artifact: {
      artifactPath: "/tmp/AppSandboxHelper.app",
      sha256: "c".repeat(64),
      bytes: 128,
      files: 2,
      directories: 3,
      device: "1",
      inode: "2",
      mode: 0o700
    },
    signature: {
      artifactPath: "/tmp/AppSandboxHelper.app",
      valid: true,
      identifier: "com.macoperator.mopappsandboxhelper",
      teamIdentifier,
      cdHash,
      signatureType: "developer-id" as const,
      authority: "Developer ID Application: Mac Operator (ABCDE12345)"
    },
    notarization: {
      artifactPath: "/tmp/AppSandboxHelper.app",
      assessed: true as const,
      source: "Notarized Developer ID" as const,
      teamIdentifier,
      origin: "Developer ID Application: Mac Operator (ABCDE12345)"
    },
    policy: "developer-id-notarized" as const
  };
  validateAppSandboxHelperReleaseEvidence(evidence, {
    helperPath,
    helperContentSha256,
    signature: { identifier: "com.macoperator.mopappsandboxhelper", teamIdentifier, cdHash }
  });
  assert.throws(
    () => validateAppSandboxHelperReleaseEvidence({
      ...evidence,
      signature: { ...evidence.signature, signatureType: "development-ad-hoc", authority: null, teamIdentifier: null }
    }, {
      helperPath,
      helperContentSha256,
      signature: { identifier: "com.macoperator.mopappsandboxhelper", teamIdentifier, cdHash }
    }),
    /release signature or notarization/u
  );
});
