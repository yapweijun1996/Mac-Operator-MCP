import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPrivilegedHelperPackagePlan,
  PrivilegedHelperPackageError,
  validatePrivilegedHelperPackageReadback,
  type PrivilegedHelperPackagePlanInput
} from "./privileged-helper-package.js";

const root = "/Library/Application Support/MacOperator/PrivilegedHelper";
const base: PrivilegedHelperPackagePlanInput = {
  helperRoot: root,
  service: {
    label: "com.mac-operator.privileged-helper",
    program: `${root}/bin/mac-operator-privileged-helper`,
    programArguments: [`${root}/bin/mac-operator-privileged-helper`],
    workingDirectory: root,
    stdoutPath: `${root}/logs/helper.out.log`,
    stderrPath: `${root}/logs/helper.err.log`
  },
  signedArtifactPath: `${root}/MacOperatorPrivilegedHelper.app`,
  signature: { identifier: "com.mac-operator.privileged-helper", teamIdentifier: "ABCDE12345" },
  helperKeyConfigPath: `${root}/config/helper-keys.json`,
  helperSocketPath: `${root}/run/helper.sock`,
  brokerSocketPath: "/Users/operator/Library/Application Support/MacOperator/run/broker.sock",
  brokerPeer: { uid: 501, gid: 20 },
  sourceRevision: "0123456789abcdef0123456789abcdef01234567",
  contractVersion: "0.1",
  policyVersion: "policy-0.1"
};

test("privileged helper package plan is a fixed root-domain native LaunchDaemon", () => {
  const plan = buildPrivilegedHelperPackagePlan(base);
  assert.equal(plan.domain, "system");
  assert.equal(plan.plistPath, "/Library/LaunchDaemons/com.mac-operator.privileged-helper.plist");
  assert.deepEqual(plan.install.bootstrap, {
    executable: "/bin/launchctl",
    args: ["bootstrap", "system", plan.plistPath],
    cwd: "/",
    environment: {},
    timeoutMs: 5_000,
    outputCapBytes: 131_072
  });
  assert.deepEqual(plan.rollback.bootout.args, ["bootout", "system/com.mac-operator.privileged-helper"]);
  assert.equal(plan.install.file.ownerUid, 0);
  assert.equal(plan.install.file.mode, 0o600);
  assert.equal(plan.adapterAvailable, false);
  assert.deepEqual(plan.enabledCapabilities, []);
  assert.match(plan.renderedPlist, /<key>UserName<\/key><string>root<\/string>/u);
  assert.doesNotMatch(plan.renderedPlist, /EnvironmentVariables|Shell/u);
  assert.deepEqual(plan.signatureVerify, {
    executable: "/usr/bin/codesign",
    args: ["--verify", "--strict", "--deep", base.signedArtifactPath],
    cwd: "/",
    environment: {},
    timeoutMs: 5_000,
    outputCapBytes: 131_072
  });
});

test("privileged helper package plan rejects user-domain, interpreter, socket, and signature escapes", () => {
  assert.throws(
    () => buildPrivilegedHelperPackagePlan({ ...base, plistPath: "/Users/operator/Library/LaunchAgents/helper.plist" }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_ROOT_DOMAIN"
  );
  assert.throws(
    () => buildPrivilegedHelperPackagePlan({ ...base, service: { ...base.service, program: `${root}/bin/node`, programArguments: [`${root}/bin/node`] } }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_PACKAGE_PATH"
  );
  assert.throws(
    () => buildPrivilegedHelperPackagePlan({ ...base, service: { ...base.service, programArguments: [base.service.program, "--unsafe"] } }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_PACKAGE_PATH"
  );
  assert.throws(
    () => buildPrivilegedHelperPackagePlan({ ...base, brokerSocketPath: base.helperSocketPath }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_SOCKET_BOUNDARY"
  );
  assert.throws(
    () => buildPrivilegedHelperPackagePlan({ ...base, signature: { identifier: "com.attacker.helper" } }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_SIGNATURE"
  );
  assert.throws(
    () => buildPrivilegedHelperPackagePlan({ ...base, helperRoot: "/Users/operator/Library/Application Support/MacOperator/PrivilegedHelper" }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_PACKAGE_PATH"
  );
});

test("privileged helper package readback binds root service, Broker peer, and disabled adapter", () => {
  const plan = buildPrivilegedHelperPackagePlan(base);
  const readback = {
    domain: "system" as const,
    label: plan.label,
    plistPath: plan.plistPath,
    pid: 1234,
    launchd: plan.launchd,
    helper: {
      component: "mac-operator-privileged-helper" as const,
      state: "running" as const,
      runtimeState: "running" as const,
      nativeTransportRequired: true as const,
      adapterAvailable: false as const,
      helperSocketPath: plan.helperSocketPath,
      brokerSocketPath: plan.brokerSocketPath,
      brokerPeerUid: plan.brokerPeer.uid,
      brokerPeerGid: plan.brokerPeer.gid ?? null,
      sourceRevision: plan.sourceRevision,
      contractVersion: plan.contractVersion,
      policyVersion: plan.policyVersion,
      enabledCapabilities: [] as const
    },
    signature: {
      artifactPath: plan.signedArtifactPath,
      valid: true,
      identifier: plan.signature.identifier,
      teamIdentifier: plan.signature.teamIdentifier ?? null,
      cdHash: plan.signature.cdHash ?? null
    }
  };
  validatePrivilegedHelperPackageReadback(plan, readback);
  assert.throws(
    () => validatePrivilegedHelperPackageReadback(plan, { ...readback, helper: { ...readback.helper, adapterAvailable: true as never } }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "SERVICE_MISMATCH"
  );
  assert.throws(
    () => validatePrivilegedHelperPackageReadback(plan, { ...readback, signature: { ...readback.signature, identifier: "com.attacker.helper" } }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "SIGNATURE_MISMATCH"
  );
});

test("privileged helper package upgrades require an exact previous source revision", () => {
  assert.throws(
    () => buildPrivilegedHelperPackagePlan({ ...base, operation: "upgrade" }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_REVISION"
  );
  const plan = buildPrivilegedHelperPackagePlan({
    ...base,
    operation: "upgrade",
    expectedPreviousSourceRevision: "abcdef0123456789abcdef0123456789abcdef01"
  });
  assert.equal(plan.expectedPreviousSourceRevision, "abcdef0123456789abcdef0123456789abcdef01");
});
