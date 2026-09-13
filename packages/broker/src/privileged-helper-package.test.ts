import assert from "node:assert/strict";
import { mkdir, rm, writeFile } from "node:fs/promises";
import { mkdtemp } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import {
  applyPrivilegedHelperPlistPlan,
  buildPrivilegedHelperPackageExecutionPlan,
  buildPrivilegedHelperPackagePlan,
  requiredPrivilegedHelperFilesystemPaths,
  PrivilegedHelperPackageError,
  validatePrivilegedHelperFilesystemReadback,
  validatePrivilegedHelperPackageReadback,
  type PrivilegedHelperPackagePlanInput
} from "./privileged-helper-package.js";
import { ProcessSupervisor } from "./process-supervisor.js";

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

test("privileged helper execution contract fixes preconditions, command order, and recovery", () => {
  const install = buildPrivilegedHelperPackagePlan(base);
  const installExecution = buildPrivilegedHelperPackageExecutionPlan(install, { present: false, sourceRevision: null });
  assert.deepEqual(installExecution.steps.map((step) => step.kind), ["verify-signature", "apply-plist", "bootstrap", "readback"]);
  assert.deepEqual(installExecution.recoverySteps.map((step) => step.kind), ["bootout", "apply-plist", "readback"]);
  assert.equal(installExecution.steps[0]?.kind, "verify-signature");
  if (installExecution.steps[0]?.kind === "verify-signature") {
    assert.deepEqual(installExecution.steps[0].command.args, ["--verify", "--strict", "--deep", base.signedArtifactPath]);
  }
  assert.throws(
    () => buildPrivilegedHelperPackageExecutionPlan(install, { present: true, sourceRevision: base.sourceRevision }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "SERVICE_MISMATCH"
  );

  const previous = base.sourceRevision;
  const upgrade = buildPrivilegedHelperPackagePlan({ ...base, operation: "upgrade", expectedPreviousSourceRevision: previous });
  const upgradeExecution = buildPrivilegedHelperPackageExecutionPlan(upgrade, { present: true, sourceRevision: previous });
  assert.deepEqual(upgradeExecution.steps.map((step) => step.kind), ["verify-signature", "bootout", "apply-plist", "bootstrap", "readback"]);
  assert.deepEqual(upgradeExecution.recoverySteps.map((step) => step.kind), ["bootout", "apply-plist", "bootstrap", "readback"]);
  assert.throws(
    () => buildPrivilegedHelperPackageExecutionPlan(upgrade, { present: true, sourceRevision: "abcdef0123456789abcdef0123456789abcdef01" }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "SERVICE_MISMATCH"
  );

  const uninstall = buildPrivilegedHelperPackagePlan({ ...base, operation: "uninstall", expectedPreviousSourceRevision: previous });
  const uninstallExecution = buildPrivilegedHelperPackageExecutionPlan(uninstall, { present: true, sourceRevision: previous });
  assert.deepEqual(uninstallExecution.steps.map((step) => step.kind), ["bootout", "apply-plist", "readback"]);
  assert.deepEqual(uninstallExecution.recoverySteps.map((step) => step.kind), ["readback"]);
});

test("privileged helper package signature command verifies a real temporary macOS artifact", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("The production privileged-helper packaging target is macOS");
    return;
  }
  const temporaryRoot = await mkdtemp(join(tmpdir(), "mac-operator-helper-signature-"));
  try {
    const artifact = join(temporaryRoot, "MacOperatorPrivilegedHelper.app");
    const contents = join(artifact, "Contents");
    const executable = join(contents, "MacOS", "helper");
    await mkdir(join(contents, "MacOS"), { recursive: true, mode: 0o700 });
    await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    await writeFile(join(contents, "Info.plist"), [
      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
      "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
      "<plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>com.mac-operator.privileged-helper</string><key>CFBundleExecutable</key><string>helper</string></dict></plist>"
    ].join("\n"), { mode: 0o600 });
    const supervisor = new ProcessSupervisor({ allowedEnvironmentKeys: [] });
    const signed = await supervisor.run({
      executable: "/usr/bin/codesign",
      args: ["--force", "--deep", "--sign", "-", "--timestamp=none", artifact],
      cwd: "/",
      environment: {},
      timeoutMs: 5_000,
      outputCapBytes: 131_072
    });
    assert.equal(signed.resultClass, "SUCCEEDED");
    const plan = buildPrivilegedHelperPackagePlan({
      ...base,
      helperRoot: temporaryRoot,
      signedArtifactPath: artifact,
      service: {
        ...base.service,
        program: executable,
        programArguments: [executable],
        workingDirectory: temporaryRoot,
        stdoutPath: join(temporaryRoot, "logs", "helper.out.log"),
        stderrPath: join(temporaryRoot, "logs", "helper.err.log")
      },
      helperKeyConfigPath: join(temporaryRoot, "config", "helper-keys.json"),
      helperSocketPath: join(temporaryRoot, "run", "helper.sock")
    });
    const verified = await supervisor.run(plan.signatureVerify);
    assert.equal(verified.resultClass, "SUCCEEDED");
    const details = await supervisor.run({
      executable: "/usr/bin/codesign",
      args: ["-dv", "--verbose=4", artifact],
      cwd: "/",
      environment: {},
      timeoutMs: 5_000,
      outputCapBytes: 131_072
    });
    assert.equal(details.resultClass, "SUCCEEDED");
    assert.match(`${details.stdout}\n${details.stderr}`, /Identifier=com\.mac-operator\.privileged-helper/u);
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
});

test("privileged helper filesystem readback rejects ownership, mode, and target swaps", () => {
  const plan = buildPrivilegedHelperPackagePlan(base);
  const entries = requiredPrivilegedHelperFilesystemPaths(plan, false).map(([path, expectedKind], index) => ({
    path,
    kind: expectedKind === "directory" ? "directory" as const : "file" as const,
    ownerUid: 0,
    mode: path === plan.helperKeyConfigPath ? 0o600 : path === plan.launchd.program ? 0o700 : 0o755,
    device: 1,
    inode: index + 1
  }));
  validatePrivilegedHelperFilesystemReadback(plan, { ownerUid: 0, entries }, false);
  assert.throws(
    () => validatePrivilegedHelperFilesystemReadback(plan, { ownerUid: 0, entries: entries.map((entry) => entry.path === plan.helperKeyConfigPath ? { ...entry, mode: 0o640 } : entry) }, false),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_PACKAGE_PATH"
  );
  assert.throws(
    () => validatePrivilegedHelperFilesystemReadback(plan, { ownerUid: 0, entries: entries.map((entry) => entry.path === plan.launchd.program ? { ...entry, kind: "directory" as const } : entry) }, false),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_PACKAGE_PATH"
  );
  assert.throws(
    () => validatePrivilegedHelperFilesystemReadback(plan, { ownerUid: 0, entries: entries.map((entry) => entry.path === plan.helperRoot ? { ...entry, ownerUid: 501 } : entry) }, false),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_PACKAGE_PATH"
  );
});

test("privileged helper plist apply requires explicit operation confirmation and root ownership", async () => {
  const plan = buildPrivilegedHelperPackagePlan(base);
  await assert.rejects(
    applyPrivilegedHelperPlistPlan(plan, { confirmOperation: "upgrade", ownerUid: 501 }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "CONFIRMATION_REQUIRED"
  );
  await assert.rejects(
    applyPrivilegedHelperPlistPlan(plan, { confirmOperation: "install", ownerUid: 501 }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_PEER_IDENTITY"
  );
});

test("privileged helper plist apply rejects a forged root UID before filesystem access", async (t) => {
  if (process.getuid?.() === 0) {
    t.skip("The test host is already root");
    return;
  }
  const plan = buildPrivilegedHelperPackagePlan(base);
  await assert.rejects(
    applyPrivilegedHelperPlistPlan(plan, { confirmOperation: "install", ownerUid: 0 }),
    (error: unknown) => error instanceof PrivilegedHelperPackageError && error.code === "INVALID_PEER_IDENTITY"
  );
});
