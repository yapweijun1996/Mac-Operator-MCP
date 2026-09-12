import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import test from "node:test";
import { join } from "node:path";
import { tmpdir } from "node:os";
import {
  buildMacOsInstallPlan,
  applyMacOsPlistPlan,
  inspectMacOsInstallFilesystem,
  MacOsInstallPlanError,
  validateCodeSignatureReadback,
  validateExistingServicePrecondition,
  validateMacOsInstallReadback,
  type MacOsInstallPlanInput
} from "./macos-install-plan.js";

const base: MacOsInstallPlanInput = {
  uid: 501,
  userHome: "/Users/operator",
  installRoot: "/Users/operator/Library/Application Support/MacOperator",
  plistPath: "/Users/operator/Library/LaunchAgents/com.mac-operator.broker.plist",
  service: {
    label: "com.mac-operator.broker",
    program: "/Users/operator/Library/Application Support/MacOperator/bin/node",
    programArguments: [
      "/Users/operator/Library/Application Support/MacOperator/bin/node",
      "/Users/operator/Library/Application Support/MacOperator/service-entrypoint.js"
    ],
    workingDirectory: "/Users/operator/Library/Application Support/MacOperator",
    stdoutPath: "/Users/operator/Library/Application Support/MacOperator/logs/broker.out.log",
    stderrPath: "/Users/operator/Library/Application Support/MacOperator/logs/broker.err.log"
  },
  metadata: {
    component: "mac-operator-broker",
    sourceRevision: "0123456789abcdef0123456789abcdef01234567",
    contractVersion: "0.1",
    policyVersion: "0.1"
  },
  signature: {
    identifier: "com.mac-operator.broker",
    teamIdentifier: "ABCDE12345",
    cdHash: "0123456789abcdef0123456789abcdef01234567"
  },
  signedArtifactPath: "/Users/operator/Library/Application Support/MacOperator/MacOperatorBroker.app",
  enabledCapabilities: []
};

test("install plan uses a per-user domain, fixed argv, and explicit rollback actions", () => {
  const plan = buildMacOsInstallPlan(base);
  assert.equal(plan.domain, "gui/501");
  assert.deepEqual(plan.install.bootstrap, {
    executable: "/bin/launchctl",
    args: ["bootstrap", "gui/501", base.plistPath],
    cwd: "/",
    environment: {},
    timeoutMs: 5_000,
    outputCapBytes: 131_072
  });
  assert.deepEqual(plan.rollback.bootout.args, ["bootout", "gui/501/com.mac-operator.broker"]);
  assert.equal(plan.install.file.mode, 0o600);
  assert.deepEqual(plan.signatureVerify, {
    executable: "/usr/bin/codesign",
    args: ["--verify", "--strict", "--deep", base.signedArtifactPath],
    cwd: "/",
    environment: {},
    timeoutMs: 5_000,
    outputCapBytes: 131_072
  });
  assert.equal(plan.rollback.file.kind, "restore-plist");
  assert.equal(plan.uninstall.file.kind, "remove-plist");
  assert.doesNotMatch(plan.renderedPlist, /EnvironmentVariables|UserName|Shell/u);
});

test("install plan rejects root domains, daemon paths, escapes, and script-like argv", () => {
  assert.throws(() => buildMacOsInstallPlan({ ...base, uid: 0 }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_USER_DOMAIN");
  assert.throws(() => buildMacOsInstallPlan({ ...base, plistPath: "/Library/LaunchDaemons/com.mac-operator.broker.plist" }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_PLIST_PATH");
  assert.throws(() => buildMacOsInstallPlan({ ...base, service: { ...base.service, program: "/usr/local/bin/node", programArguments: ["/usr/local/bin/node", base.service.programArguments[1]!] } }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_PACKAGE_PATH");
  assert.throws(() => buildMacOsInstallPlan({ ...base, service: { ...base.service, programArguments: [base.service.program, "-e", "process.exit()"] } }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_PACKAGE_PATH");
  assert.throws(() => buildMacOsInstallPlan({ ...base, installRoot: "/Users/operator/Library/Application Support/MacOperator/../Other" }), /canonical absolute path/u);
});

test("readback requires matching signature, launchd identity, native transport, and Broker metadata", () => {
  const plan = buildMacOsInstallPlan(base);
  const readback = {
    domain: plan.domain,
    label: plan.label,
    plistPath: plan.plistPath,
    pid: 1234,
    launchd: plan.launchd,
    broker: {
      ...base.metadata,
      state: "running" as const,
      runtimeState: "running" as const,
      nativeTransportRequired: true as const,
      enabledCapabilities: []
    },
    signature: {
      artifactPath: base.signedArtifactPath,
      valid: true,
      identifier: base.signature.identifier,
      teamIdentifier: base.signature.teamIdentifier ?? null,
      cdHash: base.signature.cdHash ?? null
    }
  };
  validateMacOsInstallReadback(plan, readback);
  validateCodeSignatureReadback(base.signature, readback.signature, base.signedArtifactPath);
  assert.throws(() => validateMacOsInstallReadback(plan, { ...readback, broker: { ...readback.broker, nativeTransportRequired: false as never } }), /Broker service readback/u);
  assert.throws(() => validateCodeSignatureReadback(base.signature, { ...readback.signature, identifier: "com.attacker.broker" }, base.signedArtifactPath), /code signature readback/u);
});

test("upgrade and uninstall plans bind an exact existing revision and fail closed on precondition mismatch", () => {
  const previous = "abcdef0123456789abcdef0123456789abcdef01";
  const plan = buildMacOsInstallPlan({ ...base, operation: "upgrade", expectedPreviousSourceRevision: previous });
  assert.equal(plan.expectedPreviousSourceRevision, previous);
  validateExistingServicePrecondition(plan, { present: true, sourceRevision: previous });
  assert.throws(() => validateExistingServicePrecondition(plan, { present: false, sourceRevision: null }), /approved operation precondition/u);
  assert.throws(() => buildMacOsInstallPlan({ ...base, operation: "upgrade" }), /previous source revision/u);
  const uninstall = buildMacOsInstallPlan({ ...base, operation: "uninstall", expectedPreviousSourceRevision: previous });
  validateExistingServicePrecondition(uninstall, { present: true, sourceRevision: previous });
});

test("malformed nested readback is rejected with a stable plan error", () => {
  const plan = buildMacOsInstallPlan(base);
  assert.throws(() => validateMacOsInstallReadback(plan, { launchd: null } as never), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "INVALID_READBACK");
});

test("filesystem preflight rejects symlinks and writable paths, then returns stable identity readback", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-install-"));
  try {
    const userHome = join(root, "home");
    const installRoot = join(userHome, "MacOperator");
    const binRoot = join(installRoot, "bin");
    const logRoot = join(installRoot, "logs");
    const artifact = join(installRoot, "MacOperatorBroker.app");
    const launchAgents = join(userHome, "Library", "LaunchAgents");
    await mkdir(binRoot, { recursive: true, mode: 0o700 });
    await mkdir(logRoot, { recursive: true, mode: 0o700 });
    await mkdir(artifact, { recursive: true, mode: 0o700 });
    await mkdir(launchAgents, { recursive: true, mode: 0o700 });
    await writeFile(join(binRoot, "node"), "node", { mode: 0o700 });
    await writeFile(join(installRoot, "service-entrypoint.js"), "", { mode: 0o600 });
    await chmod(userHome, 0o700);
    await chmod(join(userHome, "Library"), 0o700);
    await chmod(launchAgents, 0o700);
    await chmod(installRoot, 0o700);
    await chmod(binRoot, 0o700);
    await chmod(logRoot, 0o700);
    await chmod(artifact, 0o700);
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("POSIX identity is unavailable");
    const plan = buildMacOsInstallPlan({
      ...base,
      uid,
      userHome,
      installRoot,
      plistPath: join(launchAgents, "com.mac-operator.broker.plist"),
      signedArtifactPath: artifact,
      service: {
        ...base.service,
        program: join(binRoot, "node"),
        programArguments: [join(binRoot, "node"), join(installRoot, "service-entrypoint.js")],
        workingDirectory: installRoot,
        stdoutPath: join(logRoot, "broker.out.log"),
        stderrPath: join(logRoot, "broker.err.log")
      }
    });
    const preflight = await inspectMacOsInstallFilesystem(plan, { ownerUid: uid });
    assert.ok(preflight.entries.some((entry) => entry.path === artifact && entry.kind === "directory"));
    await chmod(join(binRoot, "node"), 0o722);
    await assert.rejects(inspectMacOsInstallFilesystem(plan, { ownerUid: uid }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "FILESYSTEM_MISMATCH");
    await chmod(join(binRoot, "node"), 0o700);
    await rm(join(binRoot, "node"));
    await symlink(join(installRoot, "service-entrypoint.js"), join(binRoot, "node"));
    await assert.rejects(inspectMacOsInstallFilesystem(plan, { ownerUid: uid }), (error: unknown) => error instanceof MacOsInstallPlanError && error.code === "FILESYSTEM_MISMATCH");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("plist apply uses native atomic write, creates a backup on upgrade, and restores it on rollback", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-apply-"));
  try {
    const userHome = join(root, "home");
    const installRoot = join(userHome, "MacOperator");
    const binRoot = join(installRoot, "bin");
    const logRoot = join(installRoot, "logs");
    const artifact = join(installRoot, "MacOperatorBroker.app");
    const launchAgents = join(userHome, "Library", "LaunchAgents");
    await mkdir(binRoot, { recursive: true, mode: 0o700 });
    await mkdir(logRoot, { recursive: true, mode: 0o700 });
    await mkdir(artifact, { recursive: true, mode: 0o700 });
    await mkdir(launchAgents, { recursive: true, mode: 0o700 });
    await writeFile(join(binRoot, "node"), "node", { mode: 0o700 });
    await writeFile(join(installRoot, "service-entrypoint.js"), "", { mode: 0o600 });
    for (const directory of [userHome, join(userHome, "Library"), launchAgents, installRoot, binRoot, logRoot, artifact]) await chmod(directory, 0o700);
    const uid = process.getuid?.();
    if (uid === undefined) throw new Error("POSIX identity is unavailable");
    const service = {
      ...base.service,
      program: join(binRoot, "node"),
      programArguments: [join(binRoot, "node"), join(installRoot, "service-entrypoint.js")],
      workingDirectory: installRoot,
      stdoutPath: join(logRoot, "broker.out.log"),
      stderrPath: join(logRoot, "broker.err.log")
    };
    const common = { ...base, uid, userHome, installRoot, plistPath: join(launchAgents, "com.mac-operator.broker.plist"), signedArtifactPath: artifact, service };
    const install = buildMacOsInstallPlan(common);
    const first = await applyMacOsPlistPlan(install, { ownerUid: uid });
    assert.equal(first.created, true);
    const oldContent = await readFile(install.plistPath, "utf8");
    const upgrade = buildMacOsInstallPlan({ ...common, operation: "upgrade", expectedPreviousSourceRevision: base.metadata.sourceRevision, metadata: { ...base.metadata, sourceRevision: "abcdef0123456789abcdef0123456789abcdef01" } });
    const second = await applyMacOsPlistPlan(upgrade, { ownerUid: uid });
    assert.equal(second.backupPath, upgrade.backupPath);
    assert.equal(await readFile(upgrade.backupPath, "utf8"), oldContent);
    assert.equal((await readFile(upgrade.plistPath, "utf8")), upgrade.renderedPlist);
    const rollback = buildMacOsInstallPlan({ ...common, operation: "rollback", expectedPreviousSourceRevision: upgrade.metadata.sourceRevision, metadata: base.metadata });
    const third = await applyMacOsPlistPlan(rollback, { ownerUid: uid });
    assert.equal(third.operation, "rollback");
    assert.equal(await readFile(rollback.plistPath, "utf8"), oldContent);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
