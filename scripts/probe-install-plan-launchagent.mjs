import { copyFile, lstat, mkdir, mkdtemp, readFile, rm, unlink, writeFile, chmod } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import {
  ProcessSupervisor,
  applyMacOsPlistPlan,
  buildMacOsInstallPlan,
  readLaunchdJobReadback,
  readMacOsCodeSignature
} from "../packages/broker/dist/index.js";

const uid = typeof process.getuid === "function" ? process.getuid() : -1;
const serviceId = `gui/${uid}/com.mac-operator.broker`;
const launchctl = new ProcessSupervisor({ allowedEnvironmentKeys: [] });

if (process.env.MOPS_REAL_INSTALL_PLAN !== "1") {
  throw new Error("Set MOPS_REAL_INSTALL_PLAN=1 to run the disposable install-plan LaunchAgent probe");
}
if (process.platform !== "darwin" || !Number.isSafeInteger(uid) || uid < 1) {
  throw new Error("The install-plan LaunchAgent probe requires a non-root macOS user");
}

let root;
let plistPath;
let loaded = false;

try {
  root = await mkdtemp(join(tmpdir(), "mac-operator-install-plan-"));
  const userHome = join(root, "home");
  const installRoot = join(userHome, "Library", "Application Support", "MacOperator");
  const logRoot = join(installRoot, "logs");
  const artifact = join(installRoot, "MacOperatorBroker.app");
  const artifactContents = join(artifact, "Contents");
  const artifactExecutable = join(artifactContents, "MacOS", "broker");
  const program = artifactExecutable;
  const entrypoint = join(artifactContents, "Resources", "runtime", "service-entrypoint.js");
  plistPath = join(userHome, "Library", "LaunchAgents", "com.mac-operator.broker.plist");
  const sourceRevision = "0123456789abcdef0123456789abcdef01234567";

  for (const directory of [
    userHome,
    join(userHome, "Library"),
    dirname(plistPath),
    installRoot,
    logRoot,
    artifact,
    artifactContents,
    dirname(artifactExecutable),
    dirname(entrypoint),
  ]) {
    await mkdir(directory, { recursive: true, mode: 0o700 });
    await chmod(directory, 0o700);
  }
  await copyFile(process.execPath, program);
  await chmod(program, 0o700);
  await writeFile(entrypoint, "setInterval(() => {}, 1000);\n", { mode: 0o600 });
  await writeFile(join(artifactContents, "Info.plist"), [
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
    "<plist version=\"1.0\"><dict>",
    "<key>CFBundleIdentifier</key><string>com.mac-operator.broker</string>",
    "<key>CFBundleExecutable</key><string>broker</string>",
    "</dict></plist>"
  ].join("\n"), { mode: 0o600 });

  const signResult = await launchctl.run({
    executable: "/usr/bin/codesign",
    args: ["--force", "--deep", "--sign", "-", "--timestamp=none", artifact],
    cwd: "/",
    environment: {},
    timeoutMs: 5_000,
    outputCapBytes: 131_072
  });
  if (signResult.resultClass !== "SUCCEEDED") throw new Error("disposable artifact ad-hoc signing failed");

  const input = {
    uid,
    userHome,
    installRoot,
    plistPath,
    signedArtifactPath: artifact,
    signaturePolicy: "development-ad-hoc",
    signature: { identifier: "com.mac-operator.broker" },
    enabledCapabilities: [],
    service: {
      label: "com.mac-operator.broker",
      program,
      programArguments: [program, entrypoint],
      workingDirectory: installRoot,
      stdoutPath: join(logRoot, "broker.out.log"),
      stderrPath: join(logRoot, "broker.err.log"),
      runAtLoad: true,
      keepAlive: false,
      throttleIntervalSeconds: 1
    },
    metadata: {
      component: "mac-operator-broker",
      sourceRevision,
      contractVersion: "0.1",
      policyVersion: "policy-1"
    }
  };
  const plan = buildMacOsInstallPlan(input);
  const before = await readAbsent(serviceId);
  if (!before) throw new Error("existing broker LaunchAgent label is already present");
  const signature = await readMacOsCodeSignature(plan, launchctl);
  const plist = await applyMacOsPlistPlan(plan, { ownerUid: uid });
  const written = await lstat(plistPath);
  if (!written.isFile() || written.uid !== uid || (written.mode & 0o077) !== 0) {
    throw new Error("install-plan plist is not owner-only");
  }

  await runLaunchctl(plan.install.bootstrap);
  loaded = true;
  const launchd = await waitForLaunchd(plan, "running");
  if (launchd.program !== plan.launchd.program ||
      JSON.stringify(launchd.arguments) !== JSON.stringify(plan.launchd.programArguments) ||
      launchd.plistPath !== plist.path || launchd.type !== "LaunchAgent") {
    throw new Error("LaunchAgent readback does not match the install plan");
  }

  await runLaunchctl(plan.rollback.bootout);
  loaded = false;
  const afterBootout = await readAbsent(serviceId);
  if (!afterBootout) throw new Error("LaunchAgent remained loaded after bootout");

  const uninstall = buildMacOsInstallPlan({
    ...input,
    operation: "uninstall",
    expectedPreviousSourceRevision: sourceRevision
  });
  await applyMacOsPlistPlan(uninstall, { ownerUid: uid });
  await assertMissing(plistPath);
  await assertMissing(uninstall.backupPath);
  process.stdout.write(`${JSON.stringify({
    schemaVersion: "0.1",
    mechanism: "macos-install-plan-launchagent-v1",
    serviceId,
    domain: plan.domain,
    label: plan.label,
    plistPath: plist.path,
    state: launchd.state,
    program: launchd.program,
    arguments: launchd.arguments,
    signatureType: signature.signatureType,
    signatureIdentifier: signature.identifier,
    readbackVerified: true,
    bootoutVerified: true,
    cleanupVerified: true
  })}\n`);
} finally {
  let cleanupComplete = true;
  if (loaded) {
    cleanupComplete = await runBestEffort(["bootout", serviceId]);
    if (cleanupComplete) {
      try { cleanupComplete = await readAbsent(serviceId); } catch { cleanupComplete = false; }
    }
  }
  if (cleanupComplete) {
    if (plistPath !== undefined) await unlinkBestEffort(plistPath);
    if (root !== undefined) await rm(root, { recursive: true, force: true });
  } else {
    process.stderr.write("install-plan probe cleanup could not prove the LaunchAgent was unloaded; temporary state was retained\n");
    process.exitCode = 1;
  }
}

async function runLaunchctl(command) {
  const result = await launchctl.run(command);
  if (result.resultClass !== "SUCCEEDED") throw new Error(`launchctl ${command.args[0]} failed`);
}

async function waitForLaunchd(plan, expectedState) {
  let lastError;
  for (let attempt = 0; attempt < 50; attempt += 1) {
    try {
      const readback = await readLaunchdJobReadback(serviceId, { executor: launchctl });
      if (readback.state === expectedState && readback.pid !== null) return readback;
      lastError = new Error("LaunchAgent has not reached the expected running state");
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw lastError ?? new Error("LaunchAgent readback timed out");
}

async function readAbsent(id) {
  try {
    await readLaunchdJobReadback(id, { executor: launchctl });
    return false;
  } catch (error) {
    return error?.code === "UNAVAILABLE";
  }
}

async function assertMissing(path) {
  try {
    await readFile(path);
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
  throw new Error("install-plan cleanup left an unexpected file");
}

async function runBestEffort(args) {
  try {
    const result = await launchctl.run({
      executable: "/bin/launchctl",
      args,
      cwd: "/",
      environment: {},
      timeoutMs: 5_000,
      outputCapBytes: 131_072
    });
    return result.resultClass === "SUCCEEDED";
  } catch {
    return false;
  }
}

async function unlinkBestEffort(path) {
  try { await unlink(path); } catch (error) { if (error?.code !== "ENOENT") throw error; }
}
