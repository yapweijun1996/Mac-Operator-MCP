import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { constants, cp, chmod, lstat, mkdir, mkdtemp, open, readFile, readdir, realpath, rename, rm, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const NODE_VERSION = "24.21.0";
const NODE_TEAM_IDENTIFIER = "HX7739G8FX";
const NODE_ARCHIVE_SHA256 = "bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057";
const HELPER_IDENTIFIER = "com.mac-operator.privileged-helper";
const HELPER_EXECUTABLE = "mac-operator-privileged-helper";
const POSTJECT_PACKAGE = "postject@1.0.0-alpha.6";
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

try {
  await build();
} catch (error) {
  const message = error instanceof Error ? error.message : "privileged helper app build failed";
  process.stderr.write(`Privileged helper app build failed closed: ${message}\n`);
  process.exitCode = 1;
}

async function build() {
  requireHost();
  const args = parseArguments(process.argv.slice(2));
  const outputPath = args.output;
  const outputParent = dirname(outputPath);
  const parent = await lstat(outputParent).catch(() => undefined);
  if (!parent?.isDirectory() || parent.isSymbolicLink() || await realpath(outputParent) !== outputParent) {
    throw new Error("output parent must be an existing canonical directory");
  }
  if (await lstat(outputPath).catch(() => undefined)) throw new Error("output app bundle already exists");

  const { parsePrivilegedHelperRuntimeDescriptor } = await import(
    new URL("../packages/broker/dist/privileged-helper-main.js", import.meta.url).href
  );
  const descriptorBytes = await readOwnerOnlyInput(args.descriptor, 512 * 1024, "runtime descriptor");
  const descriptor = parsePrivilegedHelperRuntimeDescriptor(descriptorBytes);
  const enabledCapabilities = getEnabledCapabilities(descriptor);
  if (args.identity === undefined && enabledCapabilities.length > 0) {
    throw new Error("ad-hoc helper bundles cannot enable privileged capabilities");
  }

  const nodeArchiveBytes = await readVerifiedNodeArchive(args.nodeArchive);
  const signer = args.identity === undefined ? undefined : verifySigningIdentity(args.identity);

  const temporaryRoot = await mkdtemp(join(outputParent, ".privileged-helper-build-"));
  const appPath = join(temporaryRoot, "MacOperatorPrivilegedHelper.app");
  const contentsPath = join(appPath, "Contents");
  const resourcesPath = join(contentsPath, "Resources");
  const runtimeRoot = join(resourcesPath, "runtime");
  const brokerPackage = join(runtimeRoot, "packages/broker");
  const brokerDist = join(brokerPackage, "dist");
  let publishedOutputIdentity;

  try {
    const nodeArchivePath = join(temporaryRoot, `node-v${NODE_VERSION}-darwin-arm64.tar.gz`);
    await writeFile(nodeArchivePath, nodeArchiveBytes, { flag: "wx", mode: 0o600 });
    run("/usr/bin/tar", ["-xzf", nodeArchivePath, "-C", temporaryRoot], temporaryRoot, "verified Node runtime extraction");
    const nodeRoot = join(temporaryRoot, `node-v${NODE_VERSION}-darwin-arm64`);
    const nodeExecutable = join(nodeRoot, "bin/node");
    const nodeHeaders = join(nodeRoot, "include/node");
    const [nodeStat, headersStat] = await Promise.all([lstat(nodeExecutable), lstat(nodeHeaders)]);
    if (!nodeStat.isFile() || nodeStat.isSymbolicLink() || !headersStat.isDirectory() || headersStat.isSymbolicLink()) {
      throw new Error("Node runtime executable or matching N-API headers are unavailable");
    }
    verifyNodeRuntime(nodeExecutable);
    await mkdir(join(contentsPath, "MacOS"), { recursive: true, mode: 0o755 });
    await mkdir(brokerDist, { recursive: true, mode: 0o755 });
    await mkdir(join(runtimeRoot, "packages/contracts"), { recursive: true, mode: 0o755 });
    await writeFile(join(runtimeRoot, "package.json"), JSON.stringify({ name: "mac-operator-helper-runtime", private: true, type: "module" }) + "\n", { flag: "wx", mode: 0o644 });
    await writeFile(join(runtimeRoot, "packages/broker/package.json"), JSON.stringify({ name: "@mac-operator/broker", private: true, type: "module", exports: "./dist/index.js" }) + "\n", { flag: "wx", mode: 0o644 });
    await writeFile(join(runtimeRoot, "packages/contracts/package.json"), JSON.stringify({ name: "@mac-operator/contracts", private: true, type: "module", exports: "./dist/index.js" }) + "\n", { flag: "wx", mode: 0o644 });
    await cp(join(repositoryRoot, "packages/broker/dist"), brokerDist, { recursive: true, dereference: true, errorOnExist: true });
    await cp(join(repositoryRoot, "packages/contracts/dist"), join(runtimeRoot, "packages/contracts/dist"), { recursive: true, dereference: true, errorOnExist: true });
    await copyProductionDependencies(runtimeRoot);
    const nativeAddonPath = join(brokerDist, "peer_credentials.node");
    await buildNativeAdapter(nodeHeaders, nativeAddonPath);
    verifyNativeAddonRuntime(nodeExecutable, nativeAddonPath);

    const executablePath = join(contentsPath, "MacOS", HELPER_EXECUTABLE);
    await cp(nodeExecutable, executablePath, { errorOnExist: true });
    await chmod(executablePath, 0o755);
    removeCodeSignature(executablePath);
    await runRuntimeImportSmoke(nodeExecutable, dirname(executablePath), temporaryRoot);

    const infoPlistPath = join(contentsPath, "Info.plist");
    await writeFile(infoPlistPath, buildInfoPlist(), { flag: "wx", mode: 0o644 });
    await normalizeBundleModes(appPath);
    const seaConfigPath = join(temporaryRoot, "sea-config.json");
    const seaBlobPath = join(temporaryRoot, "sea-prep.blob");
    await writeFile(seaConfigPath, JSON.stringify({
      main: join(repositoryRoot, "packaging/macos/privileged-helper-sea-main.cjs"),
      output: seaBlobPath,
      disableExperimentalSEAWarning: true,
      useSnapshot: false,
      useCodeCache: false,
      execArgvExtension: "none",
      assets: { "privileged-helper-runtime.json": args.descriptor }
    }) + "\n", { flag: "wx", mode: 0o600 });
    run(nodeExecutable, ["--experimental-sea-config", seaConfigPath], temporaryRoot, "SEA preparation");
    run("npm", ["exec", "--yes", "--package", POSTJECT_PACKAGE, "--", "postject", executablePath,
      "NODE_SEA_BLOB", seaBlobPath, "--sentinel-fuse", "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
      "--macho-segment-name", "NODE_SEA"], repositoryRoot, "SEA asset injection");

    if (signer === undefined) {
      signAdHoc(join(brokerDist, "peer_credentials.node"), "com.mac-operator.privileged-helper.native");
      signAdHoc(appPath, HELPER_IDENTIFIER);
    } else {
      const entitlementsPath = join(temporaryRoot, "node-runtime.entitlements.plist");
      await writeFile(entitlementsPath, minimalRuntimeEntitlements(), { flag: "wx", mode: 0o600 });
      signDeveloperId(join(brokerDist, "peer_credentials.node"), "com.mac-operator.privileged-helper.native", args.identity, entitlementsPath);
      signDeveloperId(appPath, HELPER_IDENTIFIER, args.identity, entitlementsPath);
    }
    verifyBundle(appPath, signer?.teamIdentifier);

    const outputDirectory = await mkdir(outputPath, { mode: 0o700 }).then(async () => lstat(outputPath));
    publishedOutputIdentity = { device: outputDirectory.dev, inode: outputDirectory.ino };
    if (!outputDirectory.isDirectory() || await readdir(outputPath).then((entries) => entries.length) !== 0) {
      throw new Error("output path changed during build publication");
    }
    await rename(contentsPath, join(outputPath, "Contents"));
    await chmod(outputPath, 0o755);
    verifyBundle(outputPath, signer?.teamIdentifier);
    const identity = readSignatureIdentity(outputPath);
    if (identity.identifier !== HELPER_IDENTIFIER || identity.cdHash === undefined ||
        (signer !== undefined && identity.teamIdentifier !== signer.teamIdentifier) ||
        (signer === undefined && identity.teamIdentifier !== undefined)) {
      throw new Error("built app signature identity does not match the selected release mode");
    }
    process.stdout.write(`${JSON.stringify({
      status: "built-and-verified",
      runtimeVersion: `v${NODE_VERSION}`,
      outputPath,
      executablePath: join(outputPath, "Contents/MacOS", HELPER_EXECUTABLE),
      signature: { identifier: identity.identifier, teamIdentifier: identity.teamIdentifier ?? null, cdHash: identity.cdHash },
      enabledCapabilities,
      nativeAdapterVerified: true,
      notarized: false,
      installed: false,
      launchDaemonStarted: false
    })}\n`);
  } catch (error) {
    if (publishedOutputIdentity !== undefined) {
      const current = await lstat(outputPath).catch(() => undefined);
      if (current?.isDirectory() && current.dev === publishedOutputIdentity.device && current.ino === publishedOutputIdentity.inode &&
          await readdir(outputPath).then((entries) => entries.length === 0).catch(() => false)) {
        await rm(outputPath).catch(() => undefined);
      }
    }
    throw error;
  } finally {
    await rm(temporaryRoot, { recursive: true, force: true });
  }
}

function parseArguments(args) {
  const values = new Map();
  for (let index = 0; index < args.length; index += 2) {
    const key = args[index];
    const value = args[index + 1];
    if (!new Set(["--runtime-descriptor", "--node-archive", "--output", "--identity", "--ad-hoc"]).has(key) ||
        values.has(key) || (key !== "--ad-hoc" && typeof value !== "string")) {
      throw new Error("usage: node scripts/build-privileged-helper-app.mjs --runtime-descriptor FILE --node-archive FILE --output NEW.app (--identity 'Developer ID Application: Name (TEAM)' | --ad-hoc)");
    }
    values.set(key, key === "--ad-hoc" ? true : value);
  }
  const descriptor = values.get("--runtime-descriptor");
  const nodeArchive = values.get("--node-archive");
  const output = values.get("--output");
  const identity = values.get("--identity");
  if (typeof descriptor !== "string" || typeof nodeArchive !== "string" || typeof output !== "string" ||
      (typeof identity !== "string") === (values.get("--ad-hoc") !== true)) {
    throw new Error("runtime descriptor, verified Node archive, output, and exactly one signing mode are required");
  }
  for (const [path, label] of [[descriptor, "runtime descriptor"], [nodeArchive, "Node runtime archive"], [output, "output path"]]) {
    if (!isAbsolute(path) || resolve(path) !== path || path.includes("\0") || path.includes("\n") || path.includes("\r")) {
      throw new Error(`${label} must be a canonical absolute path`);
    }
  }
  if (!output.endsWith(".app")) throw new Error("output path must end in .app");
  return { descriptor, nodeArchive, output, ...(typeof identity === "string" ? { identity } : {}) };
}

function requireHost() {
  if (process.platform !== "darwin" || process.arch !== "arm64") {
    throw new Error("privileged helper app packaging requires macOS arm64");
  }
  if ((process.geteuid?.() ?? 0) === 0) throw new Error("privileged helper app packaging must run as a non-root owner");
}

async function readOwnerOnlyInput(path, maxBytes, label) {
  if (!isAbsolute(path) || resolve(path) !== path || await realpath(path).catch(() => "") !== path) {
    throw new Error(`${label} path must be canonical and available`);
  }
  const before = await lstat(path);
  if (!before.isFile() || before.isSymbolicLink() || before.uid !== (process.getuid?.() ?? -1) ||
      (before.mode & 0o077) !== 0 || before.size > maxBytes) {
    throw new Error(`${label} must be a bounded owner-only regular file`);
  }
  const bytes = await readFile(path);
  const after = await lstat(path);
  if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size || before.mtimeMs !== after.mtimeMs) {
    throw new Error(`${label} changed while being read`);
  }
  return bytes;
}

async function readVerifiedNodeArchive(path) {
  if (!isAbsolute(path) || resolve(path) !== path || await realpath(path).catch(() => "") !== path) {
    throw new Error("Node runtime archive path must be canonical and available");
  }
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const before = await file.stat();
    if (!before.isFile() || before.uid !== (process.getuid?.() ?? -1) || (before.mode & 0o022) !== 0 ||
        before.size < 1 || before.size > 256 * 1024 * 1024) {
      throw new Error("Node runtime archive must be a bounded, user-owned regular file");
    }
    const bytes = await file.readFile();
    const after = await file.stat();
    if (before.dev !== after.dev || before.ino !== after.ino || before.size !== after.size ||
        before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs || bytes.byteLength !== before.size) {
      throw new Error("Node runtime archive changed while being read");
    }
    const digest = createHash("sha256").update(bytes).digest("hex");
    if (digest !== NODE_ARCHIVE_SHA256) throw new Error("Node runtime archive SHA-256 does not match the pinned official release");
    return bytes;
  } finally {
    await file.close();
  }
}

function verifyNodeRuntime(nodeExecutable) {
  const version = run(nodeExecutable, ["--version"], repositoryRoot, "Node runtime version check").trim();
  if (version !== `v${NODE_VERSION}`) throw new Error(`Node runtime must be exactly v${NODE_VERSION}`);
  run("/usr/bin/codesign", ["--verify", "--strict", "--deep", nodeExecutable], repositoryRoot, "Node runtime signature verification");
  const identity = readSignatureIdentity(nodeExecutable);
  if (identity.teamIdentifier !== NODE_TEAM_IDENTIFIER) throw new Error("Node runtime is not signed by the pinned Node.js Foundation team");
}

function verifyNativeAddonRuntime(nodeExecutable, nativeAddonPath) {
  const smokeScript = `const addon = require(process.argv[1]);\nif (addon.nativeNodeVersion !== process.versions.node || addon.nativePlatform !== process.platform || addon.nativeArch !== process.arch) throw new Error("native adapter ABI mismatch");\nconst identity = addon.getProcessIdentity(process.pid);\nif (!identity || identity.pid !== process.pid || !Number.isSafeInteger(identity.startTimeMicros) || identity.startTimeMicros < 1) throw new Error("native process identity probe failed");\nprocess.stdout.write("native-adapter-runtime-passed\\n");\n`;
  const result = run(nodeExecutable, ["-e", smokeScript, nativeAddonPath], repositoryRoot, "Node-version-matched native addon smoke");
  if (result !== "native-adapter-runtime-passed\n") throw new Error("Node native adapter smoke returned an unexpected result");
}

function verifySigningIdentity(identity) {
  const match = /^Developer ID Application: .+ \(([A-Z0-9]{10})\)$/u.exec(identity);
  if (!match) throw new Error("signing identity must be an exact Developer ID Application identity");
  const listing = run("/usr/bin/security", ["find-identity", "-v", "-p", "codesigning"], repositoryRoot, "Developer ID identity lookup");
  if (!listing.split("\n").some((line) => line.includes(`"${identity}"`))) {
    throw new Error("requested Developer ID identity is not currently valid on this host");
  }
  return { teamIdentifier: match[1] };
}

async function buildNativeAdapter(nodeHeaders, outputPath) {
  const sourcePath = join(repositoryRoot, "packages/broker/native/peer_credentials.cc");
  const temporaryOutput = `${outputPath}.tmp-${process.pid}`;
  try {
    run("/usr/bin/xcrun", ["clang++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-bundle",
      "-undefined", "dynamic_lookup", "-framework", "Security", "-framework", "CoreFoundation",
      `-I${nodeHeaders}`, sourcePath, "-o", temporaryOutput], repositoryRoot, "Node-version-matched native adapter build");
    run("/usr/bin/codesign", ["--verify", "--strict", temporaryOutput], repositoryRoot, "native adapter signature check");
    await chmod(temporaryOutput, 0o755);
    await rename(temporaryOutput, outputPath);
  } catch (error) {
    await rm(temporaryOutput, { force: true }).catch(() => undefined);
    throw error;
  }
}

async function copyProductionDependencies(runtimeRoot) {
  const nodeModulesRoot = join(repositoryRoot, "node_modules");
  const packageList = run("npm", ["ls", "--omit=dev", "--all", "--parseable", "--workspace", "@mac-operator/broker"], repositoryRoot, "production dependency inventory");
  const runtimeNodeModules = join(runtimeRoot, "node_modules");
  const contractPackage = join(runtimeNodeModules, "@mac-operator/contracts");
  await mkdir(contractPackage, { recursive: true, mode: 0o755 });
  await writeFile(join(contractPackage, "package.json"), JSON.stringify({ name: "@mac-operator/contracts", private: true, type: "module", exports: "./dist/index.js" }) + "\n", { flag: "wx", mode: 0o644 });
  await cp(join(repositoryRoot, "packages/contracts/dist"), join(contractPackage, "dist"), { recursive: true, dereference: true, errorOnExist: true });

  const realNodeModulesRoot = await realpath(nodeModulesRoot);
  const copiedPackages = new Set();
  for (const sourceCandidate of packageList.split("\n").filter((line) => line.startsWith(`${nodeModulesRoot}${sep}`))) {
    const packageRelativePath = relative(nodeModulesRoot, sourceCandidate);
    if (packageRelativePath.startsWith(`@mac-operator${sep}`)) continue;
    const sourcePath = await realpath(sourceCandidate);
    if (sourcePath !== realNodeModulesRoot && !sourcePath.startsWith(`${realNodeModulesRoot}${sep}`)) {
      throw new Error("production dependency resolves outside node_modules");
    }
    const targetPath = join(runtimeNodeModules, packageRelativePath);
    if (copiedPackages.has(targetPath)) continue;
    const sourceStat = await lstat(sourceCandidate);
    if (!sourceStat.isDirectory()) throw new Error("production dependency inventory contains a non-directory package");
    await mkdir(dirname(targetPath), { recursive: true, mode: 0o755 });
    await cp(sourcePath, targetPath, { recursive: true, dereference: true, errorOnExist: true });
    copiedPackages.add(targetPath);
  }
  if (copiedPackages.size === 0) throw new Error("production dependency inventory is empty");
}

async function runRuntimeImportSmoke(nodeExecutable, executableDirectory, temporaryRoot) {
  const probeMainPath = join(temporaryRoot, "runtime-import-probe.cjs");
  const probeConfigPath = join(temporaryRoot, "runtime-import-probe.json");
  const probeBlobPath = join(temporaryRoot, "runtime-import-probe.blob");
  const probeExecutablePath = join(executableDirectory, ".runtime-import-probe");
  const probeMain = `"use strict";\nconst path = require("node:path");\nconst { pathToFileURL } = require("node:url");\nconst sea = require("node:sea");\nif (!sea.isSea()) throw new Error("SEA mode unavailable");\nconst entry = path.resolve(__dirname, "../Resources/runtime/packages/broker/dist/privileged-helper-main.js");\nimport(pathToFileURL(entry).href).then((runtime) => {\n  if (typeof runtime.runEmbeddedPrivilegedHelper !== "function") throw new Error("helper runtime entry is unavailable");\n  process.stdout.write("runtime-import-passed\\n");\n}).catch(() => { process.exitCode = 1; });\n`;
  await writeFile(probeMainPath, probeMain, { flag: "wx", mode: 0o600 });
  await writeFile(probeConfigPath, JSON.stringify({
    main: probeMainPath,
    output: probeBlobPath,
    disableExperimentalSEAWarning: true,
    useSnapshot: false,
    useCodeCache: false,
    execArgvExtension: "none"
  }) + "\n", { flag: "wx", mode: 0o600 });
  try {
    run(nodeExecutable, ["--experimental-sea-config", probeConfigPath], temporaryRoot, "runtime import SEA preparation");
    await cp(nodeExecutable, probeExecutablePath, { errorOnExist: true });
    await chmod(probeExecutablePath, 0o700);
    removeCodeSignature(probeExecutablePath);
    run("npm", ["exec", "--yes", "--package", POSTJECT_PACKAGE, "--", "postject", probeExecutablePath,
      "NODE_SEA_BLOB", probeBlobPath, "--sentinel-fuse", "NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2",
      "--macho-segment-name", "NODE_SEA"], repositoryRoot, "runtime import SEA injection");
    signAdHoc(probeExecutablePath, "com.mac-operator.privileged-helper.import-probe");
    const result = spawnSync(probeExecutablePath, [], {
      cwd: temporaryRoot,
      env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", NODE_OPTIONS: "" },
      encoding: "utf8",
      windowsHide: true,
      shell: false,
      timeout: 30_000,
      maxBuffer: 1024 * 1024
    });
    if (result.error !== undefined || result.status !== 0 || result.stdout !== "runtime-import-passed\n") {
      throw new Error("Node SEA could not load the packaged ESM helper runtime and production dependency graph");
    }
  } finally {
    await rm(probeExecutablePath, { force: true });
  }
}

function removeCodeSignature(executablePath) {
  const inspection = spawnSync("/usr/bin/codesign", ["--display", "--verbose=2", executablePath], {
    cwd: repositoryRoot,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", NODE_OPTIONS: "" },
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    timeout: 30_000,
    maxBuffer: 1024 * 1024
  });
  if (inspection.status === 0) {
    run("/usr/bin/codesign", ["--remove-signature", executablePath], repositoryRoot, "removing copied runtime signature");
    return;
  }
  if (!`${inspection.stdout ?? ""}\n${inspection.stderr ?? ""}`.includes("code object is not signed at all")) {
    throw new Error("copied Node runtime signature could not be inspected");
  }
}

function signAdHoc(path, identifier) {
  run("/usr/bin/codesign", ["--force", "--sign", "-", "--identifier", identifier, path], repositoryRoot, "ad-hoc local signing");
}

function signDeveloperId(path, identifier, identity, entitlementsPath) {
  run("/usr/bin/codesign", ["--force", "--sign", identity, "--identifier", identifier, "--options", "runtime",
    "--entitlements", entitlementsPath, "--timestamp", path], repositoryRoot, "Developer ID signing");
}

function verifyBundle(path, expectedTeamIdentifier) {
  run("/usr/bin/codesign", ["--verify", "--strict", "--deep", path], repositoryRoot, "signed app bundle verification");
  const nativeAddonPath = join(path, "Contents/Resources/runtime/packages/broker/dist/peer_credentials.node");
  run("/usr/bin/codesign", ["--verify", "--strict", nativeAddonPath], repositoryRoot, "native addon signature verification");
  const identity = readSignatureIdentity(path);
  const nativeIdentity = readSignatureIdentity(nativeAddonPath);
  if (identity.identifier !== HELPER_IDENTIFIER ||
      (expectedTeamIdentifier !== undefined && (identity.teamIdentifier !== expectedTeamIdentifier || nativeIdentity.teamIdentifier !== expectedTeamIdentifier)) ||
      (expectedTeamIdentifier === undefined && (identity.teamIdentifier !== undefined || nativeIdentity.teamIdentifier !== undefined))) {
    throw new Error("signed app bundle identifier or Team ID does not match the expected release identity");
  }
}

function readSignatureIdentity(path) {
  const inspection = spawnSync("/usr/bin/codesign", ["--display", "--verbose=4", path], {
    cwd: repositoryRoot,
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", NODE_OPTIONS: "" },
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    timeout: 30_000,
    maxBuffer: 1024 * 1024
  });
  if (inspection.error !== undefined || inspection.status !== 0) throw new Error("code-signature identity could not be read");
  const details = `${inspection.stdout ?? ""}\n${inspection.stderr ?? ""}`;
  const identifier = /^Identifier=(.+)$/mu.exec(details)?.[1];
  const teamValue = /^TeamIdentifier=(.+)$/mu.exec(details)?.[1];
  const cdHash = /^CDHash=(.+)$/mu.exec(details)?.[1];
  if (identifier === undefined || cdHash === undefined || !/^[a-fA-F0-9]{20,64}$/u.test(cdHash)) {
    throw new Error("code-signature identity readback is incomplete");
  }
  return { identifier, ...(teamValue === undefined || teamValue === "not set" ? {} : { teamIdentifier: teamValue }), cdHash };
}

async function normalizeBundleModes(rootPath) {
  const entries = await readdir(rootPath, { withFileTypes: true });
  for (const entry of entries) {
    const path = join(rootPath, entry.name);
    if (entry.isSymbolicLink()) throw new Error("app bundle contains an unexpected symbolic link");
    if (entry.isDirectory()) {
      await chmod(path, 0o755);
      await normalizeBundleModes(path);
    } else if (entry.isFile()) {
      await chmod(path, entry.name === HELPER_EXECUTABLE || entry.name.endsWith(".node") ? 0o755 : 0o644);
    } else {
      throw new Error("app bundle contains an unsupported filesystem entry");
    }
  }
}

function getEnabledCapabilities(descriptor) {
  const result = [];
  if (descriptor.capabilities.serviceControl.enabled) result.push("mac_priv_service_control");
  if (descriptor.capabilities.packageInstall.enabled) result.push("mac_priv_package_install");
  if (descriptor.capabilities.power.enabled) result.push("mac_priv_power");
  return result;
}

function buildInfoPlist() {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>CFBundleDevelopmentRegion</key><string>English</string><key>CFBundleExecutable</key><string>${HELPER_EXECUTABLE}</string><key>CFBundleIdentifier</key><string>${HELPER_IDENTIFIER}</string><key>CFBundleName</key><string>Mac Operator Privileged Helper</string><key>CFBundlePackageType</key><string>APPL</string><key>CFBundleShortVersionString</key><string>0.1.0</string><key>CFBundleVersion</key><string>0.1.0</string></dict></plist>\n`;
}

function minimalRuntimeEntitlements() {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0"><dict><key>com.apple.security.cs.allow-jit</key><true/><key>com.apple.security.cs.allow-unsigned-executable-memory</key><true/></dict></plist>\n`;
}

function run(executable, args, cwd, label) {
  const result = spawnSync(executable, args, {
    cwd,
    env: { PATH: process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin", NODE_OPTIONS: "" },
    encoding: "utf8",
    windowsHide: true,
    shell: false,
    timeout: 120_000,
    maxBuffer: 2 * 1024 * 1024
  });
  if (result.error !== undefined) throw new Error(`${label} could not run: ${result.error.message}`);
  if (result.status !== 0) {
    const detail = (result.stderr ?? "").trim().slice(-2_000);
    throw new Error(`${label} failed with exit code ${String(result.status)}${detail === "" ? "" : `: ${detail}`}`);
  }
  return result.stdout ?? "";
}
