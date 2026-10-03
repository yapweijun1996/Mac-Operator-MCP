import { execFile } from "node:child_process";
import { access, lstat, mkdir, mkdtemp, rm } from "node:fs/promises";
import { constants } from "node:fs";
import { userInfo } from "node:os";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const run = promisify(execFile);
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const applicationName = "Mac Operator GUI.app";
const bundleIdentifier = "dev.macoperator.personal.gui";
const options = {
  cwd: packageRoot,
  env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" },
  shell: false,
  timeout: 30_000,
  maxBuffer: 16_384
};

async function exists(path) {
  try {
    return await lstat(path);
  } catch (error) {
    if (error.code === "ENOENT") return undefined;
    throw error;
  }
}

export async function validateGuiApplication(app) {
  const directory = await exists(app);
  if (!directory?.isDirectory()) throw new Error("GUI helper must be an application directory, not a symbolic link");
  for (const component of ["Contents", "Contents/MacOS"]) {
    if (!(await lstat(join(app, component))).isDirectory()) throw new Error("GUI helper bundle directory is invalid");
  }
  for (const component of ["Contents/Info.plist", "Contents/MacOS/gui_vision"]) {
    if (!(await lstat(join(app, component))).isFile()) throw new Error("GUI helper bundle file is invalid");
  }
  await access(join(app, "Contents/MacOS/gui_vision"), constants.X_OK);
  const plist = join(app, "Contents/Info.plist");
  for (const [key, expected] of [
    ["CFBundleIdentifier", bundleIdentifier],
    ["CFBundleExecutable", "gui_vision"],
    ["CFBundlePackageType", "APPL"]
  ]) {
    const result = await run("/usr/libexec/PlistBuddy", ["-c", `Print :${key}`, plist], options);
    if (result.stdout.trim() !== expected) throw new Error(`GUI helper ${key} is invalid`);
  }
  await run("/usr/bin/codesign", [
    "--verify", "--strict", "--all-architectures", "-R", `=identifier "${bundleIdentifier}"`, app
  ], options);
}

// Deployment calls this without a destination override. The argument allows
// real signed-bundle tests to exercise installation in disposable directories.
export async function installGuiApplication({
  sourceApp = join(packageRoot, "dist", applicationName),
  applicationsDirectory = join(userInfo().homedir, "Applications"),
  renameExecutable = join(packageRoot, "dist", "gui_install")
} = {}) {
  if (process.platform !== "darwin") throw new Error("GUI helper installation requires macOS");
  const destination = join(applicationsDirectory, applicationName);
  await mkdir(applicationsDirectory, { recursive: true, mode: 0o700 });
  const parent = await lstat(applicationsDirectory);
  if (!parent.isDirectory() || parent.uid !== process.getuid() || (parent.mode & 0o022) !== 0) {
    throw new Error("GUI application directory must be owner-controlled and must not be a symbolic link");
  }
  if (await exists(destination)) {
    await validateGuiApplication(destination);
    return { action: "preserved", path: destination };
  }
  await validateGuiApplication(sourceApp);
  const renamer = await lstat(renameExecutable);
  if (!renamer.isFile()) throw new Error("Build the GUI atomic installer before installation");
  await access(renameExecutable, constants.X_OK);
  const temporary = await mkdtemp(join(applicationsDirectory, ".mac-operator-gui-"));
  try {
    const staged = join(temporary, applicationName);
    await run("/usr/bin/ditto", [sourceApp, staged], options);
    await validateGuiApplication(staged);
    try {
      // RENAME_EXCL is atomic even when another installer publishes first.
      // Plain mv can instead nest the app inside a concurrently created app.
      await run(renameExecutable, [staged, destination], options);
    } catch (error) {
      if (error.code !== 73) throw error;
      await validateGuiApplication(destination);
      return { action: "preserved", path: destination };
    }
    await validateGuiApplication(destination);
    return { action: "installed", path: destination };
  } finally {
    await rm(temporary, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 0 && (args.length !== 2 || args[0] !== "--source" || !isAbsolute(args[1]))) {
      throw new Error("usage: install-gui-app.sh [--source /absolute/release/Mac Operator GUI.app]");
    }
    const result = await installGuiApplication(args.length === 2 ? { sourceApp: args[1] } : {});
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } catch (error) {
    process.stderr.write(`GUI_HELPER_UNAVAILABLE: ${error instanceof Error ? error.message : "GUI helper installation failed"}\n`);
    process.exitCode = 1;
  }
}
