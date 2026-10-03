import { execFile } from "node:child_process";
import { access, lstat, mkdir, mkdtemp, readFile, rename, rm } from "node:fs/promises";
import { constants } from "node:fs";
import { userInfo } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { validateGuiApplication } from "./install-gui-app.mjs";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const run = promisify(execFile);
const name = "Mac Operator GUI.app";
const options = { env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" }, shell: false, timeout: 30000, maxBuffer: 16384 };

/** Intentional binary upgrade; normal installation still never replaces an existing app. */
export async function upgradeGuiApplication({ sourceApp = join(packageRoot, "dist", name),
  applicationsDirectory = join(userInfo().homedir, "Applications"),
  renameExecutable = join(packageRoot, "dist", "gui_install") } = {}) {
  if (process.platform !== "darwin") throw new Error("GUI helper upgrade requires macOS");
  const parent = await lstat(applicationsDirectory);
  if (!parent.isDirectory() || parent.uid !== process.getuid() || (parent.mode & 0o022) !== 0) {
    throw new Error("GUI application directory must be owner-controlled and not a symbolic link");
  }
  const destination = join(applicationsDirectory, name);
  await validateGuiApplication(destination);
  await validateGuiApplication(sourceApp);
  const components = ["Contents/MacOS/gui_vision", "Contents/Info.plist", "Contents/_CodeSignature/CodeResources"];
  const matches = await Promise.all(components.map(async component =>
    (await readFile(join(destination, component))).equals(await readFile(join(sourceApp, component)))));
  if (matches.every(Boolean)) return { action: "preserved", path: destination };
  const renamer = await lstat(renameExecutable);
  if (!renamer.isFile()) throw new Error("GUI atomic upgrade executable is invalid");
  await access(renameExecutable, constants.X_OK);
  const lock = join(applicationsDirectory, ".mac-operator-gui-upgrade.lock");
  await mkdir(lock, { mode: 0o700 });
  let temporary;
  let preserveStaging = false;
  try {
    temporary = await mkdtemp(join(applicationsDirectory, ".mac-operator-gui-upgrade-"));
    const staged = join(temporary, name);
    await run("/usr/bin/ditto", [sourceApp, staged], options);
    await validateGuiApplication(staged);
    await validateGuiApplication(destination);
    // A failed publisher result does not prove the atomic exchange did not
    // happen. The stage may already hold the previous signed identity.
    preserveStaging = true;
    await run(renameExecutable, ["--exchange", staged, destination], options);
    try { await validateGuiApplication(destination); }
    catch (error) {
      await run(renameExecutable, ["--exchange", staged, destination], options);
      preserveStaging = false;
      throw error;
    }
    const backup = join(temporary, "previous.app");
    await rename(staged, backup);
    // Retain the old signed bundle. Reinstalling it is an explicit rollback,
    // and a new ad-hoc identity may require owner TCC authorization once.
    return { action: "upgraded", path: destination, backup };
  } finally {
    if (temporary && !preserveStaging) await rm(temporary, { recursive: true, force: true });
    await rm(lock, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== "--upgrade") throw new Error("Explicit --upgrade required; normal deployment preserves the installed app");
    process.stdout.write(`${JSON.stringify(await upgradeGuiApplication())}\n`);
  } catch (error) {
    process.stderr.write(`GUI_HELPER_UPGRADE_FAILED: ${error instanceof Error ? error.message : "Upgrade failed"}\n`);
    process.exitCode = 1;
  }
}
