import { execFile } from "node:child_process";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

// Read-only permission checks. Run from the service's launch context when
// comparing TCC attribution; an interactive terminal has different authority.
const run = promisify(execFile);
const app = join(homedir(), "Applications", "Mac Operator GUI.app");
const executable = join(app, "Contents", "MacOS", "gui_vision");
const options = { timeout: 10_000, maxBuffer: 16_384, shell: false };

function permissionResult(text) {
  const result = JSON.parse(text);
  if (result.status !== "ok" || ![0, 1, false, true].includes(result.accessibility) ||
      typeof result.screen_recording !== "boolean") throw new Error("Invalid permission readback");
  return { accessibility: Boolean(result.accessibility), screenRecording: result.screen_recording };
}

if (process.platform !== "darwin") throw new Error("This probe requires macOS");
await run("/usr/bin/codesign", ["--verify", "--strict", app], options);
const directory = await mkdtemp(join(tmpdir(), "mac-operator-gui-launch-"));
await chmod(directory, 0o700);
try {
  const direct = await run(executable, ["permission"], options);
  const outputPath = join(directory, "stdout.json");
  const errorPath = join(directory, "stderr.txt");
  await writeFile(outputPath, "", { mode: 0o600 });
  await writeFile(errorPath, "", { mode: 0o600 });
  const launched = await run("/usr/bin/open", ["-n", "-g", "-W", "-a", app,
    "--stdout", outputPath, "--stderr", errorPath, "--args", "permission"], options);
  console.log(JSON.stringify({
    direct: permissionResult(direct.stdout),
    launchServices: permissionResult(await readFile(outputPath, "utf8")),
    launchWaitWarning: launched.stderr.includes("Unable to block on application"),
    note: "Permission preflight only; no GUI operation or permission grant was performed."
  }));
} finally {
  await rm(directory, { recursive: true, force: true });
}
