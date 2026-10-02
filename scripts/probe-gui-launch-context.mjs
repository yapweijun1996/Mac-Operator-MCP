import { execFile } from "node:child_process";
import { homedir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { guiLauncherExecutable } from "../packages/broker/dist/gui-process-supervisor.js";

// Read-only permission checks. Run from the service's launch context when
// comparing TCC attribution; an interactive terminal has different authority.
const run = promisify(execFile);
const app = join(homedir(), "Applications", "Mac Operator GUI.app");
const executable = join(app, "Contents", "MacOS", "gui_vision");
const options = { timeout: 15_000, maxBuffer: 16_384, shell: false };

function permissionResult(text) {
  const result = JSON.parse(text);
  if (result.status !== "ok" || ![0, 1, false, true].includes(result.accessibility) ||
      typeof result.screen_recording !== "boolean") throw new Error("Invalid permission readback");
  return { accessibility: Boolean(result.accessibility), screenRecording: result.screen_recording };
}

if (process.platform !== "darwin") throw new Error("This probe requires macOS");
await run("/usr/bin/codesign", ["--verify", "--strict", app], options);
const direct = await run(executable, ["permission"], options);
// Use the Broker's authenticated LaunchServices transport rather than open -W,
// whose process-exit race can fail even after the permission result was emitted.
const launched = await new Promise((resolve, reject) => {
  const child = execFile(guiLauncherExecutable, [], options, (error, stdout) => {
    if (error) reject(error);
    else resolve(stdout);
  });
  child.stdin.on("error", reject);
  child.stdin.end(JSON.stringify({ args: ["permission"], stdin: "" }));
});
console.log(JSON.stringify({
  direct: permissionResult(direct.stdout),
  launchServices: permissionResult(launched),
  note: "Only the LaunchServices result represents the GUI adapter permission boundary. No grant was performed."
}));
