import { mkdtemp, mkdir, writeFile, rm, stat } from "node:fs/promises";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { homedir, tmpdir } from "node:os";
import { spawn } from "node:child_process";
import { createServer } from "node:net";

const MAX_CHILD_OUTPUT_BYTES = 64 * 1024;
const CHILD_TIMEOUT_MS = 15_000;

const bundle = join(process.cwd(), "packages/broker/dist/AppSandboxProbe.app");
const executable = join(bundle, "Contents/MacOS/app_sandbox_probe");
const root = await mkdtemp(join(tmpdir(), "mac-operator-app-sandbox-"));
const containerRoot = join(process.env.HOME ?? root, "Library/Containers/com.macoperator.mopsandboxprobe/Data");
const allowedRoot = join(containerRoot, "probe");
const allowedPath = join(allowedRoot, "allowed.txt");
const deniedRoot = join(root, "denied");
const deniedPath = join(deniedRoot, "denied.txt");
const deniedReadPath = join(root, "read-me.txt");
const childDeniedPath = join(root, "child-denied.txt");
const persistencePath = join(homedir(), "Library/LaunchAgents", `com.macoperator.mop-probe-${process.pid}.plist`);
const credentialZonePath = join(homedir(), ".ssh");

await rm(allowedRoot, { recursive: true, force: true });
await rm(deniedRoot, { recursive: true, force: true });
await rm(deniedReadPath, { force: true });
await rm(childDeniedPath, { force: true });
await rm(persistencePath, { force: true });
await mkdir(allowedRoot, { recursive: true, mode: 0o700 });
await writeFile(deniedReadPath, "outside-app-container\n", { mode: 0o600 });
await stat(join(homedir(), "Library/LaunchAgents"));
await stat(credentialZonePath);

const networkServer = createServer((socket) => socket.destroy());
await new Promise((resolve, reject) => {
  networkServer.once("error", reject);
  networkServer.listen(0, "127.0.0.1", resolve);
});
const networkAddress = networkServer.address();
if (networkAddress === null || typeof networkAddress === "string") throw new Error("Loopback probe server did not expose a port");

const result = await new Promise((resolve, reject) => {
  let settled = false;
  let timedOut = false;
  let outputOverflow = false;
  let timer;
  const child = spawn(executable, [
    "--read", deniedReadPath,
    "--write", allowedPath,
    "--child-write", childDeniedPath,
    "--connect-host", "127.0.0.1",
    "--connect-port", String(networkAddress.port),
    "--persistence", persistencePath,
    "--credential-zone", credentialZonePath
  ], {
    cwd: root,
    env: {},
    shell: false,
    stdio: ["ignore", "pipe", "pipe"]
  });
  let stdout = "";
  let stderr = "";
  const finish = (value) => {
    if (settled) return;
    settled = true;
    if (timer !== undefined) clearTimeout(timer);
    resolve({ ...value, stdout, stderr, timedOut, outputOverflow });
  };
  const append = (current, chunk) => {
    const next = `${current}${chunk}`;
    if (Buffer.byteLength(next, "utf8") > MAX_CHILD_OUTPUT_BYTES) {
      outputOverflow = true;
      try { child.kill("SIGKILL"); } catch { /* child may already be closed */ }
      return next.slice(0, MAX_CHILD_OUTPUT_BYTES);
    }
    return next;
  };
  child.stdout.setEncoding("utf8");
  child.stderr.setEncoding("utf8");
  child.stdout.on("data", (chunk) => { stdout = append(stdout, chunk); });
  child.stderr.on("data", (chunk) => { stderr = append(stderr, chunk); });
  child.once("error", () => finish({ code: null, signal: null }));
  child.once("exit", (code, signal) => finish({ code, signal }));
  timer = setTimeout(() => {
    timedOut = true;
    try { child.kill("SIGKILL"); } catch { /* child may already be closed */ }
  }, CHILD_TIMEOUT_MS);
});

let allowedStats = null;
try {
  allowedStats = await stat(allowedPath);
} catch {
  allowedStats = null;
}
let childStats = null;
try {
  childStats = await stat(childDeniedPath);
} catch {
  childStats = null;
}

const nativeOperations = result.stdout.trim().split("\n").filter(Boolean).map((line) => JSON.parse(line));
const operation = (name) => nativeOperations.find((entry) => entry.operation === name);

const output = {
  schema_version: "0.1",
  probe: "macos-app-sandbox-boundary",
  bundle_identifier: "com.macoperator.mopsandboxprobe",
  app_sandbox_entitlement: true,
  launch: {
    code: result.code,
    signal: result.signal,
    stderr: result.stderr.slice(0, 512),
    outputBounded: !result.outputOverflow,
    timeoutBounded: !result.timedOut
  },
  stdout: nativeOperations,
  allowed_container_write: allowedStats !== null,
  child_outside_container_write: childStats !== null,
  outside_container_read_fixture: result.stdout.includes('"operation":"read"') && result.stdout.includes('"allowed":false'),
  network_connect_denied: operation("network-connect")?.allowed === false,
  persistence_write_denied: operation("persistence-write")?.allowed === false && !existsSync(persistencePath),
  credential_zone_denied: operation("credential-zone-open")?.allowed === false,
  production_enablement: "disabled"
};
console.log(JSON.stringify(output, null, 2));
networkServer.close();
await rm(root, { recursive: true, force: true });
// The OS owns the App Sandbox container metadata and standard directories.
// Remove only the probe-created file; do not delete the container itself.
await rm(allowedPath, { force: true });
await rm(persistencePath, { force: true });

if (result.code !== 0 || result.timedOut || result.outputOverflow ||
    !output.allowed_container_write || output.child_outside_container_write ||
    !output.outside_container_read_fixture || !output.network_connect_denied ||
    !output.persistence_write_denied || !output.credential_zone_denied) {
  process.exitCode = 1;
}
