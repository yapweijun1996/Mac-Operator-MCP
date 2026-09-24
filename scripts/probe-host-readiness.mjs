import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const ownerUid = typeof process.getuid === "function" ? process.getuid() : -1;
const launchdTargets = [
  `gui/${ownerUid}/com.mac-operator.edge`,
  `gui/${ownerUid}/com.mac-operator.broker`,
  "system/com.mac-operator.root-helper-snapshot"
];

if (process.platform !== "darwin") {
  emit({
    schemaVersion: "0.1",
    mechanism: "macos-host-readiness-v1",
    capturedAtMs: Date.now(),
    status: "unsupported-platform",
    failClosed: true,
    readyForRelease: false,
    readyForGui: false,
    persistentServiceVerified: false
  }, 2);
} else {
  const signing = readSigningIdentity();
  const gatekeeper = readGatekeeper();
  const accessibility = readAccessibility();
  const services = readLaunchdTargets();
  const readyForRelease = signing.developerIdCount > 0 && gatekeeper.enabled;
  const readyForGui = accessibility.status === "observed";
  const persistentServiceVerified = services.every((service) => service.present);
  const result = {
    schemaVersion: "0.1",
    mechanism: "macos-host-readiness-v1",
    capturedAtMs: Date.now(),
    status: readyForRelease && readyForGui && persistentServiceVerified ? "ready" : "blocked",
    failClosed: true,
    readyForRelease,
    readyForGui,
    persistentServiceVerified,
    host: { platform: process.platform, arch: process.arch, ownerUid },
    signing,
    gatekeeper,
    accessibility,
    launchd: services
  };
  emit(result, result.status === "ready" ? 0 : 1);
}

function readSigningIdentity() {
  const result = run("/usr/bin/security", ["find-identity", "-v", "-p", "codesigning"]);
  const output = `${result.stdout}\n${result.stderr}`;
  const match = output.match(/(\d+)\s+valid identities found/u);
  const validIdentityCount = match === null ? 0 : Number(match[1]);
  const developerIdCount = (output.match(/Developer ID Application:/gu) ?? []).length;
  return {
    status: result.ok ? "read" : "unavailable",
    validIdentityCount: Number.isSafeInteger(validIdentityCount) ? validIdentityCount : 0,
    developerIdCount,
    ready: result.ok && developerIdCount > 0
  };
}

function readGatekeeper() {
  const result = run("/usr/sbin/spctl", ["--status"]);
  const output = `${result.stdout}\n${result.stderr}`.trim();
  return { status: result.ok ? "read" : "unavailable", enabled: output === "assessments enabled" };
}

function readAccessibility() {
  const result = run(process.execPath, [resolve(repositoryRoot, "scripts/probe-accessibility-boundary.mjs")], {
    env: { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" }
  });
  const line = result.stdout.trim().split("\n").at(-1) ?? "";
  try {
    const value = JSON.parse(line);
    if (value === null || typeof value !== "object" || Array.isArray(value) ||
        typeof value.status !== "string" || value.failClosed !== true) throw new Error("malformed");
    return { status: value.status, failClosed: true };
  } catch {
    return { status: "probe-failed", failClosed: true };
  }
}

function readLaunchdTargets() {
  return launchdTargets.map((label) => {
    const result = run("/bin/launchctl", ["print", label]);
    return {
      label,
      status: result.error === undefined ? (result.ok ? "present" : "absent") : "unavailable",
      present: result.ok
    };
  });
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: repositoryRoot,
    env: options.env ?? { PATH: "/usr/bin:/bin:/usr/sbin:/sbin", LANG: "C" },
    encoding: "utf8",
    maxBuffer: 64 * 1024,
    timeout: 5_000,
    shell: false,
    windowsHide: true
  });
  return {
    ok: result.error === undefined && result.status === 0,
    error: result.error,
    stdout: typeof result.stdout === "string" ? result.stdout : "",
    stderr: typeof result.stderr === "string" ? result.stderr : ""
  };
}

function emit(value, exitCode) {
  process.stdout.write(`${JSON.stringify(value)}\n`);
  process.exitCode = exitCode;
}
