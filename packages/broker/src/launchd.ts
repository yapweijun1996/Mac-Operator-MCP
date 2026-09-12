import { dirname, isAbsolute, resolve } from "node:path";

const MAX_ARGUMENT_BYTES = 4_096;
const MAX_ARGUMENT_COUNT = 64;
const MAX_ARGUMENT_TOTAL_BYTES = 64 * 1_024;

export interface LaunchdServiceConfig {
  label: string;
  program: string;
  programArguments: readonly string[];
  workingDirectory: string;
  stdoutPath: string;
  stderrPath: string;
  runAtLoad?: boolean;
  keepAlive?: boolean;
  throttleIntervalSeconds?: number;
}

export interface LaunchdServiceReadback {
  label: string;
  program: string;
  workingDirectory: string;
  stdoutPath: string;
  stderrPath: string;
  runsAsUnprivilegedUser: true;
  usesEnvironmentVariables: false;
  usesShell: false;
  runAtLoad: boolean;
  keepAlive: boolean;
  throttleIntervalSeconds: number;
}

/**
 * Validates and renders a launchd job without exposing shell or environment
 * injection surfaces. The caller must still install and code-sign the exact
 * program separately; this module never loads or installs the job.
 */
export function renderLaunchdPlist(config: LaunchdServiceConfig): string {
  const normalized = normalizeLaunchdServiceConfig(config);
  const argumentsXml = normalized.programArguments.map((argument) => `      <string>${escapeXml(argument)}</string>`).join("\n");
  return [
    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
    "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">",
    "<plist version=\"1.0\">",
    "  <dict>",
    `    <key>Label</key><string>${escapeXml(normalized.label)}</string>`,
    "    <key>ProgramArguments</key>",
    "    <array>",
    argumentsXml,
    "    </array>",
    `    <key>WorkingDirectory</key><string>${escapeXml(normalized.workingDirectory)}</string>`,
    `    <key>StandardOutPath</key><string>${escapeXml(normalized.stdoutPath)}</string>`,
    `    <key>StandardErrorPath</key><string>${escapeXml(normalized.stderrPath)}</string>`,
    `    <key>RunAtLoad</key><${normalized.runAtLoad ? "true" : "false"}/>`,
    `    <key>KeepAlive</key><${normalized.keepAlive ? "true" : "false"}/>`,
    `    <key>ThrottleInterval</key><integer>${normalized.throttleIntervalSeconds}</integer>`,
    "    <key>ProcessType</key><string>Background</string>",
    "    <key>AbandonProcessGroup</key><false/>",
    "  </dict>",
    "</plist>",
    ""
  ].join("\n");
}

export function normalizeLaunchdServiceConfig(config: LaunchdServiceConfig): Required<LaunchdServiceConfig> {
  if (config === null || typeof config !== "object") throw new Error("launchd service configuration is malformed");
  if (!/^com\.mac-operator\.[A-Za-z0-9.-]{1,96}$/u.test(config.label)) {
    throw new Error("launchd service label is invalid");
  }
  assertAbsoluteCanonicalPath(config.program, "launchd program");
  assertAbsoluteCanonicalPath(config.workingDirectory, "launchd working directory");
  assertAbsoluteCanonicalPath(config.stdoutPath, "launchd stdout path");
  assertAbsoluteCanonicalPath(config.stderrPath, "launchd stderr path");
  if (config.stdoutPath === config.stderrPath) throw new Error("launchd stdout and stderr paths must differ");
  if (!Array.isArray(config.programArguments) || config.programArguments.length < 1 || config.programArguments.length > MAX_ARGUMENT_COUNT) {
    throw new Error("launchd program arguments are invalid");
  }
  if (config.programArguments[0] !== config.program) {
    throw new Error("launchd program arguments must begin with the program path");
  }
  let totalBytes = 0;
  for (const argument of config.programArguments) {
    if (typeof argument !== "string" || argument.length === 0 || argument.includes("\0") || Buffer.byteLength(argument, "utf8") > MAX_ARGUMENT_BYTES) {
      throw new Error("launchd program arguments contain an invalid value");
    }
    totalBytes += Buffer.byteLength(argument, "utf8");
  }
  if (totalBytes > MAX_ARGUMENT_TOTAL_BYTES) throw new Error("launchd program arguments are too large");
  const runAtLoad = config.runAtLoad ?? true;
  const keepAlive = config.keepAlive ?? true;
  const throttleIntervalSeconds = config.throttleIntervalSeconds ?? 5;
  if (typeof runAtLoad !== "boolean" || typeof keepAlive !== "boolean" ||
      !Number.isSafeInteger(throttleIntervalSeconds) || throttleIntervalSeconds < 1 || throttleIntervalSeconds > 3_600) {
    throw new Error("launchd lifecycle settings are invalid");
  }
  return { ...config, runAtLoad, keepAlive, throttleIntervalSeconds };
}

export function launchdReadback(config: LaunchdServiceConfig): LaunchdServiceReadback {
  const normalized = normalizeLaunchdServiceConfig(config);
  return {
    label: normalized.label,
    program: normalized.program,
    workingDirectory: normalized.workingDirectory,
    stdoutPath: normalized.stdoutPath,
    stderrPath: normalized.stderrPath,
    runsAsUnprivilegedUser: true,
    usesEnvironmentVariables: false,
    usesShell: false,
    runAtLoad: normalized.runAtLoad,
    keepAlive: normalized.keepAlive,
    throttleIntervalSeconds: normalized.throttleIntervalSeconds
  };
}

function assertAbsoluteCanonicalPath(value: unknown, label: string): asserts value is string {
  if (typeof value !== "string" || !isAbsolute(value) || resolve(value) !== value || value.includes("\0") || dirname(value) === value && value !== "/") {
    throw new Error(`${label} must be a canonical absolute path`);
  }
}

function escapeXml(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll("\"", "&quot;").replaceAll("'", "&apos;");
}
