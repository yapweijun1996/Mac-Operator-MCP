import { isAbsolute, relative, resolve, sep } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { parseTaskNetworkDestination, type ResolvedTaskProfile } from "./task-profile.js";

const MAX_PROFILE_BYTES = 128 * 1024;
// Keep the serialized SBPL argument bounded while leaving room for the fixed
// secret-zone deny set and a bounded multi-root task profile.
const MAX_PROFILE_ARGUMENT_LENGTH = 8_192;
const PROTECTED_ROOTS = new Set(["/", "/System", "/Users", "/private"]);
const GLOBAL_SECRET_ZONES = [
  "/private/etc/passwd", "/private/etc/master.passwd", "/private/etc/group", "/private/etc/sudoers", "/private/etc/sudoers.d",
  "/private/etc/pam.d", "/private/etc/security", "/private/etc/ssh", "/private/etc/krb5.keytab", "/private/etc/ssl/private",
  "/private/var/root", "/var/root"
] as const;
const GLOBAL_SECRET_ZONE_PATTERNS = [
  "^/(?:private/)?Library/Application Support/com\\.apple\\.TCC(?:/|$)",
  "^/(?:private/)?var/db/(?:TCC|dslocal|ConfigurationProfiles|keychains|authd|lockdown)(?:/|$)"
] as const;
const DOCKER_SOCKET_PATHS = ["/var/run/docker.sock", "/private/var/run/docker.sock"] as const;
const PROJECT_SECRET_DIRECTORIES = [
  ".aws", ".codex", ".config", ".docker", ".gnupg", ".kube", ".openai", ".ssh",
  "Library/Keychains", "Library/Application Support/Google/Chrome", "Library/Application Support/com.apple.TCC",
  "Library/Application Support/com.apple.tcc", "Library/Safari", "Library/Mail", "Library/Messages"
] as const;
const PROJECT_SECRET_FILES = [
  ".env", ".env.local", ".env.production", ".env.development", ".env.test", ".git-credentials", ".npmrc"
] as const;

export interface TaskSandboxProfileOptions {
  /** Broker-owned roots that must remain inaccessible even when task roots overlap them. */
  protectedFilesystemRoots?: readonly string[];
}

export function normalizeTaskSandboxProfileOptions(options: TaskSandboxProfileOptions = {}): TaskSandboxProfileOptions {
  if (options === null || typeof options !== "object" || Array.isArray(options)) {
    throw new BrokerError("POLICY_DENIED", "Sandbox profile options are malformed");
  }
  return { protectedFilesystemRoots: normalizeProtectedFilesystemRoots(options.protectedFilesystemRoots) };
}

/**
 * Render only the Broker-owned subset of Seatbelt policy. The profile is
 * intentionally deny-default and supports only loopback network destinations;
 * callers must not pass arbitrary SBPL text.
 */
export function renderTaskSandboxProfile(profile: ResolvedTaskProfile, options: TaskSandboxProfileOptions = {}): string {
  if (profile === null || typeof profile !== "object" || Array.isArray(profile) ||
      typeof profile.sandboxProfile !== "string" || profile.sandboxProfile.length < 1 ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(profile.sandboxProfile) ||
      !isCanonicalAbsolutePath(profile.cwd) || profile.process === null || typeof profile.process !== "object" ||
      !isCanonicalAbsolutePath(profile.process.executable) ||
      !Array.isArray(profile.filesystemRoots) || profile.filesystemRoots.length < 1 ||
      profile.filesystemRoots.some((root) => !isSafeFilesystemRoot(root)) ||
      !Array.isArray(profile.networkAllowlist) ||
      (profile.credentialPolicy !== undefined && profile.credentialPolicy !== "none") ||
      (profile.networkPolicy !== "none" && profile.networkPolicy !== "allowlist")) {
    throw new BrokerError("POLICY_DENIED", "Task sandbox profile is not supported by the Broker boundary");
  }
  if (profile.networkPolicy === "none" && profile.networkAllowlist.length !== 0) {
    throw new BrokerError("NETWORK_DENIED", "No-network task cannot declare destinations");
  }
  if ((profile.credentialPolicy ?? "none") !== "none") {
    throw new BrokerError("POLICY_DENIED", "Task credential policy is not supported by the Broker boundary");
  }
  const networkDestinations = profile.networkPolicy === "allowlist"
    ? profile.networkAllowlist.map(parseTaskNetworkDestination)
    : [];
  if (profile.networkPolicy === "allowlist" && (networkDestinations.length === 0 || networkDestinations.some((destination) => destination === null))) {
    throw new BrokerError("NETWORK_DENIED", "Task sandbox network allowlist requires loopback destinations");
  }
  const processTreePolicy = profile.processTreePolicy ?? "single_process";
  if (processTreePolicy !== "single_process" && processTreePolicy !== "owned_group") {
    throw new BrokerError("POLICY_DENIED", "Task process-tree policy is not supported by the Broker boundary");
  }

  const roots = [...new Set(profile.filesystemRoots)].sort();
  if (!roots.some((root) => isContained(root, profile.cwd))) {
    throw new BrokerError("POLICY_DENIED", "Task cwd is not inside an allowed sandbox root");
  }
  const protectedRoots = normalizeTaskSandboxProfileOptions(options).protectedFilesystemRoots ?? [];

  const lines = [
    "(version 1)",
    '(import "system.sb")',
    "(deny default)",
    `(allow process-exec (literal ${quote(profile.process.executable)}))`,
    `(allow file-read* (literal ${quote(profile.process.executable)}))`,
    "(allow file-read* (subpath \"/System/Library\"))",
    "(allow file-read* (subpath \"/usr/lib\"))",
    "(allow file-read* (subpath \"/usr/share\"))",
    "(allow file-read* (subpath \"/private/etc/ssl\"))",
    "(allow file-read* (literal \"/private/etc/hosts\"))",
    "(allow file-read* (literal \"/private/etc/resolv.conf\"))",
  ];
  if (processTreePolicy === "owned_group") lines.splice(3, 0, "(allow process-fork)");
  for (const destination of networkDestinations) {
    if (destination !== null) lines.push(`(allow network-outbound (remote ${destination.protocol} \"${destination.address}:${destination.port}\"))`);
  }
  for (const root of roots) {
    lines.push(`(allow file-read* (subpath ${quote(root)}))`);
    lines.push(`(allow file-write* (subpath ${quote(root)}))`);
  }
  for (const root of protectedRoots) {
    lines.push(`(deny file-read* (subpath ${quote(root)}))`);
    lines.push(`(deny file-write* (subpath ${quote(root)}))`);
  }
  for (const zone of secretZones(roots)) {
    lines.push(`(deny file-read* (subpath ${quote(zone)}))`);
    lines.push(`(deny file-write* (subpath ${quote(zone)}))`);
  }
  for (const pattern of GLOBAL_SECRET_ZONE_PATTERNS) {
    lines.push(`(deny file-read* (regex #"${pattern}"))`);
    lines.push(`(deny file-write* (regex #"${pattern}"))`);
  }
  for (const socketPath of DOCKER_SOCKET_PATHS) {
    lines.push(`(deny file-read* (literal ${quote(socketPath)}))`);
    lines.push(`(deny file-write* (literal ${quote(socketPath)}))`);
  }
  for (const base of secretRegexBases(roots)) {
    const names = [...PROJECT_SECRET_DIRECTORIES, ...PROJECT_SECRET_FILES].map(escapeRegex).join("|");
    const pattern = `^${escapeRegex(base)}\\/.*(${names})(\\/|$)`;
    lines.push(`(deny file-read* (regex #"${pattern}"))`);
    lines.push(`(deny file-write* (regex #"${pattern}"))`);
  }
  const rendered = `${lines.join("\n")}\n`;
  if (rendered.length > MAX_PROFILE_ARGUMENT_LENGTH || Buffer.byteLength(rendered, "utf8") > MAX_PROFILE_BYTES) {
    throw new BrokerError("OUTPUT_LIMIT", "Task sandbox profile exceeds the supported size");
  }
  return rendered;
}

export function buildSandboxExecArguments(profile: ResolvedTaskProfile, options: TaskSandboxProfileOptions = {}): readonly string[] {
  const sandboxProfile = renderTaskSandboxProfile(profile, options);
  return ["-p", sandboxProfile, profile.process.executable, ...profile.process.args];
}

function quote(value: string): string {
  if (!isCanonicalAbsolutePath(value)) throw new BrokerError("PATH_DENIED", "Sandbox path is not canonical");
  return `"${value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")}"`;
}

function isCanonicalAbsolutePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 4_096 &&
    isAbsolute(value) && resolve(value) === value && !value.includes("\0") && !value.includes("\n");
}

function isSafeFilesystemRoot(value: unknown): value is string {
  return isCanonicalAbsolutePath(value) && !PROTECTED_ROOTS.has(value);
}

function normalizeProtectedFilesystemRoots(value: readonly string[] | undefined): readonly string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 32 || value.some((root) => !isCanonicalAbsolutePath(root))) {
    throw new BrokerError("POLICY_DENIED", "Protected sandbox roots are malformed");
  }
  return [...new Set(value)].sort();
}

function secretZones(roots: readonly string[]): readonly string[] {
  const zones = new Set<string>(GLOBAL_SECRET_ZONES);
  return [...zones].sort();
}

function secretRegexBases(roots: readonly string[]): readonly string[] {
  const bases = new Set<string>(roots);
  for (const root of roots) {
    const match = /^\/Users\/([^/]+)(?:\/|$)/u.exec(root);
    if (match) bases.add(`/Users/${match[1]}`);
  }
  return [...bases].sort();
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&").replaceAll('"', '\\"');
}

function isContained(root: string, target: string): boolean {
  const child = relative(root, target);
  return child === "" || (!child.startsWith(`..${sep}`) && child !== ".." && !isAbsolute(child));
}
