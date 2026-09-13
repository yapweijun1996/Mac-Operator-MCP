import { isAbsolute, relative, resolve, sep } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import type { ResolvedTaskProfile } from "./task-profile.js";

const MAX_PROFILE_BYTES = 128 * 1024;
const MAX_PROFILE_ARGUMENT_LENGTH = 4_096;
const PROTECTED_ROOTS = new Set(["/", "/System", "/Users", "/private"]);
const GLOBAL_SECRET_ZONES = [
  "/private/etc/passwd", "/private/etc/master.passwd", "/private/etc/group", "/private/etc/sudoers", "/private/etc/sudoers.d",
  "/private/etc/pam.d", "/private/etc/security", "/private/etc/ssh", "/private/etc/krb5.keytab", "/private/etc/ssl/private",
  "/private/var/root", "/var/root"
] as const;
const PROJECT_SECRET_DIRECTORIES = [
  ".aws", ".config", ".docker", ".gnupg", ".kube", ".ssh",
  "Library/Keychains", "Library/Application Support/Google/Chrome", "Library/Safari", "Library/Mail", "Library/Messages"
] as const;
const PROJECT_SECRET_FILES = [
  ".env", ".env.local", ".env.production", ".env.development", ".env.test", ".git-credentials", ".npmrc"
] as const;

/**
 * Render only the Broker-owned subset of Seatbelt policy. The profile is
 * intentionally deny-default and currently supports no network allowlist;
 * callers must not pass arbitrary SBPL text.
 */
export function renderTaskSandboxProfile(profile: ResolvedTaskProfile): string {
  if (profile === null || typeof profile !== "object" || Array.isArray(profile) ||
      typeof profile.sandboxProfile !== "string" || profile.sandboxProfile.length < 1 ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(profile.sandboxProfile) ||
      !isCanonicalAbsolutePath(profile.cwd) || profile.process === null || typeof profile.process !== "object" ||
      !isCanonicalAbsolutePath(profile.process.executable) ||
      !Array.isArray(profile.filesystemRoots) || profile.filesystemRoots.length < 1 ||
      profile.filesystemRoots.some((root) => !isSafeFilesystemRoot(root)) ||
      !Array.isArray(profile.networkAllowlist)) {
    throw new BrokerError("POLICY_DENIED", "Task sandbox profile is not supported by the Broker boundary");
  }
  if (profile.networkPolicy !== "none" || profile.networkAllowlist.length !== 0) {
    throw new BrokerError("NETWORK_DENIED", "Task sandbox network allowlists are not supported by this boundary");
  }

  const roots = [...new Set(profile.filesystemRoots)].sort();
  if (!roots.some((root) => isContained(root, profile.cwd))) {
    throw new BrokerError("POLICY_DENIED", "Task cwd is not inside an allowed sandbox root");
  }

  const lines = [
    "(version 1)",
    '(import "system.sb")',
    "(deny default)",
    "(allow process-fork)",
    `(allow process-exec (literal ${quote(profile.process.executable)}))`,
    `(allow file-read* (literal ${quote(profile.process.executable)}))`,
    "(allow file-read* (subpath \"/System/Library\"))",
    "(allow file-read* (subpath \"/usr/lib\"))",
    "(allow file-read* (subpath \"/usr/share\"))",
    "(allow file-read* (subpath \"/private/etc/ssl\"))",
    "(allow file-read* (literal \"/private/etc/hosts\"))",
    "(allow file-read* (literal \"/private/etc/resolv.conf\"))",
  ];
  for (const root of roots) {
    lines.push(`(allow file-read* (subpath ${quote(root)}))`);
    lines.push(`(allow file-write* (subpath ${quote(root)}))`);
  }
  for (const zone of secretZones(roots)) {
    lines.push(`(deny file-read* (subpath ${quote(zone)}))`);
    lines.push(`(deny file-write* (subpath ${quote(zone)}))`);
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

export function buildSandboxExecArguments(profile: ResolvedTaskProfile): readonly string[] {
  const sandboxProfile = renderTaskSandboxProfile(profile);
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
