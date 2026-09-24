import { lstatSync, realpathSync } from "node:fs";
import { lstat, realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { BrokerError } from "@mac-operator/contracts";

const MAX_PATH_LENGTH = 4_096;

/**
 * A fixed executable published by the system volume or another root-owned
 * administrator-controlled tree. This is intentionally narrower than a
 * descriptor launcher: it is suitable for Broker-owned fixed adapters, not
 * caller-selected scripts or arbitrary task profiles.
 *
 * The target and every canonical ancestor must be root-owned, non-symlink,
 * and non-writable by group/other, with setuid/setgid disabled. That prevents
 * an unprivileged same-user process from replacing the pathname between
 * validation and pathname spawn and prevents fixed adapters from becoming
 * privilege-escalation entry points.
 */
export async function assertSystemPublishedExecutablePath(path: string): Promise<void> {
  if (!isCanonicalAbsolutePath(path)) {
    throw new BrokerError("PRECONDITION_FAILED", "System-published executable path is malformed");
  }
  if (process.platform !== "darwin") {
    throw new BrokerError("POLICY_DENIED", "System-published executable boundary requires macOS");
  }
  const currentUid = process.getuid?.();
  if (currentUid === undefined || currentUid === 0) {
    throw new BrokerError("POLICY_DENIED", "System-published executable requires an unprivileged Broker");
  }
  const target = await lstat(path).catch(() => undefined);
  if (!target || target.isSymbolicLink() || !target.isFile() || target.uid !== 0 ||
      (target.mode & 0o022) !== 0 || (target.mode & 0o6000) !== 0 ||
      (target.mode & 0o111) === 0 || (target.mode & 0o444) === 0) {
    throw new BrokerError("POLICY_DENIED", "Executable is not a protected system-published file");
  }
  if (await realpath(path).catch(() => undefined) !== path) {
    throw new BrokerError("POLICY_DENIED", "System-published executable path is not canonical");
  }
  await assertSystemPublishedAncestors(dirname(path));
}

/**
 * Synchronous startup/readiness form. It is observational only and returns
 * false for malformed, unavailable, or untrusted paths.
 */
export function inspectSystemPublishedExecutablePath(path: unknown): boolean {
  if (typeof path !== "string" || !isCanonicalAbsolutePath(path) || process.platform !== "darwin") return false;
  const currentUid = process.getuid?.();
  if (currentUid === undefined || currentUid === 0) return false;
  try {
    const target = lstatSync(path);
    if (target.isSymbolicLink() || !target.isFile() || target.uid !== 0 ||
        (target.mode & 0o022) !== 0 || (target.mode & 0o6000) !== 0 ||
        (target.mode & 0o111) === 0 || (target.mode & 0o444) === 0 ||
        realpathSync(path) !== path) return false;
    let cursor = dirname(path);
    for (;;) {
      const directory = lstatSync(cursor);
      if (directory.isSymbolicLink() || !directory.isDirectory() || directory.uid !== 0 || (directory.mode & 0o022) !== 0) return false;
      const parent = dirname(cursor);
      if (parent === cursor) break;
      cursor = parent;
    }
    return true;
  } catch {
    return false;
  }
}

function isCanonicalAbsolutePath(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_PATH_LENGTH &&
    isAbsolute(value) && resolve(value) === value && !value.includes("\0") && !value.includes("\n");
}

async function assertSystemPublishedAncestors(path: string): Promise<void> {
  let cursor = path;
  for (;;) {
    const directory = await lstat(cursor).catch(() => undefined);
    if (!directory || directory.isSymbolicLink() || !directory.isDirectory() || directory.uid !== 0 || (directory.mode & 0o022) !== 0) {
      throw new BrokerError("POLICY_DENIED", "Executable directory is not system-published");
    }
    const parent = dirname(cursor);
    if (parent === cursor) break;
    cursor = parent;
  }
}
