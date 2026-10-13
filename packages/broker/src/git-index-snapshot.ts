import { randomUUID } from "node:crypto";
import { constants, closeSync, fstatSync, lstatSync, openSync, readSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { BrokerError } from "@mac-operator/contracts";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";

const MAX_INDEX_BYTES = 4 * 1024 * 1024;
const activeSnapshots = new Map<string, { project: string; assertIdentity: () => void; device: number; inode: number }>();

/** Only a live fixed-adapter snapshot may cross the process environment boundary. */
export function assertGitIndexSnapshot(path: string, project: string, executable: string): void {
  const snapshot = activeSnapshots.get(path);
  if (!snapshot || snapshot.project !== project || executable !== "/usr/bin/git") {
    throw new BrokerError("POLICY_DENIED", "Git index environment is not a live Broker-owned snapshot");
  }
  snapshot.assertIdentity();
  const stat = lstatSync(path);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.dev !== snapshot.device || stat.ino !== snapshot.inode ||
      stat.uid !== process.getuid?.() || (stat.mode & 0o077) !== 0) {
    throw new BrokerError("POLICY_DENIED", "Git index snapshot identity changed");
  }
}

/** Hold Git's ordinary index lock while committing through a private copy. */
export function captureGitIndex(gitDirectory: string, project: string, assertIdentity: () => void): { path: string; release: () => void; abandon: () => void } {
  assertIdentity();
  const lockPath = join(gitDirectory, "index.lock");
  let lock: number;
  try { lock = openSync(lockPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "EEXIST") throw new BrokerError("CONFLICT", "Git index is locked by another operation; retry after it completes");
    throw error;
  }
  const lockIdentity = fstatSync(lock);
  closeSync(lock);
  const path = join(gitDirectory, `.mac-operator-index-${randomUUID()}`);
  let created = false;
  const release = (): void => {
    activeSnapshots.delete(path);
    assertIdentity();
    if (created) {
      // Git may replace the private index or leave its lock after a terminated
      // process. These unpredictable names belong exclusively to this call.
      removeOwnedFile(gitDirectory, `${path}.lock`);
      removeOwnedFile(gitDirectory, path);
    }
    removeOwnedFile(gitDirectory, lockPath, lockIdentity);
  };
  try {
    const content = readIndex(join(gitDirectory, "index"));
    // A missing index represents no staged entries. Do not manufacture an
    // empty index file: Git interprets a zero-byte file as corruption.
    if (content === undefined) throw new BrokerError("PRECONDITION_FAILED", "Nothing is staged to commit; stage the intended paths with mac_git_stage first");
    const descriptor = openSync(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    created = true;
    try { writeFileSync(descriptor, content); } finally { closeSync(descriptor); }
    assertIdentity();
    const snapshot = lstatSync(path);
    activeSnapshots.set(path, { project, assertIdentity, device: snapshot.dev, inode: snapshot.ino });
    return { path, release, abandon: () => { activeSnapshots.delete(path); } };
  } catch (error) { release(); throw error; }
}

function readIndex(path: string): Buffer | undefined {
  let before;
  try { before = lstatSync(path); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > MAX_INDEX_BYTES) {
    throw new BrokerError("POLICY_DENIED", "Git index is not a bounded regular file");
  }
  const descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = fstatSync(descriptor);
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) {
      throw new BrokerError("CONFLICT", "Git index changed while opening its snapshot");
    }
    const buffer = Buffer.allocUnsafe(opened.size + 1);
    let length = 0;
    while (length < buffer.length) {
      const read = readSync(descriptor, buffer, length, buffer.length - length, length);
      if (read === 0) break;
      length += read;
    }
    const bytes = buffer.subarray(0, length);
    const after = fstatSync(descriptor);
    if (after.size !== bytes.length || after.size > MAX_INDEX_BYTES || opened.size !== after.size ||
        opened.mtimeMs !== after.mtimeMs || opened.ctimeMs !== after.ctimeMs) {
      throw new BrokerError("CONFLICT", "Git index changed while capturing its snapshot");
    }
    return bytes;
  } finally { closeSync(descriptor); }
}

function removeOwnedFile(root: string, path: string, expected?: { dev: number; ino: number }): void {
  let current;
  try { current = lstatSync(path); }
  catch (error) { if (!expected && (error as NodeJS.ErrnoException).code === "ENOENT") return; throw error; }
  if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1 || current.uid !== process.getuid?.() ||
      (expected && (current.dev !== expected.dev || current.ino !== expected.ino))) {
    throw new BrokerError("POLICY_DENIED", "Git snapshot cleanup identity changed; operator reconciliation is required");
  }
  const result = loadNativePeerAdapter().unlinkFileWithinRoot(root, path, true, String(current.dev), String(current.ino));
  if (!isPlainDataRecord(result) || result.removed !== true || result.path !== path || result.rootPath !== root) {
    throw new BrokerError("VERIFICATION_FAILED", "Git snapshot cleanup could not be verified");
  }
}
