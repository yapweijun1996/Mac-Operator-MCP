import { constants, lstatSync } from "node:fs";
import { open } from "node:fs/promises";

/**
 * Opens and reads a protected evidence file through one descriptor. The path
 * may be checked separately for parent-chain safety; this function binds the
 * final object with O_NOFOLLOW and verifies that its identity stays stable.
 */
export async function readProtectedRegularFile(path, {
  ownerUid,
  maxBytes,
  unavailableMessage,
  invalidMessage,
  oversizedMessage
}) {
  let handle;
  try {
    handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch (error) {
    if (error?.code === "ENOENT") throw new Error(unavailableMessage);
    throw new Error(invalidMessage);
  }
  try {
    const before = await handle.stat({ bigint: true });
    const expectedOwner = BigInt(ownerUid);
    if (!before.isFile() || before.uid !== expectedOwner || (before.mode & 0o077n) !== 0n) {
      throw new ProtectedFileError(invalidMessage);
    }
    if (!samePathIdentity(path, before)) throw new ProtectedFileError(invalidMessage);
    if (before.size > BigInt(maxBytes)) throw new ProtectedFileError(oversizedMessage);

    const buffer = Buffer.alloc(Number(before.size) + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const result = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }
    const after = await handle.stat({ bigint: true });
    if (!sameFileIdentity(before, after) || !samePathIdentity(path, after) ||
        after.size > BigInt(maxBytes) ||
        bytesRead !== Number(after.size)) {
      throw new ProtectedFileError(invalidMessage);
    }
    return buffer.subarray(0, bytesRead);
  } catch (error) {
    if (error instanceof ProtectedFileError) throw error;
    throw new Error(invalidMessage);
  } finally {
    await handle.close().catch(() => {});
  }
}

function samePathIdentity(path, descriptorStats) {
  let pathStats;
  try {
    pathStats = lstatSync(path, { bigint: true });
  } catch {
    return false;
  }
  return pathStats.isFile() && !pathStats.isSymbolicLink() &&
    pathStats.dev === descriptorStats.dev && pathStats.ino === descriptorStats.ino &&
    pathStats.uid === descriptorStats.uid && pathStats.mode === descriptorStats.mode;
}

function sameFileIdentity(before, after) {
  return before.dev === after.dev && before.ino === after.ino &&
    before.uid === after.uid && before.mode === after.mode &&
    before.size === after.size && before.mtimeNs === after.mtimeNs &&
    before.ctimeNs === after.ctimeNs;
}

class ProtectedFileError extends Error {}
