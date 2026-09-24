import { lstatSync, realpathSync } from "node:fs";
import { dirname, resolve } from "node:path";

/**
 * Rejects symlinked or attacker-writable ancestors for a protected file.
 * Root-owned sticky directories such as /tmp are allowed because their sticky
 * bit prevents unrelated users from replacing another owner's file.
 */
export function hasSafeParentChain(path, ownerUid) {
  let current = dirname(resolve(path));
  while (true) {
    let stats;
    try {
      stats = lstatSync(current);
    } catch {
      return false;
    }
    if (stats.isSymbolicLink()) {
      let resolved;
      try {
        resolved = realpathSync(current);
      } catch {
        return false;
      }
      if (!isTrustedSystemAlias(current, resolved)) return false;
      current = resolved;
      stats = lstatSync(current);
    }
    if (!stats.isDirectory() ||
        (stats.uid !== ownerUid && stats.uid !== 0) ||
        ((stats.mode & 0o022) !== 0 && !(stats.uid === 0 && (stats.mode & 0o1000) !== 0))) {
      return false;
    }
    const parent = dirname(current);
    if (parent === current) return true;
    current = parent;
  }
}

function isTrustedSystemAlias(path, resolved) {
  return (path === "/var" && resolved === "/private/var") ||
    (path === "/tmp" && resolved === "/private/tmp") ||
    (path === "/etc" && resolved === "/private/etc");
}
