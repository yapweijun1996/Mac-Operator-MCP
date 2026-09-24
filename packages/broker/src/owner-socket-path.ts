import { lstat, readlink } from "node:fs/promises";
import { dirname } from "node:path";

export type OwnerSocketParentChainErrorCode = "UNAVAILABLE" | "UNSAFE";

export class OwnerSocketParentChainError extends Error {
  readonly code: OwnerSocketParentChainErrorCode;

  constructor(code: OwnerSocketParentChainErrorCode, message: string) {
    super(message);
    this.name = "OwnerSocketParentChainError";
    this.code = code;
  }
}

/**
 * Verifies every directory traversed before an owner-only local socket.
 * Shared macOS /var and /tmp aliases are accepted only when their link target
 * is the fixed private path; all other symlinks are rejected.
 */
export async function validateOwnerSocketParentChain(socketPath: string, ownerUid: number): Promise<void> {
  let current = dirname(socketPath);
  let immediateParent = true;
  for (;;) {
    let entry;
    try {
      entry = await lstat(current);
    } catch {
      throw new OwnerSocketParentChainError("UNAVAILABLE", "owner socket parent is unavailable");
    }
    if (entry.isSymbolicLink()) {
      const fixedTarget = current === "/var" ? "/private/var" : current === "/tmp" ? "/private/tmp" : undefined;
      let target;
      try { target = await readlink(current); } catch { target = undefined; }
      if (fixedTarget === undefined || target !== fixedTarget.slice(1)) {
        throw new OwnerSocketParentChainError("UNSAFE", "owner socket parent chain is unsafe");
      }
      current = fixedTarget;
      continue;
    }
    const writableWithoutStickyProtection = (entry.mode & 0o022) !== 0 && (entry.mode & 0o1000) === 0;
    if (!entry.isDirectory() || writableWithoutStickyProtection ||
        (immediateParent && (entry.uid !== ownerUid || (entry.mode & 0o077) !== 0))) {
      throw new OwnerSocketParentChainError("UNSAFE", "owner socket parent chain is unsafe");
    }
    if (current === "/") return;
    const parent = dirname(current);
    if (parent === current) throw new OwnerSocketParentChainError("UNSAFE", "owner socket parent chain is malformed");
    current = parent;
    immediateParent = false;
  }
}

/**
 * Validates a root-owned socket directory that is traversable by one peer
 * group. The immediate parent is deliberately owner:peer-group 0710 so the
 * peer can reach a single socket without listing sibling names.
 */
export async function validateGroupSocketParentChain(
  socketPath: string,
  ownerUid: number,
  peerUid: number,
  peerGid: number
): Promise<void> {
  if (!Number.isSafeInteger(ownerUid) || ownerUid < 0 || ownerUid > 2_147_483_647 ||
      !Number.isSafeInteger(peerUid) || peerUid < 1 || peerUid > 2_147_483_647 ||
      !Number.isSafeInteger(peerGid) || peerGid < 0 || peerGid > 2_147_483_647) {
    throw new OwnerSocketParentChainError("UNSAFE", "group socket peer identity is invalid");
  }
  let current = dirname(socketPath);
  let immediateParent = true;
  for (;;) {
    let entry;
    try {
      entry = await lstat(current);
    } catch {
      throw new OwnerSocketParentChainError("UNAVAILABLE", "group socket parent is unavailable");
    }
    if (entry.isSymbolicLink()) {
      const fixedTarget = current === "/var" ? "/private/var" : current === "/tmp" ? "/private/tmp" : undefined;
      let target;
      try { target = await readlink(current); } catch { target = undefined; }
      if (fixedTarget === undefined || target !== fixedTarget.slice(1)) {
        throw new OwnerSocketParentChainError("UNSAFE", "group socket parent chain is unsafe");
      }
      current = fixedTarget;
      continue;
    }
    const writableWithoutStickyProtection = (entry.mode & 0o022) !== 0 && (entry.mode & 0o1000) === 0;
    if (!entry.isDirectory() || writableWithoutStickyProtection) {
      throw new OwnerSocketParentChainError("UNSAFE", "group socket parent chain is unsafe");
    }
    if (immediateParent) {
      if (entry.uid !== ownerUid || entry.gid !== peerGid || (entry.mode & 0o777) !== 0o710) {
        throw new OwnerSocketParentChainError("UNSAFE", "group socket parent permissions do not match the peer boundary");
      }
    } else {
      const peerExecuteBit = entry.uid === peerUid ? 0o100 : entry.gid === peerGid ? 0o010 : 0o001;
      if ((entry.mode & peerExecuteBit) === 0) {
        throw new OwnerSocketParentChainError("UNSAFE", "group socket parent is not traversable by the peer");
      }
    }
    if (current === "/") return;
    const parent = dirname(current);
    if (parent === current) throw new OwnerSocketParentChainError("UNSAFE", "group socket parent chain is malformed");
    current = parent;
    immediateParent = false;
  }
}

/**
 * Validates a root-owned socket directory exposed to one user through a
 * socket-only extended ACL. When supplied, the ACL reader must run in a
 * context that can inspect every ancestor; the immediate parent is root:root
 * 0711 in either case.
 */
export async function validateUserAclSocketParentChain(
  socketPath: string,
  ownerUid: number,
  ownerGid: number,
  peerUid: number,
  peerGid: number,
  hasExtendedAclEntries?: (path: string) => boolean
): Promise<void> {
  if (!Number.isSafeInteger(ownerUid) || ownerUid < 0 || ownerUid > 2_147_483_647 ||
      !Number.isSafeInteger(ownerGid) || ownerGid < 0 || ownerGid > 2_147_483_647 ||
      !Number.isSafeInteger(peerUid) || peerUid < 1 || peerUid > 2_147_483_647 ||
      !Number.isSafeInteger(peerGid) || peerGid < 0 || peerGid > 2_147_483_647 ||
      (hasExtendedAclEntries !== undefined && typeof hasExtendedAclEntries !== "function")) {
    throw new OwnerSocketParentChainError("UNSAFE", "user ACL socket identity is invalid");
  }
  let current = dirname(socketPath);
  let immediateParent = true;
  for (;;) {
    let entry;
    try {
      entry = await lstat(current);
    } catch {
      throw new OwnerSocketParentChainError("UNAVAILABLE", "user ACL socket parent is unavailable");
    }
    if (entry.isSymbolicLink()) {
      const fixedTarget = current === "/var" ? "/private/var" : current === "/tmp" ? "/private/tmp" : undefined;
      let target;
      try { target = await readlink(current); } catch { target = undefined; }
      if (fixedTarget === undefined || target !== fixedTarget.slice(1)) {
        throw new OwnerSocketParentChainError("UNSAFE", "user ACL socket parent chain is unsafe");
      }
      current = fixedTarget;
      continue;
    }
    if (hasExtendedAclEntries !== undefined) {
      try {
        if (hasExtendedAclEntries(current) !== false) {
          throw new OwnerSocketParentChainError("UNSAFE", "user ACL socket parent has an extended ACL");
        }
      } catch (error) {
        if (error instanceof OwnerSocketParentChainError) throw error;
        throw new OwnerSocketParentChainError("UNAVAILABLE", "user ACL socket parent ACL is unavailable");
      }
    }
    const writableWithoutStickyProtection = (entry.mode & 0o022) !== 0 && (entry.mode & 0o1000) === 0;
    if (!entry.isDirectory() || writableWithoutStickyProtection) {
      throw new OwnerSocketParentChainError("UNSAFE", "user ACL socket parent chain is unsafe");
    }
    if (immediateParent) {
      if (entry.uid !== ownerUid || entry.gid !== ownerGid || (entry.mode & 0o777) !== 0o711) {
        throw new OwnerSocketParentChainError("UNSAFE", "user ACL socket directory is not root:root 0711");
      }
    } else {
      const peerExecuteBit = entry.uid === peerUid ? 0o100 : entry.gid === peerGid ? 0o010 : 0o001;
      if ((entry.mode & peerExecuteBit) === 0) {
        throw new OwnerSocketParentChainError("UNSAFE", "user ACL socket parent is not traversable by the peer");
      }
    }
    if (current === "/") return;
    const parent = dirname(current);
    if (parent === current) throw new OwnerSocketParentChainError("UNSAFE", "user ACL socket parent chain is malformed");
    current = parent;
    immediateParent = false;
  }
}
