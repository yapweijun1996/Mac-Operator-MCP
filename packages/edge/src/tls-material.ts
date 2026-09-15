import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { readProtectedFileAfterIdentity, sameProtectedFileMetadata } from "./protected-file.js";

const MAX_TLS_FILE_BYTES = 256 * 1024;

export interface ProtectedTlsMaterialPaths {
  certificatePath: string;
  privateKeyPath: string;
}

export interface ProtectedTlsMaterial {
  certificate: Buffer;
  privateKey: Buffer;
}

/**
 * Loads TLS material only from owner-only, regular, non-symlink files.
 *
 * The descriptor is opened with O_NOFOLLOW and checked against the path
 * identity observed before opening. The caller still owns the HTTPS server
 * lifecycle; this helper only provides bounded, protected bytes.
 */
export async function loadProtectedTlsMaterial(
  paths: ProtectedTlsMaterialPaths
): Promise<ProtectedTlsMaterial> {
  const certificate = await readProtectedTlsFile(paths.certificatePath, "TLS certificate");
  try {
    return {
      certificate,
      privateKey: await readProtectedTlsFile(paths.privateKeyPath, "TLS private key")
    };
  } catch (error) {
    certificate.fill(0);
    throw error;
  }
}

async function readProtectedTlsFile(path: string, label: string): Promise<Buffer> {
  if (typeof path !== "string" || !isAbsolute(path) || resolve(path) !== path || path.includes("\0")) {
    throw new Error(`${label} path must be canonical and absolute`);
  }
  const before = await lstat(path);
  const currentUid = process.getuid?.();
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new Error(`${label} must be a regular non-symlink file`);
  }
  if (currentUid === undefined || before.uid !== currentUid) {
    throw new Error(`${label} must be owned by the Edge user`);
  }
  if ((before.mode & 0o077) !== 0) {
    throw new Error(`${label} must not be accessible by group or other users`);
  }
  if (before.size < 1 || before.size > MAX_TLS_FILE_BYTES) {
    throw new Error(`${label} size is invalid`);
  }

  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameProtectedFileMetadata(before, opened)) {
      throw new Error(`${label} target changed while opening`);
    }
    return await readProtectedFileAfterIdentity(handle, opened, MAX_TLS_FILE_BYTES, label);
  } finally {
    await handle.close();
  }
}
