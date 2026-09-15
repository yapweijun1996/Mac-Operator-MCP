import { constants } from "node:fs";
import { lstat, open } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";
import { sha256 } from "@mac-operator/contracts";
import { readProtectedFileAfterIdentity, sameProtectedFileMetadata } from "./protected-file.js";

const HEX_KEY_PATTERN = /^[A-Fa-f0-9]{64}$/u;

/**
 * Loads an Edge-to-Broker HMAC key from a protected file and binds the bytes
 * to the expected digest supplied by startup configuration. MCP arguments do
 * not select this source, and the returned bytes are intended to remain in
 * process memory only.
 */
export async function loadProtectedEdgeAuthenticationKey(
  path: string,
  expectedDigest: string
): Promise<Buffer> {
  if (!isAbsolute(path) || resolve(path) !== path || path.includes("\0")) {
    throw new Error("Edge authentication key path must be canonical and absolute");
  }
  if (!/^[a-f0-9]{64}$/u.test(expectedDigest)) {
    throw new Error("Expected Edge authentication key digest is malformed");
  }
  await assertProtectedKeyDirectory(dirname(path));
  const before = await lstat(path);
  const currentUid = process.getuid?.();
  if (!before.isFile() || before.isSymbolicLink()) {
    throw new Error("Edge authentication key must be a regular non-symlink file");
  }
  if (currentUid === undefined || before.uid !== currentUid) {
    throw new Error("Edge authentication key must be owned by the Edge user");
  }
  if ((before.mode & 0o077) !== 0) {
    throw new Error("Edge authentication key must not be accessible by group or other users");
  }
  if (before.size < 32 || before.size > 65) {
    throw new Error("Edge authentication key file has an invalid size");
  }

  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameProtectedFileMetadata(before, opened)) {
      throw new Error("Edge authentication key target changed while opening");
    }
    const content = await readProtectedFileAfterIdentity(handle, opened, 65, "Edge authentication key");
    try {
      const key = content.byteLength === 32
        ? Buffer.from(content)
        : parseHexKey(content.toString("ascii"));
      if (sha256(key) !== expectedDigest) {
        key.fill(0);
        throw new Error("Edge authentication key digest precondition failed");
      }
      return key;
    } finally {
      content.fill(0);
    }
  } finally {
    await handle.close();
  }
}

async function assertProtectedKeyDirectory(path: string): Promise<void> {
  const directory = await lstat(path);
  const currentUid = process.getuid?.();
  if (!directory.isDirectory() || directory.isSymbolicLink()) {
    throw new Error("Edge authentication key directory must be a non-symlink directory");
  }
  if (currentUid === undefined || directory.uid !== currentUid) {
    throw new Error("Edge authentication key directory must be owned by the Edge user");
  }
  if ((directory.mode & 0o077) !== 0) {
    throw new Error("Edge authentication key directory must not be accessible by group or other users");
  }
}

function parseHexKey(value: string): Buffer {
  const text = value.trim();
  if (!HEX_KEY_PATTERN.test(text)) {
    throw new Error("Edge authentication key must be 32 raw bytes or 64 hexadecimal characters");
  }
  return Buffer.from(text, "hex");
}
