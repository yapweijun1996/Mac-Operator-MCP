/** Metadata required to prove that a protected descriptor did not change. */
export interface ProtectedFileMetadata {
  dev: number;
  ino: number;
  uid: number;
  gid: number;
  mode: number;
  size: number;
  mtimeMs: number;
  ctimeMs: number;
}

export interface ProtectedFileHandle {
  readFile(): Promise<Buffer>;
  stat(): Promise<ProtectedFileMetadata>;
}

/**
 * Reads through an already-open protected descriptor and performs a second
 * metadata readback. In-place writes must not be able to change the bytes
 * accepted as policy or key material during the read window.
 */
export async function readProtectedFileAfterIdentity(
  handle: ProtectedFileHandle,
  opened: ProtectedFileMetadata,
  maxBytes: number,
  label: string
): Promise<Buffer> {
  const content = await handle.readFile();
  const after = await handle.stat();
  if (!sameProtectedFileMetadata(opened, after) || content.byteLength !== after.size || content.byteLength > maxBytes) {
    content.fill(0);
    throw new Error(`${label} changed while reading`);
  }
  return content;
}

export function sameProtectedFileMetadata(left: ProtectedFileMetadata, right: ProtectedFileMetadata): boolean {
  return left.dev === right.dev && left.ino === right.ino && left.uid === right.uid && left.gid === right.gid &&
    (left.mode & 0o7777) === (right.mode & 0o7777) && left.size === right.size &&
    left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs;
}
