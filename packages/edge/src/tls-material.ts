import { constants } from "node:fs";
import { createPrivateKey, createPublicKey, timingSafeEqual, X509Certificate } from "node:crypto";
import { lstat, open } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import { readProtectedFileAfterIdentity, sameProtectedFileMetadata } from "./protected-file.js";

const MAX_TLS_FILE_BYTES = 256 * 1024;

export interface ProtectedTlsMaterialPaths {
  certificatePath: string;
  privateKeyPath: string;
  /** Optional startup-bound hostname that the certificate must cover. */
  expectedHostname?: string;
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
    const privateKey = await readProtectedTlsFile(paths.privateKeyPath, "TLS private key");
    try {
      assertTlsCertificateMatchesPrivateKey(certificate, privateKey, paths.expectedHostname);
    } catch (error) {
      privateKey.fill(0);
      throw error;
    }
    return {
      certificate,
      privateKey
    };
  } catch (error) {
    certificate.fill(0);
    throw error;
  }
}

/**
 * Prove the pair is usable before the HTTPS listener is constructed. Node's
 * TLS server otherwise may defer this failure until the first client
 * handshake, which would publish a running Edge with invalid authority.
 */
export function assertTlsCertificateMatchesPrivateKey(
  certificateBytes: Buffer,
  privateKeyBytes: Buffer,
  expectedHostname?: string
): void {
  try {
    const certificate = new X509Certificate(certificateBytes);
    if (expectedHostname !== undefined &&
        (typeof expectedHostname !== "string" || expectedHostname.length === 0 ||
         expectedHostname !== expectedHostname.toLowerCase() || /[^a-z0-9.-]/u.test(expectedHostname) ||
         certificate.checkHost(expectedHostname) === undefined)) {
      throw new Error("TLS certificate hostname does not match");
    }
    const privateKey = createPrivateKey(privateKeyBytes);
    const certificatePublicKey = Buffer.from(certificate.publicKey.export({ format: "der", type: "spki" }));
    const privatePublicKey = Buffer.from(createPublicKey(privateKey).export({ format: "der", type: "spki" }));
    if (certificatePublicKey.byteLength !== privatePublicKey.byteLength ||
        !timingSafeEqual(certificatePublicKey, privatePublicKey)) {
      throw new Error("TLS certificate and private key do not match");
    }
  } catch (error) {
    if (error instanceof Error && (error.message === "TLS certificate and private key do not match" ||
        error.message === "TLS certificate hostname does not match")) throw error;
    throw new Error("TLS certificate and private key are invalid");
  }
}

/** Reject a leaf certificate when a startup boundary requires a CA bundle. */
export function assertTlsCertificateAuthority(certificateBytes: Buffer): void {
  try {
    if (!new X509Certificate(certificateBytes).ca) throw new Error("TLS certificate is not a certificate authority");
  } catch (error) {
    if (error instanceof Error && error.message === "TLS certificate is not a certificate authority") throw error;
    throw new Error("TLS certificate authority is invalid");
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

/** Load a protected CA bundle or certificate without treating it as a key pair. */
export async function loadProtectedTlsCertificate(path: string, label = "TLS certificate"): Promise<Buffer> {
  return await readProtectedTlsFile(path, label);
}
