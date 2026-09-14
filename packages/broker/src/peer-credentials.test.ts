import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createConnection, createServer } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import {
  capturePeerProcessIdentity,
  loadNativePeerAdapter,
  MacOsPeerCredentialVerifier,
  validateNativeAdapterPath
} from "./peer-credentials.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

test("macOS peer credentials bind an accepted UDS connection to uid, gid, and pid", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-peer-"));
  const socketPath = join(directory, "peer.sock");
  const uid = process.getuid?.();
  const gid = process.getgid?.();
  if (uid === undefined || gid === undefined) throw new Error("POSIX identity is unavailable");
  const verifier = new MacOsPeerCredentialVerifier({
    expectedUid: uid,
    expectedGid: gid,
    allowedProcessIds: new Set([process.pid])
  });
  const observed = new Promise<void>((resolve, reject) => {
    const server = createServer((socket) => {
      try {
        assert.deepEqual(verifier.verify(socket), { uid, gid, pid: process.pid });
        socket.end();
        server.close((error) => error ? reject(error) : resolve());
      } catch (error) {
        reject(error);
      }
    });
    server.once("error", reject);
    server.listen(socketPath, () => createConnection(socketPath));
  });
  try {
    await observed;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("macOS peer credentials bind the accepted PID to its start-time identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-peer-identity-"));
  const socketPath = join(directory, "peer.sock");
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error("POSIX identity is unavailable");
  const identity = capturePeerProcessIdentity(process.pid);
  const verifier = new MacOsPeerCredentialVerifier({
    expectedUid: uid,
    allowedProcessIdentity: identity
  });
  const observed = new Promise<void>((resolve, reject) => {
    const server = createServer((socket) => {
      try {
        assert.deepEqual(verifier.verify(socket), { uid, gid: process.getgid?.(), pid: process.pid });
        socket.end();
        server.close((error) => error ? reject(error) : resolve());
      } catch (error) {
        reject(error);
      }
    });
    server.once("error", reject);
    server.listen(socketPath, () => createConnection(socketPath));
  });
  try {
    await observed;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("macOS peer credentials reject a PID whose start-time identity does not match", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-peer-identity-deny-"));
  const socketPath = join(directory, "peer.sock");
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error("POSIX identity is unavailable");
  const identity = capturePeerProcessIdentity(process.pid);
  const verifier = new MacOsPeerCredentialVerifier({
    expectedUid: uid,
    allowedProcessIdentity: { ...identity, startTimeMicros: identity.startTimeMicros + 1 }
  });
  const observed = new Promise<void>((resolve, reject) => {
    const server = createServer((socket) => {
      try {
        assert.throws(() => verifier.verify(socket), /process identity is not authorized/u);
        socket.end();
        server.close((error) => error ? reject(error) : resolve());
      } catch (error) {
        reject(error);
      }
    });
    server.once("error", reject);
    server.listen(socketPath, () => createConnection(socketPath));
  });
  try {
    await observed;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("macOS peer credential policy rejects an unlisted process identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-peer-deny-"));
  const socketPath = join(directory, "peer.sock");
  const uid = process.getuid?.();
  if (uid === undefined) throw new Error("POSIX identity is unavailable");
  const verifier = new MacOsPeerCredentialVerifier({
    expectedUid: uid,
    allowedProcessIds: new Set([process.pid + 1])
  });
  const observed = new Promise<void>((resolve, reject) => {
    const server = createServer((socket) => {
      try {
        assert.throws(() => verifier.verify(socket), /process is not authorized/u);
        socket.end();
        server.close((error) => error ? reject(error) : resolve());
      } catch (error) {
        reject(error);
      }
    });
    server.once("error", reject);
    server.listen(socketPath, () => createConnection(socketPath));
  });
  try {
    await observed;
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native adapter binds its compiled N-API version to the runtime", () => {
  const native = loadNativePeerAdapter();
  const runtimeNapiVersion = Number.parseInt(process.versions.napi ?? "", 10);
  assert.ok(native.nativeNapiVersion >= 8);
  assert.ok(native.nativeNapiVersion <= runtimeNapiVersion);
});

test("native adapter reproduces canonical JSON vector digests", async () => {
  const vectors = JSON.parse(await readFile(join(repositoryRoot, "schemas", "canonical-json-vectors.json"), "utf8")) as {
    vectors: readonly { name: string; canonical: string; sha256: string }[];
  };
  const native = loadNativePeerAdapter();
  for (const vector of vectors.vectors) {
    const digest = native.sha256Utf8(vector.canonical);
    assert.equal(digest, vector.sha256, vector.name);
  }
});

test("native canonical digest boundary rejects oversized input", () => {
  const native = loadNativePeerAdapter();
  assert.equal(native.sha256Utf8(""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  assert.throws(() => native.sha256Utf8("x".repeat(1_048_577)), /byte limit/u);
  assert.throws(() => native.sha256Utf8(42 as never), /must be a string/u);
});

test("native adapter path validation rejects symlinks and writable artifacts", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-native-path-"));
  const canonicalDirectory = await realpath(directory);
  const regularPath = join(canonicalDirectory, "peer_credentials.node");
  const symlinkPath = join(canonicalDirectory, "peer_credentials-link.node");
  try {
    await writeFile(regularPath, "native-placeholder", { mode: 0o600 });
    validateNativeAdapterPath(regularPath);
    await symlink(regularPath, symlinkPath);
    assert.throws(() => validateNativeAdapterPath(symlinkPath), /canonical/u);
    await chmod(regularPath, 0o622);
    assert.throws(() => validateNativeAdapterPath(regularPath), /protected/u);
    assert.throws(() => validateNativeAdapterPath(`${regularPath}/..`), /canonical/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
