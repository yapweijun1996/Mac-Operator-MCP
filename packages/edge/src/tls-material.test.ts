import assert from "node:assert/strict";
import { chmod, mkdtemp, symlink, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { loadProtectedTlsMaterial } from "./tls-material.js";

test("protected TLS loader reads owner-only regular files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-edge-tls-"));
  const certificatePath = join(directory, "server.crt");
  const privateKeyPath = join(directory, "server.key");
  const certificate = Buffer.from("certificate-fixture\n", "utf8");
  const privateKey = Buffer.from("private-key-fixture\n", "utf8");
  try {
    await writeFile(certificatePath, certificate, { mode: 0o600 });
    await writeFile(privateKeyPath, privateKey, { mode: 0o600 });
    const loaded = await loadProtectedTlsMaterial({ certificatePath, privateKeyPath });
    assert.deepEqual(loaded, { certificate, privateKey });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("protected TLS loader rejects weak permissions and symlinked files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-edge-tls-"));
  const certificatePath = join(directory, "server.crt");
  const privateKeyPath = join(directory, "server.key");
  const linkPath = join(directory, "linked.key");
  try {
    await writeFile(certificatePath, "certificate", { mode: 0o644 });
    await writeFile(privateKeyPath, "private-key", { mode: 0o600 });
    await symlink(privateKeyPath, linkPath);
    await assert.rejects(
      loadProtectedTlsMaterial({ certificatePath, privateKeyPath }),
      /TLS certificate must not be accessible/u
    );
    await chmod(certificatePath, 0o600);
    await assert.rejects(
      loadProtectedTlsMaterial({ certificatePath, privateKeyPath: linkPath }),
      /TLS private key must be a regular non-symlink file/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("protected TLS loader rejects non-canonical and oversized inputs", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-edge-tls-"));
  const certificatePath = join(directory, "server.crt");
  const privateKeyPath = join(directory, "server.key");
  try {
    await writeFile(certificatePath, "certificate", { mode: 0o600 });
    await writeFile(privateKeyPath, Buffer.alloc(256 * 1024 + 1, 0x41), { mode: 0o600 });
    await assert.rejects(
      loadProtectedTlsMaterial({ certificatePath: `${directory}/./server.crt`, privateKeyPath }),
      /TLS certificate path must be canonical/u
    );
    await assert.rejects(
      loadProtectedTlsMaterial({ certificatePath, privateKeyPath }),
      /TLS private key size is invalid/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
