import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);
const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const scriptPath = join(repositoryRoot, "scripts/verify-macos-release.mjs");

function validManifest() {
  return {
    artifactPath: "/tmp/MacOperator.app",
    artifactSha256: "a".repeat(64),
    ownerUid: process.getuid?.() ?? -1,
    signature: {
      cdHash: "b".repeat(20),
      identifier: "com.mac-operator.broker",
      teamIdentifier: "ABCDE12345"
    }
  };
}

async function assertRejected(directory, value, message) {
  const path = join(directory, `${message.replace(/[^A-Za-z0-9]/gu, "-")}.json`);
  await writeFile(path, `${JSON.stringify(value)}\n`, { mode: 0o600 });
  await chmod(path, 0o600);
  await assert.rejects(
    execFileAsync(process.execPath, [scriptPath, "--manifest", path], { cwd: repositoryRoot, maxBuffer: 128 * 1024 }),
    (error) => {
      const output = `${error?.stderr ?? ""}\n${error?.stdout ?? ""}`;
      assert.match(output, new RegExp(message));
      return true;
    }
  );
}

test("macOS release verifier rejects malformed manifest identity before preflight", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-release-verifier-"));
  try {
    const invalidPath = validManifest();
    invalidPath.artifactPath = "/tmp/../tmp/MacOperator.app";
    await assertRejected(directory, invalidPath, "artifactPath is not canonical");

    const invalidDigest = validManifest();
    invalidDigest.artifactSha256 = "not-a-digest";
    await assertRejected(directory, invalidDigest, "identity fields are invalid");

    const invalidSignature = validManifest();
    invalidSignature.signature.cdHash = 42;
    await assertRejected(directory, invalidSignature, "signature fields are malformed");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("macOS release verifier rejects symlinked and weak manifest files", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-release-verifier-files-"));
  try {
    const target = join(directory, "target.json");
    const link = join(directory, "link.json");
    await writeFile(target, `${JSON.stringify(validManifest())}\n`, { mode: 0o600 });
    await symlink(target, link);
    await assert.rejects(
      execFileAsync(process.execPath, [scriptPath, "--manifest", link], { cwd: repositoryRoot, maxBuffer: 128 * 1024 }),
      /owner-only regular file/u
    );

    const weak = join(directory, "weak.json");
    await writeFile(weak, `${JSON.stringify(validManifest())}\n`, { mode: 0o644 });
    await chmod(weak, 0o644);
    await assert.rejects(
      execFileAsync(process.execPath, [scriptPath, "--manifest", weak], { cwd: repositoryRoot, maxBuffer: 128 * 1024 }),
      /owner-only regular file/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("macOS release verifier rejects a manifest under a writable parent", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-release-verifier-parent-"));
  try {
    const nested = join(directory, "nested");
    await mkdir(nested, { mode: 0o700 });
    const manifest = join(nested, "manifest.json");
    await writeFile(manifest, `${JSON.stringify(validManifest())}\n`, { mode: 0o600 });
    await chmod(nested, 0o777);
    await assert.rejects(
      execFileAsync(process.execPath, [scriptPath, "--manifest", manifest], { cwd: repositoryRoot, maxBuffer: 128 * 1024 }),
      /owner-only regular file/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
