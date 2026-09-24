import assert from "node:assert/strict";
import { execFile as execFileCallback } from "node:child_process";
import { chmod, lstat, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { tmpdir, userInfo } from "node:os";
import { promisify } from "node:util";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { loadVirtualizationGuestImage } from "./virtualization-guest-image.js";

const execFile = promisify(execFileCallback);

test("guest image preflight binds protected bytes to guest identity", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-image-"));
  const imagePath = join(directory, "guest.img");
  const content = Buffer.from("guest-image-fixture\n", "utf8");
  await writeFile(imagePath, content, { mode: 0o600 });
  try {
    const digest = createHash("sha256").update(content).digest("hex");
    const result = await loadVirtualizationGuestImage({
      path: imagePath,
      expectedSha256: digest,
      runtimeVersion: "test-generic-efi-vz-1",
      maxBytes: 1024
    });
    assert.equal(result.path, await realpath(imagePath));
    assert.deepEqual(result.guestIdentity, { imageSha256: digest, runtimeVersion: "test-generic-efi-vz-1" });
    assert.equal(result.sizeBytes, content.byteLength);
    const stat = await lstat(imagePath);
    assert.equal(result.inode, String(stat.ino));
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("guest image preflight rejects digest, symlink, permission, and budget escapes", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-image-deny-"));
  const imagePath = join(directory, "guest.img");
  const linkPath = join(directory, "guest-link.img");
  await writeFile(imagePath, "guest-image-fixture\n", { mode: 0o600 });
  await symlink(imagePath, linkPath);
  try {
    const digest = createHash("sha256").update("guest-image-fixture\n", "utf8").digest("hex");
    await assert.rejects(
      () => loadVirtualizationGuestImage({ path: imagePath, expectedSha256: "0".repeat(64), runtimeVersion: "test-generic-efi-vz-1" }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    await assert.rejects(
      () => loadVirtualizationGuestImage({ path: linkPath, expectedSha256: digest, runtimeVersion: "test-generic-efi-vz-1" }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    await chmod(imagePath, 0o644);
    await assert.rejects(
      () => loadVirtualizationGuestImage({ path: imagePath, expectedSha256: digest, runtimeVersion: "test-generic-efi-vz-1" }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    await chmod(imagePath, 0o600);
    await assert.rejects(
      () => loadVirtualizationGuestImage({ path: imagePath, expectedSha256: digest, runtimeVersion: "test-generic-efi-vz-1", maxBytes: 1 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("guest image preflight rejects malformed startup configuration", async () => {
  await assert.rejects(
    () => loadVirtualizationGuestImage({ path: "relative.img", expectedSha256: "0".repeat(64), runtimeVersion: "test-generic-efi-vz-1" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  await assert.rejects(
    () => loadVirtualizationGuestImage({ path: "/tmp/guest.img", expectedSha256: "0".repeat(63), runtimeVersion: "test-generic-efi-vz-1" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  await assert.rejects(
    () => loadVirtualizationGuestImage({ path: "/tmp/guest.img", expectedSha256: "0".repeat(64), runtimeVersion: "bad version" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  await assert.rejects(
    () => loadVirtualizationGuestImage({
      path: "/tmp/guest.img",
      expectedSha256: "0".repeat(64),
      runtimeVersion: "test-generic-efi-vz-1",
      publication: "untrusted" as never
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});

test("system-published image policy rejects broker-owned fixtures", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-image-system-"));
  const imagePath = join(directory, "guest.img");
  const content = Buffer.from("guest-image-fixture\n", "utf8");
  await writeFile(imagePath, content, { mode: 0o600 });
  try {
    await assert.rejects(
      () => loadVirtualizationGuestImage({
        path: imagePath,
        expectedSha256: createHash("sha256").update(content).digest("hex"),
        runtimeVersion: "test-generic-efi-vz-1",
        publication: "system-published"
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native ACL readback detects extended ACLs on files and directories", {
  skip: process.platform !== "darwin"
}, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-guest-image-acl-"));
  const imagePath = join(directory, "guest.img");
  try {
    const native = loadNativePeerAdapter();
    await writeFile(imagePath, "guest-image-fixture\n", { mode: 0o600 });
    assert.equal(native.hasExtendedAclEntries(imagePath), false);
    assert.equal(native.hasExtendedAclEntries(directory), false);

    const aclEntry = `user:${userInfo().username} allow write`;
    await execFile("/bin/chmod", ["+a", aclEntry, imagePath], { timeout: 5_000 });
    await execFile("/bin/chmod", ["+a", aclEntry, directory], { timeout: 5_000 });

    assert.equal(native.hasExtendedAclEntries(imagePath), true);
    assert.equal(native.hasExtendedAclEntries(directory), true);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
