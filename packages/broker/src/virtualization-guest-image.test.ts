import assert from "node:assert/strict";
import { chmod, lstat, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { loadVirtualizationGuestImage } from "./virtualization-guest-image.js";

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
      runtimeVersion: "macos-26.2-vz-1",
      maxBytes: 1024
    });
    assert.equal(result.path, await realpath(imagePath));
    assert.deepEqual(result.guestIdentity, { imageSha256: digest, runtimeVersion: "macos-26.2-vz-1" });
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
      () => loadVirtualizationGuestImage({ path: imagePath, expectedSha256: "0".repeat(64), runtimeVersion: "macos-26.2-vz-1" }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    await assert.rejects(
      () => loadVirtualizationGuestImage({ path: linkPath, expectedSha256: digest, runtimeVersion: "macos-26.2-vz-1" }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    await chmod(imagePath, 0o644);
    await assert.rejects(
      () => loadVirtualizationGuestImage({ path: imagePath, expectedSha256: digest, runtimeVersion: "macos-26.2-vz-1" }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    await chmod(imagePath, 0o600);
    await assert.rejects(
      () => loadVirtualizationGuestImage({ path: imagePath, expectedSha256: digest, runtimeVersion: "macos-26.2-vz-1", maxBytes: 1 }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("guest image preflight rejects malformed startup configuration", async () => {
  await assert.rejects(
    () => loadVirtualizationGuestImage({ path: "relative.img", expectedSha256: "0".repeat(64), runtimeVersion: "macos-26.2-vz-1" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  await assert.rejects(
    () => loadVirtualizationGuestImage({ path: "/tmp/guest.img", expectedSha256: "0".repeat(63), runtimeVersion: "macos-26.2-vz-1" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  await assert.rejects(
    () => loadVirtualizationGuestImage({ path: "/tmp/guest.img", expectedSha256: "0".repeat(64), runtimeVersion: "bad version" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});
