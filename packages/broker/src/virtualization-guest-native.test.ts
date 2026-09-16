import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import { lstat, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import {
  inspectVirtualizationGuestConfiguration,
  loadNativeVirtualizationGuestAdapter,
  parseVirtualizationGuestConfigurationResult,
  validateNativeVirtualizationGuestAdapterPath
} from "./virtualization-guest-native.js";

const require = createRequire(import.meta.url);

test("native Virtualization.framework guest artifact performs read-only image/configuration readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-vz-native-"));
  const imagePath = join(directory, "guest.raw");
  const image = Buffer.alloc(1024 * 1024, 0);
  await writeFile(imagePath, image, { mode: 0o600 });
  try {
    const stat = await lstat(imagePath);
    const canonicalPath = await realpath(imagePath);
    const digest = createHash("sha256").update(image).digest("hex");
    const native = loadNativeVirtualizationGuestAdapter();
    assert.equal(typeof native.inspectGuestConfiguration, "function");
    assert.equal(native.nativeNodeVersion, process.versions.node);
    assert.equal(native.nativePlatform, process.platform);
    assert.equal(native.nativeArch, process.arch);
    const result = inspectVirtualizationGuestConfiguration(
      canonicalPath,
      String(stat.dev),
      String(stat.ino),
      digest
    );
    assert.equal(result.path, canonicalPath);
    assert.equal(result.device, String(stat.dev));
    assert.equal(result.inode, String(stat.ino));
    assert.equal(result.sha256, digest);
    assert.equal(result.sizeBytes, image.byteLength);
    assert.equal(result.readOnlyAttachment, true);
    assert.equal(result.vmBootAttempted, false);
    assert.equal(result.hostNetworkAttached, false);
    assert.equal(result.hostDirectorySharingAttached, false);
    assert.equal(typeof result.configurationValid, "boolean");
    validateNativeVirtualizationGuestAdapterPath(
      require.resolve("./virtualization_guest.node")
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native Virtualization.framework guest artifact rejects symlinked or mismatched identities", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-vz-native-link-"));
  const imagePath = join(directory, "guest.raw");
  const linkPath = join(directory, "guest-link.raw");
  const image = Buffer.alloc(512, 0x5a);
  await writeFile(imagePath, image, { mode: 0o600 });
  await symlink(imagePath, linkPath);
  try {
    const stat = await lstat(imagePath);
    const canonicalPath = await realpath(imagePath);
    const digest = createHash("sha256").update(image).digest("hex");
    assert.throws(
      () => inspectVirtualizationGuestConfiguration(linkPath, String(stat.dev), String(stat.ino), digest),
      /symlink|canonical/u
    );
    assert.throws(
      () => inspectVirtualizationGuestConfiguration(canonicalPath, String(stat.dev), String(stat.ino), "0".repeat(64)),
      /digest|identity/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("native Virtualization guest configuration readback rejects unstable authority fields", () => {
  const valid = {
    path: "/private/tmp/guest.raw",
    device: "1",
    inode: "2",
    sha256: "a".repeat(64),
    sizeBytes: 1_024,
    readOnlyAttachment: true,
    configurationValid: true,
    vmBootAttempted: false,
    hostNetworkAttached: false,
    hostDirectorySharingAttached: false
  };
  assert.deepEqual(parseVirtualizationGuestConfigurationResult(valid), valid);
  assert.throws(
    () => parseVirtualizationGuestConfigurationResult({ ...valid, extra: "authority" }),
    /malformed/u
  );
  const accessor = { ...valid } as Record<string, unknown>;
  Object.defineProperty(accessor, "sha256", { enumerable: true, get: () => valid.sha256 });
  assert.throws(() => parseVirtualizationGuestConfigurationResult(accessor), /malformed/u);
});
