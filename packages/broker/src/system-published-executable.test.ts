import assert from "node:assert/strict";
import { chmod, mkdtemp, realpath, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  assertSystemPublishedExecutablePath,
  inspectSystemPublishedExecutablePath
} from "./system-published-executable.js";

test("system-published executable readiness accepts a fixed root-owned macOS binary", async (t) => {
  if (process.platform !== "darwin") {
    t.skip("System-published executable evidence is a macOS boundary");
    return;
  }
  assert.equal(inspectSystemPublishedExecutablePath("/usr/bin/printf"), true);
  await assert.doesNotReject(assertSystemPublishedExecutablePath("/usr/bin/printf"));
});

test("system-published executable boundary rejects user-owned trees and symlinks", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-system-published-executable-"));
  const root = await realpath(directory);
  const executable = join(root, "runner");
  const executableLink = join(root, "runner-link");
  try {
    await writeFile(executable, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
    assert.equal(inspectSystemPublishedExecutablePath(executable), false);
    await assert.rejects(
      assertSystemPublishedExecutablePath(executable),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
    await symlink(executable, executableLink);
    assert.equal(inspectSystemPublishedExecutablePath(executableLink), false);
    await assert.rejects(assertSystemPublishedExecutablePath(executableLink), /protected system-published/u);
    await chmod(executable, 0o722);
    await assert.rejects(assertSystemPublishedExecutablePath(executable), /protected system-published/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("system-published executable boundary rejects malformed and non-canonical paths", async () => {
  assert.equal(inspectSystemPublishedExecutablePath("relative/path"), false);
  assert.equal(inspectSystemPublishedExecutablePath("/usr/bin/../bin/printf"), false);
  await assert.rejects(
    assertSystemPublishedExecutablePath("/usr/bin/../bin/printf"),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});
