import assert from "node:assert/strict";
import { chmod, lstat, mkdir, mkdtemp, readFile, realpath, rm, symlink, writeFile } from "node:fs/promises";
import test, { after } from "node:test";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  macOsDeploymentJournalPath,
  readMacOsDeploymentJournal,
  writeMacOsDeploymentJournal,
  type MacOsDeploymentJournalRecord
} from "./macos-deployment-journal.js";

// Shared OS temporary directories can violate the journal's ancestor permissions.
const fixtureAncestor = await realpath(fileURLToPath(new URL(".", import.meta.url)));
assert.equal((await lstat(fixtureAncestor)).uid, process.getuid?.());
const tempRoot = await mkdtemp(join(fixtureAncestor, "mac-operator-journal-tests-"));
after(async () => {
  await rm(tempRoot, { recursive: true, force: true });
});

function record(overrides: Partial<MacOsDeploymentJournalRecord> = {}): MacOsDeploymentJournalRecord {
  return {
    schemaVersion: "0.1",
    mechanism: "macos-launchagent-deployment-journal-v1",
    transactionId: "tx-20260923-1",
    operation: "install",
    order: ["edge", "broker"],
    completedComponents: [],
    phase: "in-progress",
    sourceDigest: "a".repeat(64),
    updatedAtMs: 1_759_000_000_000,
    failedComponent: null,
    ...overrides
  };
}

test("deployment journal atomically publishes and reads an owner-only record", async () => {
  const directory = await mkdtemp(join(tempRoot, "mac-operator-journal-"));
  try {
    await chmod(directory, 0o700);
    const path = macOsDeploymentJournalPath(directory);
    const current = record({ phase: "applied", completedComponents: ["edge", "broker"] });
    await writeMacOsDeploymentJournal(path, current);
    assert.deepEqual(await readMacOsDeploymentJournal(path), current);
    assert.equal((await lstat(path)).mode & 0o7777, 0o600);
    assert.match(await readFile(path, "utf8"), /macos-launchagent-deployment-journal-v1/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("deployment journal rejects unsafe parent directories and symlink targets", async () => {
  const directory = await mkdtemp(join(tempRoot, "mac-operator-journal-unsafe-"));
  try {
    const path = macOsDeploymentJournalPath(directory);
    await chmod(directory, 0o755);
    await assert.rejects(writeMacOsDeploymentJournal(path, record()), /owner-only/u);
    await chmod(directory, 0o700);
    const target = join(directory, "target");
    await writeFile(target, "outside\n", { mode: 0o600 });
    await symlink(target, path);
    await assert.rejects(readMacOsDeploymentJournal(path), /regular file/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("deployment journal rejects unsupported fields, malformed order, and incomplete applied state", async () => {
  const directory = await mkdtemp(join(tempRoot, "mac-operator-journal-invalid-"));
  try {
    await chmod(directory, 0o700);
    const path = macOsDeploymentJournalPath(directory);
    await writeFile(path, JSON.stringify({ ...record(), unexpected: true }), { mode: 0o600 });
    await assert.rejects(readMacOsDeploymentJournal(path), /unsupported or missing/u);
    await writeFile(path, JSON.stringify(record({ order: ["edge", "edge"] })), { mode: 0o600 });
    await assert.rejects(readMacOsDeploymentJournal(path), /component order/u);
    await writeFile(path, JSON.stringify(record({ phase: "applied" })), { mode: 0o600 });
    await assert.rejects(readMacOsDeploymentJournal(path), /all completed/u);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("deployment journal rejects a symlinked ancestor even when the direct parent is a regular directory", async () => {
  const directory = await mkdtemp(join(tempRoot, "mac-operator-journal-ancestor-"));
  const outside = await mkdtemp(join(tempRoot, "mac-operator-journal-outside-"));
  try {
    const link = join(directory, "linked-root");
    await symlink(outside, link);
    const installRoot = join(link, "package");
    await mkdir(installRoot, { mode: 0o700 });
    await assert.rejects(
      writeMacOsDeploymentJournal(macOsDeploymentJournalPath(installRoot), record()),
      /unsafe directory chain/u
    );
  } finally {
    await rm(directory, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});
