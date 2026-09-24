import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { readProductionAcceptanceRecord } from "./production-acceptance-record.mjs";

test("production acceptance record validates the exact host and referenced evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-production-acceptance-"));
  const evidenceDirectory = join(root, "evidence");
  const ownerUid = process.getuid?.() ?? -1;
  const host = { host: { platform: "darwin", arch: "arm64", ownerUid } };
  try {
    await mkdir(evidenceDirectory);
    const evidenceRefs = ["VERIFICATION.md", "review.md", "rollback.md", "keychain.md"];
    for (const ref of evidenceRefs) await writeFile(join(root, ref), "evidence\n", { mode: 0o600 });
    const now = Date.now();
    const record = {
      schemaVersion: "0.1",
      mechanism: "mac-operator-production-acceptance-v1",
      capturedAtMs: now - 1_000,
      sourceRevision: "0123456789abcdef0123456789abcdef01234567",
      host: host.host,
      productionMaterial: { keychainAclReadback: "verified", helperMaterial: "verified" },
      rollback: { rootHelperRollback: "verified", edgeBrokerRollback: "verified" },
      securityReview: { status: "passed", p0Findings: 0, p1Findings: 0, reviewRef: "review.md" },
      evidenceRefs
    };
    const recordPath = join(evidenceDirectory, "production-acceptance.json");
    await writeFile(recordPath, JSON.stringify(record), { mode: 0o600 });
    const result = await readProductionAcceptanceRecord({ repositoryRoot: root, currentHost: host, path: recordPath, now });
    assert.equal(result.valid, true);
    assert.equal(result.status, "verified");
    assert.equal(result.evidenceCount, evidenceRefs.length);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("production acceptance record rejects host drift, stale records, and symlinked evidence", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-production-acceptance-invalid-"));
  const evidenceDirectory = join(root, "evidence");
  const ownerUid = process.getuid?.() ?? -1;
  const host = { host: { platform: "darwin", arch: "arm64", ownerUid } };
  try {
    await mkdir(evidenceDirectory);
    const evidenceRefs = ["VERIFICATION.md", "review.md", "rollback.md", "keychain.md"];
    for (const ref of evidenceRefs) await writeFile(join(root, ref), "evidence\n", { mode: 0o600 });
    await symlink(join(root, "review.md"), join(root, "review-link.md"));
    const record = {
      schemaVersion: "0.1",
      mechanism: "mac-operator-production-acceptance-v1",
      capturedAtMs: Date.now() - 8 * 24 * 60 * 60 * 1_000,
      sourceRevision: "0123456789abcdef0123456789abcdef01234567",
      host: { platform: "darwin", arch: "x86_64", ownerUid },
      productionMaterial: { keychainAclReadback: "verified", helperMaterial: "verified" },
      rollback: { rootHelperRollback: "verified", edgeBrokerRollback: "verified" },
      securityReview: { status: "passed", p0Findings: 0, p1Findings: 0, reviewRef: "review-link.md" },
      evidenceRefs
    };
    const recordPath = join(evidenceDirectory, "production-acceptance.json");
    await writeFile(recordPath, JSON.stringify(record), { mode: 0o600 });
    const result = await readProductionAcceptanceRecord({ repositoryRoot: root, currentHost: host });
    assert.equal(result.valid, false);
    assert.equal(result.status, "invalid");

    record.capturedAtMs = Date.now() - 1_000;
    record.host.arch = "arm64";
    record.evidenceRefs[1] = "review-link.md";
    await writeFile(recordPath, JSON.stringify(record), { mode: 0o600 });
    const symlinkResult = await readProductionAcceptanceRecord({ repositoryRoot: root, currentHost: host });
    assert.equal(symlinkResult.valid, false);
    assert.equal(symlinkResult.status, "invalid");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("production acceptance record binds the security review reference to evidenceRefs", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-production-acceptance-review-ref-"));
  const evidenceDirectory = join(root, "evidence");
  const ownerUid = process.getuid?.() ?? -1;
  const host = { host: { platform: "darwin", arch: "arm64", ownerUid } };
  try {
    await mkdir(evidenceDirectory);
    const evidenceRefs = ["VERIFICATION.md", "rollback.md", "keychain.md", "release.md"];
    for (const ref of evidenceRefs) await writeFile(join(root, ref), "evidence\n", { mode: 0o600 });
    const record = {
      schemaVersion: "0.1",
      mechanism: "mac-operator-production-acceptance-v1",
      capturedAtMs: Date.now() - 1_000,
      sourceRevision: "0123456789abcdef0123456789abcdef01234567",
      host: host.host,
      productionMaterial: { keychainAclReadback: "verified", helperMaterial: "verified" },
      rollback: { rootHelperRollback: "verified", edgeBrokerRollback: "verified" },
      securityReview: { status: "passed", p0Findings: 0, p1Findings: 0, reviewRef: "review.md" },
      evidenceRefs
    };
    const recordPath = join(evidenceDirectory, "production-acceptance.json");
    await writeFile(recordPath, JSON.stringify(record), { mode: 0o600 });
    const result = await readProductionAcceptanceRecord({ repositoryRoot: root, currentHost: host, path: recordPath });
    assert.equal(result.valid, false);
    assert.equal(result.status, "invalid");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("production acceptance record rejects symlinked parent directories", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-production-acceptance-parent-link-"));
  const outside = await mkdtemp(join(tmpdir(), "mac-operator-production-acceptance-outside-"));
  const ownerUid = process.getuid?.() ?? -1;
  const host = { host: { platform: "darwin", arch: "arm64", ownerUid } };
  try {
    const evidenceRefs = ["VERIFICATION.md", "review.md", "rollback.md", "keychain.md"];
    for (const ref of evidenceRefs) await writeFile(join(outside, ref), "evidence\n", { mode: 0o600 });
    await symlink(outside, join(root, "evidence"));
    const record = {
      schemaVersion: "0.1",
      mechanism: "mac-operator-production-acceptance-v1",
      capturedAtMs: Date.now() - 1_000,
      sourceRevision: "0123456789abcdef0123456789abcdef01234567",
      host: host.host,
      productionMaterial: { keychainAclReadback: "verified", helperMaterial: "verified" },
      rollback: { rootHelperRollback: "verified", edgeBrokerRollback: "verified" },
      securityReview: { status: "passed", p0Findings: 0, p1Findings: 0, reviewRef: "review.md" },
      evidenceRefs
    };
    const recordPath = join(root, "evidence", "production-acceptance.json");
    await writeFile(recordPath, JSON.stringify(record), { mode: 0o600 });
    const result = await readProductionAcceptanceRecord({ repositoryRoot: root, currentHost: host, path: recordPath });
    assert.equal(result.valid, false);
    assert.equal(result.status, "invalid");
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("production acceptance record rejects evidence references through symlinked parents", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-production-acceptance-evidence-link-"));
  const outside = await mkdtemp(join(tmpdir(), "mac-operator-production-acceptance-evidence-outside-"));
  const evidenceDirectory = join(root, "evidence");
  const ownerUid = process.getuid?.() ?? -1;
  const host = { host: { platform: "darwin", arch: "arm64", ownerUid } };
  try {
    await mkdir(evidenceDirectory);
    await writeFile(join(root, "VERIFICATION.md"), "evidence\n", { mode: 0o600 });
    await writeFile(join(root, "rollback.md"), "evidence\n", { mode: 0o600 });
    await writeFile(join(root, "keychain.md"), "evidence\n", { mode: 0o600 });
    await writeFile(join(outside, "review.md"), "evidence\n", { mode: 0o600 });
    await symlink(outside, join(root, "linked-evidence"));
    const evidenceRefs = ["VERIFICATION.md", "linked-evidence/review.md", "rollback.md", "keychain.md"];
    const record = {
      schemaVersion: "0.1",
      mechanism: "mac-operator-production-acceptance-v1",
      capturedAtMs: Date.now() - 1_000,
      sourceRevision: "0123456789abcdef0123456789abcdef01234567",
      host: host.host,
      productionMaterial: { keychainAclReadback: "verified", helperMaterial: "verified" },
      rollback: { rootHelperRollback: "verified", edgeBrokerRollback: "verified" },
      securityReview: { status: "passed", p0Findings: 0, p1Findings: 0, reviewRef: "linked-evidence/review.md" },
      evidenceRefs
    };
    const recordPath = join(evidenceDirectory, "production-acceptance.json");
    await writeFile(recordPath, JSON.stringify(record), { mode: 0o600 });
    const result = await readProductionAcceptanceRecord({ repositoryRoot: root, currentHost: host, path: recordPath });
    assert.equal(result.valid, false);
    assert.equal(result.status, "invalid");
  } finally {
    await rm(root, { recursive: true, force: true });
    await rm(outside, { recursive: true, force: true });
  }
});

test("production acceptance record rejects writable parent directories", async () => {
  const root = await mkdtemp(join(tmpdir(), "mac-operator-production-acceptance-writable-parent-"));
  const evidenceDirectory = join(root, "evidence");
  const ownerUid = process.getuid?.() ?? -1;
  const host = { host: { platform: "darwin", arch: "arm64", ownerUid } };
  try {
    await mkdir(evidenceDirectory, { mode: 0o700 });
    const evidenceRefs = ["VERIFICATION.md", "review.md", "rollback.md", "keychain.md"];
    for (const ref of evidenceRefs) await writeFile(join(root, ref), "evidence\n", { mode: 0o600 });
    const record = {
      schemaVersion: "0.1",
      mechanism: "mac-operator-production-acceptance-v1",
      capturedAtMs: Date.now() - 1_000,
      sourceRevision: "0123456789abcdef0123456789abcdef01234567",
      host: host.host,
      productionMaterial: { keychainAclReadback: "verified", helperMaterial: "verified" },
      rollback: { rootHelperRollback: "verified", edgeBrokerRollback: "verified" },
      securityReview: { status: "passed", p0Findings: 0, p1Findings: 0, reviewRef: "review.md" },
      evidenceRefs
    };
    const recordPath = join(evidenceDirectory, "production-acceptance.json");
    await writeFile(recordPath, JSON.stringify(record), { mode: 0o600 });
    await chmod(evidenceDirectory, 0o777);
    const result = await readProductionAcceptanceRecord({ repositoryRoot: root, currentHost: host, path: recordPath });
    assert.equal(result.valid, false);
    assert.equal(result.status, "invalid");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
