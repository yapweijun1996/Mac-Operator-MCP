import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { lstat, mkdtemp, readFile, readdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

const archiveKey = {
  keyId: "audit-export-test-1",
  loadKey: () => Buffer.from("0123456789abcdef0123456789abcdef", "ascii")
};

function appendAudit(store: BrokerStore, requestId: string, index: number): void {
  store.appendAudit({
    requestId,
    principalId: "principal-1",
    tool: "mac_health",
    eventType: "completion",
    decision: "allow",
    resultClass: "SUCCEEDED",
    targetRef: "host:broker",
    policyVersion: "policy-0.1",
    evidence: { index, token: "TOKEN=must-remain-encrypted" },
    timestampMs: index + 1
  });
}

test("BrokerStore exports an encrypted audit archive with verified chain metadata", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-audit-export-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    appendAudit(store, "audit-export-1", 1);
    appendAudit(store, "audit-export-2", 2);
    const manifest = await store.exportAuditArchive(directory, { keySource: archiveKey, nowMs: 1_700_000_000_000 });
    assert.match(manifest.path, /audit-export-1700000000000-[a-f0-9]{24}\.json\.enc$/u);
    assert.equal(manifest.auditEventCount, 2);
    assert.equal(manifest.firstSequence, 1);
    assert.equal(manifest.tailSequence, 2);
    assert.equal(manifest.encrypted, true);
    assert.equal((await lstat(manifest.path)).mode & 0o777, 0o600);
    const bytes = await readFile(manifest.path);
    assert.equal(bytes.includes(Buffer.from("TOKEN=must-remain-encrypted", "utf8")), false);
    const inspected = await BrokerStore.inspectAuditArchive(manifest.path, archiveKey);
    assert.deepEqual(inspected, manifest);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit export remains available as a retention recovery artifact without deleting the ledger", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-audit-retention-export-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"), {
    auditRetention: { maxEvents: 1, maxBytes: 16 * 1024 }
  });
  try {
    appendAudit(store, "audit-retention-1", 1);
    await assert.rejects(
      async () => { appendAudit(store, "audit-retention-2", 2); },
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    const archive = await store.exportAuditArchive(directory, { keySource: archiveKey, nowMs: 1_700_000_000_001 });
    assert.equal(archive.auditEventCount, 1);
    assert.equal(store.auditRows().length, 1);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit export fails before creating a temporary file when capacity is insufficient", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-audit-export-capacity-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  let requiredBytes = 0;
  try {
    await assert.rejects(
      store.exportAuditArchive(directory, {
        keySource: archiveKey,
        nowMs: 1_700_000_000_004,
        capacityProbe: async (_path, required) => {
          requiredBytes = required;
          return required - 1;
        }
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE" && error.retryable
    );
    assert.ok(requiredBytes > 0);
    const names = await readdir(directory);
    assert.equal(names.some((name) => name.startsWith("audit-export-") || name.startsWith(".audit-export-")), false);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit archive inspection rejects ciphertext tampering and wrong key material", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-audit-export-tamper-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    appendAudit(store, "audit-tamper-1", 1);
    const manifest = await store.exportAuditArchive(directory, { keySource: archiveKey, nowMs: 1_700_000_000_002 });
    const tampered = await readFile(manifest.path);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 0xff;
    await writeFile(manifest.path, tampered, { mode: 0o600 });
    await assert.rejects(
      BrokerStore.inspectAuditArchive(manifest.path, archiveKey),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
    await assert.rejects(
      BrokerStore.inspectAuditArchive(manifest.path, {
        keyId: archiveKey.keyId,
        loadKey: () => randomBytes(32)
      }),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("audit archive inspection rejects a symlinked archive path", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-broker-audit-export-symlink-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    appendAudit(store, "audit-symlink-1", 1);
    const manifest = await store.exportAuditArchive(directory, { keySource: archiveKey, nowMs: 1_700_000_000_003 });
    const alias = join(directory, `audit-export-1700000000004-${"a".repeat(24)}.json.enc`);
    await symlink(manifest.path, alias);
    await assert.rejects(
      BrokerStore.inspectAuditArchive(alias, archiveKey),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
