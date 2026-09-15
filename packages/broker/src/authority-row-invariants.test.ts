import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

test("stored revocation rows fail closed during startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-revocation-row-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.revoke("session", "session-corrupt", "TEST", 20);
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE revocations SET revoked_at_ms = ? WHERE kind = ? AND subject_id = ?")
        .run(-1, "session", "session-corrupt");
    } finally {
      database.close();
    }
    let reopened: BrokerStore | undefined;
    try {
      assert.throws(
        () => { reopened = new BrokerStore(databasePath); },
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      reopened?.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("stored kill-switch rows fail closed during startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-switch-row-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.setSwitch("process", false, "TEST", 20);
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.prepare("UPDATE switches SET changed_at_ms = ? WHERE name = ?").run(-1, "process");
    } finally {
      database.close();
    }
    let reopened: BrokerStore | undefined;
    try {
      assert.throws(
        () => { reopened = new BrokerStore(databasePath); },
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      reopened?.close();
    }
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
