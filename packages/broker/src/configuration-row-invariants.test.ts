import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

interface ConfigurationLedgerCase {
  label: string;
  historyTable: string;
  activeTable: string;
  policy: boolean;
}

const cases: readonly ConfigurationLedgerCase[] = [
  { label: "policy", historyTable: "policy_history", activeTable: "active_policy", policy: true },
  { label: "approval key", historyTable: "approval_key_config_history", activeTable: "active_approval_key_config", policy: false },
  { label: "Edge key", historyTable: "edge_key_config_history", activeTable: "active_edge_key_config", policy: false },
  { label: "authority key", historyTable: "authority_key_config_history", activeTable: "active_authority_key_config", policy: false },
  { label: "helper key", historyTable: "helper_key_config_history", activeTable: "active_helper_key_config", policy: false },
  { label: "guest attestation key", historyTable: "guest_attestation_key_config_history", activeTable: "active_guest_attestation_key_config", policy: false },
  { label: "policy signer", historyTable: "policy_signer_config_history", activeTable: "active_policy_signer_config", policy: false }
];

for (const configuration of cases) {
  test(`BrokerStore refuses an active ${configuration.label} row that diverges from history`, async () => {
    const directory = await mkdtemp(join(tmpdir(), "mac-operator-config-row-"));
    const databasePath = join(directory, "broker.sqlite");
    const store = new BrokerStore(databasePath);
    store.close();
    const database = new DatabaseSync(databasePath);
    try {
      if (configuration.policy) {
        database.prepare(
          "INSERT INTO policy_history(revision, version, payload_digest, key_id, activated_at_ms) VALUES (?, ?, ?, ?, ?)"
        ).run(1, "policy-1", "a".repeat(64), "policy-key-1", 10);
        database.prepare(
          "INSERT INTO active_policy(singleton, revision, version, payload_digest, key_id, activated_at_ms) VALUES (?, ?, ?, ?, ?, ?)"
        ).run(1, 1, "policy-1", "b".repeat(64), "policy-key-1", 10);
      } else {
        database.prepare(
          `INSERT INTO ${configuration.historyTable}(revision, payload_digest, activated_at_ms) VALUES (?, ?, ?)`
        ).run(1, "a".repeat(64), 10);
        database.prepare(
          `INSERT INTO ${configuration.activeTable}(singleton, revision, payload_digest, activated_at_ms) VALUES (?, ?, ?, ?)`
        ).run(1, 1, "b".repeat(64), 10);
      }
    } finally {
      database.close();
    }
    try {
      assert.throws(
        () => new BrokerStore(databasePath),
        (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE"
      );
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
}
