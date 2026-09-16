import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

const PERSISTENCE_TABLES = [
  "nonces", "schema_migrations", "broker_runtime_fence",
  "approval_nonces", "policy_signer_nonces", "authority_control_nonces",
  "privileged_helper_nonces", "broker_status_nonces", "virtualization_guest_nonces",
  "keychain_delivery_nonces",
  "policy_history", "active_policy", "approval_key_config_history",
  "active_approval_key_config", "edge_key_config_history", "active_edge_key_config",
  "authority_key_config_history", "active_authority_key_config", "helper_key_config_history",
  "active_helper_key_config", "policy_signer_config_history", "active_policy_signer_config",
  "guest_attestation_key_config_history", "active_guest_attestation_key_config",
  "requests", "approvals", "jobs", "audit_events", "revocations", "switches"
] as const;

test("BrokerStore rejects unknown core authority columns during startup", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-schema-layout-"));
  const databasePath = join(directory, "broker.sqlite");
  const store = new BrokerStore(databasePath);
  store.close();
  try {
    const database = new DatabaseSync(databasePath);
    try {
      database.exec("ALTER TABLE requests ADD COLUMN unrecognized_authority_state TEXT");
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

test("BrokerStore rejects unknown columns in every persisted table", async () => {
  for (const table of PERSISTENCE_TABLES) {
    const directory = await mkdtemp(join(tmpdir(), "mac-operator-schema-layout-all-"));
    const databasePath = join(directory, "broker.sqlite");
    try {
      const store = new BrokerStore(databasePath);
      store.close();
      const database = new DatabaseSync(databasePath);
      try {
        database.exec(`ALTER TABLE ${table} ADD COLUMN unrecognized_schema_field TEXT`);
      } finally {
        database.close();
      }
      let reopened: BrokerStore | undefined;
      try {
        assert.throws(
          () => { reopened = new BrokerStore(databasePath); },
          (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE",
          `expected unknown column rejection for ${table}`
        );
      } finally {
        reopened?.close();
      }
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  }
});
