import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { BrokerStore } from "./persistence.js";

interface ReplayCorruptionCase {
  name: string;
  insert: (database: DatabaseSync) => void;
  corrupt: (database: DatabaseSync) => void;
}

const cases: readonly ReplayCorruptionCase[] = [
  {
    name: "request",
    insert: (database) => database.prepare(
      "INSERT INTO nonces(edge_id, nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?)"
    ).run("edge-1", "nonce-1", "request-1", 1, 100),
    corrupt: (database) => database.prepare("UPDATE nonces SET expires_at_ms = accepted_at_ms").run()
  },
  {
    name: "approval issuance",
    insert: (database) => database.prepare(
      "INSERT INTO approval_nonces(issuer_id, key_id, nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?, ?)"
    ).run("issuer-1", "key-1", "approval-nonce-1", "approval-issue:1", 1, 100),
    corrupt: (database) => database.prepare("UPDATE approval_nonces SET key_id = ?").run("")
  },
  {
    name: "policy signer",
    insert: (database) => database.prepare(
      "INSERT INTO policy_signer_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
    ).run("policy-nonce-123456", "policy-request-1", 1, 100),
    corrupt: (database) => database.prepare("UPDATE policy_signer_nonces SET accepted_at_ms = ?").run(-1)
  },
  {
    name: "authority control",
    insert: (database) => database.prepare(
      "INSERT INTO authority_control_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
    ).run("authority-nonce-123456", "authority-request-1", 1, 100),
    corrupt: (database) => database.prepare("UPDATE authority_control_nonces SET request_id = ?").run("")
  },
  {
    name: "privileged helper",
    insert: (database) => database.prepare(
      "INSERT INTO privileged_helper_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
    ).run("helper-nonce-123456", "request:helper-1", 1, 100),
    corrupt: (database) => database.prepare("UPDATE privileged_helper_nonces SET expires_at_ms = ?").run(0)
  },
  {
    name: "Broker status",
    insert: (database) => database.prepare(
      "INSERT INTO broker_status_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
    ).run("broker-status-nonce-123456", "request:broker-status-123456", 1, 100),
    corrupt: (database) => database.prepare("UPDATE broker_status_nonces SET nonce = ?").run("bad")
  },
  {
    name: "virtualization guest",
    insert: (database) => database.prepare(
      "INSERT INTO virtualization_guest_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
    ).run("guest-nonce-123456", "request:guest-123456", 1, 100),
    corrupt: (database) => database.prepare("UPDATE virtualization_guest_nonces SET request_id = ?").run("bad")
  },
  {
    name: "Keychain delivery",
    insert: (database) => database.prepare(
      "INSERT INTO keychain_delivery_nonces(nonce, request_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?)"
    ).run("keychain-nonce-123456", "keychain-request-1", 1, 100),
    corrupt: (database) => database.prepare("UPDATE keychain_delivery_nonces SET nonce = ?").run("bad nonce")
  },
  {
    name: "Edge revocation",
    insert: (database) => database.prepare(
      "INSERT INTO edge_revocation_nonces(nonce, request_id, edge_id, accepted_at_ms, expires_at_ms) VALUES (?, ?, ?, ?, ?)"
    ).run("edge-revoke-nonce-123456", "edge-revoke:1234567890123456", "edge-1", 1, 100),
    corrupt: (database) => database.prepare("UPDATE edge_revocation_nonces SET edge_id = ?").run("")
  }
];

for (const corruption of cases) {
  test(`BrokerStore refuses a malformed persisted ${corruption.name} replay row`, async () => {
    const directory = await mkdtemp(join(tmpdir(), "mac-operator-replay-row-"));
    const databasePath = join(directory, "broker.sqlite");
    const store = new BrokerStore(databasePath);
    store.close();
    const database = new DatabaseSync(databasePath);
    try {
      corruption.insert(database);
      corruption.corrupt(database);
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
