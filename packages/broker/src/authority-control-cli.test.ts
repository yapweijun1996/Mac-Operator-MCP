import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError, sha256 } from "@mac-operator/contracts";
import {
  executeAuthorityControlCliCommand,
  parseAuthorityControlCliArgs,
  runAuthorityControlCli,
  type AuthorityControlCliClient
} from "./authority-control-cli.js";
import { AuthorityControlIpcServer } from "./authority-control-ipc.js";
import { AuthorityControlKeyManager, writeAuthorityControlKeyConfig } from "./authority-control-keyring.js";
import { BrokerStore } from "./persistence.js";

const COMMON = [
  "--database", "/Users/operator/Library/Application Support/MacOperator/state/broker.sqlite",
  "--socket", "/Users/operator/Library/Application Support/MacOperator/run/authority.sock",
  "--key-config", "/Users/operator/Library/Application Support/MacOperator/config/authority-key.json"
] as const;

test("authority CLI parser exposes only bounded operator operations", () => {
  const status = parseAuthorityControlCliArgs(["status", ...COMMON]);
  assert.equal(status.kind, "status");
  if (status.kind === "status") assert.equal(status.timeoutMs, 15_000);

  const switchCommand = parseAuthorityControlCliArgs([
    "set-switch", ...COMMON,
    "--name", "process", "--disabled", "true", "--expected-disabled", "false",
    "--reason", "INCIDENT_CONTAINMENT", "--confirm", "set-switch"
  ]);
  assert.equal(switchCommand.kind, "set-switch");
  if (switchCommand.kind === "set-switch") {
    assert.equal(switchCommand.disabled, true);
    assert.equal(switchCommand.expectedDisabled, false);
  }

  assert.throws(
    () => parseAuthorityControlCliArgs(["set-switch", ...COMMON, "--name", "process", "--disabled", "true", "--expected-disabled", "false", "--reason", "INCIDENT_CONTAINMENT"]),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
  const guestKeyRevocation = parseAuthorityControlCliArgs([
    "revoke", ...COMMON,
    "--kind", "guest_attestation_key", "--subject-id", "guest-key-1", "--reason", "REVOKE_GUEST_KEY", "--confirm", "revoke"
  ]);
  assert.equal(guestKeyRevocation.kind, "revoke");
  assert.throws(
    () => parseAuthorityControlCliArgs(["revoke", ...COMMON, "--kind", "session", "--subject-id", "session-1", "--reason", "REVOKE", "--confirm", "revoke", "--key", "raw-secret"]),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
});

test("authority CLI verifies switch mutations with a readback", async () => {
  const calls: string[] = [];
  let disabled = false;
  const client: AuthorityControlCliClient = {
    async setSwitch(name, value, expected, reason) {
      calls.push(`set:${name}:${String(value)}:${String(expected)}:${reason}`);
      disabled = value;
    },
    async revoke() { throw new Error("unexpected revoke"); },
    async readSwitch(name) {
      calls.push(`read:${name}`);
      return disabled;
    },
    async readRevocation() { throw new Error("unexpected revocation read"); }
  };
  const command = parseAuthorityControlCliArgs([
    "set-switch", ...COMMON,
    "--name", "process", "--disabled", "true", "--expected-disabled", "false",
    "--reason", "INCIDENT_CONTAINMENT", "--confirm", "set-switch"
  ]);
  const result = await executeAuthorityControlCliCommand(command, client);
  assert.deepEqual(result, { schemaVersion: "0.1", operation: "set-switch", switchName: "process", disabled: true, verified: true });
  assert.deepEqual(calls, ["set:process:true:false:INCIDENT_CONTAINMENT", "read:process"]);
});

test("authority CLI refuses to publish an unconfirmed revocation and verifies confirmed revocation", async () => {
  const client: AuthorityControlCliClient = {
    async setSwitch() { throw new Error("unexpected switch"); },
    async revoke() { return undefined; },
    async readSwitch() { throw new Error("unexpected switch read"); },
    async readRevocation() { return true; }
  };
  const command = parseAuthorityControlCliArgs([
    "revoke", ...COMMON,
    "--kind", "session", "--subject-id", "session-1", "--reason", "REVOKE_SESSION", "--confirm", "revoke"
  ]);
  const result = await executeAuthorityControlCliCommand(command, client);
  assert.deepEqual(result, {
    schemaVersion: "0.1",
    operation: "revoke",
    revocationKind: "session",
    subjectId: "session-1",
    revoked: true,
    verified: true
  });
});

test("authority CLI restores the active key and completes an authenticated switch readback", async () => {
  const directory = await mkdtemp(join(tmpdir(), "acli-"));
  const databasePath = join(directory, "broker.sqlite");
  const socketPath = join(directory, "authority.sock");
  const keyPath = join(directory, "authority.key");
  const keyConfigPath = join(directory, "authority-key.json");
  const key = randomBytes(32);
  let store: BrokerStore | undefined;
  let manager: AuthorityControlKeyManager | undefined;
  let server: AuthorityControlIpcServer | undefined;
  try {
    await writeFile(keyPath, key, { mode: 0o600 });
    await chmod(keyPath, 0o600);
    store = new BrokerStore(databasePath);
    await chmod(databasePath, 0o600);
    const document = {
      schemaVersion: "0.1" as const,
      revision: 1,
      keys: [{
        keyId: "authority-cli-test",
        keySource: "file" as const,
        path: keyPath,
        keyDigest: sha256(key),
        notBeforeMs: 1_000,
        expiresAtMs: 2_000_000_000_000
      }]
    };
    await writeAuthorityControlKeyConfig(keyConfigPath, document);
    manager = new AuthorityControlKeyManager(keyConfigPath, store);
    await manager.activate();
    server = new AuthorityControlIpcServer({
      socketPath,
      store,
      authenticationKey: key,
      peerCredentialVerifier: { verify: () => undefined },
    });
    await server.listen();

    const result = await runAuthorityControlCli([
      "set-switch", "--database", databasePath, "--socket", socketPath, "--key-config", keyConfigPath,
      "--name", "process", "--disabled", "true", "--expected-disabled", "false",
      "--reason", "INTEGRATION_CONTAINMENT", "--confirm", "set-switch"
    ]);
    assert.deepEqual(result, { schemaVersion: "0.1", operation: "set-switch", switchName: "process", disabled: true, verified: true });
    assert.equal(store.isSwitchDisabled("process"), true);
  } finally {
    await server?.close();
    manager?.dispose();
    store?.close();
    key.fill(0);
    await rm(directory, { recursive: true, force: true });
  }
});
