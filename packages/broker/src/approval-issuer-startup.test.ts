import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  ApprovalIpcClient,
  ApprovalIssuerKeyManager,
  createApprovalIssuerRuntime,
  writeApprovalIssuerKeyConfig
} from "./index.js";
import { loadAuthenticationKey, provisionAuthenticationKey } from "./credentials.js";
import { BrokerStore, type IssueApprovalInput } from "./persistence.js";

const NOW = 1_700_000_000_000;

test("approval issuer startup is disabled without reading key material", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mop-asd-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    const runtime = await createApprovalIssuerRuntime({
      store,
      startup: { enabled: false },
      now: () => NOW
    });
    assert.equal(runtime, undefined);
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("approval issuer startup restores an activated config and exposes a separate owner channel", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mop-ase-"));
  const databasePath = join(directory, "broker.sqlite");
  const keyPath = join(directory, "operator.key");
  const configPath = join(directory, "approval-keys.json");
  const socketPath = join(directory, "approval.sock");
  const store = new BrokerStore(databasePath);
  let activationManager: ApprovalIssuerKeyManager | undefined;
  let runtime: Awaited<ReturnType<typeof createApprovalIssuerRuntime>> | undefined;
  let client: ApprovalIpcClient | undefined;
  try {
    await provisionAuthenticationKey(keyPath);
    await writeApprovalIssuerKeyConfig(configPath, {
      schemaVersion: "0.1",
      revision: 1,
      keys: [{
        issuerId: "operator-1",
        keyId: "operator-key-1",
        path: keyPath,
        notBeforeMs: NOW - 1_000,
        expiresAtMs: NOW + 60_000,
        allowUnattended: false
      }]
    });
    activationManager = new ApprovalIssuerKeyManager(configPath, store, () => NOW);
    await activationManager.activate();
    activationManager.dispose();
    activationManager = undefined;

    runtime = await createApprovalIssuerRuntime({
      store,
      startup: {
        enabled: true,
        keyConfigPath: configPath,
        socketPath,
        peerCredentialVerifier: { verify: () => undefined }
      },
      now: () => NOW
    });
    assert.ok(runtime);
    await runtime.channel.listen();
    const key = await loadAuthenticationKey(keyPath);
    client = new ApprovalIpcClient({
      socketPath,
      issuerId: "operator-1",
      keyId: "operator-key-1",
      authenticationKey: key,
      now: () => NOW
    });
    const approval = ownerApproval();
    const response = await client.issue(approval);
    assert.equal(response.approval_id, approval.approvalId);
    assert.equal(store.approvalRecord(approval.approvalId)?.usedCount, 0);
  } finally {
    client?.dispose();
    await runtime?.close().catch(() => undefined);
    activationManager?.dispose();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

test("enabled approval issuer startup fails closed without an exact active key configuration", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mop-asm-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try {
    await assert.rejects(
      createApprovalIssuerRuntime({
        store,
        startup: {
          enabled: true,
          keyConfigPath: join(directory, "missing.json"),
          socketPath: join(directory, "approval.sock"),
          peerCredentialVerifier: { verify: () => undefined }
        },
        now: () => NOW
      }),
      /ENOENT|issuer key config/u
    );
  } finally {
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});

function ownerApproval(): IssueApprovalInput {
  return {
    approvalId: "approval:startup-client",
    approverPrincipalId: "operator-1",
    requestingPrincipalId: "agent-1",
    tool: "mac_user_service_control",
    contractVersion: "0.1",
    targetKind: "service",
    targetRef: "service:gui/501/com.example.agent",
    payloadDigest: "a".repeat(64),
    policyVersion: "policy-r2",
    approvalClass: "trusted_write",
    unattended: false,
    issuedAtMs: NOW,
    expiresAtMs: NOW + 30_000,
    useLimit: 1
  };
}
