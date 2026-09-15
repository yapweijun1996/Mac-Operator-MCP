import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { canonicalJson, sha256, signRequest, type UnsignedBrokerRequest } from "@mac-operator/contracts";
import { Broker } from "./broker.js";
import { createDefaultPolicy } from "./default-policy.js";
import { EdgeKeyring } from "./edge-keyring.js";
import { BrokerStore } from "./persistence.js";
import { UiSnapshotRegistry } from "./ui-inspector.js";

const NOW = 1_700_000_000_000;
const appId = "bundle:com.example.Accessible";
const elementRef = "element:0123456789abcdef0123456789abcdef0123456789abcdef";
const windowId = "window:0123456789abcdef0123456789abcdef0123456789abcdef";

function request(argumentsValue: Record<string, unknown>): UnsignedBrokerRequest {
  return {
    protocolVersion: "0.1", requestId: "ui-type-request", contractVersion: "0.1", tool: "mac_ui_type", arguments: argumentsValue,
    principal: { principalId: "principal-1", sessionId: "session-1", issuer: "test-issuer", audience: "mac-operator-broker", scopes: ["mac.ui.control"], issuedAtMs: NOW - 1_000, expiresAtMs: NOW + 60_000, edgeId: "edge-1" },
    timestampMs: NOW, nonce: "ui-type-nonce", policyAudience: "mac-operator-broker", policyVersion: "policy-0.1", authenticationKeyId: "edge-key-1"
  };
}

test("mac_ui_type binds stdin-only input to an approved owned snapshot and stores no text", async () => {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-ui-type-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  const key = randomBytes(32);
  const registry = new UiSnapshotRegistry();
  registry.recordObservation({ appId, windowId, windowIndex: 0, windowTitle: "Example", focused: true, nodes: [{ elementRef, role: "AXTextField", label: "Name", enabled: true, focused: false, secure: false }], truncated: false, warnings: [] }, "principal-1", "session-1", NOW);
  const basePolicy = createDefaultPolicy("edge-1", true, ["mac.ui.control"], ["edge-key-1"], [], [], [], [], [], [], [appId]);
  const typeTool = basePolicy.tools.get("mac_ui_type")!;
  const policy = { ...basePolicy, tools: new Map(basePolicy.tools).set("mac_ui_type", { ...typeTool, enabled: true }) };
  const broker = new Broker({
    store,
    policy,
    edgeAuthenticationKeys: new EdgeKeyring([{ edgeId: "edge-1", keyId: "edge-key-1", key, notBeforeMs: NOW - 1_000, expiresAtMs: NOW + 60_000 }]),
    uiSnapshotRegistry: registry,
    now: () => NOW,
    uiInspector: {
      async observe() { throw new Error("unused"); },
      async type(execution) {
        assert.equal(execution.text, "Alice");
        assert.deepEqual(execution.keys, ["TAB"]);
        return { elementRef, charactersAccepted: 5, keysAccepted: ["TAB"], submitted: false, focusConfirmed: true, appId, windowId, reobserved: { role: "AXTextField", focused: true, secure: false }, warnings: [], truncated: false, verified: true };
      }
    }
  });
  const argumentsValue = { element_ref: elementRef, text: "Alice", keys: ["TAB"], submit: false };
  const signed = signRequest(request(argumentsValue), key);
  try {
    store.issueApproval({ approvalId: "approval:ui-type", approverPrincipalId: "operator-1", requestingPrincipalId: "principal-1", tool: "mac_ui_type", contractVersion: "0.1", targetKind: "ui_element", targetRef: `ui_element:${elementRef}`, payloadDigest: sha256(canonicalJson(argumentsValue)), policyVersion: "policy-0.1", approvalClass: "trusted_gui", unattended: false, issuedAtMs: NOW - 1_000, expiresAtMs: NOW + 1_000 });
    const result = await broker.handle(signed);
    assert.equal(result.ok, true, JSON.stringify(result));
    if (result.ok) assert.deepEqual(result.data, { element_ref: elementRef, characters_accepted: 5, keys_accepted: ["TAB"], submitted: false, focus_confirmed: true, reobserved: { role: "AXTextField", focused: true, secure: false }, job_id: store.requestRecord("ui-type-request")?.jobId });
    const job = store.ownedJobByIdempotencyKey("ui-type:ui-type-request", "principal-1");
    assert.equal(job?.state, "completed");
    assert.equal(job?.stdout.includes("Alice"), false);
  } finally {
    await broker.close();
    store.close();
    await rm(directory, { recursive: true, force: true });
  }
});
