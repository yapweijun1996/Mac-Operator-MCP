import assert from "node:assert/strict";
import test from "node:test";
import type { AuthInfo } from "@modelcontextprotocol/server";
import { projectPrincipal } from "./principal.js";

const resourceServerUrl = new URL("https://edge.example.test/mcp");

test("verified token projection keeps only governed identity data and known scopes", () => {
  const auth: AuthInfo = {
    token: "must-not-cross-the-edge",
    clientId: "client-1",
    scopes: ["mac.control.read", "unknown.scope"],
    expiresAt: 1_700_000_060,
    resource: resourceServerUrl,
    extra: {
      principalId: "principal-1",
      issuer: "issuer-1",
      sessionId: "session-1",
      issuedAtMs: 1_700_000_000_000
    }
  };
  const principal = projectPrincipal(auth, {
    edgeId: "edge-1",
    brokerAudience: "mac-operator-broker",
    resourceServerUrl
  });
  assert.deepEqual(principal.scopes, ["mac.control.read"]);
  assert.equal(principal.expiresAtMs, 1_700_000_060_000);
  assert.equal(JSON.stringify(principal).includes(auth.token), false);
});

test("verified token projection rejects the wrong resource audience", () => {
  const auth: AuthInfo = {
    token: "secret",
    clientId: "client-1",
    scopes: ["mac.control.read"],
    expiresAt: 1_700_000_060,
    resource: new URL("https://other.example.test/mcp"),
    extra: {
      principalId: "principal-1",
      issuer: "issuer-1",
      sessionId: "session-1",
      issuedAtMs: 1_700_000_000_000
    }
  };
  assert.throws(() => projectPrincipal(auth, {
    edgeId: "edge-1",
    brokerAudience: "mac-operator-broker",
    resourceServerUrl
  }), /resource does not match/u);
});
