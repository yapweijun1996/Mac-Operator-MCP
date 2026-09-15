import assert from "node:assert/strict";
import test from "node:test";
import { redactEvidence } from "./persistence.js";

test("audit evidence redacts common credential field aliases", () => {
  assert.deepEqual(
    redactEvidence({
      api_key: "api-secret",
      access_token: "access-secret",
      signing_key: "signing-secret",
      hmacKey: "hmac-secret",
      client_secret: "client-secret",
      safe: "retained"
    }),
    {
      api_key: "[REDACTED]",
      access_token: "[REDACTED]",
      signing_key: "[REDACTED]",
      hmacKey: "[REDACTED]",
      client_secret: "[REDACTED]",
      safe: "retained"
    }
  );
});
