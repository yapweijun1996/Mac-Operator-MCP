import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { parseOwnerTerminalSessionRequest } from "./owner-terminal-session-request.js";

const require = createRequire(import.meta.url);
const Ajv2020 = require("ajv/dist/2020").default;
const ajv = new Ajv2020({ strict: true, allErrors: true });
require("ajv-formats").default(ajv);
const contractsDirectory = resolve(dirname(fileURLToPath(import.meta.url)), "../../../tool-contracts");
const contract = JSON.parse(await readFile(join(contractsDirectory, "mac_terminal_session.json"), "utf8"));
const validate = ajv.compile(contract.input_schema);
const sessionId = `tsess_${"a".repeat(24)}`;
const validRequests = [
  { action: "start", cwd: "/tmp", idempotency_key: "start-1" },
  { action: "start", cwd: "/tmp", idempotency_key: "start-2", rows: 24, cols: 80,
    lifetime_ms: 60_000, idle_timeout_ms: 30_000 },
  { action: "write", session_id: sessionId, data: "echo hello\n" },
  { action: "read", session_id: sessionId, cursor: 0 },
  { action: "read", session_id: sessionId, cursor: 10, max_bytes: 1024, wait_ms: 100 },
  { action: "stop", session_id: sessionId }
];

test("terminal session contract supports action branches and valid requests match the runtime parser", async () => {
  const contractSchema = JSON.parse(await readFile(join(contractsDirectory, "tool-contract.schema.json"), "utf8"));
  assert.equal(ajv.compile(contractSchema)(contract), true);
  assert.equal(contract.input_schema.oneOf.length, 4);
  for (const request of validRequests) {
    assert.equal(validate(request), true, JSON.stringify(request));
    assert.equal(parseOwnerTerminalSessionRequest(request).action, request.action);
  }
});

test("terminal session public schema and runtime reject foreign, unknown and missing action fields", () => {
  const invalidRequests: Record<string, unknown>[] = [
    { action: "write", session_id: sessionId, data: "echo hello\n", idempotency_key: "write-1" },
    { action: "read", session_id: sessionId, cursor: 0, idempotency_key: "read-1" },
    { action: "stop", session_id: sessionId, idempotency_key: "stop-1" },
    { action: "start", cwd: "/tmp", idempotency_key: "start-1", session_id: sessionId },
    { action: "write", session_id: sessionId, data: "x", cursor: 0 },
    { action: "read", session_id: sessionId, cursor: 0, data: "x" },
    { action: "stop", session_id: sessionId, wait_ms: 0 },
    { action: "unknown" },
    {}
  ];
  for (const request of validRequests) {
    invalidRequests.push({ ...request, unexpected: true });
    for (const field of ["action", "cwd", "idempotency_key", "session_id", "data", "cursor"]) {
      if (!Object.hasOwn(request, field)) continue;
      const missing: Record<string, unknown> = { ...request };
      delete missing[field];
      invalidRequests.push(missing);
    }
  }
  for (const request of invalidRequests) {
    assert.equal(validate(request), false, JSON.stringify(request));
    assert.throws(() => parseOwnerTerminalSessionRequest(request),
      (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED",
      JSON.stringify(request));
  }
});
