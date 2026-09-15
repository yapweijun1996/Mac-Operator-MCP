import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  inspectProcessDescriptorExecutionCapability,
  parseProcessDescriptorExecutionCapability,
  requireProcessDescriptorExecution
} from "./process-launch-capability.js";

test("descriptor execution capability is unavailable without the native launcher", () => {
  const capability = inspectProcessDescriptorExecutionCapability();
  assert.equal(capability.schemaVersion, "0.1");
  assert.equal(capability.mechanism, "darwin-descriptor-exec-v1");
  assert.equal(capability.available, false);
  assert.equal(capability.immutableSelection, "unproven");
  assert.equal(capability.closeOnExec, "unproven");
  assert.throws(
    () => requireProcessDescriptorExecution(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("descriptor execution capability requires an attested complete boundary", () => {
  const valid = {
    schemaVersion: "0.1",
    mechanism: "darwin-descriptor-exec-v1",
    available: true,
    immutableSelection: "enforced",
    closeOnExec: "enforced",
    evidenceRef: "evidence://descriptor-exec"
  } as const;
  assert.deepEqual(parseProcessDescriptorExecutionCapability(valid), valid);
  assert.throws(
    () => parseProcessDescriptorExecutionCapability({ ...valid, evidenceRef: undefined }),
    /incomplete/u
  );
  assert.throws(
    () => parseProcessDescriptorExecutionCapability({ ...valid, closeOnExec: "unproven" }),
    /incomplete/u
  );
  assert.throws(
    () => parseProcessDescriptorExecutionCapability({ ...valid, extra: true }),
    /malformed/u
  );
});

test("descriptor execution capability rejects accessor and prototype authority", () => {
  const valid = {
    schemaVersion: "0.1",
    mechanism: "darwin-descriptor-exec-v1",
    available: true,
    immutableSelection: "enforced",
    closeOnExec: "enforced",
    evidenceRef: "evidence://descriptor-exec"
  } as const;
  const inherited = Object.create(valid) as unknown;
  assert.throws(() => parseProcessDescriptorExecutionCapability(inherited), /malformed/u);
  const accessor = { ...valid } as Record<string, unknown>;
  Object.defineProperty(accessor, "evidenceRef", { enumerable: true, get: () => valid.evidenceRef });
  assert.throws(() => parseProcessDescriptorExecutionCapability(accessor), /malformed/u);
});
