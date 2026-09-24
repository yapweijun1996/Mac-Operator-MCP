import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  inspectDescriptorExecProbe,
  parseDescriptorExecProbe
} from "./descriptor-exec-probe.js";
import {
  inspectProcessDescriptorExecutionCapability,
  requireProcessDescriptorExecution
} from "./process-launch-capability.js";

test("descriptor execution probe reports host evidence without becoming a launch capability", () => {
  const probe = inspectDescriptorExecProbe();
  assert.equal(probe.schemaVersion, "0.1");
  assert.equal(probe.mechanism, "darwin-descriptor-exec-probe-v1");
  assert.ok(probe.fexecveSymbol === "absent" || probe.fexecveSymbol === "present");
  assert.ok(probe.execveatSymbol === "absent");
  assert.ok(probe.executableCoverage === "unproven" || probe.executableCoverage === "single-fixed-executable");
  assert.ok(probe.immutableSelection === "unproven" || probe.immutableSelection === "single-fixed-executable");
  if (probe.fexecveSymbol === "absent") assert.equal(probe.fexecveExecution, "unavailable");
  assert.notEqual(probe.immutableSelection, "enforced");

  const capability = inspectProcessDescriptorExecutionCapability();
  assert.equal(capability.available, false);
  assert.throws(
    () => requireProcessDescriptorExecution(),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});

test("descriptor execution probe parser rejects malformed or inconsistent evidence", () => {
  const valid = {
    schemaVersion: "0.1",
    mechanism: "darwin-descriptor-exec-probe-v1",
    fexecveSymbol: "absent",
    fexecveExecution: "unavailable",
    execveatSymbol: "absent",
    executableCoverage: "unproven",
    immutableSelection: "unproven",
    evidenceRef: "evidence://descriptor-exec-probe"
  } as const;
  assert.deepEqual(parseDescriptorExecProbe(valid), valid);
  assert.throws(
    () => parseDescriptorExecProbe({ ...valid, extra: true }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => parseDescriptorExecProbe({ ...valid, fexecveExecution: "passed" }),
    /inconsistent/u
  );
  assert.throws(
    () => parseDescriptorExecProbe(Object.create(valid)),
    /malformed/u
  );
  assert.deepEqual(parseDescriptorExecProbe({
    ...valid,
    descriptorPathOpen: "passed",
    descriptorPathExecution: "failed"
  }), {
    ...valid,
    descriptorPathOpen: "passed",
    descriptorPathExecution: "failed"
  });
  assert.throws(
    () => parseDescriptorExecProbe({ ...valid, descriptorPathOpen: "failed", descriptorPathExecution: "passed" }),
    /inconsistent/u
  );
});
