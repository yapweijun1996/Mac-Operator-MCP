import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  inspectDescriptorHandoffCapability,
  parseDescriptorHandoffCapability,
  requireDescriptorHandoffTransport
} from "./descriptor-handoff-capability.js";

test("native descriptor handoff probe reports only the ancillary-FD transport boundary", () => {
  const capability = inspectDescriptorHandoffCapability();
  assert.equal(capability.schemaVersion, "0.1");
  assert.equal(capability.mechanism, "darwin-scm-rights-v1");
  if (process.platform === "darwin") {
    assert.equal(capability.available, true);
    assert.equal(capability.fdTransfer, "verified");
    assert.equal(capability.fdCloseOnExec, "verified");
    assert.equal(capability.immutableSelection, "unproven");
    assert.doesNotThrow(() => requireDescriptorHandoffTransport());
  } else {
    assert.equal(capability.available, false);
  }
});

test("descriptor handoff capability parser requires an exact, incomplete-safe shape", () => {
  const valid = {
    schemaVersion: "0.1",
    mechanism: "darwin-scm-rights-v1",
    available: true,
    fdTransfer: "verified",
    fdCloseOnExec: "verified",
    peerAuthentication: "unproven",
    immutableSelection: "unproven",
    evidenceRef: "evidence://descriptor-handoff"
  } as const;
  assert.deepEqual(parseDescriptorHandoffCapability(valid), valid);
  assert.throws(
    () => parseDescriptorHandoffCapability({ ...valid, fdCloseOnExec: "unproven" }),
    /incomplete/u
  );
  assert.throws(
    () => parseDescriptorHandoffCapability({ ...valid, immutableSelection: "enforced", extra: true }),
    /malformed/u
  );
  assert.throws(
    () => parseDescriptorHandoffCapability(Object.create(valid)),
    /malformed/u
  );
});

test("descriptor handoff transport remains separate from executable launch proof", () => {
  const capability = parseDescriptorHandoffCapability({
    schemaVersion: "0.1",
    mechanism: "darwin-scm-rights-v1",
    available: true,
    fdTransfer: "verified",
    fdCloseOnExec: "verified",
    peerAuthentication: "unproven",
    immutableSelection: "unproven",
    evidenceRef: "evidence://descriptor-handoff"
  });
  assert.equal(capability.immutableSelection, "unproven");
  assert.throws(
    () => parseDescriptorHandoffCapability({
      ...capability,
      fdTransfer: "unproven",
      available: true
    }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});
