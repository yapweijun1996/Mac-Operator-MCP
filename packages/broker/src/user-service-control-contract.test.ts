import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  USER_SERVICE_CONTROL_CONTRACT,
  validateUserServiceControlContract
} from "./user-service-control-contract.js";

test("user service-control candidate contract is versioned, bounded, and disabled by default", () => {
  validateUserServiceControlContract(USER_SERVICE_CONTROL_CONTRACT);
  assert.equal(USER_SERVICE_CONTROL_CONTRACT.contractVersion, "0.1");
  assert.equal(USER_SERVICE_CONTROL_CONTRACT.proposedScope, "mac.service.control");
  assert.deepEqual(USER_SERVICE_CONTROL_CONTRACT.actions, ["start", "stop", "restart"]);
  assert.equal(USER_SERVICE_CONTROL_CONTRACT.enabledByDefault, false);
});

test("user service-control candidate contract rejects scope or safety drift", () => {
  assert.throws(
    () => validateUserServiceControlContract({ ...USER_SERVICE_CONTROL_CONTRACT, proposedScope: "mac.files.write" }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
  assert.throws(
    () => validateUserServiceControlContract({ ...USER_SERVICE_CONTROL_CONTRACT, enabledByDefault: true }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "POLICY_DENIED"
  );
});
