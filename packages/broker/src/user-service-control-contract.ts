import { BrokerError } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";

/** Candidate contract only: the scope is materialized but remains disabled by default. */
export const USER_SERVICE_CONTROL_CONTRACT = Object.freeze({
  contractVersion: "0.1",
  tool: "mac_service_control",
  proposedScope: "mac.service.control",
  targetType: "user_launch_agent",
  mutation: true,
  approvalClass: "trusted_write",
  actions: Object.freeze(["start", "stop", "restart"] as const),
  argumentKeys: Object.freeze(["action", "expected_state", "idempotency_key", "service_id"] as const),
  maxOperationTimeoutMs: 30_000,
  commandTimeoutMs: 5_000,
  outputCapBytes: 128 * 1024,
  network: "none",
  inputSecretPolicy: "reject",
  outputSecretPolicy: "redact",
  verification: "precondition_postcondition_source_revision",
  rollback: "inverse_action_with_verified_readback",
  recovery: "retain_unknown_until_owner_readback",
  auditClass: "user_service_mutation",
  enabledByDefault: false
} as const);

export type UserServiceControlContract = typeof USER_SERVICE_CONTROL_CONTRACT;

export function validateUserServiceControlContract(value: unknown): asserts value is UserServiceControlContract {
  if (!isPlainDataRecord(value) ||
      value.contractVersion !== "0.1" ||
      value.tool !== "mac_service_control" ||
      value.proposedScope !== "mac.service.control" ||
      value.targetType !== "user_launch_agent" ||
      value.mutation !== true ||
      value.approvalClass !== "trusted_write" ||
      !Array.isArray(value.actions) ||
      value.actions.length !== 3 ||
      value.actions.join(",") !== "start,stop,restart" ||
      !Array.isArray(value.argumentKeys) ||
      value.argumentKeys.length !== 4 ||
      value.argumentKeys.join(",") !== "action,expected_state,idempotency_key,service_id" ||
      value.maxOperationTimeoutMs !== 30_000 ||
      value.commandTimeoutMs !== 5_000 ||
      value.outputCapBytes !== 128 * 1024 ||
      value.network !== "none" ||
      value.inputSecretPolicy !== "reject" ||
      value.outputSecretPolicy !== "redact" ||
      value.verification !== "precondition_postcondition_source_revision" ||
      value.rollback !== "inverse_action_with_verified_readback" ||
      value.recovery !== "retain_unknown_until_owner_readback" ||
      value.auditClass !== "user_service_mutation" ||
      value.enabledByDefault !== false) {
    throw new BrokerError("POLICY_DENIED", "User service-control candidate contract is malformed");
  }
  const keys = Object.keys(value).sort().join(",");
  if (keys !== "actions,approvalClass,argumentKeys,auditClass,commandTimeoutMs,contractVersion,enabledByDefault,inputSecretPolicy,maxOperationTimeoutMs,mutation,network,outputCapBytes,outputSecretPolicy,proposedScope,recovery,rollback,targetType,tool,verification") {
    throw new BrokerError("POLICY_DENIED", "User service-control candidate contract contains unknown fields");
  }
}

validateUserServiceControlContract(USER_SERVICE_CONTROL_CONTRACT);
