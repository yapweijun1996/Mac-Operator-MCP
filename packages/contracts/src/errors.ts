export const ERROR_CLASSES = [
  "AUTH_REQUIRED",
  "AUTH_INVALID",
  "AUTH_EXPIRED",
  "REPLAY_DENIED",
  "REVOKED",
  "SCOPE_DENIED",
  "SECRET_BOUNDARY_DENIED",
  "PATH_DENIED",
  "NETWORK_DENIED",
  "PRIVILEGE_DENIED",
  "POLICY_DENIED",
  "TARGET_NOT_FOUND",
  "PRECONDITION_FAILED",
  "CONFLICT",
  "TIMEOUT",
  "OUTPUT_LIMIT",
  "CANCELLED",
  "EXECUTION_FAILED",
  "VERIFICATION_FAILED",
  "AUDIT_UNAVAILABLE",
  "UNKNOWN_OUTCOME",
  "UNSUPPORTED_CAPABILITY"
] as const;

export type ErrorClass = (typeof ERROR_CLASSES)[number];

/**
 * Stable machine-readable detail for a policy denial. Codes are static and must never be built from
 * paths, root ids, deny-list entries or rule contents, so mac_policy_explain cannot become an oracle.
 */
export type PolicyReasonCode =
  | "OUTSIDE_AUTHORIZED_ROOTS"
  | "ROOT_CAPABILITY_NOT_GRANTED"
  | "DENIED_ZONE"
  | "SECRET_PATH_ACCESS"
  | "GIT_METADATA_WRITE_DENIED"
  | "MANAGED_WORKTREE_PATH"
  | "TOOL_DISABLED"
  | "TARGET_EXPLICITLY_DENIED"
  | "TARGET_NOT_AUTHORIZED";

export class BrokerError extends Error {
  constructor(
    readonly errorClass: ErrorClass,
    message: string,
    readonly retryable = false,
    readonly reasonCode?: PolicyReasonCode
  ) {
    super(message);
    this.name = "BrokerError";
  }
}
