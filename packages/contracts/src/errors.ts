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

export class BrokerError extends Error {
  constructor(
    readonly errorClass: ErrorClass,
    message: string,
    readonly retryable = false
  ) {
    super(message);
    this.name = "BrokerError";
  }
}
