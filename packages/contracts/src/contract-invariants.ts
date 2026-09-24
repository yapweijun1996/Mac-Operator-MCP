/**
 * Cross-field safety invariants that must hold both when contracts are built
 * and when the Edge loads them from disk. Keeping these rules shared prevents
 * a contract from passing one boundary and being interpreted differently at
 * the next boundary.
 */
export const APPROVAL_POLICIES = [
  "trusted_read",
  "trusted_write",
  "trusted_profile",
  "trusted_gui",
  "explicit_privileged_policy"
] as const;

const APPROVAL_POLICY_SET = new Set<string>(APPROVAL_POLICIES);

export function validateToolContractSafety(record: Record<string, unknown>, label = "tool contract"): void {
  const safetyClass = record.safety_class;
  const postcondition = record.postcondition_verification;
  if (typeof record.approval_policy !== "string" || !APPROVAL_POLICY_SET.has(record.approval_policy)) {
    throw new Error(`${label}: approval_policy is not a supported policy`);
  }
  if (safetyClass === "read_only" && record.idempotent !== true) {
    throw new Error(`${label}: read_only tools must be idempotent`);
  }
  if (safetyClass !== "read_only" && (!isRecord(postcondition) || postcondition.required !== true)) {
    throw new Error(`${label}: non-read-only tools must require postcondition verification`);
  }
  if (safetyClass === "privileged" && record.audit_class !== "privileged") {
    throw new Error(`${label}: privileged tools must use the privileged audit class`);
  }
  if (safetyClass === "privileged" && record.approval_policy !== "explicit_privileged_policy") {
    throw new Error(`${label}: privileged tools must require explicit privileged approval`);
  }
  if (safetyClass !== "read_only" && record.approval_policy === "trusted_read") {
    const subject = safetyClass === "writes_local" ? "local writes" : "non-read-only tools";
    throw new Error(`${label}: ${subject} cannot use trusted-read approval`);
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
