/**
 * Bounded, non-sensitive audit integrity readback for authenticated host
 * recovery/status channels. Raw audit rows and evidence are intentionally not
 * part of this contract.
 */
export interface AuditIntegrityReadback {
  format: "mac-operator-audit-integrity-v1";
  eventCount: number;
  tailSequence: number | null;
  tailHash: string | null;
  keyedAnchor: "verified" | "not_configured";
}
