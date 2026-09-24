/**
 * Public exposure state for D1 developer mutations. Direct staging probes may
 * exercise these boundaries, but production startup requires an explicit
 * host-owned release/readiness decision.
 */
export type DeveloperPublicEnablement = "unavailable" | "staging-only" | "production";

export const DEVELOPER_MUTATION_TOOLS = [
  "mac_write_file_atomic",
  "mac_apply_patch",
  "mac_git_stage",
  "mac_git_commit",
  "mac_job_cancel"
] as const;

export function requiresDeveloperReadiness(toolName: string): boolean {
  return (DEVELOPER_MUTATION_TOOLS as readonly string[]).includes(toolName);
}

export function assertDeveloperPublicEnablement(
  toolEnabled: boolean,
  publicEnablement: DeveloperPublicEnablement
): void {
  if (!toolEnabled) return;
  if (publicEnablement !== "production") {
    throw new Error("Enabled developer mutation tools require production readiness evidence");
  }
}
