/**
 * Public exposure state for Accessibility-dependent GUI capabilities.
 * Permission-denied adapters may still be exercised by direct staging probes,
 * but production startup must not publish them without host evidence.
 */
export type GuiPublicEnablement = "unavailable" | "staging-only" | "production";

export const ACCESSIBILITY_BOUND_GUI_TOOLS = [
  "mac_app_focus",
  "mac_ui_observe",
  "mac_ui_action",
  "mac_ui_type"
] as const;

export function requiresAccessibilityPermission(toolName: string): boolean {
  return (ACCESSIBILITY_BOUND_GUI_TOOLS as readonly string[]).includes(toolName);
}

export function assertGuiPublicEnablement(
  toolEnabled: boolean,
  publicEnablement: GuiPublicEnablement
): void {
  if (!toolEnabled) return;
  if (publicEnablement !== "production") {
    throw new Error("Enabled Accessibility-dependent GUI tools require production permission evidence");
  }
}
