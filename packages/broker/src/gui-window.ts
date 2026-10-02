import { BrokerError } from "@mac-operator/contracts";

/** Native identity is process generation plus CGWindowID, never presentation text. */
export function nativeWindowIdentity(record: Record<string, unknown>, required = false): string | undefined {
  if (!required && record.window_identity === undefined) return undefined;
  if (typeof record.window_identity !== "string" || !/^[1-9][0-9]{0,9}:[1-9][0-9]{0,15}:[1-9][0-9]{0,9}$/u.test(record.window_identity)) {
    throw new BrokerError("VERIFICATION_FAILED", "Native GUI window identity is missing or malformed");
  }
  return record.window_identity;
}

export function guiWindowFields(record: Record<string, unknown>, fields: readonly string[]): string[] {
  return [...fields, ...(record.window_identity === undefined ? [] : ["window_identity"])];
}

/** Preserve the failed boundary instead of translating every discovery error to absence. */
export function throwGuiWindowError(reason: unknown): void {
  switch (reason) {
    case "accessibility_permission": throw new BrokerError("POLICY_DENIED", "AX_PERMISSION_DENIED: Accessibility permission is not granted to the production GUI application");
    case "screen_recording_permission": throw new BrokerError("POLICY_DENIED", "SCREEN_CAPTURE_DENIED: Screen Recording permission is not granted to the production GUI application");
    case "app_not_running": throw new BrokerError("TARGET_NOT_FOUND", "APP_NOT_RUNNING: The requested app is not running");
    case "protected_session": throw new BrokerError("SECRET_BOUNDARY_DENIED", "PROTECTED_SESSION: Unlock the Mac or dismiss the system authorization UI before browser automation");
    case "activation_failed": throw new BrokerError("EXECUTION_FAILED", "ACTIVATION_FAILED: macOS rejected app activation or window raise");
    case "frontmost_timeout": throw new BrokerError("TIMEOUT", "FRONTMOST_TIMEOUT: The requested app did not become frontmost within the bounded focus deadline", true);
    case "focused_app_mismatch": throw new BrokerError("VERIFICATION_FAILED", "FOCUSED_APP_MISMATCH: Workspace and system-wide AX did not confirm the requested process");
    case "focused_window_not_found": throw new BrokerError("VERIFICATION_FAILED", "FOCUSED_WINDOW_NOT_FOUND: AX did not confirm the selected process window");
    case "app_not_frontmost": throw new BrokerError("PRECONDITION_FAILED", "The requested app is running but is not frontmost");
    case "window_not_found": throw new BrokerError("TARGET_NOT_FOUND", "FOCUSED_WINDOW_NOT_FOUND: The requested app has no matching window");
    case "window_unavailable": throw new BrokerError("PRECONDITION_FAILED", "The requested window is hidden or minimized");
    case "window_correlation_failed": throw new BrokerError("VERIFICATION_FAILED", "The AX window exists but cannot be correlated to a visible CG window");
    case "window_ambiguous": throw new BrokerError("VERIFICATION_FAILED", "WINDOW_IDENTITY_AMBIGUOUS: The requested window cannot be resolved uniquely");
    case "ax_enumeration_failed": throw new BrokerError("VERIFICATION_FAILED", "Accessibility window enumeration or metadata read failed");
    case "stale_target": throw new BrokerError("TARGET_NOT_FOUND", "The observed window identity is stale; observe it again");
    case "focus_changed": throw new BrokerError("VERIFICATION_FAILED", "The focused window changed during the GUI operation");
    case "navigation_unverified": throw new BrokerError("VERIFICATION_FAILED", "Browser navigation dispatched but its target address could not be verified");
    case "target_denied": throw new BrokerError("SECRET_BOUNDARY_DENIED", "The window is outside the authorized browser or sensitive UI boundary; screenshot contents were not inspected");
    case "secure_target": throw new BrokerError("SECRET_BOUNDARY_DENIED", "Secure or sensitive UI cannot be controlled");
    case "capture_failed": throw new BrokerError("EXECUTION_FAILED", "ScreenCaptureKit failed to capture the resolved window");
  }
}
