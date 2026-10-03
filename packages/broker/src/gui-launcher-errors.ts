import { BrokerError } from "@mac-operator/contracts";
import type { ProcessExecutionResult } from "./process-supervisor.js";

/** Only the fixed production launcher defines these exit statuses. */
export function guiLauncherFailureError(
  result: Pick<ProcessExecutionResult, "resultClass" | "exitCode">
): BrokerError | undefined {
  // Supervisor outcomes take precedence over a child status observed during cleanup.
  if (result.resultClass !== "EXECUTION_FAILED") return undefined;
  switch (result.exitCode) {
    case 70: return new BrokerError("PRECONDITION_FAILED", "GUI_HELPER_OWNER_UNAVAILABLE: Mac Operator GUI launcher could not resolve the current user");
    case 71: return new BrokerError("PRECONDITION_FAILED", "GUI_HELPER_UNAVAILABLE: Mac Operator GUI helper is missing or failed identity validation");
    case 72: return new BrokerError("PRECONDITION_FAILED", "GUI_LAUNCHER_REQUEST_INVALID: Mac Operator GUI launcher rejected its bounded request");
    case 73: return new BrokerError("EXECUTION_FAILED", "GUI_LAUNCHER_IPC_SETUP_FAILED: Mac Operator GUI launcher could not create its private IPC channel", true);
    case 74: return new BrokerError("EXECUTION_FAILED", "GUI_LAUNCHER_TRANSPORT_FAILED: Mac Operator GUI helper launch or IPC exchange failed", true);
    case 75: return new BrokerError("EXECUTION_FAILED", "GUI_HELPER_CLEANUP_FAILED: Mac Operator GUI helper termination could not be confirmed");
    case 76: return new BrokerError("EXECUTION_FAILED", "GUI_LAUNCHER_OUTPUT_FAILED: Mac Operator GUI launcher could not write its result");
    default: return undefined;
  }
}

export function throwGuiLauncherFailure(result: Pick<ProcessExecutionResult, "resultClass" | "exitCode">): void {
  const error = guiLauncherFailureError(result);
  if (error) throw error;
}
