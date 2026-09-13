import {
  executeMacOsInstallPlan,
  MacOsInstallPlanError,
  type MacOsInstallExecutionOptions,
  type MacOsInstallExecutionResult,
  type MacOsInstallPlan
} from "./macos-install-plan.js";
import type { AuthorityControlIpcClient } from "./authority-control-ipc.js";

export interface MacOsUninstallAuthorityReadback {
  globalDisabled: boolean;
  edgeRevoked: boolean;
}

export type MacOsUninstallExecutionOptions = Omit<MacOsInstallExecutionOptions, "confirmOperation"> & {
  confirmOperation: "uninstall";
  edgeId: string;
  /** These callbacks must use the separately authenticated host authority channel. */
  disableGlobal: () => Promise<void>;
  revokeEdge: (edgeId: string) => Promise<void>;
  authorityReadback: () => Promise<MacOsUninstallAuthorityReadback>;
};

export interface MacOsUninstallAuthorityActions {
  disableGlobal: () => Promise<void>;
  revokeEdge: (edgeId: string) => Promise<void>;
  authorityReadback: () => Promise<MacOsUninstallAuthorityReadback>;
}

/**
 * Binds uninstall to the real owner-only Authority Control IPC client. The
 * read-before-write checks make repeated operator recovery idempotent while
 * the coordinator's pre/post readback still fences races and target swaps.
 */
export function createAuthorityControlUninstallActions(
  client: Pick<AuthorityControlIpcClient, "readSwitch" | "setSwitch" | "readRevocation" | "revoke">,
  edgeId: string,
  reason = "service-uninstall"
): MacOsUninstallAuthorityActions {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(edgeId)) {
    throw new MacOsInstallPlanError("INVALID_ARGUMENT", "Edge identity is invalid");
  }
  return {
    disableGlobal: async () => {
      if (!await client.readSwitch("global")) await client.setSwitch("global", true, false, reason);
    },
    revokeEdge: async (requestedEdgeId) => {
      if (requestedEdgeId !== edgeId) throw new MacOsInstallPlanError("INVALID_ARGUMENT", "Uninstall Edge identity does not match the authority binding");
      if (!await client.readRevocation("edge", edgeId)) await client.revoke("edge", edgeId, reason);
    },
    authorityReadback: async () => ({
      globalDisabled: await client.readSwitch("global"),
      edgeRevoked: await client.readRevocation("edge", edgeId)
    })
  };
}

/**
 * Removes a per-user service only after remote authority is durably disabled.
 * This host-only coordinator is intentionally not exposed through MCP and never
 * re-enables authority if service removal fails; recovery remains explicit.
 */
export async function executeMacOsUninstallPlan(
  plan: MacOsInstallPlan,
  options: MacOsUninstallExecutionOptions
): Promise<MacOsInstallExecutionResult> {
  if (plan.operation !== "uninstall" || options.confirmOperation !== "uninstall") {
    throw new MacOsInstallPlanError("CONFIRMATION_REQUIRED", "uninstall requires an explicit uninstall operation");
  }
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(options.edgeId)) {
    throw new MacOsInstallPlanError("INVALID_ARGUMENT", "Edge identity is invalid");
  }

  try {
    await options.disableGlobal();
    await options.revokeEdge(options.edgeId);
  } catch (error) {
    if (error instanceof MacOsInstallPlanError) throw error;
    throw new MacOsInstallPlanError("AUTHORITY_FAILED", "remote authority could not be disabled before uninstall");
  }
  await requireAuthorityReadback(options.authorityReadback);

  const result = await executeMacOsInstallPlan(plan, options);
  await requireAuthorityReadback(options.authorityReadback);
  return result;
}

async function requireAuthorityReadback(
  readback: () => Promise<MacOsUninstallAuthorityReadback>
): Promise<void> {
  let value: MacOsUninstallAuthorityReadback;
  try {
    value = await readback();
  } catch (error) {
    if (error instanceof MacOsInstallPlanError) throw error;
    throw new MacOsInstallPlanError("AUTHORITY_FAILED", "authority readback failed during uninstall");
  }
  if (value === null || typeof value !== "object" ||
      typeof value.globalDisabled !== "boolean" || typeof value.edgeRevoked !== "boolean") {
    throw new MacOsInstallPlanError("AUTHORITY_MISMATCH", "authority readback is malformed");
  }
  if (!value.globalDisabled || !value.edgeRevoked) {
    throw new MacOsInstallPlanError("AUTHORITY_MISMATCH", "remote authority remains enabled during uninstall");
  }
}
