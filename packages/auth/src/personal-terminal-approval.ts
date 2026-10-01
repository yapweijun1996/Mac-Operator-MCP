import { ApprovalIpcClient, type ApprovalIssuerRuntimeAssembly, type OwnerTerminalOperation } from "@mac-operator/broker";
import { sha256 } from "@mac-operator/contracts";

/** Local O1 setup delegates exact single-use approvals to a distinct terminal issuer. */
export function createPersonalTerminalApprover(options: {
  principalId: string; runtime: ApprovalIssuerRuntimeAssembly; socketPath: string; now?: () => number;
}) {
  const now = options.now ?? Date.now;
  return async (operation: OwnerTerminalOperation): Promise<boolean> => {
    if (operation.principalId !== options.principalId || operation.tool !== "mac_terminal_exec" ||
        operation.targetKind !== "host" || operation.targetRef !== "host:owner-terminal" ||
        !Number.isSafeInteger(operation.timeoutMs) || operation.timeoutMs < 100 || operation.timeoutMs > 120000) return false;
    const keys = options.runtime.keyManager.current().keys.filter(key => key.allowUnattended);
    if (keys.length !== 1) throw new Error("Owner terminal requires its separate delegated issuer");
    const issuer = keys[0]!;
    const client = new ApprovalIpcClient({ socketPath: options.socketPath, issuerId: issuer.issuerId,
      keyId: issuer.keyId, authenticationKey: issuer.key, allowUnattended: true, timeoutMs: 5_000, now });
    try {
      const issuedAtMs = now();
      await client.issue({ approvalId: `approval:owner-terminal-${sha256(operation.requestId).slice(0, 48)}`,
        approverPrincipalId: issuer.issuerId, requestingPrincipalId: operation.principalId,
        tool: operation.tool, contractVersion: operation.contractVersion, targetKind: operation.targetKind,
        targetRef: operation.targetRef, payloadDigest: operation.payloadDigest, policyVersion: operation.policyVersion,
        approvalClass: "trusted_profile", unattended: true, issuedAtMs,
        expiresAtMs: Math.min(operation.expiresAtMs, issuedAtMs + operation.timeoutMs + 30_000), useLimit: 1 });
      return true;
    } finally { client.dispose(); }
  };
}
