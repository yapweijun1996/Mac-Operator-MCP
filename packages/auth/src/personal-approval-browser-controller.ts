import {
  ApprovalIpcClient,
  type ApprovalIssuerRuntimeAssembly,
  type BrokerStore,
  type IssueApprovalInput
} from "@mac-operator/broker";
import type { AuthStore } from "./store.js";
import { browserConsentApp, GuiSessionApprovals } from "./gui-session-approval.js";
import type { GuiSessionOperation } from "@mac-operator/broker";
import { sha256 } from "@mac-operator/contracts";
import type { ApprovalBrowserIssuanceResult, ApprovalBrowserPreview } from "./approval-browser-bridge.js";

export interface PersonalApprovalBrowserController {
  preview(requestId: string): ApprovalBrowserPreview | undefined;
  issue(requestId: string): Promise<ApprovalBrowserIssuanceResult>;
  sessions: GuiSessionApprovals;
  authorizeGuiSession(operation: GuiSessionOperation): Promise<boolean>;
}

/**
 * Binds browser review to a durable Broker preview and the separate owner
 * approval IPC channel. The browser receives only non-secret preview fields;
 * issuer key material remains inside the supervisor/runtime boundary.
 */
export function createPersonalApprovalBrowserController(options: {
  store: BrokerStore;
  authStore?: AuthStore;
  approvalIssuerRuntime: ApprovalIssuerRuntimeAssembly;
  socketPath: string;
  now?: () => number;
}): PersonalApprovalBrowserController {
  const now = options.now ?? Date.now;
  const issueExact = async (approval: Omit<IssueApprovalInput, "approverPrincipalId">): Promise<void> => {
    const loaded = { keys: options.approvalIssuerRuntime.keyManager.current().keys.filter(key => !key.allowUnattended) };
    if (loaded.keys.length !== 1 || loaded.keys[0]!.allowUnattended) throw new Error("Browser approval requires one attended issuer key");
    const issuer = loaded.keys[0]!;
    const client = new ApprovalIpcClient({ socketPath: options.socketPath, issuerId: issuer.issuerId,
      keyId: issuer.keyId, authenticationKey: issuer.key, timeoutMs: 15_000, now });
    try { await client.issue({ ...approval, approverPrincipalId: issuer.issuerId }); }
    finally { client.dispose(); }
  };
  const sessions = new GuiSessionApprovals(options.store, issueExact, now, options.authStore);
  const flights = new Map<string, Promise<ApprovalBrowserIssuanceResult>>();
  const preview = (requestId: string): ApprovalBrowserPreview | undefined => {
    const record = options.store.approvalPreview(requestId, now());
    if (!record) return undefined;
    return {
      requestId: record.requestId,
      requestingPrincipalId: record.requestingPrincipalId,
      tool: record.tool,
      contractVersion: record.contractVersion,
      targetKind: record.targetKind,
      targetRef: record.targetRef,
      payloadDigest: record.payloadDigest,
      policyVersion: record.policyVersion,
      approvalClass: record.approvalClass,
      unattended: record.unattended,
      expiresAtMs: record.expiresAtMs,
      sessionEligible: browserConsentApp(record) !== undefined
    };
  };
  const issue = (requestId: string): Promise<ApprovalBrowserIssuanceResult> => {
    const existingFlight = flights.get(requestId);
    if (existingFlight) return existingFlight;
    const flight = (async () => {
      const issuedAtMs = now();
      const record = options.store.approvalPreview(requestId, issuedAtMs);
      if (!record) throw new Error("Approval preview is no longer pending");
      const loaded = { keys: options.approvalIssuerRuntime.keyManager.current().keys.filter(key => !key.allowUnattended) };
      if (loaded.keys.length !== 1 || loaded.keys[0]!.allowUnattended) {
        throw new Error("Browser approval requires one attended issuer key");
      }
      const issuer = loaded.keys[0]!;
      const approvalId = `approval:owner-preview-${sha256(requestId).slice(0, 48)}`;
      const existing = options.store.approvalRecord(approvalId);
      if (existing) {
        const linked = options.store.markApprovalPreviewIssued(requestId, approvalId, issuedAtMs);
        return { approvalId: linked.approvalId ?? approvalId, expiresAtMs: record.expiresAtMs, revision: existing.revision };
      }
      const approval: IssueApprovalInput = {
        approvalId,
        approverPrincipalId: issuer.issuerId,
        requestingPrincipalId: record.requestingPrincipalId,
        tool: record.tool,
        contractVersion: record.contractVersion,
        targetKind: record.targetKind,
        targetRef: record.targetRef,
        payloadDigest: record.payloadDigest,
        policyVersion: record.policyVersion,
        approvalClass: record.approvalClass,
        unattended: false,
        issuedAtMs,
        expiresAtMs: record.expiresAtMs,
        useLimit: 1
      };
      const client = new ApprovalIpcClient({
        socketPath: options.socketPath,
        issuerId: issuer.issuerId,
        keyId: issuer.keyId,
        authenticationKey: issuer.key,
        timeoutMs: 15_000,
        now
      });
      try {
        const response = await client.issue(approval);
        const linked = options.store.markApprovalPreviewIssued(requestId, response.approval_id, issuedAtMs);
        return { approvalId: linked.approvalId ?? response.approval_id, expiresAtMs: response.expires_at_ms, revision: response.revision };
      } catch (error) {
        // The issuer may have committed before the browser bridge lost its
        // response. Re-link the deterministic approval instead of issuing a
        // second approval.
        const committed = options.store.approvalRecord(approvalId);
        if (!committed) throw error;
        const linked = options.store.markApprovalPreviewIssued(requestId, approvalId, issuedAtMs);
        return { approvalId: linked.approvalId ?? approvalId, expiresAtMs: committed.expiresAtMs, revision: committed.revision };
      } finally {
        client.dispose();
      }
    })();
    flights.set(requestId, flight);
    void flight.then(() => flights.delete(requestId), () => flights.delete(requestId));
    return flight;
  };
  return { preview, issue, sessions, authorizeGuiSession: operation => sessions.authorize(operation) };
}
