import type { AuthStore } from "./store.js";
import { randomUUID } from "node:crypto";
import { guiSessionApprovalId, type BrokerStore, type GuiSessionOperation, type IssueApprovalInput } from "@mac-operator/broker";

export const GUI_SESSION_MS = 30 * 60_000;
const MAX_OPERATIONS = 500;
const APPS = ["bundle:com.google.Chrome", "bundle:com.apple.Safari"];
const TOOLS = ["mac_app_focus", "mac_ui_action", "mac_ui_type"];
export interface GuiSessionView {
  id: string;
  appId: string;
  persistent?: boolean;
  expiresAtMs: number;
  remainingOperations: number;
}
interface Grant extends GuiSessionView {
  principalId: string;
  sessionId: string;
  policyVersion: string;
  approvals: Map<string, number>;
}

/** Owner browser delegation; policy and authenticated OAuth authority remain independent. */
export class GuiSessionApprovals {
  private readonly grants = new Map<string, Grant>();
  private readonly requestGrants = new Map<string, string>();
  constructor(private readonly store: BrokerStore,
    private readonly issueExact: (approval: Omit<IssueApprovalInput, "approverPrincipalId">) => Promise<void>,
    private readonly now: () => number = Date.now,
    private readonly authStore?: AuthStore) {
    this.restore();
  }

  private restore(): void {
    for (const record of this.authStore?.browserGrants() ?? []) {
      this.requestGrants.set(record.consentRequestId, record.id);
      if (!record.revoked && !this.grants.has(record.id)) this.grants.set(record.id, {
        id: record.id, principalId: record.principalId, sessionId: record.sessionId,
        appId: record.appId, policyVersion: record.policyVersion, persistent: true,
        expiresAtMs: Number.MAX_SAFE_INTEGER, remainingOperations: Number.MAX_SAFE_INTEGER, approvals: new Map()
      });
    }
  }

  list(principalId: string): GuiSessionView[] {
    this.restore();
    return [...this.grants.values()].filter(grant => grant.principalId === principalId && this.active(grant)).map(grant => this.view(grant));
  }

  start(requestId: string, persistent = false): GuiSessionView {
    this.restore();
    if (persistent && !this.authStore) throw new Error("Persistent browser storage is unavailable");
    const previous = this.requestGrants.get(requestId);
    if (previous) {
      const active = this.status(previous);
      if (active && Boolean(active.persistent) === persistent) return active;
      throw new Error("Session consent has already been used");
    }
    const preview = this.store.approvalPreview(requestId, this.now());
    const request = this.store.requestRecord(requestId);
    const appId = preview?.targetRef.replace(/^app_window:window:/u, "");
    if (!preview || !request || preview.tool !== "mac_app_focus" || preview.approvalClass !== "trusted_gui" ||
        preview.unattended || preview.targetKind !== "app_window" || !appId || !APPS.includes(appId) ||
        this.store.isRevoked("session", request.sessionId) || this.store.isRevoked("principal", request.principalId)) {
      throw new Error("Session consent requires a current browser focus preview");
    }
    this.prune();
    if (this.grants.size >= 16 || this.requestGrants.size >= 4096) throw new Error("Too many active GUI sessions");
    const grant: Grant = { id: `gui-session:${randomUUID()}`, principalId: request.principalId,
      sessionId: request.sessionId, policyVersion: request.policyVersion, appId,
      ...(persistent ? { persistent: true } : {}),
      expiresAtMs: persistent ? Number.MAX_SAFE_INTEGER : this.now() + GUI_SESSION_MS,
      remainingOperations: persistent ? Number.MAX_SAFE_INTEGER : MAX_OPERATIONS, approvals: new Map() };
    this.audit(grant, "GUI_SESSION_GRANTED");
    if (persistent) this.authStore!.put("browser_grant", grant.id, { id: grant.id, principalId: grant.principalId,
      sessionId: grant.sessionId, appId: appId as "bundle:com.google.Chrome" | "bundle:com.apple.Safari",
      policyVersion: grant.policyVersion, consentRequestId: requestId, createdAt: this.now(), revoked: false });
    this.grants.set(grant.id, grant);
    this.requestGrants.set(requestId, grant.id);
    return this.view(grant);
  }

  status(id: string): GuiSessionView | undefined {
    const grant = this.grants.get(id);
    return grant && this.active(grant) ? this.view(grant) : undefined;
  }

  revoke(id: string): void {
    this.restore();
    const grant = this.grants.get(id);
    if (!grant) return;
    // Remove authority before audit or cleanup can fail.
    if (grant.persistent) {
      const record = this.authStore?.get("browser_grant", id);
      if (record) this.authStore!.put("browser_grant", id, { ...record, revoked: true });
    }
    this.grants.delete(id);
    for (const approvalId of grant.approvals.keys()) this.store.revokeApproval(approvalId, "GUI_SESSION_ENDED", this.now());
    this.audit(grant, "GUI_SESSION_REVOKED");
  }

  async authorize(operation: GuiSessionOperation): Promise<boolean> {
    this.restore();
    if (this.store.isRevoked("session", operation.sessionId)) return false;
    if (operation.requiresExplicitApproval || !TOOLS.includes(operation.tool) || !APPS.includes(operation.appId)) return false;
    // The Broker resolves element ownership first; reject mismatched delegation shapes too.
    if (operation.tool === "mac_app_focus"
      ? operation.targetKind !== "app_window" || operation.targetRef !== `app_window:window:${operation.appId}`
      : operation.targetKind !== "ui_element" || !/^ui_element:element:[a-f0-9]{48}$/u.test(operation.targetRef)) return false;
    const grant = [...this.grants.values()].find(candidate => this.active(candidate) &&
      candidate.principalId === operation.principalId && (candidate.persistent || candidate.sessionId === operation.sessionId) &&
      candidate.policyVersion === operation.policyVersion && candidate.appId === operation.appId);
    if (!grant || operation.expiresAtMs <= this.now()) return false;
    const approvalId = guiSessionApprovalId(operation.requestId);
    // Reserve synchronously so concurrent requests cannot exceed the use bound.
    if (!grant.persistent) grant.remainingOperations--;
    for (const [id, expiry] of grant.approvals) if (expiry <= this.now()) grant.approvals.delete(id);
    try {
      await this.issueExact({ approvalId, requestingPrincipalId: operation.principalId, tool: operation.tool,
        contractVersion: operation.contractVersion, targetKind: operation.targetKind, targetRef: operation.targetRef,
        payloadDigest: operation.payloadDigest, policyVersion: operation.policyVersion, approvalClass: "trusted_gui",
        unattended: false, issuedAtMs: this.now(), expiresAtMs: Math.min(this.now() + 30_000, grant.expiresAtMs, operation.expiresAtMs), useLimit: 1 });
      grant.approvals.set(approvalId, Math.min(this.now() + 30_000, grant.expiresAtMs, operation.expiresAtMs));
      if (!this.grants.has(grant.id) || this.now() >= grant.expiresAtMs ||
          !this.authorityActive(grant) || this.store.isRevoked("session", operation.sessionId)) {
        this.store.revokeApproval(approvalId, "GUI_SESSION_ENDED", this.now());
        throw new Error("GUI session ended during issuance");
      }
      this.audit(grant, "GUI_SESSION_OPERATION", operation.requestId, approvalId);
      return true;
    } catch (error) {
      const issued = this.store.approvalRecord(approvalId);
      if (issued && issued.revokedAtMs === null) this.store.revokeApproval(approvalId, "GUI_SESSION_ISSUANCE_FAILED", this.now());
      throw error;
    }
  }

  close(): void {
    for (const [id, grant] of this.grants) {
      if (!grant.persistent) this.revoke(id);
      else for (const approvalId of grant.approvals.keys()) this.store.revokeApproval(approvalId, "GUI_SERVICE_STOPPED", this.now());
    }
    this.grants.clear();
  }
  private authorityActive(grant: Grant): boolean {
    const record = grant.persistent ? this.authStore?.get("browser_grant", grant.id) : undefined;
    return !this.store.isRevoked("principal", grant.principalId) && (grant.persistent
      ? !!record && !record.revoked && record.principalId === grant.principalId && record.appId === grant.appId && record.policyVersion === grant.policyVersion
      : !this.store.isRevoked("session", grant.sessionId));
  }
  private active(grant: Grant): boolean {
    return this.now() < grant.expiresAtMs && grant.remainingOperations > 0 &&
      this.authorityActive(grant);
  }
  private prune(): void {
    for (const [id, grant] of this.grants) if (!this.active(grant)) this.revoke(id);
    // Consent previews expire before their session; bound replay markers as well.
    for (const [requestId, id] of this.requestGrants) if (!this.grants.has(id) && !this.store.approvalPreview(requestId, this.now())) this.requestGrants.delete(requestId);
  }
  private view(grant: Grant): GuiSessionView {
    return { ...(grant.persistent ? { persistent: true } : {}), id: grant.id, appId: grant.appId, expiresAtMs: grant.expiresAtMs, remainingOperations: grant.remainingOperations };
  }
  private audit(grant: Grant, resultClass: string, requestId?: string, approvalId?: string): void {
    this.store.appendAudit({ requestId: `gui-session-audit:${randomUUID()}`, principalId: grant.principalId,
      tool: "internal_gui_session", eventType: "decision", decision: "allow", resultClass,
      targetRef: `app_window:window:${grant.appId}`, policyVersion: grant.policyVersion,
      evidence: { guiSessionId: grant.id, sessionId: grant.sessionId, persistent: grant.persistent === true, expiresAtMs: grant.expiresAtMs,
        ...(requestId ? { operationRequestId: requestId } : {}), ...(approvalId ? { approvalId } : {}) }, timestampMs: this.now() });
  }
}
