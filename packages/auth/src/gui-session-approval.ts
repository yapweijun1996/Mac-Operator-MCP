import type { AuthStore } from "./store.js";
import { randomUUID } from "node:crypto";
import { guiSessionApprovalId, validateSensitiveUiTarget, validateUiObserveRequest, type BrokerStore, type GuiSessionOperation, type IssueApprovalInput } from "@mac-operator/broker";

export const GUI_SESSION_MS = 30 * 60_000;
const MAX_OPERATIONS = 500;
const APPS = ["bundle:com.google.Chrome", "bundle:com.apple.Safari"];
const TOOLS = ["mac_app_open", "mac_app_focus", "mac_ui_action", "mac_ui_type"];

export function browserConsentApp(preview: { tool: string; approvalClass: string; unattended: boolean; targetKind: string; targetRef: string }): string | undefined {
  if (preview.approvalClass !== "trusted_gui" || preview.unattended) return undefined;
  const app = preview.tool === "mac_app_focus" && preview.targetKind === "app_window"
    ? preview.targetRef.replace(/^app_window:window:/u, "")
    : preview.tool === "mac_app_open" && preview.targetKind === "app"
      ? preview.targetRef.replace(/^app:/u, "") : undefined;
  const expected = preview.tool === "mac_app_focus" ? `app_window:window:${app}` : `app:${app}`;
  return app !== undefined && APPS.includes(app) && preview.targetRef === expected ? app : undefined;
}
export interface GuiSessionView {
  id: string;
  appId: string;
  desktop?: true;
  persistent?: boolean;
  expiresAtMs: number;
  remainingOperations: number;
}
interface Grant extends GuiSessionView {
  principalId: string;
  sessionId?: string;
  policyVersion: string;
  approvals: Map<string, number>;
}

/** Explicit owner GUI delegation; policy and authenticated OAuth authority remain independent. */
export class GuiSessionApprovals {
  private readonly grants = new Map<string, Grant>();
  private readonly requestGrants = new Map<string, string>();
  private readonly allowDesktop: boolean;
  private readonly defaultBrowserPrincipalId: string | undefined;
  constructor(private readonly store: BrokerStore,
    private readonly issueExact: (approval: Omit<IssueApprovalInput, "approverPrincipalId">) => Promise<void>,
    private readonly now: () => number = Date.now,
    private readonly authStore?: AuthStore,
    options: { allowDesktop?: boolean; defaultBrowserPrincipalId?: string } = {}) {
    this.allowDesktop = options.allowDesktop === true;
    this.defaultBrowserPrincipalId = this.authStore ? options.defaultBrowserPrincipalId : undefined;
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
    if (this.allowDesktop) for (const record of this.authStore?.desktopGrants() ?? []) {
      this.requestGrants.set(record.consentRequestId, record.id);
      if (!record.revoked && !this.grants.has(record.id)) this.grants.set(record.id, {
        id: record.id, principalId: record.principalId, policyVersion: record.policyVersion,
        appId: "desktop", desktop: true, persistent: true,
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
      if (active && !active.desktop && Boolean(active.persistent) === persistent) return active;
      throw new Error("Session consent has already been used");
    }
    const preview = this.store.approvalPreview(requestId, this.now());
    const request = this.store.requestRecord(requestId);
    const appId = preview && browserConsentApp(preview);
    if (!preview || !request || !appId ||
        this.store.isRevoked("session", request.sessionId) || this.store.isRevoked("principal", request.principalId)) {
      throw new Error("Session consent requires a current browser focus preview or browser launch preview");
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
      sessionId: request.sessionId, appId: appId as "bundle:com.google.Chrome" | "bundle:com.apple.Safari",
      policyVersion: grant.policyVersion, consentRequestId: requestId, createdAt: this.now(), revoked: false });
    this.grants.set(grant.id, grant);
    this.requestGrants.set(requestId, grant.id);
    return this.view(grant);
  }

  /** Explicit owner opt-in; browser session consent is never promoted to desktop authority. */
  startDesktop(requestId: string): GuiSessionView {
    if (!this.allowDesktop || !this.authStore) throw new Error("Desktop delegation is not enabled");
    this.restore();
    const previous = this.requestGrants.get(requestId);
    if (previous) {
      const active = this.status(previous);
      if (active?.desktop) return active;
      throw new Error("Session consent has already been used");
    }
    const preview = this.store.approvalPreview(requestId, this.now());
    const request = this.store.requestRecord(requestId);
    const appId = preview?.tool === "mac_app_focus" && preview.targetKind === "app_window"
      ? preview.targetRef.replace(/^app_window:window:/u, "")
      : preview?.tool === "mac_app_open" && preview.targetKind === "app"
      ? preview.targetRef.replace(/^app:/u, "") : undefined;
    const expected = preview?.tool === "mac_app_focus" ? `app_window:window:${appId}` : `app:${appId}`;
    if (!preview || !request || preview.approvalClass !== "trusted_gui" || preview.unattended ||
        !appId || preview.targetRef !== expected || !ordinaryGuiApp(appId) ||
        this.store.isRevoked("session", request.sessionId) || this.store.isRevoked("principal", request.principalId)) {
      throw new Error("Desktop consent requires a current concrete app focus or launch preview");
    }
    this.prune();
    if (this.grants.size >= 16 || this.requestGrants.size >= 4096) throw new Error("Too many active GUI sessions");
    const grant: Grant = { id: `gui-session:${randomUUID()}`, principalId: request.principalId,
      policyVersion: request.policyVersion, appId: "desktop", desktop: true, persistent: true,
      expiresAtMs: Number.MAX_SAFE_INTEGER, remainingOperations: Number.MAX_SAFE_INTEGER, approvals: new Map() };
    this.audit(grant, "DESKTOP_SESSION_GRANTED");
    this.authStore.put("desktop_grant", grant.id, { id: grant.id, principalId: grant.principalId,
      policyVersion: grant.policyVersion, consentRequestId: requestId, createdAt: this.now(), revoked: false });
    this.grants.set(grant.id, grant);
    this.requestGrants.set(requestId, grant.id);
    return this.view(grant);
  }

  /**
   * Owner-configured default for ordinary browsing. It creates the same persistent, audited and
   * revocable browser grant as the approval page, bound to the current policy. Explicit-approval
   * operations never reach this point, desktop authority is never created, and an owner revocation
   * at the same policy version is never undone.
   */
  private ensureDefaultBrowserGrant(operation: GuiSessionOperation): void {
    if (this.defaultBrowserPrincipalId === undefined || !this.authStore ||
        operation.principalId !== this.defaultBrowserPrincipalId || !APPS.includes(operation.appId)) return;
    const consentRequestId = `default-browser:${operation.principalId}:${operation.appId}:${operation.policyVersion}`;
    if (consentRequestId.length > 128 || this.requestGrants.has(consentRequestId)) return;
    if (this.store.isRevoked("principal", operation.principalId)) return;
    this.prune();
    if (this.grants.size >= 16 || this.requestGrants.size >= 4096) return;
    const grant: Grant = { id: `gui-session:${randomUUID()}`, principalId: operation.principalId,
      sessionId: operation.sessionId, policyVersion: operation.policyVersion, appId: operation.appId, persistent: true,
      expiresAtMs: Number.MAX_SAFE_INTEGER, remainingOperations: Number.MAX_SAFE_INTEGER, approvals: new Map() };
    this.audit(grant, "GUI_DEFAULT_BROWSER_GRANTED", operation.requestId);
    this.authStore.put("browser_grant", grant.id, { id: grant.id, principalId: grant.principalId, sessionId: operation.sessionId,
      appId: operation.appId as "bundle:com.google.Chrome" | "bundle:com.apple.Safari", policyVersion: grant.policyVersion,
      consentRequestId, createdAt: this.now(), revoked: false });
    this.grants.set(grant.id, grant);
    this.requestGrants.set(consentRequestId, grant.id);
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
      if (grant.desktop) {
        const record = this.authStore?.get("desktop_grant", id);
        if (record) this.authStore!.put("desktop_grant", id, { ...record, revoked: true });
      } else {
        const record = this.authStore?.get("browser_grant", id);
        if (record) this.authStore!.put("browser_grant", id, { ...record, revoked: true });
      }
    }
    this.grants.delete(id);
    for (const approvalId of grant.approvals.keys()) this.store.revokeApproval(approvalId, "GUI_SESSION_ENDED", this.now());
    this.audit(grant, "GUI_SESSION_REVOKED");
  }

  async authorize(operation: GuiSessionOperation): Promise<boolean> {
    this.restore();
    if (this.store.isRevoked("session", operation.sessionId)) return false;
    if (operation.requiresExplicitApproval || !TOOLS.includes(operation.tool) || !ordinaryGuiApp(operation.appId)) return false;
    // The Broker resolves element ownership first; reject mismatched delegation shapes too.
    if (operation.tool === "mac_app_open"
      ? operation.targetKind !== "app" || operation.targetRef !== `app:${operation.appId}`
      : operation.tool === "mac_app_focus"
      ? operation.targetKind !== "app_window" || operation.targetRef !== `app_window:window:${operation.appId}`
      : operation.targetKind !== "ui_element" || !/^ui_element:element:[a-f0-9]{48}$/u.test(operation.targetRef)) return false;
    this.ensureDefaultBrowserGrant(operation);
    const grant = [...this.grants.values()].find(candidate => this.active(candidate) &&
      candidate.principalId === operation.principalId && (candidate.persistent || candidate.sessionId === operation.sessionId) &&
      candidate.policyVersion === operation.policyVersion && (candidate.desktop
        ? this.allowDesktop : candidate.appId === operation.appId));
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
          !this.authorityActive(grant) || this.now() >= operation.expiresAtMs || this.store.isRevoked("session", operation.sessionId)) {
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
    if (grant.desktop) {
      const record = this.allowDesktop ? this.authStore?.get("desktop_grant", grant.id) : undefined;
      return !this.store.isRevoked("principal", grant.principalId) && !!record && !record.revoked &&
        record.principalId === grant.principalId && record.policyVersion === grant.policyVersion;
    }
    const record = grant.persistent ? this.authStore?.get("browser_grant", grant.id) : undefined;
    return !this.store.isRevoked("principal", grant.principalId) && (grant.persistent
      ? !!record && !record.revoked && record.principalId === grant.principalId && record.appId === grant.appId && record.policyVersion === grant.policyVersion
      : grant.sessionId !== undefined && !this.store.isRevoked("session", grant.sessionId));
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
    return { ...(grant.persistent ? { persistent: true } : {}), ...(grant.desktop ? { desktop: true } : {}),
      id: grant.id, appId: grant.appId, expiresAtMs: grant.expiresAtMs, remainingOperations: grant.remainingOperations };
  }
  private audit(grant: Grant, resultClass: string, requestId?: string, approvalId?: string): void {
    this.store.appendAudit({ requestId: `gui-session-audit:${randomUUID()}`, principalId: grant.principalId,
      tool: "internal_gui_session", eventType: "decision", decision: "allow", resultClass,
      targetRef: grant.desktop ? "owner-desktop" : `app_window:window:${grant.appId}`, policyVersion: grant.policyVersion,
      evidence: { guiSessionId: grant.id, ...(grant.sessionId ? { sessionId: grant.sessionId } : {}),
        desktop: grant.desktop === true, persistent: grant.persistent === true, expiresAtMs: grant.expiresAtMs,
        ...(requestId ? { operationRequestId: requestId } : {}), ...(approvalId ? { approvalId } : {}) }, timestampMs: this.now() });
  }
}

function ordinaryGuiApp(appId: string): boolean {
  try {
    validateUiObserveRequest(appId);
    validateSensitiveUiTarget(appId);
    return true;
  } catch { return false; }
}
