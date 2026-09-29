import type { GuiSessionView } from "./gui-session-approval.js";
import { BrokerError } from "@mac-operator/contracts";

export interface ApprovalBrowserPreview {
  sessionEligible?: boolean;
  requestId: string;
  requestingPrincipalId: string;
  tool: string;
  contractVersion: string;
  targetKind: string;
  targetRef: string;
  payloadDigest: string;
  policyVersion: string;
  approvalClass: string;
  unattended: boolean;
  expiresAtMs: number;
}

export interface ApprovalBrowserIssuanceResult {
  approvalId: string;
  expiresAtMs: number;
  revision: number;
}

export interface ApprovalBrowserBridge {
  preview(requestId: string): Promise<ApprovalBrowserPreview | undefined>;
  issue(requestId: string): Promise<ApprovalBrowserIssuanceResult>;
  startSession?(requestId: string): Promise<GuiSessionView>;
  startPersistentSession?(requestId: string): Promise<GuiSessionView>;
  listSessions?(): Promise<GuiSessionView[]>;
  sessionStatus?(id: string): Promise<GuiSessionView | undefined>;
  revokeSession?(id: string): Promise<void>;
}

interface BrowserBridgeRequest {
  type: "approval-browser-request";
  id: string;
  operation: "preview" | "issue" | "session-start" | "session-persistent-start" | "session-list" | "session-status" | "session-revoke";
  requestId: string;
}

interface BrowserBridgeResponse {
  type: "approval-browser-response";
  id: string;
  ok: boolean;
  preview?: ApprovalBrowserPreview;
  session?: GuiSessionView;
  sessions?: GuiSessionView[];
  approvalId?: string;
  expiresAtMs?: number;
  revision?: number;
}

/**
 * Auth is the browser-facing process, while the supervisor owns BrokerStore
 * and the issuer key. This bridge keeps the browser process keyless and sends
 * only the non-secret preview or bounded issuance readback over Node IPC.
 */
export function createProcessApprovalBrowserBridge(): ApprovalBrowserBridge & { close(): void } {
  if (typeof process.send !== "function") throw new Error("Approval browser bridge requires supervisor IPC");
  const pending = new Map<string, { resolve: (value: BrowserBridgeResponse) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }>();
  let sequence = 0;
  let closed = false;
  const onMessage = (raw: unknown) => {
    const response = parseResponse(raw);
    if (!response) return;
    const request = pending.get(response.id);
    if (!request) return;
    pending.delete(response.id);
    clearTimeout(request.timer);
    request.resolve(response);
  };
  process.on("message", onMessage);
  const call = (operation: BrowserBridgeRequest["operation"], requestId: string): Promise<BrowserBridgeResponse> => {
    if (closed) return Promise.reject(new BrokerError("CANCELLED", "Approval browser bridge is closed"));
    if (!/^[A-Za-z0-9._:@/+-]{1,128}$/u.test(requestId)) return Promise.reject(new BrokerError("PRECONDITION_FAILED", "Approval request ID is malformed"));
    const id = `approval-browser:${++sequence}`;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        pending.delete(id);
        reject(new BrokerError("TIMEOUT", "Approval browser bridge timed out", true));
      }, 15_000);
      pending.set(id, { resolve, reject, timer });
      try {
        process.send!({ type: "approval-browser-request", id, operation, requestId } satisfies BrowserBridgeRequest, error => {
          if (error) {
            pending.delete(id);
            clearTimeout(timer);
            reject(new BrokerError("EXECUTION_FAILED", "Approval browser bridge transport failed", true));
          }
        });
      } catch {
        pending.delete(id);
        clearTimeout(timer);
        reject(new BrokerError("EXECUTION_FAILED", "Approval browser bridge transport failed", true));
      }
    });
  };
  return {
    async preview(requestId) {
      const response = await call("preview", requestId);
      if (!response.ok) return undefined;
      return response.preview;
    },
    async issue(requestId) {
      const response = await call("issue", requestId);
      if (!response.ok || response.approvalId === undefined || response.expiresAtMs === undefined || response.revision === undefined) {
        throw new BrokerError("POLICY_DENIED", "Approval was not issued");
      }
      return { approvalId: response.approvalId, expiresAtMs: response.expiresAtMs, revision: response.revision };
    },
    async startSession(requestId) {
      const response = await call("session-start", requestId);
      if (!response.ok || !response.session) throw new BrokerError("POLICY_DENIED", "GUI session was not granted");
      return response.session;
    },
    async startPersistentSession(requestId) {
      const response = await call("session-persistent-start", requestId);
      if (!response.ok || !response.session?.persistent) throw new BrokerError("POLICY_DENIED", "Persistent browser access was not granted");
      return response.session;
    },
    async listSessions() {
      const response = await call("session-list", "owner");
      if (!response.ok || !response.sessions) throw new BrokerError("EXECUTION_FAILED", "Browser access is unavailable");
      return response.sessions;
    },
    async sessionStatus(id) {
      const response = await call("session-status", id);
      return response.ok ? response.session : undefined;
    },
    async revokeSession(id) {
      const response = await call("session-revoke", id);
      if (!response.ok) throw new BrokerError("EXECUTION_FAILED", "GUI session could not be ended");
    },
    close() {
      if (closed) return;
      closed = true;
      process.off("message", onMessage);
      for (const [id, request] of pending) {
        clearTimeout(request.timer);
        request.reject(new BrokerError("CANCELLED", "Approval browser bridge is closed"));
        pending.delete(id);
      }
    }
  };
}

export function parseApprovalBrowserRequest(value: unknown): BrowserBridgeRequest | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (record.type !== "approval-browser-request" || typeof record.id !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(record.id) ||
      !["preview", "issue", "session-start", "session-persistent-start", "session-list", "session-status", "session-revoke"].includes(String(record.operation)) || typeof record.requestId !== "string" ||
      !/^[A-Za-z0-9._:@/+-]{1,128}$/u.test(record.requestId) || Object.keys(record).some(key => !["type", "id", "operation", "requestId"].includes(key))) return undefined;
  return record as unknown as BrowserBridgeRequest;
}

function parseResponse(value: unknown): BrowserBridgeResponse | undefined {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return undefined;
  const record = value as Record<string, unknown>;
  if (record.type !== "approval-browser-response" || typeof record.id !== "string" ||
      !/^[A-Za-z0-9._:-]{1,128}$/u.test(record.id) || typeof record.ok !== "boolean") return undefined;
  return record as unknown as BrowserBridgeResponse;
}
