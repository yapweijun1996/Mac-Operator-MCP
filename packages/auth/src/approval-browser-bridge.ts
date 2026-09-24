import { BrokerError } from "@mac-operator/contracts";

export interface ApprovalBrowserPreview {
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
}

interface BrowserBridgeRequest {
  type: "approval-browser-request";
  id: string;
  operation: "preview" | "issue";
  requestId: string;
}

interface BrowserBridgeResponse {
  type: "approval-browser-response";
  id: string;
  ok: boolean;
  preview?: ApprovalBrowserPreview;
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
      !["preview", "issue"].includes(String(record.operation)) || typeof record.requestId !== "string" ||
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
