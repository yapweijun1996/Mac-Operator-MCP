import { lstat } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import { isAbsolute } from "node:path";
import {
  BrokerError,
  type AuthenticatedBrokerResponse,
  type BrokerRequest,
  type BrokerResult
} from "@mac-operator/contracts";

export type BrokerResponseVerifier = (
  request: BrokerRequest,
  response: AuthenticatedBrokerResponse
) => boolean;

export class BrokerIpcClient {
  private readonly timeoutMs: number;
  private readonly maxResponseBytes: number;

  constructor(
    private readonly socketPath: string,
    private readonly verifyResponse: BrokerResponseVerifier,
    options: { timeoutMs?: number; maxResponseBytes?: number } = {}
  ) {
    if (!isAbsolute(socketPath)) throw new Error("Broker IPC socket path must be absolute");
    this.timeoutMs = options.timeoutMs ?? 15_000;
    this.maxResponseBytes = options.maxResponseBytes ?? 2_097_152;
  }

  async call(request: BrokerRequest, signal?: AbortSignal): Promise<BrokerResult> {
    const socketStat = await lstat(this.socketPath);
    const currentUid = process.getuid?.();
    if (
      !socketStat.isSocket() ||
      socketStat.isSymbolicLink() ||
      currentUid === undefined ||
      socketStat.uid !== currentUid ||
      (socketStat.mode & 0o177) !== 0
    ) {
      throw new BrokerError("AUTH_INVALID", "Broker IPC target failed ownership or permission checks");
    }
    const rawResponse = await this.exchange(`${JSON.stringify(request)}\n`, signal);
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawResponse) as unknown;
    } catch {
      throw new BrokerError("AUTH_INVALID", "Broker IPC response is not valid JSON");
    }
    if (!isAuthenticatedResponse(parsed)) throw new BrokerError("AUTH_INVALID", "Broker IPC response is not authenticated");
    if (!this.verifyResponse(request, parsed)) {
      throw new BrokerError("AUTH_INVALID", "Broker IPC response authentication failed");
    }
    if (
      parsed.response.request_id !== request.requestId ||
      parsed.response.tool !== request.tool
    ) {
      throw new BrokerError("AUTH_INVALID", "Broker IPC response identity does not match the request");
    }
    return parsed.response;
  }

  private exchange(body: string, signal?: AbortSignal): Promise<string> {
    return new Promise((resolve, reject) => {
      const socket = createConnection(this.socketPath);
      let settled = false;
      let total = 0;
      const chunks: Buffer[] = [];
      const finish = (error?: Error, value?: string) => {
        if (settled) return;
        settled = true;
        signal?.removeEventListener("abort", onAbort);
        socket.destroy();
        if (error) reject(error);
        else resolve(value ?? "");
      };
      const onAbort = () => finish(new BrokerError("CANCELLED", "Broker IPC request was cancelled"));
      signal?.addEventListener("abort", onAbort, { once: true });
      if (signal?.aborted) return onAbort();
      socket.setTimeout(this.timeoutMs, () => finish(new BrokerError("TIMEOUT", "Broker IPC request timed out", true)));
      socket.on("connect", () => socket.write(body));
      socket.on("data", (chunk: Buffer) => {
        total += chunk.byteLength;
        if (total > this.maxResponseBytes) return finish(new BrokerError("OUTPUT_LIMIT", "Broker IPC response exceeded the byte limit"));
        chunks.push(chunk);
      });
      socket.on("end", () => finish(undefined, Buffer.concat(chunks).toString("utf8").trim()));
      socket.on("error", () => finish(new BrokerError("EXECUTION_FAILED", "Broker IPC transport failed", true)));
    });
  }
}

function isAuthenticatedResponse(value: unknown): value is AuthenticatedBrokerResponse {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  return record.protocolVersion === "0.1" &&
    typeof record.requestPayloadDigest === "string" &&
    typeof record.authenticationKeyId === "string" &&
    typeof record.responseDigest === "string" &&
    typeof record.authenticationProof === "string" &&
    record.response !== null && typeof record.response === "object" && !Array.isArray(record.response);
}
