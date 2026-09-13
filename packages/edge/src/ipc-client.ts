import { lstat, realpath } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
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
    const socketIdentity = await validateBrokerSocketTarget(this.socketPath);
    const rawResponse = await this.exchange(`${JSON.stringify(request)}\n`, signal, socketIdentity);
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

  private exchange(
    body: string,
    signal: AbortSignal | undefined,
    expectedIdentity: { dev: number; ino: number }
  ): Promise<string> {
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
      socket.on("connect", () => {
        void lstat(this.socketPath).then((after) => {
          if (!after.isSocket() || after.isSymbolicLink() || after.dev !== expectedIdentity.dev || after.ino !== expectedIdentity.ino) {
            finish(new BrokerError("AUTH_INVALID", "Broker IPC target changed while connecting"));
            return;
          }
          socket.write(body);
        }).catch(() => finish(new BrokerError("AUTH_INVALID", "Broker IPC target could not be revalidated")));
      });
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

export async function validateBrokerSocketTarget(socketPath: string): Promise<{ dev: number; ino: number }> {
  if (!isAbsolute(socketPath) || resolve(socketPath) !== socketPath || socketPath.includes("\0")) {
    throw new BrokerError("AUTH_INVALID", "Broker IPC socket path is not canonical");
  }
  const parentPath = dirname(socketPath);
  const parent = await lstat(parentPath);
  const currentUid = process.getuid?.();
  if (!parent.isDirectory() || parent.isSymbolicLink() || currentUid === undefined || parent.uid !== currentUid || (parent.mode & 0o077) !== 0) {
    throw new BrokerError("AUTH_INVALID", "Broker IPC socket directory failed ownership or permission checks");
  }
  let canonicalParent: string;
  try {
    canonicalParent = await realpath(parentPath);
  } catch {
    throw new BrokerError("AUTH_INVALID", "Broker IPC socket directory could not be canonicalized");
  }
  const canonicalParentStat = await lstat(canonicalParent);
  if (!canonicalParentStat.isDirectory() || canonicalParentStat.dev !== parent.dev || canonicalParentStat.ino !== parent.ino) {
    throw new BrokerError("AUTH_INVALID", "Broker IPC socket directory target changed while canonicalizing");
  }
  const socket = await lstat(socketPath);
  if (!socket.isSocket() || socket.isSymbolicLink() || currentUid === undefined || socket.uid !== currentUid || (socket.mode & 0o177) !== 0) {
    throw new BrokerError("AUTH_INVALID", "Broker IPC target failed ownership or permission checks");
  }
  return { dev: socket.dev, ino: socket.ino };
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
