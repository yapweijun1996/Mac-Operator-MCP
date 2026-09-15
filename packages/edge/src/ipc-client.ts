import { lstat, realpath } from "node:fs/promises";
import { createConnection, type Socket } from "node:net";
import { dirname, isAbsolute, resolve } from "node:path";
import {
  BrokerError,
  ERROR_CLASSES,
  decodeUtf8Strict,
  parseJsonStrict,
  type AuthenticatedBrokerResponse,
  type BrokerRequest,
  type BrokerResult
} from "@mac-operator/contracts";

const ERROR_CLASS_SET = new Set<string>(ERROR_CLASSES);

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
      parsed = parseJsonStrict(rawResponse);
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
      socket.on("end", () => {
        try { finish(undefined, decodeUtf8Strict(Buffer.concat(chunks)).trim()); }
        catch { finish(new BrokerError("AUTH_INVALID", "Broker IPC response is not valid UTF-8")); }
      });
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

export function isAuthenticatedResponse(value: unknown): value is AuthenticatedBrokerResponse {
  if (!isPlainDataRecord(value) || !hasExactKeys(value, [
    "protocolVersion", "requestPayloadDigest", "authenticationKeyId", "responseDigest", "authenticationProof", "response"
  ])) return false;
  if (value.protocolVersion !== "0.1" ||
      !/^[a-f0-9]{64}$/u.test(value.requestPayloadDigest as string) ||
      !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/u.test(value.authenticationKeyId as string) ||
      !/^[a-f0-9]{64}$/u.test(value.responseDigest as string) ||
      !/^[a-f0-9]{64}$/u.test(value.authenticationProof as string) ||
      !isPlainDataRecord(value.response)) return false;
  return isBrokerResult(value.response);
}

function isBrokerResult(value: unknown): value is BrokerResult {
  if (!isPlainDataRecord(value)) return false;
  const durationMs = value.duration_ms;
  if (typeof value.ok !== "boolean" ||
      typeof value.request_id !== "string" || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,240}$/u.test(value.request_id) ||
      typeof value.tool !== "string" || !/^mac_[A-Za-z0-9_]{1,127}$/u.test(value.tool) ||
      !Number.isSafeInteger(durationMs)) return false;
  const safeDurationMs = durationMs as number;
  if (safeDurationMs < 0 || safeDurationMs > 86_400_000) return false;
  if (value.ok === true) {
    if (!hasExactKeys(value, ["ok", "request_id", "tool", "result_class", "data", "warnings", "truncated", "verification", "duration_ms"]) ||
        value.result_class !== "SUCCEEDED" || typeof value.truncated !== "boolean" ||
        !Array.isArray(value.warnings) || value.warnings.length > 32 ||
        !value.warnings.every((warning) => typeof warning === "string" && warning.length <= 4_096) ||
        !isPlainDataRecord(value.verification)) return false;
    return true;
  }
  if (!hasExactKeys(value, ["ok", "request_id", "tool", "result_class", "error", "duration_ms"]) ||
      typeof value.result_class !== "string" ||
      !ERROR_CLASS_SET.has(value.result_class) ||
      !isPlainDataRecord(value.error) || !hasExactKeys(value.error, ["message", "retryable"]) ||
      typeof value.error.message !== "string" || value.error.message.length > 4_096 || typeof value.error.retryable !== "boolean") return false;
  return true;
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const keys = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return keys.length === sortedExpected.length && keys.every((key, index) => key === sortedExpected[index]);
}

function isPlainDataRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  try {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) return false;
    const names = Object.getOwnPropertyNames(value);
    if (Object.getOwnPropertySymbols(value).length > 0 || names.length !== Object.keys(value).length) return false;
    for (const name of names) {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      if (descriptor === undefined || !("value" in descriptor)) return false;
    }
    return true;
  } catch {
    return false;
  }
}
