import { BrokerError, type BrokerRequest } from "@mac-operator/contracts";

export interface EdgeAuthenticationKey {
  edgeId: string;
  keyId: string;
  key: Buffer;
  notBeforeMs: number;
  expiresAtMs: number;
}

export class EdgeKeyring {
  private readonly keys = new Map<string, EdgeAuthenticationKey>();

  constructor(keys: readonly EdgeAuthenticationKey[]) {
    for (const key of keys) this.add(key);
  }

  add(record: EdgeAuthenticationKey): void {
    if (record.key.byteLength < 32) throw new Error("Edge authentication key must contain at least 32 bytes");
    if (record.expiresAtMs <= record.notBeforeMs) throw new Error("Edge authentication key validity window is invalid");
    const identity = keyIdentity(record.edgeId, record.keyId);
    if (this.keys.has(identity)) throw new Error("Edge authentication key identity is duplicated");
    this.keys.set(identity, { ...record, key: Buffer.from(record.key) });
  }

  keyFor(request: BrokerRequest, nowMs: number): Buffer {
    const record = this.keys.get(keyIdentity(request.principal.edgeId, request.authenticationKeyId));
    if (!record) throw new BrokerError("AUTH_INVALID", "Request authentication failed");
    if (nowMs < record.notBeforeMs || nowMs >= record.expiresAtMs) {
      throw new BrokerError("AUTH_EXPIRED", "Edge authentication key is not currently valid");
    }
    return Buffer.from(record.key);
  }

  keyByIdentity(edgeId: string, keyId: string): Buffer | undefined {
    const record = this.keys.get(keyIdentity(edgeId, keyId));
    return record ? Buffer.from(record.key) : undefined;
  }

  /** Wipes loaded authentication keys when the owning Broker service stops. */
  dispose(): void {
    for (const record of this.keys.values()) record.key.fill(0);
    this.keys.clear();
  }
}

export function keyIdentity(edgeId: string, keyId: string): string {
  return `${edgeId}:${keyId}`;
}
