import { randomUUID } from "node:crypto";
import {
  CONTRACT_VERSION,
  PROTOCOL_VERSION,
  signRequest,
  verifyBrokerResponse,
  type AuthenticatedBrokerResponse,
  type BrokerRequest,
  type PrincipalContext
} from "@mac-operator/contracts";

export class EdgeRequestFactory {
  constructor(private readonly options: {
    authenticationKey: Buffer;
    authenticationKeyId: string;
    brokerAudience: string;
    policyVersion: () => string;
    now?: () => number;
    randomId?: () => string;
  }) {
    if (options.authenticationKey.byteLength < 32) throw new Error("Edge authentication key must contain at least 32 bytes");
  }

  create(tool: string, argumentsValue: Readonly<Record<string, unknown>>, principal: PrincipalContext): BrokerRequest {
    const now = (this.options.now ?? Date.now)();
    const randomId = this.options.randomId ?? randomUUID;
    const request = signRequest({
      protocolVersion: PROTOCOL_VERSION,
      requestId: randomId(),
      contractVersion: CONTRACT_VERSION,
      tool,
      arguments: argumentsValue,
      principal,
      timestampMs: now,
      nonce: randomId(),
      policyAudience: this.options.brokerAudience,
      policyVersion: this.options.policyVersion(),
      authenticationKeyId: this.options.authenticationKeyId
    }, this.options.authenticationKey);
    return request;
  }

  verifyResponse(request: BrokerRequest, response: AuthenticatedBrokerResponse): boolean {
    return verifyBrokerResponse(request, response, this.options.authenticationKey);
  }
}
