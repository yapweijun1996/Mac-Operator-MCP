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
import { loadProtectedEdgeAuthenticationKey } from "./authentication-key.js";
import { loadEdgeAuthenticationKeyFromBroker, type KeychainDeliveryClientOptions } from "./keychain-delivery-client.js";

export interface EdgeRequestFactoryOptions {
  authenticationKey: Buffer;
  authenticationKeyId: string;
  brokerAudience: string;
  policyVersion: () => string;
  now?: () => number;
  randomId?: () => string;
}

export class EdgeRequestFactory {
  private readonly options: EdgeRequestFactoryOptions;

  constructor(options: EdgeRequestFactoryOptions) {
    if (options.authenticationKey.byteLength < 32) throw new Error("Edge authentication key must contain at least 32 bytes");
    if (typeof options.authenticationKeyId !== "string" || !/^[A-Za-z0-9._:-]{1,128}$/u.test(options.authenticationKeyId)) {
      throw new Error("Edge authentication key ID is malformed");
    }
    this.options = {
      authenticationKey: Buffer.from(options.authenticationKey),
      authenticationKeyId: options.authenticationKeyId,
      brokerAudience: options.brokerAudience,
      policyVersion: options.policyVersion,
      ...(options.now === undefined ? {} : { now: options.now }),
      ...(options.randomId === undefined ? {} : { randomId: options.randomId })
    };
  }

  static async fromProtectedKeyFile(
    options: Omit<EdgeRequestFactoryOptions, "authenticationKey"> & {
      authenticationKeyPath: string;
      expectedAuthenticationKeyDigest: string;
    }
  ): Promise<EdgeRequestFactory> {
    const authenticationKey = await loadProtectedEdgeAuthenticationKey(
      options.authenticationKeyPath,
      options.expectedAuthenticationKeyDigest
    );
    try {
      return new EdgeRequestFactory({
        authenticationKey,
        authenticationKeyId: options.authenticationKeyId,
        brokerAudience: options.brokerAudience,
        policyVersion: options.policyVersion,
        ...(options.now === undefined ? {} : { now: options.now }),
        ...(options.randomId === undefined ? {} : { randomId: options.randomId })
      });
    } finally {
      authenticationKey.fill(0);
    }
  }

  static async fromKeychainDelivery(
    options: Omit<EdgeRequestFactoryOptions, "authenticationKey"> & KeychainDeliveryClientOptions
  ): Promise<EdgeRequestFactory> {
    if (options.authenticationKeyId !== options.keyId) {
      throw new Error("Edge authentication key IDs must match Keychain delivery configuration");
    }
    const authenticationKey = await loadEdgeAuthenticationKeyFromBroker(options);
    try {
      return new EdgeRequestFactory({
        authenticationKey,
        authenticationKeyId: options.authenticationKeyId,
        brokerAudience: options.brokerAudience,
        policyVersion: options.policyVersion,
        ...(options.now === undefined ? {} : { now: options.now }),
        ...(options.randomId === undefined ? {} : { randomId: options.randomId })
      });
    } finally {
      authenticationKey.fill(0);
    }
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

  /** Wipe the in-memory Edge-to-Broker authentication key during shutdown. */
  dispose(): void {
    this.options.authenticationKey.fill(0);
  }
}
