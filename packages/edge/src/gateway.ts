import { BrokerError, type BrokerResult, type PrincipalContext } from "@mac-operator/contracts";
import { BrokerIpcClient } from "./ipc-client.js";
import { EdgeRequestFactory } from "./request-factory.js";

export interface BrokerGateway {
  execute(
    tool: string,
    argumentsValue: Readonly<Record<string, unknown>>,
    principal: PrincipalContext,
    signal?: AbortSignal
  ): Promise<BrokerResult>;
  /** Host-only authority propagation; this is not an MCP capability. */
  revokeSession?(edgeId: string, principalId: string, sessionId: string): Promise<void>;
}

export class AuthenticatedIpcBrokerGateway implements BrokerGateway {
  constructor(
    private readonly requestFactory: EdgeRequestFactory,
    private readonly client: BrokerIpcClient
  ) {}

  execute(
    tool: string,
    argumentsValue: Readonly<Record<string, unknown>>,
    principal: PrincipalContext,
    signal?: AbortSignal
  ): Promise<BrokerResult> {
    return this.client.call(this.requestFactory.create(tool, argumentsValue, principal), signal);
  }

  async revokeSession(edgeId: string, principalId: string, sessionId: string): Promise<void> {
    const event = this.requestFactory.createRevocationEvent(edgeId, principalId, sessionId);
    const response = await this.client.revokeSession(
      event,
      (candidate, envelope) => this.requestFactory.verifyRevocationResponse(candidate, envelope)
    );
    if (!response.ok) throw new BrokerError(response.result_class, response.error.message, response.error.retryable);
  }
}
