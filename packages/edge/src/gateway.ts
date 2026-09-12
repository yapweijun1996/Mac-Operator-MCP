import type { BrokerResult, PrincipalContext } from "@mac-operator/contracts";
import { BrokerIpcClient } from "./ipc-client.js";
import { EdgeRequestFactory } from "./request-factory.js";

export interface BrokerGateway {
  execute(
    tool: string,
    argumentsValue: Readonly<Record<string, unknown>>,
    principal: PrincipalContext,
    signal?: AbortSignal
  ): Promise<BrokerResult>;
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
}
