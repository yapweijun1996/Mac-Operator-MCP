import type { ErrorClass } from "./errors.js";

export const CONTRACT_VERSION = "0.1" as const;
export const PROTOCOL_VERSION = "0.1" as const;

export const SCOPES = [
  "mac.control.read", "mac.policy.explain", "mac.system.read", "mac.storage.read",
  "mac.process.read", "mac.log.read", "mac.network.read", "mac.service.read",
  "mac.package.read", "mac.files.read", "mac.files.search", "mac.files.hash", "mac.files.write",
  "mac.project.read", "mac.project.write", "mac.git.read", "mac.git.write", "mac.git.push",
  "mac.agent.read", "mac.agent.run", "mac.audit.read",
  "mac.terminal.exec", "mac.task.run", "mac.job.read", "mac.job.cancel", "mac.docker.read",
  "mac.app.read", "mac.app.control", "mac.ui.observe", "mac.ui.control",
  "mac.service.control",
  "mac.priv.service", "mac.priv.package", "mac.priv.power"
] as const;

export type Scope = (typeof SCOPES)[number];

export type CapabilityFamily =
  | "read"
  | "write"
  | "process"
  | "network"
  | "gui"
  | "destructive"
  | "privileged";

export const CAPABILITY_FAMILIES = [
  "read", "write", "process", "network", "gui", "destructive", "privileged"
] as const satisfies readonly CapabilityFamily[];

export interface PrincipalContext {
  principalId: string;
  sessionId: string;
  issuer: string;
  audience: string;
  scopes: readonly Scope[];
  issuedAtMs: number;
  expiresAtMs: number;
  edgeId: string;
}

export interface UnsignedBrokerRequest {
  protocolVersion: typeof PROTOCOL_VERSION;
  requestId: string;
  contractVersion: typeof CONTRACT_VERSION;
  tool: string;
  arguments: Readonly<Record<string, unknown>>;
  principal: PrincipalContext;
  timestampMs: number;
  nonce: string;
  policyAudience: string;
  policyVersion: string;
  authenticationKeyId: string;
}

export interface BrokerRequest extends UnsignedBrokerRequest {
  payloadDigest: string;
  authenticationProof: string;
}

export interface BrokerSuccess {
  ok: true;
  request_id: string;
  tool: string;
  result_class: "SUCCEEDED";
  data: unknown;
  warnings: string[];
  truncated: boolean;
  verification: Record<string, unknown>;
  duration_ms: number;
}

export interface BrokerFailure {
  ok: false;
  request_id: string;
  tool: string;
  result_class: ErrorClass;
  error: { message: string; retryable: boolean };
  duration_ms: number;
}

export type BrokerResult = BrokerSuccess | BrokerFailure;

export interface AuthenticatedBrokerResponse {
  protocolVersion: typeof PROTOCOL_VERSION;
  requestPayloadDigest: string;
  authenticationKeyId: string;
  responseDigest: string;
  authenticationProof: string;
  response: BrokerResult;
}

/**
 * Authenticated host event used by the Edge to propagate an issuer-side
 * OAuth authority loss into the Broker. This is deliberately separate from
 * MCP tool requests: it cannot execute an adapter or grant a capability.
 */
export interface UnsignedBrokerRevocationEvent {
  protocolVersion: typeof PROTOCOL_VERSION;
  eventType: "oauth_authority_revoked";
  requestId: string;
  nonce: string;
  edgeId: string;
  authenticationKeyId: string;
  principalId: string;
  sessionId: string;
  timestampMs: number;
}

export interface BrokerRevocationEvent extends UnsignedBrokerRevocationEvent {
  payloadDigest: string;
  authenticationProof: string;
}

export interface BrokerRevocationSuccess {
  ok: true;
  request_id: string;
  event_type: "oauth_authority_revoked";
  revoked: true;
  duration_ms: number;
}

export interface BrokerRevocationFailure {
  ok: false;
  request_id: string;
  event_type: "oauth_authority_revoked";
  result_class: ErrorClass;
  error: { message: string; retryable: boolean };
  duration_ms: number;
}

export type BrokerRevocationResult = BrokerRevocationSuccess | BrokerRevocationFailure;

export interface AuthenticatedBrokerRevocationResponse {
  protocolVersion: typeof PROTOCOL_VERSION;
  requestPayloadDigest: string;
  authenticationKeyId: string;
  responseDigest: string;
  authenticationProof: string;
  response: BrokerRevocationResult;
}

export interface RuntimeToolState {
  tool: string;
  planned: boolean;
  implemented: boolean;
  enabled: boolean;
  disabledReason?: string;
}
