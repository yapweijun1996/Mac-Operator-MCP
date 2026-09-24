import { CONTRACT_VERSION, PROTOCOL_VERSION } from "./types.js";

export type VersionCompatibilityDomain =
  | "edge_broker"
  | "broker_helper"
  | "authority_control"
  | "capability_discovery";

const PROTOCOL_VERSIONS = [PROTOCOL_VERSION] as const;
const CONTRACT_VERSIONS = [CONTRACT_VERSION] as const;

/**
 * The supported wire-version matrix is intentionally exact and append-only.
 * A future version must be added deliberately with compatibility tests before
 * any boundary can accept it.
 */
export const VERSION_COMPATIBILITY = Object.freeze({
  edge_broker: Object.freeze({ protocolVersions: PROTOCOL_VERSIONS, contractVersions: CONTRACT_VERSIONS }),
  broker_helper: Object.freeze({ protocolVersions: PROTOCOL_VERSIONS, contractVersions: CONTRACT_VERSIONS }),
  authority_control: Object.freeze({ protocolVersions: PROTOCOL_VERSIONS, contractVersions: [] as const }),
  capability_discovery: Object.freeze({ protocolVersions: PROTOCOL_VERSIONS, contractVersions: CONTRACT_VERSIONS })
});

export function isSupportedProtocolVersion(value: unknown): value is typeof PROTOCOL_VERSION {
  return value === PROTOCOL_VERSION;
}

export function isSupportedContractVersion(value: unknown): value is typeof CONTRACT_VERSION {
  return value === CONTRACT_VERSION;
}

export function isCompatibleVersionPair(
  domain: VersionCompatibilityDomain,
  protocolVersion: unknown,
  contractVersion?: unknown
): boolean {
  const supported = VERSION_COMPATIBILITY[domain];
  if (!supported.protocolVersions.includes(protocolVersion as typeof PROTOCOL_VERSION)) return false;
  if (supported.contractVersions.length === 0) return contractVersion === undefined;
  return supported.contractVersions.includes(contractVersion as typeof CONTRACT_VERSION);
}
