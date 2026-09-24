import { BrokerError } from "@mac-operator/contracts";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";

const EVIDENCE_REFERENCE_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;

/**
 * Host capability for transferring already-open descriptors over a native
 * UNIX socket. This is intentionally separate from executable launch: a
 * successful SCM_RIGHTS probe cannot prove fexec/execveat, immutable program
 * selection, peer authorization, or sandbox isolation.
 */
export interface DescriptorHandoffCapability {
  schemaVersion: "0.1";
  mechanism: "darwin-scm-rights-v1";
  available: boolean;
  fdTransfer: "verified" | "unproven";
  fdCloseOnExec: "verified" | "unproven";
  peerAuthentication: "native-peer-credentials" | "unproven";
  immutableSelection: "enforced" | "unproven";
  evidenceRef?: string;
}

interface NativeDescriptorHandoffAdapter {
  getDescriptorHandoffCapability?: () => unknown;
}

/** Read only the host-owned native transport probe; MCP arguments are absent. */
export function inspectDescriptorHandoffCapability(): DescriptorHandoffCapability {
  if (process.platform !== "darwin") return unavailableCapability();
  let native: NativeDescriptorHandoffAdapter;
  try {
    native = loadNativePeerAdapter() as unknown as NativeDescriptorHandoffAdapter;
  } catch {
    return unavailableCapability();
  }
  if (typeof native.getDescriptorHandoffCapability !== "function") return unavailableCapability();
  try {
    return parseDescriptorHandoffCapability(native.getDescriptorHandoffCapability());
  } catch {
    return unavailableCapability();
  }
}

/** Require only the ancillary-FD transport; this does not authorize process launch. */
export function requireDescriptorHandoffTransport(): DescriptorHandoffCapability {
  const capability = inspectDescriptorHandoffCapability();
  if (!capability.available || capability.fdTransfer !== "verified" || capability.fdCloseOnExec !== "verified") {
    throw new BrokerError("POLICY_DENIED", "Native descriptor handoff transport is unavailable");
  }
  return capability;
}

export function parseDescriptorHandoffCapability(value: unknown): DescriptorHandoffCapability {
  if (!isPlainDataRecord(value)) throw new BrokerError("POLICY_DENIED", "Descriptor handoff capability is malformed");
  const capability = value as Partial<DescriptorHandoffCapability>;
  const allowed = new Set([
    "available", "evidenceRef", "fdCloseOnExec", "fdTransfer", "immutableSelection", "mechanism",
    "peerAuthentication", "schemaVersion"
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key)) ||
      capability.schemaVersion !== "0.1" || capability.mechanism !== "darwin-scm-rights-v1" ||
      typeof capability.available !== "boolean" ||
      (capability.fdTransfer !== "verified" && capability.fdTransfer !== "unproven") ||
      (capability.fdCloseOnExec !== "verified" && capability.fdCloseOnExec !== "unproven") ||
      (capability.peerAuthentication !== "native-peer-credentials" && capability.peerAuthentication !== "unproven") ||
      (capability.immutableSelection !== "enforced" && capability.immutableSelection !== "unproven") ||
      (capability.evidenceRef !== undefined &&
       (typeof capability.evidenceRef !== "string" || !EVIDENCE_REFERENCE_PATTERN.test(capability.evidenceRef)))) {
    throw new BrokerError("POLICY_DENIED", "Descriptor handoff capability is malformed");
  }
  if (capability.available && (capability.fdTransfer !== "verified" || capability.fdCloseOnExec !== "verified" || capability.evidenceRef === undefined)) {
    throw new BrokerError("POLICY_DENIED", "Descriptor handoff capability is incomplete");
  }
  return {
    schemaVersion: "0.1",
    mechanism: "darwin-scm-rights-v1",
    available: capability.available,
    fdTransfer: capability.fdTransfer,
    fdCloseOnExec: capability.fdCloseOnExec,
    peerAuthentication: capability.peerAuthentication,
    immutableSelection: capability.immutableSelection,
    ...(capability.evidenceRef === undefined ? {} : { evidenceRef: capability.evidenceRef })
  };
}

function unavailableCapability(): DescriptorHandoffCapability {
  return {
    schemaVersion: "0.1",
    mechanism: "darwin-scm-rights-v1",
    available: false,
    fdTransfer: "unproven",
    fdCloseOnExec: "unproven",
    peerAuthentication: "unproven",
    immutableSelection: "unproven"
  };
}
