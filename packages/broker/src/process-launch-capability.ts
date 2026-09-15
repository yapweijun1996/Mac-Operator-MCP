import { BrokerError } from "@mac-operator/contracts";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";

const EVIDENCE_REFERENCE_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;

/**
 * Versioned host capability for launching an already-open executable.
 *
 * `ProcessSupervisor` currently uses the compensating pathname identity
 * checks. This capability is deliberately separate so a future native
 * launcher cannot be treated as available merely because a pathname was
 * validated. The native adapter must provide both the launcher and an
 * attestation of its close-on-exec and immutable-selection properties.
 */
export interface ProcessDescriptorExecutionCapability {
  schemaVersion: "0.1";
  mechanism: "darwin-descriptor-exec-v1";
  available: boolean;
  /** Whether the proof covers every executable in a task boundary. */
  executableCoverage: "unproven" | "launcher-only" | "all-child-executables";
  immutableSelection: "enforced" | "unproven";
  closeOnExec: "enforced" | "unproven";
  evidenceRef?: string;
}

interface NativeProcessLaunchCapabilityAdapter {
  getProcessLaunchCapability?: () => unknown;
  spawnProcessFromDescriptor?: unknown;
}

/**
 * Read the host-owned descriptor launch capability without consulting any
 * MCP request or policy argument. Missing native support is an ordinary
 * unavailable result, not an exception that could be mistaken for success.
 */
export function inspectProcessDescriptorExecutionCapability(): ProcessDescriptorExecutionCapability {
  if (process.platform !== "darwin") return unavailableCapability();
  let native: NativeProcessLaunchCapabilityAdapter;
  try {
    native = loadNativePeerAdapter() as unknown as NativeProcessLaunchCapabilityAdapter;
  } catch {
    return unavailableCapability();
  }
  if (typeof native.getProcessLaunchCapability !== "function" ||
      typeof native.spawnProcessFromDescriptor !== "function") {
    return unavailableCapability();
  }
  try {
    return parseProcessDescriptorExecutionCapability(native.getProcessLaunchCapability());
  } catch {
    return unavailableCapability();
  }
}

/**
 * Require the complete host boundary before a caller can select descriptor
 * execution. This function is intentionally not a pathname fallback.
 */
export function requireProcessDescriptorExecution(): ProcessDescriptorExecutionCapability {
  const capability = inspectProcessDescriptorExecutionCapability();
  if (!capability.available || capability.executableCoverage !== "all-child-executables" ||
      capability.immutableSelection !== "enforced" || capability.closeOnExec !== "enforced") {
    throw new BrokerError("POLICY_DENIED", "Kernel descriptor executable launch is unavailable");
  }
  return capability;
}

export function parseProcessDescriptorExecutionCapability(value: unknown): ProcessDescriptorExecutionCapability {
  if (!isPlainDataRecord(value)) throw new BrokerError("POLICY_DENIED", "Process descriptor launch capability is malformed");
  const capability = value as Partial<ProcessDescriptorExecutionCapability>;
  const keys = Object.keys(value);
  const allowed = new Set(["schemaVersion", "mechanism", "available", "executableCoverage", "immutableSelection", "closeOnExec", "evidenceRef"]);
  if (keys.some((key) => !allowed.has(key)) ||
      capability.schemaVersion !== "0.1" ||
      capability.mechanism !== "darwin-descriptor-exec-v1" ||
      typeof capability.available !== "boolean" ||
      (capability.executableCoverage !== "unproven" && capability.executableCoverage !== "launcher-only" &&
       capability.executableCoverage !== "all-child-executables") ||
      (capability.immutableSelection !== "enforced" && capability.immutableSelection !== "unproven") ||
      (capability.closeOnExec !== "enforced" && capability.closeOnExec !== "unproven") ||
      (capability.evidenceRef !== undefined &&
       (typeof capability.evidenceRef !== "string" || !EVIDENCE_REFERENCE_PATTERN.test(capability.evidenceRef)))) {
    throw new BrokerError("POLICY_DENIED", "Process descriptor launch capability is malformed");
  }
  if (capability.available && (capability.executableCoverage !== "all-child-executables" ||
      capability.immutableSelection !== "enforced" || capability.closeOnExec !== "enforced" || capability.evidenceRef === undefined)) {
    throw new BrokerError("POLICY_DENIED", "Process descriptor launch capability is incomplete");
  }
  return {
    schemaVersion: "0.1",
    mechanism: "darwin-descriptor-exec-v1",
    available: capability.available,
    executableCoverage: capability.executableCoverage,
    immutableSelection: capability.immutableSelection,
    closeOnExec: capability.closeOnExec,
    ...(capability.evidenceRef === undefined ? {} : { evidenceRef: capability.evidenceRef })
  };
}

function unavailableCapability(): ProcessDescriptorExecutionCapability {
  return {
    schemaVersion: "0.1",
    mechanism: "darwin-descriptor-exec-v1",
    available: false,
    executableCoverage: "unproven",
    immutableSelection: "unproven",
    closeOnExec: "unproven"
  };
}
