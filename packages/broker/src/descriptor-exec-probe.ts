import { BrokerError } from "@mac-operator/contracts";
import { loadNativePeerAdapter } from "./peer-credentials.js";
import { isPlainDataRecord } from "./plain-record.js";

const EVIDENCE_REFERENCE_PATTERN = /^[A-Za-z0-9._:/-]{1,256}$/u;

/**
 * Read-only evidence about host descriptor-execution primitives.
 *
 * This is intentionally not a launch capability. A successful fixed
 * `/usr/bin/true` probe cannot prove that arbitrary Broker-selected
 * executables or their descendants are bound to immutable descriptors.
 */
export interface DescriptorExecProbe {
  schemaVersion: "0.1";
  mechanism: "darwin-descriptor-exec-probe-v1";
  fexecveSymbol: "absent" | "present";
  fexecveExecution: "unavailable" | "open-failed" | "fork-failed" | "passed" | "failed" | "wait-failed" | "timeout";
  execveatSymbol: "absent";
  executableCoverage: "unproven" | "single-fixed-executable";
  immutableSelection: "unproven" | "single-fixed-executable";
  /** Experimental fixed executable test through an inherited O_EXEC descriptor. */
  descriptorPathOpen?: "passed" | "failed";
  descriptorPathExecution?: "open-failed" | "fork-failed" | "passed" | "failed" | "wait-failed" | "timeout";
  evidenceRef: string;
}

interface NativeDescriptorExecProbeAdapter {
  getDescriptorExecProbe?: () => unknown;
}

/** Read host-owned probe evidence without consulting MCP arguments or policy. */
export function inspectDescriptorExecProbe(): DescriptorExecProbe {
  if (process.platform !== "darwin") return unavailableProbe();
  let native: NativeDescriptorExecProbeAdapter;
  try {
    native = loadNativePeerAdapter() as unknown as NativeDescriptorExecProbeAdapter;
  } catch {
    return unavailableProbe();
  }
  if (typeof native.getDescriptorExecProbe !== "function") return unavailableProbe();
  try {
    return parseDescriptorExecProbe(native.getDescriptorExecProbe());
  } catch {
    return unavailableProbe();
  }
}

export function parseDescriptorExecProbe(value: unknown): DescriptorExecProbe {
  if (!isPlainDataRecord(value)) throw new BrokerError("POLICY_DENIED", "Descriptor execution probe is malformed");
  const probe = value as Partial<DescriptorExecProbe>;
  const allowed = new Set([
    "descriptorPathExecution", "descriptorPathOpen", "evidenceRef", "execveatSymbol",
    "executableCoverage", "fexecveExecution", "fexecveSymbol", "immutableSelection", "mechanism", "schemaVersion"
  ]);
  const validExecution = new Set<DescriptorExecProbe["fexecveExecution"]>([
    "unavailable", "open-failed", "fork-failed", "passed", "failed", "wait-failed", "timeout"
  ]);
  const validDescriptorPathExecution = new Set<NonNullable<DescriptorExecProbe["descriptorPathExecution"]>>([
    "open-failed", "fork-failed", "passed", "failed", "wait-failed", "timeout"
  ]);
  if (Object.keys(value).some((key) => !allowed.has(key)) ||
      probe.schemaVersion !== "0.1" ||
      probe.mechanism !== "darwin-descriptor-exec-probe-v1" ||
      (probe.fexecveSymbol !== "absent" && probe.fexecveSymbol !== "present") ||
      typeof probe.fexecveExecution !== "string" || !validExecution.has(probe.fexecveExecution) ||
      probe.execveatSymbol !== "absent" ||
      (probe.executableCoverage !== "unproven" && probe.executableCoverage !== "single-fixed-executable") ||
      (probe.immutableSelection !== "unproven" && probe.immutableSelection !== "single-fixed-executable") ||
      (probe.descriptorPathOpen !== undefined && probe.descriptorPathOpen !== "passed" && probe.descriptorPathOpen !== "failed") ||
      (probe.descriptorPathExecution !== undefined && (typeof probe.descriptorPathExecution !== "string" || !validDescriptorPathExecution.has(probe.descriptorPathExecution))) ||
      typeof probe.evidenceRef !== "string" || !EVIDENCE_REFERENCE_PATTERN.test(probe.evidenceRef)) {
    throw new BrokerError("POLICY_DENIED", "Descriptor execution probe is malformed");
  }
  const passed = probe.fexecveExecution === "passed";
  if ((probe.fexecveSymbol === "absent" && probe.fexecveExecution !== "unavailable") ||
      (passed && (probe.executableCoverage !== "single-fixed-executable" || probe.immutableSelection !== "single-fixed-executable")) ||
      (!passed && (probe.executableCoverage !== "unproven" || probe.immutableSelection !== "unproven"))) {
    throw new BrokerError("POLICY_DENIED", "Descriptor execution probe is inconsistent");
  }
  if ((probe.descriptorPathOpen === "failed" && probe.descriptorPathExecution !== "open-failed") ||
      (probe.descriptorPathOpen === "passed" && probe.descriptorPathExecution === "open-failed") ||
      (probe.descriptorPathOpen === undefined && probe.descriptorPathExecution !== undefined) ||
      (probe.descriptorPathOpen !== undefined && probe.descriptorPathExecution === undefined)) {
    throw new BrokerError("POLICY_DENIED", "Descriptor path execution probe is inconsistent");
  }
  return {
    schemaVersion: "0.1",
    mechanism: "darwin-descriptor-exec-probe-v1",
    fexecveSymbol: probe.fexecveSymbol,
    fexecveExecution: probe.fexecveExecution,
    execveatSymbol: "absent",
    executableCoverage: probe.executableCoverage,
    immutableSelection: probe.immutableSelection,
    ...(probe.descriptorPathOpen === undefined ? {} : { descriptorPathOpen: probe.descriptorPathOpen }),
    ...(probe.descriptorPathExecution === undefined ? {} : { descriptorPathExecution: probe.descriptorPathExecution }),
    evidenceRef: probe.evidenceRef
  };
}

function unavailableProbe(): DescriptorExecProbe {
  return {
    schemaVersion: "0.1",
    mechanism: "darwin-descriptor-exec-probe-v1",
    fexecveSymbol: "absent",
    fexecveExecution: "unavailable",
    execveatSymbol: "absent",
    executableCoverage: "unproven",
    immutableSelection: "unproven",
    evidenceRef: "mac-operator-native-descriptor-exec-probe-unavailable-v1"
  };
}
