import { BrokerError } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";
import {
  authorizePeerCredentials,
  loadNativePeerAdapter,
  parsePeerCredentials,
  type PeerCredentialPolicy,
  type PeerCredentials
} from "./peer-credentials.js";
import { requireDescriptorHandoffTransport } from "./descriptor-handoff-capability.js";

export const DESCRIPTOR_HANDOFF_MAX_PAYLOAD_BYTES = 64 * 1024;
export const DESCRIPTOR_HANDOFF_MAX_DESCRIPTORS = 4;
export const DESCRIPTOR_HANDOFF_DEFAULT_TIMEOUT_MS = 5_000;
export const DESCRIPTOR_HANDOFF_MAX_TIMEOUT_MS = 30_000;

export interface DescriptorHandoffFrame {
  payload: Buffer;
  descriptors: readonly number[];
}

export interface DescriptorHandoffReceiveOptions {
  maxPayloadBytes?: number;
  expectedDescriptorCount: number;
  timeoutMs?: number;
}

interface NativeDescriptorHandoffRuntime {
  createDescriptorHandoffSocketPair(): unknown;
  sendDescriptorHandoff(socketDescriptor: number, payload: Buffer, descriptors: readonly number[]): void;
  receiveDescriptorHandoff(socketDescriptor: number, maxPayloadBytes: number, expectedDescriptorCount: number, timeoutMs: number): unknown;
  getPeerCredentials(descriptor: number): unknown;
  getProcessIdentity(pid: number): unknown;
  closeUnixDescriptor(descriptor: number): void;
}

/**
 * Create only the native one-shot stream test/receiver transport. The sender
 * half-closes after one frame, so the receiver never treats a stream as a
 * message boundary. No helper process is
 * launched and no task admission path calls this function by default.
 */
export function createDescriptorHandoffSocketPair(): readonly [number, number] {
  requireDescriptorHandoffTransport();
  const native = loadNativePeerAdapter() as unknown as NativeDescriptorHandoffRuntime;
  const value = native.createDescriptorHandoffSocketPair();
  if (!Array.isArray(value) || value.length !== 2 ||
      value.some((descriptor) => !isDescriptor(descriptor))) {
    closeIfDescriptors(value, native);
    throw new BrokerError("POLICY_DENIED", "Native descriptor handoff socket pair is malformed");
  }
  return [value[0] as number, value[1] as number];
}

/** Send one opaque, bounded attestation frame with already-open descriptors. */
export function sendDescriptorHandoff(
  socketDescriptor: number,
  payload: Buffer,
  descriptors: readonly number[]
): void {
  requireDescriptor(socketDescriptor, "Descriptor handoff socket descriptor");
  if (!Buffer.isBuffer(payload) || payload.byteLength > DESCRIPTOR_HANDOFF_MAX_PAYLOAD_BYTES) {
    throw new BrokerError("POLICY_DENIED", "Descriptor handoff payload is invalid");
  }
  validateDescriptorList(descriptors);
  const native = loadNativePeerAdapter() as unknown as NativeDescriptorHandoffRuntime;
  try {
    native.sendDescriptorHandoff(socketDescriptor, Buffer.from(payload), descriptors);
  } catch {
    throw new BrokerError("POLICY_DENIED", "Descriptor handoff frame could not be sent");
  }
}

/** Receive one frame; the native boundary rejects truncation and framing ambiguity. */
export function receiveDescriptorHandoff(
  socketDescriptor: number,
  options: DescriptorHandoffReceiveOptions
): DescriptorHandoffFrame {
  requireDescriptor(socketDescriptor, "Descriptor handoff socket descriptor");
  const maxPayloadBytes = options.maxPayloadBytes ?? DESCRIPTOR_HANDOFF_MAX_PAYLOAD_BYTES;
  const timeoutMs = options.timeoutMs ?? DESCRIPTOR_HANDOFF_DEFAULT_TIMEOUT_MS;
  validateReceiveOptions(maxPayloadBytes, options.expectedDescriptorCount, timeoutMs);
  const native = loadNativePeerAdapter() as unknown as NativeDescriptorHandoffRuntime;
  let value: unknown;
  try {
    value = native.receiveDescriptorHandoff(socketDescriptor, maxPayloadBytes, options.expectedDescriptorCount, timeoutMs);
  } catch {
    throw new BrokerError("POLICY_DENIED", "Descriptor handoff frame could not be received");
  }
  return parseDescriptorHandoffFrame(value, maxPayloadBytes, options.expectedDescriptorCount);
}

/** Authenticate the connected peer before any handoff payload is parsed. */
export function authenticateDescriptorHandoffPeer(
  socketDescriptor: number,
  policy: PeerCredentialPolicy
): PeerCredentials {
  requireDescriptor(socketDescriptor, "Descriptor handoff socket descriptor");
  const native = loadNativePeerAdapter() as unknown as NativeDescriptorHandoffRuntime;
  try {
    const credentials = parsePeerCredentials(native.getPeerCredentials(socketDescriptor));
    authorizePeerCredentials(credentials, policy, (pid) => native.getProcessIdentity(pid));
    return credentials;
  } catch {
    throw new BrokerError("POLICY_DENIED", "Descriptor handoff peer is not authorized");
  }
}

/** The only supported receive sequence is peer authentication followed by one frame. */
export function receiveAuthenticatedDescriptorHandoff(
  socketDescriptor: number,
  policy: PeerCredentialPolicy,
  options: DescriptorHandoffReceiveOptions
): { credentials: PeerCredentials; frame: DescriptorHandoffFrame } {
  const credentials = authenticateDescriptorHandoffPeer(socketDescriptor, policy);
  const frame = receiveDescriptorHandoff(socketDescriptor, options);
  return { credentials, frame };
}

export function parseDescriptorHandoffFrame(
  value: unknown,
  maxPayloadBytes: number,
  expectedDescriptorCount: number
): DescriptorHandoffFrame {
  if (!isPlainDataRecord(value) || Object.keys(value).some((key) => key !== "payload" && key !== "descriptors")) {
    throw new BrokerError("POLICY_DENIED", "Descriptor handoff frame is malformed");
  }
  const record = value as Record<string, unknown>;
  if (!Buffer.isBuffer(record.payload) || record.payload.byteLength > maxPayloadBytes ||
      !Array.isArray(record.descriptors) || record.descriptors.length !== expectedDescriptorCount) {
    throw new BrokerError("POLICY_DENIED", "Descriptor handoff frame is malformed");
  }
  validateDescriptorList(record.descriptors);
  return {
    payload: Buffer.from(record.payload),
    descriptors: Object.freeze([...record.descriptors])
  };
}

function validateDescriptorList(descriptors: readonly number[]): void {
  if (!Array.isArray(descriptors) || descriptors.length < 1 || descriptors.length > DESCRIPTOR_HANDOFF_MAX_DESCRIPTORS ||
      descriptors.some((descriptor) => !isDescriptor(descriptor)) ||
      new Set(descriptors).size !== descriptors.length) {
    throw new BrokerError("POLICY_DENIED", "Descriptor handoff descriptor list is invalid");
  }
}

function validateReceiveOptions(maxPayloadBytes: number, expectedDescriptorCount: number, timeoutMs: number): void {
  if (!Number.isSafeInteger(maxPayloadBytes) || maxPayloadBytes < 0 || maxPayloadBytes > DESCRIPTOR_HANDOFF_MAX_PAYLOAD_BYTES ||
      !Number.isSafeInteger(expectedDescriptorCount) || expectedDescriptorCount < 1 ||
      expectedDescriptorCount > DESCRIPTOR_HANDOFF_MAX_DESCRIPTORS ||
      !Number.isSafeInteger(timeoutMs) || timeoutMs < 25 || timeoutMs > DESCRIPTOR_HANDOFF_MAX_TIMEOUT_MS) {
    throw new BrokerError("POLICY_DENIED", "Descriptor handoff receive limits are invalid");
  }
}

function requireDescriptor(descriptor: number, label: string): void {
  if (!isDescriptor(descriptor)) throw new BrokerError("POLICY_DENIED", `${label} is invalid`);
}

function isDescriptor(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function closeIfDescriptors(value: unknown, native: NativeDescriptorHandoffRuntime): void {
  if (!Array.isArray(value)) return;
  for (const descriptor of value) {
    if (isDescriptor(descriptor)) {
      try { native.closeUnixDescriptor(descriptor); } catch { /* best-effort cleanup */ }
    }
  }
}
