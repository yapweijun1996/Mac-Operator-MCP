import { BrokerError } from "@mac-operator/contracts";
import { loadNativePeerAdapter } from "./peer-credentials.js";

export interface SafeNetworkInterface {
  name: string;
  state: "up" | "down" | "unknown";
  addresses: readonly string[];
}

export interface SafeNetworkListener {
  protocol: "tcp" | "udp";
  address: string;
  port: number;
}

export interface SafeNetworkStatus {
  interfaces: readonly SafeNetworkInterface[];
  listeners: readonly SafeNetworkListener[];
  connectivity: "online" | "limited" | "offline" | "unknown";
  warnings: readonly string[];
  truncated: boolean;
}

interface NativeNetworkAdapter {
  inspectNetwork(includeListeners: boolean): unknown;
}

export function inspectNetwork(includeListeners: boolean): SafeNetworkStatus {
  if (typeof includeListeners !== "boolean") {
    throw new BrokerError("PRECONDITION_FAILED", "include_listeners must be a boolean");
  }
  let native: NativeNetworkAdapter;
  try {
    native = loadNativePeerAdapter() as unknown as NativeNetworkAdapter;
  } catch {
    throw new BrokerError("EXECUTION_FAILED", "Network native adapter is unavailable");
  }
  let value: unknown;
  try {
    value = native.inspectNetwork(includeListeners);
  } catch {
    throw new BrokerError("EXECUTION_FAILED", "Network interfaces could not be inspected");
  }
  const parsed = parseNativeNetwork(value);
  const warnings: string[] = ["Connectivity is inferred from local interface state; no active network probe was performed"];
  if (includeListeners && parsed.listenerQueryFailed) {
    warnings.push("Listener metadata is unavailable from the version-neutral native adapter");
  }
  if (parsed.listenersTruncated) warnings.push("Listener metadata was truncated by a fixed output budget");
  return {
    interfaces: parsed.interfaces,
    listeners: parsed.listeners,
    connectivity: inferConnectivity(parsed.interfaces),
    warnings: warnings.slice(0, 32),
    truncated: parsed.listenersTruncated
  };
}

function parseNativeNetwork(value: unknown): {
  interfaces: SafeNetworkInterface[];
  listeners: SafeNetworkListener[];
  listenerQueryFailed: boolean;
  listenersTruncated: boolean;
} {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw malformed();
  const record = value as Record<string, unknown>;
  if (!Array.isArray(record.interfaces) || record.interfaces.length > 64 ||
      !Array.isArray(record.listeners) || record.listeners.length > 256 ||
      typeof record.listenerQueryFailed !== "boolean" || typeof record.listenersTruncated !== "boolean") throw malformed();
  const interfaces: SafeNetworkInterface[] = [];
  for (const item of record.interfaces) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) throw malformed();
    const entry = item as Record<string, unknown>;
    if (typeof entry.name !== "string" || entry.name.length < 1 || entry.name.length > 128 ||
        !/^[A-Za-z0-9._:@/+-]+$/u.test(entry.name) ||
        (entry.state !== "up" && entry.state !== "down" && entry.state !== "unknown") ||
        !Array.isArray(entry.addresses) || entry.addresses.length > 32) throw malformed();
    const addresses = entry.addresses.map((address) => {
      if (typeof address !== "string" || address.length < 1 || address.length > 128 || address.includes("\0")) throw malformed();
      return address;
    });
    interfaces.push({ name: entry.name, state: entry.state, addresses });
  }
  const listeners: SafeNetworkListener[] = [];
  for (const item of record.listeners) {
    if (item === null || typeof item !== "object" || Array.isArray(item)) throw malformed();
    const entry = item as Record<string, unknown>;
    if ((entry.protocol !== "tcp" && entry.protocol !== "udp") ||
        typeof entry.address !== "string" || entry.address.length < 1 || entry.address.length > 128 || entry.address.includes("\0") ||
        !Number.isSafeInteger(entry.port) || (entry.port as number) < 1 || (entry.port as number) > 65_535) throw malformed();
    listeners.push({ protocol: entry.protocol, address: entry.address, port: entry.port as number });
  }
  return {
    interfaces,
    listeners,
    listenerQueryFailed: record.listenerQueryFailed,
    listenersTruncated: record.listenersTruncated
  };
}

function inferConnectivity(interfaces: readonly SafeNetworkInterface[]): SafeNetworkStatus["connectivity"] {
  if (interfaces.length === 0) return "unknown";
  const up = interfaces.filter((networkInterface) => networkInterface.state === "up");
  if (up.length === 0) return "offline";
  const routableAddress = up.some((networkInterface) => networkInterface.addresses.some((address) =>
    !isLoopback(address) && !isLinkLocal(address) && !isUnspecified(address)));
  return routableAddress ? "online" : "limited";
}

function isLoopback(address: string): boolean {
  const normalized = address.toLocaleLowerCase("en-US");
  return normalized === "::1" || normalized.startsWith("127.");
}

function isLinkLocal(address: string): boolean {
  const normalized = address.toLocaleLowerCase("en-US");
  return normalized.startsWith("169.254.") || normalized.startsWith("fe80:");
}

function isUnspecified(address: string): boolean {
  const normalized = address.toLocaleLowerCase("en-US");
  return normalized === "0.0.0.0" || normalized === "::";
}

function malformed(): BrokerError {
  return new BrokerError("EXECUTION_FAILED", "Network adapter returned a malformed result");
}
