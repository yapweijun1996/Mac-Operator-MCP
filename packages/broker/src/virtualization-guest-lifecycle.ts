import { BrokerError } from "@mac-operator/contracts";
import { isPlainDataRecord } from "./plain-record.js";
import {
  parseVirtualizationGuestIdentity,
  sameVirtualizationGuestIdentity,
  type VirtualizationGuestIdentity
} from "./virtualization-guest-attestation.js";

const DEFAULT_START_TIMEOUT_MS = 120_000;
const DEFAULT_STOP_TIMEOUT_MS = 30_000;
const BOOT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/u;
const TASK_INSTANCE_ID_PATTERN = /^vm-[A-Za-z0-9._:-]{7,124}$/u;

export type VirtualizationGuestVmState = "disabled" | "stopped" | "starting" | "running" | "stopping" | "unknown" | "closed";

export interface VirtualizationGuestVmStartResult {
  state: "running";
  guestIdentity: VirtualizationGuestIdentity;
  bootId: string;
}

export interface VirtualizationGuestVmStopResult {
  state: "stopped";
  guestIdentity: VirtualizationGuestIdentity;
  bootId: string;
}

export interface VirtualizationGuestVmStatusResult {
  state: "running" | "stopped" | "unknown";
  guestIdentity: VirtualizationGuestIdentity | null;
  bootId: string | null;
}

export interface VirtualizationGuestVmTaskInstance {
  state: "stopped";
  guestIdentity: VirtualizationGuestIdentity;
  instanceId: string;
}

/**
 * Native adapter surface for VM lifecycle only. The adapter owns
 * Virtualization.framework objects and virtio details; it receives no host
 * executable, path, credential, or arbitrary command.
 */
export interface VirtualizationGuestVmAdapter {
  readonly available: boolean;
  readonly guestIdentity: VirtualizationGuestIdentity | null;
  readonly taskInstanceIsolation: "fresh-vm-object-per-task-v1";
  prepareTaskInstance(input: { guestIdentity: VirtualizationGuestIdentity; signal: AbortSignal }): Promise<VirtualizationGuestVmTaskInstance>;
  start(input: { guestIdentity: VirtualizationGuestIdentity; signal: AbortSignal }): Promise<VirtualizationGuestVmStartResult>;
  stop(input: { guestIdentity: VirtualizationGuestIdentity; bootId: string; signal: AbortSignal }): Promise<VirtualizationGuestVmStopResult>;
  status(input: { guestIdentity: VirtualizationGuestIdentity; signal: AbortSignal }): Promise<VirtualizationGuestVmStatusResult>;
  close?(): Promise<void>;
}

export interface VirtualizationGuestVmLifecycleOptions {
  /** Explicit host opt-in; MCP requests cannot set this flag. */
  enabled?: boolean;
  /** Independent reviewed evidence gate for the native lifecycle adapter. */
  hostEvidenceAccepted?: boolean;
  expectedGuestIdentity: VirtualizationGuestIdentity;
  adapter: VirtualizationGuestVmAdapter;
  startTimeoutMs?: number;
  stopTimeoutMs?: number;
}

/**
 * Broker-owned serialized lifecycle gate for the native VM adapter.
 * Unknown outcomes are sticky until an explicit status readback proves a
 * stable state. Identity and boot IDs are checked on every transition.
 */
export class VirtualizationGuestVmLifecycle {
  readonly available: boolean;
  readonly expectedGuestIdentity: VirtualizationGuestIdentity;
  private readonly adapter: VirtualizationGuestVmAdapter;
  private readonly startTimeoutMs: number;
  private readonly stopTimeoutMs: number;
  private queue = Promise.resolve();
  /**
   * Native lifecycle calls may ignore AbortSignal after a caller timeout.
   * Keep that operation fenced until its promise settles so a later status or
   * transition cannot overlap an unknown VM mutation.
   */
  private activeOperation: Promise<unknown> | undefined;
  private currentState: VirtualizationGuestVmState;
  private currentBootId: string | null = null;
  private lastTaskInstanceId: string | null = null;
  private closed = false;

  constructor(options: VirtualizationGuestVmLifecycleOptions) {
    if (options === null || typeof options !== "object" || options.adapter === undefined ||
        typeof options.adapter.start !== "function" || typeof options.adapter.stop !== "function" ||
        typeof options.adapter.status !== "function" || typeof options.adapter.prepareTaskInstance !== "function" ||
        options.adapter.taskInstanceIsolation !== "fresh-vm-object-per-task-v1" ||
        typeof options.adapter.available !== "boolean" ||
        options.expectedGuestIdentity === null || typeof options.expectedGuestIdentity !== "object" ||
        (options.enabled !== undefined && typeof options.enabled !== "boolean") ||
        (options.hostEvidenceAccepted !== undefined && typeof options.hostEvidenceAccepted !== "boolean")) {
      throw new Error("Virtualization guest VM lifecycle options are invalid");
    }
    const startTimeoutMs = options.startTimeoutMs ?? DEFAULT_START_TIMEOUT_MS;
    const stopTimeoutMs = options.stopTimeoutMs ?? DEFAULT_STOP_TIMEOUT_MS;
    if (!Number.isSafeInteger(startTimeoutMs) || startTimeoutMs < 1 || startTimeoutMs > 15 * 60_000 ||
        !Number.isSafeInteger(stopTimeoutMs) || stopTimeoutMs < 1 || stopTimeoutMs > 120_000) {
      throw new Error("Virtualization guest VM lifecycle timeouts are invalid");
    }
    this.expectedGuestIdentity = Object.freeze(parseVirtualizationGuestIdentity(options.expectedGuestIdentity));
    this.adapter = options.adapter;
    this.startTimeoutMs = startTimeoutMs;
    this.stopTimeoutMs = stopTimeoutMs;
    this.available = process.platform === "darwin" && options.enabled === true &&
      options.hostEvidenceAccepted === true && options.adapter.available === true &&
      sameVirtualizationGuestIdentity(this.expectedGuestIdentity, options.adapter.guestIdentity);
    this.currentState = this.available ? "stopped" : "disabled";
  }

  get state(): VirtualizationGuestVmState {
    return this.currentState;
  }

  get bootId(): string | null {
    return this.currentBootId;
  }

  async start(signal?: AbortSignal): Promise<VirtualizationGuestVmStartResult> {
    return this.serialized(() => this.startInternal(signal));
  }

  /**
   * Runs one Broker-owned guest operation in an exclusive VM boot cycle.
   * The operation must resolve only after its authenticated result has been
   * durably recorded by the caller. Stop is deliberately not cancellable: a
   * caller timeout must not skip the containment attempt.
   */
  async runTask<T>(operation: () => Promise<T>, signal?: AbortSignal): Promise<T> {
    return this.serialized(async () => {
      this.assertAvailable();
      if (signal?.aborted) throw new BrokerError("CANCELLED", "Virtualization guest task was cancelled before VM reset");
      if (this.currentState === "unknown") {
        throw new BrokerError("UNKNOWN_OUTCOME", "Virtualization guest VM state requires status recovery", true);
      }
      if (this.currentState === "running") await this.stopInternal();
      if (this.currentState !== "stopped" || this.currentBootId !== null) {
        throw new BrokerError("UNKNOWN_OUTCOME", "Virtualization guest VM is not confirmed stopped before task reset", true);
      }
      const instance = await this.withDeadline(
        (combinedSignal) => this.adapter.prepareTaskInstance({
          guestIdentity: { ...this.expectedGuestIdentity },
          signal: combinedSignal
        }),
        this.startTimeoutMs,
        signal,
        "prepare task VM"
      ).catch((error: unknown) => {
        this.currentState = "unknown";
        this.currentBootId = null;
        throw mapLifecycleError(error, "prepare task VM");
      });
      if (signal?.aborted) throw new BrokerError("CANCELLED", "Virtualization guest task was cancelled before VM start");
      let instanceId: string;
      try {
        instanceId = parseTaskInstance(instance, this.expectedGuestIdentity);
      } catch (error) {
        this.currentState = "unknown";
        this.currentBootId = null;
        throw error;
      }
      if (instanceId === this.lastTaskInstanceId) {
        this.currentState = "unknown";
        this.currentBootId = null;
        throw new BrokerError("POLICY_DENIED", "Virtualization guest task reused a previous VM instance");
      }
      this.lastTaskInstanceId = instanceId;
      await this.startInternal(signal);
      let result: T | undefined;
      let operationError: unknown;
      let operationFailed = false;
      try {
        result = await operation();
      } catch (error) {
        operationFailed = true;
        operationError = error;
      }

      let stopError: unknown;
      let stopFailed = false;
      try {
        await this.stopInternal();
      } catch (error) {
        stopFailed = true;
        stopError = error;
      }
      if (stopFailed) throw stopError;
      if (operationFailed) throw operationError;
      return result as T;
    });
  }

  private async startInternal(signal?: AbortSignal): Promise<VirtualizationGuestVmStartResult> {
      this.assertAvailable();
      if (signal?.aborted) throw new BrokerError("CANCELLED", "Virtualization guest VM start was cancelled");
      if (this.currentState === "running" && this.currentBootId !== null) {
        return { state: "running", guestIdentity: { ...this.expectedGuestIdentity }, bootId: this.currentBootId };
      }
      if (this.currentState === "starting" || this.currentState === "stopping") {
        throw new BrokerError("CONFLICT", "Virtualization guest VM lifecycle is busy");
      }
      if (this.currentState === "unknown") {
        throw new BrokerError("UNKNOWN_OUTCOME", "Virtualization guest VM state requires status recovery", true);
      }
      this.currentState = "starting";
      try {
        const result = await this.withDeadline(
          (combinedSignal) => this.adapter.start({ guestIdentity: { ...this.expectedGuestIdentity }, signal: combinedSignal }),
          this.startTimeoutMs,
          signal,
          "start"
        );
        if (result.state !== "running" || !sameVirtualizationGuestIdentity(this.expectedGuestIdentity, result.guestIdentity) ||
            !BOOT_ID_PATTERN.test(result.bootId)) {
          this.currentState = "unknown";
          this.currentBootId = null;
          throw new BrokerError("POLICY_DENIED", "Virtualization guest VM start identity is invalid");
        }
        this.currentState = "running";
        this.currentBootId = result.bootId;
        return { state: "running", guestIdentity: { ...this.expectedGuestIdentity }, bootId: result.bootId };
      } catch (error) {
        if (this.currentState !== "running") {
          this.currentState = "unknown";
          this.currentBootId = null;
        }
        throw mapLifecycleError(error, "start");
      }
  }

  async stop(signal?: AbortSignal): Promise<VirtualizationGuestVmStopResult> {
    return this.serialized(() => this.stopInternal(signal));
  }

  private async stopInternal(signal?: AbortSignal): Promise<VirtualizationGuestVmStopResult> {
      this.assertAvailable();
      if (signal?.aborted) throw new BrokerError("CANCELLED", "Virtualization guest VM stop was cancelled");
      if (this.currentState === "stopped" && this.currentBootId === null) {
        return { state: "stopped", guestIdentity: { ...this.expectedGuestIdentity }, bootId: "stopped" };
      }
      if (this.currentState === "starting") {
        throw new BrokerError("CONFLICT", "Virtualization guest VM is still starting");
      }
      if (this.currentState === "stopping") {
        throw new BrokerError("CONFLICT", "Virtualization guest VM is already stopping");
      }
      if (this.currentBootId === null) {
        throw new BrokerError("UNKNOWN_OUTCOME", "Virtualization guest VM stop identity is unavailable", true);
      }
      const bootId = this.currentBootId;
      this.currentState = "stopping";
      try {
        const result = await this.withDeadline(
          (combinedSignal) => this.adapter.stop({ guestIdentity: { ...this.expectedGuestIdentity }, bootId, signal: combinedSignal }),
          this.stopTimeoutMs,
          signal,
          "stop"
        );
        if (result.state !== "stopped" || !sameVirtualizationGuestIdentity(this.expectedGuestIdentity, result.guestIdentity) ||
            result.bootId !== bootId) {
          this.currentState = "unknown";
          this.currentBootId = null;
          throw new BrokerError("POLICY_DENIED", "Virtualization guest VM stop identity is invalid");
        }
        this.currentState = "stopped";
        this.currentBootId = null;
        return { state: "stopped", guestIdentity: { ...this.expectedGuestIdentity }, bootId };
      } catch (error) {
        this.currentState = "unknown";
        this.currentBootId = null;
        throw mapLifecycleError(error, "stop");
      }
  }

  async status(signal?: AbortSignal): Promise<VirtualizationGuestVmStatusResult> {
    return this.serialized(() => this.statusInternal(signal));
  }

  private async statusInternal(signal?: AbortSignal): Promise<VirtualizationGuestVmStatusResult> {
      this.assertAvailable();
      if (signal?.aborted) throw new BrokerError("CANCELLED", "Virtualization guest VM status was cancelled");
      try {
        const result = await this.withDeadline(
          (combinedSignal) => this.adapter.status({ guestIdentity: { ...this.expectedGuestIdentity }, signal: combinedSignal }),
          this.stopTimeoutMs,
          signal,
          "status"
        );
        const identityMatches = result.guestIdentity !== null &&
          sameVirtualizationGuestIdentity(this.expectedGuestIdentity, result.guestIdentity);
        if (!identityMatches ||
            (result.state !== "running" && result.state !== "stopped" && result.state !== "unknown") ||
            (result.state === "running" && (result.bootId === null || !BOOT_ID_PATTERN.test(result.bootId))) ||
            (result.state === "stopped" && result.bootId !== null && result.bootId !== "stopped") ||
            (result.state === "unknown" && result.bootId !== null)) {
          this.currentState = "unknown";
          this.currentBootId = null;
          throw new BrokerError("POLICY_DENIED", "Virtualization guest VM status identity is invalid");
        }
        if (result.state === "running") {
          this.currentState = "running";
          this.currentBootId = result.bootId;
        } else if (result.state === "stopped") {
          this.currentState = "stopped";
          this.currentBootId = null;
        } else {
          this.currentState = "unknown";
          this.currentBootId = null;
        }
        return {
          state: result.state,
          guestIdentity: { ...this.expectedGuestIdentity },
          bootId: result.state === "running" ? result.bootId : null
        };
      } catch (error) {
        this.currentState = "unknown";
        this.currentBootId = null;
        throw mapLifecycleError(error, "status");
      }
  }

  async close(): Promise<void> {
    await this.serialized(async () => {
      if (this.closed) return;
      if (this.available && (this.currentState === "running" || this.currentState === "unknown")) {
        await this.stopInternal();
      }
      try {
        await this.adapter.close?.();
      } catch (error) {
        throw mapLifecycleError(error, "close");
      }
      this.closed = true;
      this.currentState = "closed";
      this.currentBootId = null;
    });
  }

  private assertAvailable(): void {
    if (this.closed || this.currentState === "closed") {
      throw new BrokerError("POLICY_DENIED", "Virtualization guest VM lifecycle is closed");
    }
    if (!this.available) throw new BrokerError("POLICY_DENIED", "Virtualization guest VM lifecycle is not enabled");
    if (this.activeOperation !== undefined) {
      throw new BrokerError("UNKNOWN_OUTCOME", "Virtualization guest VM operation is still settling", true);
    }
    if (!sameVirtualizationGuestIdentity(this.expectedGuestIdentity, this.adapter.guestIdentity)) {
      this.currentState = "unknown";
      this.currentBootId = null;
      throw new BrokerError("POLICY_DENIED", "Virtualization guest VM identity is unavailable or changed");
    }
  }

  private async withDeadline<T>(
    operation: (signal: AbortSignal) => Promise<T>,
    timeoutMs: number,
    callerSignal: AbortSignal | undefined,
    operationName: string
  ): Promise<T> {
    const timeoutController = new AbortController();
    const combinedSignal = callerSignal === undefined
      ? timeoutController.signal
      : AbortSignal.any([callerSignal, timeoutController.signal]);
    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    let rejectAbort: ((reason: BrokerError) => void) | undefined;
    const abortResult = new Promise<T>((_resolve, reject) => { rejectAbort = reject; });
    const callerAbort = (): void => rejectAbort?.(new BrokerError("CANCELLED", `Virtualization guest VM ${operationName} was cancelled`));
    if (callerSignal !== undefined) callerSignal.addEventListener("abort", callerAbort, { once: true });
    timeoutHandle = setTimeout(() => {
      timeoutController.abort();
      rejectAbort?.(new BrokerError("TIMEOUT", `Virtualization guest VM ${operationName} exceeded its execution budget`, true));
    }, timeoutMs);
    const operationPromise = Promise.resolve().then(() => operation(combinedSignal));
    this.activeOperation = operationPromise;
    const clearActiveOperation = (): void => {
      if (this.activeOperation === operationPromise) this.activeOperation = undefined;
    };
    operationPromise.then(clearActiveOperation, clearActiveOperation);
    try {
      return await Promise.race([operationPromise, abortResult]);
    } finally {
      if (timeoutHandle !== undefined) clearTimeout(timeoutHandle);
      if (callerSignal !== undefined) callerSignal.removeEventListener("abort", callerAbort);
    }
  }

  private serialized<T>(operation: () => Promise<T>): Promise<T> {
    const result = this.queue.then(operation, operation);
    this.queue = result.then(() => undefined, () => undefined);
    return result;
  }
}

function parseTaskInstance(value: unknown, expectedGuestIdentity: VirtualizationGuestIdentity): string {
  if (!isPlainDataRecord(value) || Object.keys(value).length !== 3 ||
      !Object.prototype.hasOwnProperty.call(value, "state") ||
      !Object.prototype.hasOwnProperty.call(value, "guestIdentity") ||
      !Object.prototype.hasOwnProperty.call(value, "instanceId") ||
      value.state !== "stopped" || typeof value.instanceId !== "string" ||
      !TASK_INSTANCE_ID_PATTERN.test(value.instanceId) || value.guestIdentity === null ||
      typeof value.guestIdentity !== "object" ||
      !sameVirtualizationGuestIdentity(expectedGuestIdentity, value.guestIdentity as VirtualizationGuestIdentity)) {
    throw new BrokerError("POLICY_DENIED", "Virtualization guest task VM instance proof is invalid");
  }
  return value.instanceId;
}

function mapLifecycleError(error: unknown, operation: string): BrokerError {
  if (error instanceof BrokerError) return error;
  return new BrokerError("UNKNOWN_OUTCOME", `Virtualization guest VM ${operation} outcome could not be established`, true);
}
