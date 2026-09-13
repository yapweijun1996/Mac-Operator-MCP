import { Worker } from "node:worker_threads";
import { BrokerError, ERROR_CLASSES, type ErrorClass } from "@mac-operator/contracts";

export type WorkerResult<T> =
  | { ok: true; value: T }
  | { ok: false; errorClass: ErrorClass; message: string };

export type WorkerFactory<TCommand> = (command: TCommand) => Worker;

export class BoundedWorkerExecutor<TCommand, TResult> {
  private activeWorkers = 0;
  private readonly workers = new Set<Worker>();
  private closing = false;
  private closePromise: Promise<void> | undefined;

  constructor(
    private readonly workerFactory: WorkerFactory<TCommand>,
    private readonly maxConcurrent: number
  ) {
    if (!Number.isSafeInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 64) {
      throw new Error("Worker concurrency limit must be between 1 and 64");
    }
  }

  run(command: TCommand, timeoutMs: number, shouldCancel: () => boolean): Promise<TResult> {
    if (this.closing) {
      return Promise.reject(new BrokerError("CANCELLED", "Worker executor is shutting down"));
    }
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 600_000) {
      return Promise.reject(new BrokerError("PRECONDITION_FAILED", "Worker timeout is outside the supported range"));
    }
    if (this.cancelled(shouldCancel)) {
      return Promise.reject(new BrokerError("CANCELLED", "Work authority was revoked before execution"));
    }
    if (this.activeWorkers >= this.maxConcurrent) {
      return Promise.reject(new BrokerError("CONFLICT", "Worker capacity is exhausted", true));
    }

    const worker = this.workerFactory(command);
    this.activeWorkers += 1;
    this.workers.add(worker);
    return new Promise<TResult>((resolve, reject) => {
      let settled = false;
      let released = false;
      const release = () => {
        if (!released) {
          released = true;
          this.activeWorkers -= 1;
          this.workers.delete(worker);
        }
      };
      const finish = (error?: BrokerError, value?: TResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        clearInterval(cancellationPoll);
        if (error) reject(error);
        else resolve(value as TResult);
      };
      const terminate = () => { void worker.terminate().catch(() => undefined); };
      const timeout = setTimeout(() => {
        finish(new BrokerError("TIMEOUT", "Worker execution exceeded its deadline", true));
        terminate();
      }, timeoutMs);
      const cancellationPoll = setInterval(() => {
        if (!this.cancelled(shouldCancel)) return;
        finish(new BrokerError("CANCELLED", "Active work authority was revoked"));
        terminate();
      }, 25);
      timeout.unref();
      cancellationPoll.unref();

      worker.once("message", (message: unknown) => {
        if (!isWorkerResult<TResult>(message)) {
          finish(new BrokerError("EXECUTION_FAILED", "Worker returned a malformed result"));
          terminate();
          return;
        }
        if (!message.ok) {
          finish(new BrokerError(message.errorClass, message.message));
          return;
        }
        finish(undefined, message.value);
      });
      worker.once("error", () => finish(new BrokerError("EXECUTION_FAILED", "Worker execution failed")));
      worker.once("exit", (code) => {
        release();
        if (!settled) finish(new BrokerError("EXECUTION_FAILED", `Worker exited before returning a result (${code})`));
      });
    });
  }

  activeCount(): number {
    return this.activeWorkers;
  }

  /**
   * Stop accepting work and terminate every worker still owned by this
   * executor. The promise resolves only after each Worker termination request
   * settles; capacity is released from the Worker `exit` event, so callers can
   * safely close persistence after this boundary.
   */
  close(): Promise<void> {
    if (this.closePromise !== undefined) return this.closePromise;
    this.closing = true;
    const workers = [...this.workers];
    this.closePromise = Promise.all(workers.map(async (worker) => {
      try { await worker.terminate(); }
      catch { /* the exit handler still owns capacity release */ }
    })).then(() => undefined);
    return this.closePromise;
  }

  private cancelled(check: () => boolean): boolean {
    try { return check(); }
    catch { return true; }
  }
}

function isWorkerResult<T>(value: unknown): value is WorkerResult<T> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const record = value as Record<string, unknown>;
  if (record.ok === true) return Object.hasOwn(record, "value");
  return record.ok === false && typeof record.errorClass === "string" &&
    ERROR_CLASSES.includes(record.errorClass as ErrorClass) && typeof record.message === "string" &&
    record.message.length >= 1 && record.message.length <= 512;
}
