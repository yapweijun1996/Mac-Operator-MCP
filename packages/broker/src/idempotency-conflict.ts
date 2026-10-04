import { BrokerError } from "@mac-operator/contracts";
import type { ArchivedJobRecord, BrokerJob } from "./persistence.js";

const PREFIX = "IDEMPOTENCY_KEY_IN_USE:";

/** The request binding that makes a new request differ from the Job that already holds its idempotency key. */
export type IdempotencyBinding = "tool" | "arguments" | "target" | "policy version" | "OAuth login" | "Edge connection";

/**
 * What a new request would bind its idempotency key to. A caller that does not bind the OAuth login or the Edge
 * connection leaves those fields out, and they are not compared.
 */
export interface IdempotencyIdentity {
  tool: string;
  payloadDigest: string;
  targetRef: string;
  policyVersion: string;
  sessionId?: string;
  edgeId?: string | null;
  edgeKeyId?: string | null;
}

/**
 * First binding of the holder that the new request does not repeat, or undefined for an identical request. Edge ids
 * and Edge key identities match exactly, so a rotated Edge key is a different Edge connection.
 */
export function firstDifferingBinding(holder: BrokerJob, wanted: IdempotencyIdentity): IdempotencyBinding | undefined {
  if (holder.tool !== wanted.tool) return "tool";
  if (holder.payloadDigest !== wanted.payloadDigest) return "arguments";
  if (holder.targetRef !== wanted.targetRef) return "target";
  if (holder.policyVersion !== wanted.policyVersion) return "policy version";
  if (wanted.sessionId !== undefined && holder.ownerSessionId !== wanted.sessionId) return "OAuth login";
  if ((wanted.edgeId !== undefined && holder.ownerEdgeId !== wanted.edgeId) ||
      (wanted.edgeKeyId !== undefined && holder.ownerEdgeKeyId !== wanted.edgeKeyId)) return "Edge connection";
  return undefined;
}

/**
 * Stable CONFLICT for an idempotency key that is already held. Every lookup is principal-scoped, so the holder is
 * always the caller's own Job. The text never carries digests, targets, session ids, Edge ids or the key itself, and it
 * stays inside the 512-character error message bound of the failure schema.
 */
export function idempotencyConflict(
  holder: Pick<BrokerJob, "jobId" | "tool" | "state" | "createdAtMs">,
  differs?: IdempotencyBinding
): BrokerError {
  const head = `${PREFIX} this idempotency_key already belongs to job ${clip(holder.jobId, 96)} ` +
    `(${clip(holder.tool, 48)}, ${holder.state}, created ${isoTime(holder.createdAtMs)})`;
  if (differs === undefined) return new BrokerError("CONFLICT", `${head}. ${tailForState(holder.state)}`);
  const settled = holder.state === "failed" || holder.state === "cancelled"
    ? ` (the ${holder.state} job is never re-run, only replayed as ${holder.state})` : "";
  const tail = differs === "OAuth login"
    ? `Repeat the identical request from the original OAuth login${settled}, or use a new idempotency_key.`
    : "Use a new idempotency_key.";
  return new BrokerError("CONFLICT", `${head}, but the new request differs in ${differs}. ${tail}`);
}

/** CONFLICT for a key or Job id that the caller's own archived (rotated) Job still holds. */
export function archivedIdempotencyConflict(holder: Pick<ArchivedJobRecord, "jobId" | "tool" | "state" | "finishedAtMs">): BrokerError {
  return new BrokerError("CONFLICT", `${PREFIX} this idempotency_key or Job id belongs to archived job ${clip(holder.jobId, 96)} ` +
    `(${clip(holder.tool, 48)}, ${holder.state}, finished ${isoTime(holder.finishedAtMs)}). Archived keys are never released: ` +
    "inspect it with mac_job_status, or use a new idempotency_key.");
}

/** Next step when the request matches the holder but the holder's state still blocks reuse. */
function tailForState(state: BrokerJob["state"]): string {
  if (state === "queued" || state === "running") {
    return "It has not finished: check it with mac_job_status, then repeat the identical request to replay its outcome.";
  }
  if (state === "failed" || state === "cancelled") {
    return "A failed or cancelled job is never re-run under its key: use a new idempotency_key to run the request again.";
  }
  if (state === "unknown") return "Its outcome is unresolved: inspect it with mac_job_status before choosing a new idempotency_key.";
  return "It has no replayable successful outcome: use a new idempotency_key.";
}

/** Job ids and tool names are pattern-bound but long; clipping keeps the whole message inside its bound. */
function clip(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 3)}...`;
}

/** Stored timestamps are safe integers, which reach past the Date range; a CONFLICT must never turn into a RangeError. */
function isoTime(ms: number): string {
  const date = new Date(ms);
  return Number.isNaN(date.getTime()) ? String(ms) : date.toISOString();
}
