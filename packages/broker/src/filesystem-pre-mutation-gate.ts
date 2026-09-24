import { BrokerError } from "@mac-operator/contracts";

const PRE_MUTATION_WAIT_TIMEOUT_MS = 600_000;

/**
 * Pause a filesystem worker immediately before its native mutation until the
 * Broker authorizes that exact mutation boundary. The shared memory cell is
 * reset for every file in a multi-file patch.
 */
export function awaitPreMutationAuthority(
  gate: SharedArrayBuffer | undefined,
  postMessage: (message: unknown) => void
): void {
  if (gate === undefined) return;
  const state = new Int32Array(gate);
  Atomics.store(state, 0, 0);
  postMessage({ type: "pre_mutation" });
  const waitResult = Atomics.wait(state, 0, 0, PRE_MUTATION_WAIT_TIMEOUT_MS);
  if (waitResult === "timed-out") {
    throw new BrokerError("TIMEOUT", "Pre-mutation authority was not received before the deadline", true);
  }
  if (Atomics.load(state, 0) !== 1) {
    throw new BrokerError("CANCELLED", "Pre-mutation authority was revoked");
  }
}
