import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { patchEdgeConfig } from "./lib.mjs";

/** A stopped service must either complete the cutover or recover the previous release, including thrown failures. */
export async function cutoverRelease({ target, release, stateRoot, edgePath, previous, backup, failedState }, operations) {
  const priorEdge = JSON.parse(readFileSync(edgePath, "utf8"));
  const patched = patchEdgeConfig(priorEdge, { packageRoot: release, sourceRevision: target });
  // Allocate a unique backup before stopping. An old or partial snapshot cannot become this attempt's rollback source.
  mkdirSync(backup, { mode: 0o700 });
  let stateChanged = false;
  try {
    if (!operations.stop()) throw new Error("service stop failed");
    await operations.settle();
    operations.copyTree(stateRoot, join(backup, "state.partial"));
    renameSync(join(backup, "state.partial"), join(backup, "state"));
    // From this point, any failure needs the complete frozen snapshot, even if startup only partly succeeds.
    stateChanged = true;
    writeFileSync(`${edgePath}.tmp`, `${JSON.stringify(patched, null, 2)}\n`, { mode: 0o600 });
    renameSync(`${edgePath}.tmp`, edgePath);
    if (!operations.start(release) || !await operations.healthy(patched)) throw new Error("new release is unhealthy");
    if (!operations.save()) throw new Error("service persistence failed");
    return { ok: true, backup };
  } catch (error) {
    try { operations.log("rollback-start", { backup }); } catch { /* Recovery must continue if logging fails. */ }
    let restored = false;
    let recoveryError;
    try {
      if (stateChanged) {
        if (!operations.stop()) throw new Error("cannot stop failed release for state restoration");
        await operations.settle();
        // Finish the restore copy before moving live state, so a second copy failure preserves both originals.
        const restore = `${stateRoot}.restore-${process.pid}`;
        if (existsSync(restore) || existsSync(failedState)) throw new Error("state recovery path already exists");
        operations.copyTree(join(backup, "state"), restore);
        const renameState = operations.renameState ?? renameSync;
        renameState(stateRoot, failedState);
        try { renameState(restore, stateRoot); } catch (failure) {
          // Keep the original state available at its known location if snapshot publication fails.
          try { renameState(failedState, stateRoot); } catch { /* The failed-state path still holds the original. */ }
          throw failure;
        }
      }
      restored = operations.start(previous) && await operations.healthy(priorEdge);
      if (restored && !operations.save()) throw new Error("restored service persistence failed");
    } catch (failure) {
      restored = false;
      recoveryError = String(failure?.message ?? failure).slice(0, 200);
    }
    return { ok: false, restored, backup, ...(existsSync(failedState) ? { failedState } : {}),
      error: String(error?.message ?? error).slice(0, 200), ...(recoveryError ? { recoveryError } : {}) };
  }
}
