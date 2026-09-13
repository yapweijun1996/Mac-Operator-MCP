import { parentPort, workerData } from "node:worker_threads";
import { FilesystemInspector } from "./filesystem-inspector.js";
import type { FilesystemWorkerCommand } from "./filesystem-worker-protocol.js";
import { assertContentDoesNotContainSecrets } from "./secret-policy.js";

/**
 * Test-only worker that commits a real write and then exits without returning
 * a result. It models a worker crash after the mutation boundary; production
 * construction always uses filesystem-worker.js and cannot select this URL.
 */
if (!parentPort) throw new Error("Filesystem crash worker requires a parent port");

const command = workerData as FilesystemWorkerCommand;
if (command.operation !== "write") throw new Error("Filesystem crash worker supports write only");

assertContentDoesNotContainSecrets(command.content);
const inspector = new FilesystemInspector([command.plan.root]);
inspector.writePlanned(
  command.plan,
  command.content,
  command.expectedSha256,
  command.createOnly,
  command.tempName
);

// An uncaught worker exception makes the parent observe an execution failure
// and an exit without any success message. The Broker must keep the Job
// UNKNOWN because the target mutation may already have committed.
setImmediate(() => {
  throw new Error("test-only worker crash after filesystem commit");
});
