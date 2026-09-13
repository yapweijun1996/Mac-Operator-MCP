import { createRequire } from "node:module";
import { parentPort, workerData } from "node:worker_threads";
import { BrokerError } from "@mac-operator/contracts";
import { FilesystemInspector, type FilesystemNativeAdapter } from "./filesystem-inspector.js";
import type { FilesystemWorkerCommand, FilesystemWorkerResult } from "./filesystem-worker-protocol.js";
import { assertContentDoesNotContainSecrets } from "./secret-policy.js";
import type { WorkerResult } from "./worker-executor.js";

if (!parentPort) throw new Error("Filesystem fault worker requires a parent port");

const require = createRequire(import.meta.url);

try {
  const command = workerData as FilesystemWorkerCommand;
  if (command.operation !== "write") {
    throw new BrokerError("PRECONDITION_FAILED", "Filesystem fault worker supports write only");
  }
  const native = require("./peer_credentials_fault.node") as FilesystemNativeAdapter & {
    setWriteFaultPoint(point: string): void;
  };
  native.setWriteFaultPoint("before_directory_fsync");
  const inspector = new FilesystemInspector([command.plan.root], native);
  assertContentDoesNotContainSecrets(command.content);
  const write = inspector.writePlanned(
    command.plan,
    command.content,
    command.expectedSha256,
    command.createOnly,
    command.tempName
  );
  const value: FilesystemWorkerResult = {
    operation: "write",
    path: write.path,
    bytesWritten: write.bytesWritten,
    sha256: write.sha256,
    created: write.created,
    expectedSha256: write.expectedSha256,
    expectedMatched: write.expectedMatched,
    rootId: command.plan.rootId,
    device: write.device,
    inode: write.inode
  };
  parentPort.postMessage({ ok: true, value } satisfies WorkerResult<FilesystemWorkerResult>);
} catch (error) {
  const brokerError = error instanceof BrokerError
    ? error
    : new BrokerError("EXECUTION_FAILED", "Filesystem fault worker failed");
  parentPort.postMessage({
    ok: false,
    errorClass: brokerError.errorClass,
    message: brokerError.message
  } satisfies WorkerResult<never>);
}
