import { createHash } from "node:crypto";
import { parentPort, workerData } from "node:worker_threads";
import { BrokerError } from "@mac-operator/contracts";
import { FilesystemInspector } from "./filesystem-inspector.js";
import type { FilesystemWorkerCommand, FilesystemWorkerResult } from "./filesystem-worker-protocol.js";
import { assertContentDoesNotContainSecrets } from "./secret-policy.js";
import type { WorkerResult } from "./worker-executor.js";

if (!parentPort) throw new Error("Filesystem worker requires a parent port");

try {
  const command = workerData as FilesystemWorkerCommand;
  const inspector = new FilesystemInspector([command.plan.root]);
  let value: FilesystemWorkerResult;
  if (command.operation === "stat") {
    value = { operation: "stat", metadata: inspector.statPlanned(command.plan, command.followSymlink) };
  } else if (command.operation === "read") {
    const read = inspector.readPlanned(command.plan, command.offset, command.maxBytes);
    assertContentDoesNotContainSecrets(read.content);
    const sha256 = createHash("sha256").update(read.content).digest("hex");
    let content: string | undefined;
    if (command.encoding === "utf8") {
      try { content = new TextDecoder("utf-8", { fatal: true }).decode(read.content); }
      catch { throw new BrokerError("PRECONDITION_FAILED", "Filesystem content is not valid UTF-8"); }
    } else if (command.encoding === "base64") content = read.content.toString("base64");
    value = {
      operation: "read",
      path: read.path,
      encoding: command.encoding,
      ...(content !== undefined ? { content } : {}),
      sizeBytes: read.sizeBytes,
      sha256,
      truncated: read.truncated,
      rootId: read.rootId,
      device: read.device,
      inode: read.inode,
      bytesReturned: read.content.length
    };
  } else if (command.operation === "hash") {
    const hash = inspector.hashPlanned(command.plan, command.algorithm);
    value = {
      operation: "hash",
      path: hash.path,
      algorithm: hash.algorithm,
      digest: hash.digest,
      sizeBytes: hash.sizeBytes,
      rootId: hash.rootId,
      device: hash.device,
      inode: hash.inode
    };
  } else if (command.operation === "list") {
    const listing = inspector.listPlanned(command.plan, command.cursor, command.limit, command.includeHidden);
    value = {
      operation: "list",
      path: listing.path,
      entries: listing.entries,
      nextCursor: listing.nextCursor,
      rootId: listing.rootId
    };
  } else {
    assertContentDoesNotContainSecrets(command.content);
    const write = inspector.writePlanned(
      command.plan,
      command.content,
      command.expectedSha256,
      command.createOnly,
      command.tempName
    );
    value = {
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
  }
  parentPort.postMessage({ ok: true, value } satisfies WorkerResult<FilesystemWorkerResult>);
} catch (error) {
  const brokerError = error instanceof BrokerError
    ? error
    : new BrokerError("EXECUTION_FAILED", "Filesystem worker failed");
  parentPort.postMessage({
    ok: false,
    errorClass: brokerError.errorClass,
    message: brokerError.message
  } satisfies WorkerResult<never>);
}
