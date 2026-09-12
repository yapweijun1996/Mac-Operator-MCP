import type { FilesystemPathPlan, SafePathMetadata } from "./filesystem-inspector.js";

export type FilesystemWorkerCommand =
  | { operation: "stat"; plan: FilesystemPathPlan; followSymlink: boolean }
  | { operation: "read"; plan: FilesystemPathPlan; offset: number; maxBytes: number; encoding: "utf8" | "base64" | "metadata" }
  | {
      operation: "write";
      plan: FilesystemPathPlan;
      content: Buffer;
      expectedSha256: string | undefined;
      createOnly: boolean;
      tempName: string;
    };

export type FilesystemWorkerResult =
  | { operation: "stat"; metadata: SafePathMetadata }
  | {
      operation: "read";
      path: string;
      encoding: "utf8" | "base64" | "metadata";
      content?: string;
      sizeBytes: number;
      sha256: string;
      truncated: boolean;
      rootId: string;
      device: string;
      inode: string;
      bytesReturned: number;
    }
  | {
      operation: "write";
      path: string;
      bytesWritten: number;
      sha256: string;
      created: boolean;
      expectedSha256: string | null;
      expectedMatched: boolean;
      rootId: string;
      device: string;
      inode: string;
    };
