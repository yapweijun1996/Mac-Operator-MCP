import type { FilesystemPathPlan, SafeDirectoryEntry, SafePathMetadata } from "./filesystem-inspector.js";

export type FilesystemWorkerCommand =
  | { operation: "stat"; plan: FilesystemPathPlan; followSymlink: boolean }
  | { operation: "read"; plan: FilesystemPathPlan; offset: number; maxBytes: number; encoding: "utf8" | "base64" | "metadata" }
  | { operation: "hash"; plan: FilesystemPathPlan; algorithm: "sha256" | "sha512" }
  | { operation: "list"; plan: FilesystemPathPlan; cursor: string | undefined; limit: number; includeHidden: boolean }
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
      operation: "hash";
      path: string;
      algorithm: "sha256" | "sha512";
      digest: string;
      sizeBytes: number;
      rootId: string;
      device: string;
      inode: string;
    }
  | {
      operation: "list";
      path: string;
      entries: readonly SafeDirectoryEntry[];
      nextCursor: string | null;
      rootId: string;
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
