import type {
  FilesystemPathPlan,
  SafeDirectoryEntry,
  SafeFileMatch,
  SafePathMetadata,
  SafeTreeEntry
} from "./filesystem-inspector.js";

export type FilesystemWorkerCommand =
  | { operation: "stat"; plan: FilesystemPathPlan; followSymlink: boolean }
  | { operation: "read"; plan: FilesystemPathPlan; offset: number; maxBytes: number; encoding: "utf8" | "base64" | "metadata" }
  | { operation: "hash"; plan: FilesystemPathPlan; algorithm: "sha256" | "sha512" }
  | { operation: "list"; plan: FilesystemPathPlan; cursor: string | undefined; limit: number; includeHidden: boolean }
  | { operation: "tree"; plan: FilesystemPathPlan; depth: number; maxEntries: number }
  | { operation: "find"; plans: readonly FilesystemPathPlan[]; query: string; maxResults: number }
  | { operation: "recent"; plans: readonly FilesystemPathPlan[]; sinceSeconds: number; limit: number; nowMs: number }
  | { operation: "search_text"; plans: readonly FilesystemPathPlan[]; query: string; glob: string | undefined; maxResults: number }
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
      operation: "tree";
      root: string;
      entries: readonly SafeTreeEntry[];
      truncated: boolean;
      rootId: string;
    }
  | {
      operation: "find";
      roots: readonly string[];
      query: string;
      matches: readonly SafeFileMatch[];
      truncated: boolean;
    }
  | {
      operation: "recent";
      files: readonly SafeFileMatch[];
      truncated: boolean;
    }
  | {
      operation: "search_text";
      query: string;
      matches: readonly import("./filesystem-inspector.js").SafeTextMatch[];
      truncated: boolean;
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
