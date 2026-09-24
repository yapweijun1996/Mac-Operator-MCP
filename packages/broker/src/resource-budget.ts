import { BrokerError } from "@mac-operator/contracts";

/**
 * Adapter-specific semantic work budgets. Individual argument limits are not
 * sufficient when one request fans out across multiple authorized roots.
 * These values are intentionally fixed, reviewable, and fail closed.
 */
export const SEMANTIC_RESOURCE_BUDGETS = Object.freeze({
  searchResultSlots: 8_192,
  projectDiscoveryResultSlots: 4_096,
  directoryTraversalSlots: 16_384,
  storageRankingSlots: 2_048
} as const);

const SEARCH_TOOLS = new Set([
  "mac_find_files",
  "mac_recent_files",
  "mac_search_text"
]);

/**
 * Validate cross-dimensional work budgets before a tool-specific adapter is
 * planned. Malformed individual values remain the responsibility of the
 * existing tool validators; this function only applies to well-typed values.
 */
export function validateSemanticResourceBudget(
  tool: string,
  argumentsValue: Readonly<Record<string, unknown>>
): void {
  if (SEARCH_TOOLS.has(tool)) {
    const roots = argumentsValue.roots;
    const resultLimit = tool === "mac_recent_files" ? argumentsValue.limit : argumentsValue.max_results;
    if (Array.isArray(roots) && Number.isSafeInteger(resultLimit)) {
      assertBudget(
        roots.length * (resultLimit as number),
        SEMANTIC_RESOURCE_BUDGETS.searchResultSlots,
        `${tool} search fan-out`
      );
    }
    return;
  }

  if (tool === "mac_project_discover") {
    const roots = argumentsValue.roots;
    const maxResults = argumentsValue.max_results;
    if (Array.isArray(roots) && Number.isSafeInteger(maxResults)) {
      assertBudget(
        roots.length * (maxResults as number),
        SEMANTIC_RESOURCE_BUDGETS.projectDiscoveryResultSlots,
        "mac_project_discover fan-out"
      );
    }
    return;
  }

  if (tool === "mac_directory_tree") {
    const depth = argumentsValue.depth;
    const maxEntries = argumentsValue.max_entries;
    if (Number.isSafeInteger(depth) && Number.isSafeInteger(maxEntries)) {
      assertBudget(
        Math.max(1, depth as number + 1) * (maxEntries as number),
        SEMANTIC_RESOURCE_BUDGETS.directoryTraversalSlots,
        "mac_directory_tree traversal"
      );
    }
  }
}

/** Validate the resolved root fan-out used by storage analysis defaults. */
export function validateStorageSemanticResourceBudget(
  rootCount: number,
  topN: number,
  maxDepth: number
): void {
  if (!Number.isSafeInteger(rootCount) || !Number.isSafeInteger(topN) || !Number.isSafeInteger(maxDepth)) return;
  assertBudget(
    rootCount * topN * Math.max(1, maxDepth + 1),
    SEMANTIC_RESOURCE_BUDGETS.storageRankingSlots,
    "mac_storage_analysis ranking"
  );
}

function assertBudget(actual: number, maximum: number, operation: string): void {
  if (actual > maximum) {
    throw new BrokerError("PRECONDITION_FAILED", `${operation} exceeds the semantic resource budget`);
  }
}
