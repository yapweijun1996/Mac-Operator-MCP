import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import {
  SEMANTIC_RESOURCE_BUDGETS,
  validateSemanticResourceBudget,
  validateStorageSemanticResourceBudget
} from "./resource-budget.js";

function assertPreconditionFailure(action: () => void): void {
  assert.throws(action, (error: unknown) =>
    error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED"
  );
}

test("semantic search budgets reject multiplicative root fan-out", () => {
  validateSemanticResourceBudget("mac_search_text", {
    roots: Array.from({ length: 8 }, () => "/workspace"),
    query: "needle",
    max_results: 1_000
  });
  assertPreconditionFailure(() => validateSemanticResourceBudget("mac_search_text", {
    roots: Array.from({ length: 9 }, () => "/workspace"),
    query: "needle",
    max_results: 1_000
  }));
});

test("semantic project and tree budgets reject bounded-but-expansive work", () => {
  validateSemanticResourceBudget("mac_project_discover", {
    roots: Array.from({ length: 8 }, () => "/workspace"),
    types: ["node"],
    max_results: 500
  });
  assertPreconditionFailure(() => validateSemanticResourceBudget("mac_project_discover", {
    roots: Array.from({ length: 9 }, () => "/workspace"),
    types: ["node"],
    max_results: 500
  }));
  assertPreconditionFailure(() => validateSemanticResourceBudget("mac_directory_tree", {
    path: "/workspace",
    depth: 8,
    max_entries: 2_000
  }));
});

test("storage analysis applies its budget after policy-root defaults resolve", () => {
  validateStorageSemanticResourceBudget(4, 20, 4);
  assertPreconditionFailure(() => validateStorageSemanticResourceBudget(16, 20, 8));
  assert.equal(SEMANTIC_RESOURCE_BUDGETS.storageRankingSlots, 2_048);
});
