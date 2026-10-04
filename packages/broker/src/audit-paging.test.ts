import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerStore, type AuditEvent } from "./persistence.js";

const NOW = 1_700_000_000_000;
const PROJECT = "/synthetic/audit-paging/project";
const OTHER_PROJECT = "/synthetic/audit-paging/other";
const WORKTREE = "/synthetic/audit-paging/trees/task-1";
const OUTCOME_CLASSES = ["SUCCEEDED", "FAILED", "TIMEOUT", "VERIFICATION_FAILED", "CANCELLED", "OUTPUT_LIMIT", "EXECUTION_FAILED", "UNKNOWN_OUTCOME"];
const RUN_TOOLS = ["mac_test_run", "mac_build_run", "mac_task_run"];

async function withStore(body: (store: BrokerStore) => Promise<void> | void): Promise<void> {
  const directory = await mkdtemp(join(tmpdir(), "mac-operator-audit-paging-"));
  const store = new BrokerStore(join(directory, "broker.sqlite"));
  try { await body(store); } finally { store.close(); await rm(directory, { recursive: true, force: true }); }
}

function append(store: BrokerStore, requestId: string, overrides: Partial<AuditEvent> = {}): void {
  store.appendAudit({
    requestId, principalId: "principal-1", tool: "mac_git_status", eventType: "completion", decision: "allow",
    resultClass: "SUCCEEDED", targetRef: `project:${PROJECT}`, policyVersion: "policy-0.1", evidence: {}, timestampMs: NOW, ...overrides
  });
}

/** Walks the project view with one limit, following nextBeforeSequence until it is null. */
function walk(store: BrokerStore, limit: number, project = PROJECT) {
  const pages: Array<{ events: Array<Record<string, unknown>>; nextBeforeSequence: number | null }> = [];
  let before: number | undefined;
  do {
    const page = store.executionAuditPage("principal-1", { project, limit, ...(before === undefined ? {} : { beforeSequence: before }) });
    pages.push(page);
    before = page.nextBeforeSequence ?? undefined;
  } while (before !== undefined);
  return pages;
}

function pathsEvidence(index: number, count: number) {
  return { project: PROJECT, changedPaths: Array.from({ length: count }, (_, path) => `src/module-${index}/feature-${path}/implementation.ts`) };
}

test("a cursor walk of 250 project rows returns disjoint, strictly older, newest-first and complete pages", async () => {
  await withStore((store) => {
    const seeded: string[] = [];
    for (let index = 0; index < 250; index += 1) {
      append(store, `paged-${index}`); seeded.push(`paged-${index}`);
      // Rows that must never appear: another project, another principal and an internal ledger row for this project.
      if (index % 25 === 0) {
        append(store, `elsewhere-${index}`, { targetRef: `project:${OTHER_PROJECT}` });
        append(store, `stranger-${index}`, { principalId: "principal-2" });
        append(store, `reconcile-${index}`, { tool: "internal_request_reconcile", resultClass: "UNKNOWN_OUTCOME" });
      }
    }
    const pages = walk(store, 100);
    assert.deepEqual(pages.map((page) => page.events.length), [100, 100, 50]);
    assert.deepEqual(pages.map((page) => page.nextBeforeSequence === null), [false, false, true]);
    const events = pages.flatMap((page) => page.events);
    assert.deepEqual(events.map((event) => event.request_id), [...seeded].reverse());
    const sequences = events.map((event) => event.sequence as number);
    assert.deepEqual(sequences, [...sequences].sort((a, b) => b - a));
    assert.equal(new Set(sequences).size, sequences.length);
    // The cursor of every page is the sequence of its last row, so the next page is strictly older.
    for (const page of pages.slice(0, -1)) assert.equal(page.nextBeforeSequence, page.events.at(-1)!.sequence);
  });
});

test("a cursor exists exactly when older rows remain", async () => {
  await withStore((store) => {
    for (let index = 0; index < 5; index += 1) append(store, `exact-${index}`);
    assert.equal(store.executionAuditPage("principal-1", { project: PROJECT, limit: 5 }).nextBeforeSequence, null);
    assert.equal(store.executionAuditPage("principal-1", { project: PROJECT, limit: 100 }).nextBeforeSequence, null);
    const first = store.executionAuditPage("principal-1", { project: PROJECT, limit: 4 });
    assert.equal(first.events.length, 4);
    assert.notEqual(first.nextBeforeSequence, null);
    const rest = store.executionAuditPage("principal-1", { project: PROJECT, limit: 4, beforeSequence: first.nextBeforeSequence! });
    assert.deepEqual(rest.events.map((event) => event.request_id), ["exact-0"]);
    assert.equal(rest.nextBeforeSequence, null);
    assert.equal(store.executionAuditPage("principal-1", { project: PROJECT, limit: 4, beforeSequence: 1 }).nextBeforeSequence, null);
    // The list wrapper keeps returning plain rows.
    assert.deepEqual(store.executionAudit("principal-1", { project: PROJECT, limit: 2 }).map((event) => event.request_id), ["exact-4", "exact-3"]);
  });
});

test("a page cut by the byte budget hands out a cursor that recovers every remaining row exactly once", async () => {
  await withStore((store) => {
    const seeded: string[] = [];
    for (let index = 0; index < 100; index += 1) { append(store, `bulky-${index}`, { evidence: pathsEvidence(index, 24) }); seeded.push(`bulky-${index}`); }
    const pages = walk(store, 100);
    assert.ok(pages.length > 1, "the 64 KiB budget must cut the 100-row page");
    assert.ok(pages[0]!.events.length < 100);
    assert.notEqual(pages[0]!.nextBeforeSequence, null);
    for (const page of pages) assert.ok(Buffer.byteLength(JSON.stringify(page.events), "utf8") <= 64 * 1024 + 2 * page.events.length);
    assert.deepEqual(pages.flatMap((page) => page.events).map((event) => event.request_id), [...seeded].reverse());
    assert.equal(pages.at(-1)!.nextBeforeSequence, null);
  });
});

test("a first row larger than the byte budget is still returned so the cursor advances", async () => {
  await withStore((store) => {
    for (let index = 0; index < 3; index += 1) append(store, `small-${index}`);
    const deepPath = `src/${"nested-directory/".repeat(60)}implementation.ts`;
    append(store, "huge", { evidence: { project: PROJECT, changedPaths: Array.from({ length: 80 }, (_, index) => `${deepPath}.${index}`) } });
    const first = store.executionAuditPage("principal-1", { project: PROJECT, limit: 100 });
    assert.deepEqual(first.events.map((event) => event.request_id), ["huge"]);
    assert.ok(Buffer.byteLength(JSON.stringify(first.events[0]), "utf8") > 64 * 1024);
    assert.equal(first.nextBeforeSequence, first.events[0]!.sequence);
    const rest = store.executionAuditPage("principal-1", { project: PROJECT, limit: 100, beforeSequence: first.nextBeforeSequence! });
    assert.deepEqual(rest.events.map((event) => event.request_id), ["small-2", "small-1", "small-0"]);
    assert.equal(rest.nextBeforeSequence, null);
  });
});

test("internal ledger rows are hidden from the project view before the limit is applied", async () => {
  await withStore((store) => {
    for (let index = 0; index < 3; index += 1) append(store, `visible-${index}`);
    for (let index = 0; index < 4; index += 1) append(store, `reconcile-${index}`, { tool: "internal_request_reconcile", resultClass: "UNKNOWN_OUTCOME" });
    const page = store.executionAuditPage("principal-1", { project: PROJECT, limit: 3 });
    assert.deepEqual(page.events.map((event) => event.request_id), ["visible-2", "visible-1", "visible-0"]);
    assert.equal(page.nextBeforeSequence, null);
    // A lookup by request id is not the project view and still shows the ledger row.
    assert.deepEqual(store.executionAudit("principal-1", { requestId: "reconcile-0" }).map((event) => event.tool), ["internal_request_reconcile"]);
  });
});

test("audit page filters reject malformed cursors and never read accessor properties", async () => {
  await withStore((store) => {
    append(store, "seed");
    for (const beforeSequence of [0, -1, 1.5, "7", Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 1, null, {}]) {
      assert.throws(() => store.executionAuditPage("principal-1", { project: PROJECT, beforeSequence: beforeSequence as never }), /malformed/u, String(beforeSequence));
    }
    assert.throws(() => store.executionAuditPage("principal-1", { project: PROJECT, cursor: 7 } as never), /malformed/u);
    let accessed = false;
    const accessorFilters = Object.defineProperty({}, "beforeSequence", { enumerable: true, get: () => { accessed = true; return 7; } });
    assert.throws(() => store.executionAuditPage("principal-1", accessorFilters), /malformed/u);
    assert.throws(() => store.executionAudit("principal-1", accessorFilters), /malformed/u);
    assert.equal(accessed, false);
    assert.equal(store.executionAuditPage("principal-1", { project: PROJECT, beforeSequence: Number.MAX_SAFE_INTEGER }).events.length, 1);
  });
});

/** One validation run: an authorization row naming the task, an intent row and a completion with caller-chosen evidence. */
function seedRun(store: BrokerStore, requestId: string, tool: string, outcome: string, options: {
  principalId?: string; worktree?: string; taskId?: string; completionEvidence?: unknown;
} = {}): void {
  const principalId = options.principalId ?? "principal-1";
  const task = { project: PROJECT, worktree: options.worktree ?? WORKTREE, taskId: options.taskId ?? "task-1" };
  const base = { principalId, tool, targetRef: `project:${PROJECT}` };
  append(store, requestId, { ...base, eventType: "decision", resultClass: "AUTHORIZED", evidence: { scopes: ["mac.task.run"], ...task } });
  append(store, requestId, { ...base, eventType: "intent", resultClass: "INTENT_RECORDED", evidence: { scopes: ["mac.task.run"], ...task } });
  append(store, requestId, { ...base, eventType: "completion", resultClass: outcome, evidence: options.completionEvidence ?? { scopes: ["mac.task.run"], ...task } });
}

function outcomes(store: BrokerStore, overrides: Record<string, unknown> = {}, principalId = "principal-1") {
  return store.validationOutcomes(principalId, { worktree: WORKTREE, taskId: "task-1", tools: RUN_TOOLS, resultClasses: OUTCOME_CLASSES, ...overrides } as never);
}

test("validation outcomes of a task survive any amount of later project activity, including scopes-only failure completions", async () => {
  await withStore((store) => {
    seedRun(store, "run-success", "mac_test_run", "SUCCEEDED", { completionEvidence: { worktree: WORKTREE, taskId: "task-1", scopes: ["mac.task.run"] } });
    // Failure completions written before they carried task evidence hold nothing but scopes.
    seedRun(store, "run-timeout", "mac_build_run", "TIMEOUT", { completionEvidence: { scopes: ["mac.task.run"] } });
    seedRun(store, "run-failed", "mac_task_run", "FAILED", { completionEvidence: { scopes: ["mac.task.run"] } });
    // Never counted: another task, another worktree, another principal, other tools, and rows that are not outcomes.
    seedRun(store, "other-task", "mac_test_run", "FAILED", { taskId: "task-2" });
    seedRun(store, "other-tree", "mac_test_run", "FAILED", { worktree: "/synthetic/audit-paging/trees/task-2" });
    seedRun(store, "stranger", "mac_test_run", "FAILED", { principalId: "principal-2" });
    seedRun(store, "status-read", "mac_git_status", "SUCCEEDED");
    append(store, "reuse", { tool: "mac_test_run", resultClass: "IDEMPOTENT_REUSE", evidence: { worktree: WORKTREE, taskId: "task-1" } });
    for (let index = 0; index < 300; index += 1) append(store, `later-${index}`);

    // The newest-100 project view no longer reaches any of the runs, which is what used to blank the PR evidence.
    const window = store.executionAudit("principal-1", { project: PROJECT, limit: 100 });
    assert.equal(window.some((row) => ["run-success", "run-timeout", "run-failed"].includes(row.request_id as string)), false);

    assert.deepEqual(outcomes(store), [
      { tool: "mac_task_run", result_class: "FAILED" },
      { tool: "mac_build_run", result_class: "TIMEOUT" },
      { tool: "mac_test_run", result_class: "SUCCEEDED" }
    ]);
    // Each principal sees only its own runs.
    assert.deepEqual(outcomes(store, {}, "principal-2"), [{ tool: "mac_test_run", result_class: "FAILED" }]);
    assert.deepEqual(outcomes(store, {}, "principal-3"), []);
    assert.deepEqual(outcomes(store, { taskId: "task-2" }), [{ tool: "mac_test_run", result_class: "FAILED" }]);
    assert.deepEqual(outcomes(store, { resultClasses: ["SUCCEEDED"], tools: ["mac_test_run"] }), [{ tool: "mac_test_run", result_class: "SUCCEEDED" }]);
  });
});

test("validation outcomes keep the newest 32 rather than the oldest", async () => {
  await withStore((store) => {
    const expected: Array<{ tool: string; result_class: string }> = [];
    for (let index = 0; index < 40; index += 1) {
      const tool = RUN_TOOLS[index % RUN_TOOLS.length]!, outcome = OUTCOME_CLASSES[index % OUTCOME_CLASSES.length]!;
      seedRun(store, `run-${index}`, tool, outcome);
      expected.push({ tool, result_class: outcome });
    }
    assert.deepEqual(outcomes(store, { limit: 32 }), expected.slice(-32).reverse());
    assert.equal(outcomes(store, { limit: 5 }).length, 5);
  });
});

test("validation outcome filters are validated as strictly as audit filters", async () => {
  await withStore((store) => {
    seedRun(store, "run-success", "mac_test_run", "SUCCEEDED");
    const malformed: Array<Record<string, unknown>> = [
      { worktree: "relative/path" }, { worktree: "/synthetic/../escape" }, { worktree: 7 },
      { taskId: "../escape" }, { taskId: "" }, { taskId: 7 },
      { tools: [] }, { tools: "mac_test_run" }, { tools: ["internal_request_reconcile"] }, { tools: ["mac_test_run') OR 1=1 --"] }, { tools: [7] },
      { tools: Array.from({ length: 33 }, () => "mac_test_run") },
      { resultClasses: [] }, { resultClasses: ["succeeded"] }, { resultClasses: ["SUCCEEDED' OR 1=1 --"] },
      { limit: 0 }, { limit: 101 }, { limit: 1.5 }, { unexpected: true }
    ];
    for (const overrides of malformed) assert.throws(() => outcomes(store, overrides), /malformed/u, JSON.stringify(overrides));
    assert.throws(() => outcomes(store, {}, "bad principal"), /malformed/u);
    let accessed = false;
    const accessorFilters = Object.defineProperty({ worktree: WORKTREE, taskId: "task-1", resultClasses: OUTCOME_CLASSES }, "tools", { enumerable: true, get: () => { accessed = true; return RUN_TOOLS; } });
    assert.throws(() => store.validationOutcomes("principal-1", accessorFilters as never), /malformed/u);
    const accessorList = Object.defineProperty([], "0", { enumerable: true, get: () => { accessed = true; return "mac_test_run"; } });
    assert.throws(() => outcomes(store, { tools: accessorList }), /malformed/u);
    assert.equal(accessed, false);
    assert.deepEqual(outcomes(store), [{ tool: "mac_test_run", result_class: "SUCCEEDED" }]);
  });
});
