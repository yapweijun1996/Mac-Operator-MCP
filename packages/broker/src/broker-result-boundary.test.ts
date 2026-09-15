import assert from "node:assert/strict";
import test from "node:test";
import {
  parseStoredAppFocusResult,
  parseStoredAppOpenResult,
  parseStoredPatchResult,
  parseStoredUiActionResult,
  parseStoredWriteResult
} from "./broker.js";

const appId = "bundle:com.example.Editor";
const appOpenJobId = `job:app-open-${"a".repeat(48)}`;
const appFocusJobId = `job:app-focus-${"b".repeat(48)}`;
const uiActionJobId = `job:ui-action-${"c".repeat(48)}`;

test("stored mutation and app readbacks reject unknown authority fields", () => {
  const appOpen = {
    app_id: appId,
    state: "launched",
    process_id: null,
    target: { kind: "app", reference: appId },
    verified: true,
    job_id: appOpenJobId
  };
  assert.deepEqual(parseStoredAppOpenResult(JSON.stringify(appOpen)), appOpen);
  assert.throws(() => parseStoredAppOpenResult(JSON.stringify({ ...appOpen, extra: true })), /malformed/u);
  assert.throws(() => parseStoredAppOpenResult(JSON.stringify({ ...appOpen, target: { ...appOpen.target, extra: true } })), /malformed/u);

  const appFocus = {
    app_id: appId,
    window_id: `window:${"d".repeat(48)}`,
    window_title: "Editor",
    focused: true,
    reobserved_at: "2026-09-15T00:00:00.000Z",
    verified: true,
    job_id: appFocusJobId
  };
  assert.deepEqual(parseStoredAppFocusResult(JSON.stringify(appFocus)), appFocus);
  assert.throws(() => parseStoredAppFocusResult(JSON.stringify({ ...appFocus, extra: true })), /malformed/u);

  const uiAction = {
    element_ref: `element:${"e".repeat(48)}`,
    action: "press",
    accepted: true,
    job_id: uiActionJobId,
    reobserved: { role: "AXButton", enabled: true, focused: true, secure: false }
  };
  assert.deepEqual(parseStoredUiActionResult(JSON.stringify(uiAction)), uiAction);
  assert.throws(() => parseStoredUiActionResult(JSON.stringify({ ...uiAction, extra: true })), /malformed/u);
  assert.throws(() => parseStoredUiActionResult(JSON.stringify({
    ...uiAction,
    reobserved: { ...uiAction.reobserved, extra: true }
  })), /malformed/u);
});

test("stored filesystem write and patch readbacks reject unknown authority fields", () => {
  const write = {
    path: "/tmp/output.txt",
    bytes_written: 3,
    sha256: "f".repeat(64),
    created: true,
    precondition: { expected_sha256: null, matched: true, create_only: true }
  };
  assert.deepEqual(parseStoredWriteResult(JSON.stringify(write)), write);
  assert.throws(() => parseStoredWriteResult(JSON.stringify({ ...write, extra: true })), /malformed/u);
  assert.throws(() => parseStoredWriteResult(JSON.stringify({
    ...write,
    precondition: { ...write.precondition, extra: true }
  })), /malformed/u);

  const patch = {
    project_root: "/tmp/project",
    result: "applied",
    changed_paths: ["src/index.ts"],
    precondition: {
      checked: true,
      expected_sha256: null,
      actual_sha256: "1".repeat(64),
      matched: true
    },
    files: [{ path: "/tmp/project/src/index.ts", sha256: "2".repeat(64), size_bytes: 3 }]
  };
  assert.deepEqual(parseStoredPatchResult(JSON.stringify(patch)), patch);
  assert.throws(() => parseStoredPatchResult(JSON.stringify({ ...patch, extra: true })), /malformed/u);
  assert.throws(() => parseStoredPatchResult(JSON.stringify({
    ...patch,
    files: [{ ...patch.files[0], extra: true }]
  })), /malformed/u);
});
