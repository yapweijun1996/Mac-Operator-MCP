import assert from "node:assert/strict";
import test from "node:test";
import { AppSandboxRunAdmission } from "./app-sandbox-run-admission.js";

test("App Sandbox run admission rejects overlapping tasks in the shared container", () => {
  const admission = new AppSandboxRunAdmission();
  const finishFirst = admission.begin();

  assert.throws(() => admission.begin(), (error: unknown) =>
    (error as { errorClass?: string }).errorClass === "CONFLICT");

  finishFirst(true);
  const finishSecond = admission.begin();
  finishSecond(true);
});

test("App Sandbox run admission permanently fails closed after an uncertain process outcome", () => {
  const admission = new AppSandboxRunAdmission();
  const finish = admission.begin();

  finish(false);

  assert.equal(admission.isPoisoned, true);
  assert.throws(() => admission.begin(), (error: unknown) =>
    (error as { errorClass?: string }).errorClass === "POLICY_DENIED");
});
