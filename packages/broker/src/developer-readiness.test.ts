import assert from "node:assert/strict";
import test from "node:test";
import { assertDeveloperPublicEnablement, requiresDeveloperReadiness } from "./developer-readiness.js";

test("developer readiness identifies the D1 mutation tools", () => {
  assert.equal(requiresDeveloperReadiness("mac_write_file_atomic"), true);
  assert.equal(requiresDeveloperReadiness("mac_apply_patch"), true);
  assert.equal(requiresDeveloperReadiness("mac_git_stage"), true);
  assert.equal(requiresDeveloperReadiness("mac_git_commit"), true);
  assert.equal(requiresDeveloperReadiness("mac_job_cancel"), true);
  assert.equal(requiresDeveloperReadiness("mac_task_run"), false);
  assert.equal(requiresDeveloperReadiness("mac_health"), false);
});

test("developer public exposure rejects unavailable and staging readiness", () => {
  assert.doesNotThrow(() => assertDeveloperPublicEnablement(false, "unavailable"));
  assert.throws(
    () => assertDeveloperPublicEnablement(true, "unavailable"),
    /production readiness evidence/u
  );
  assert.throws(
    () => assertDeveloperPublicEnablement(true, "staging-only"),
    /production readiness evidence/u
  );
  assert.doesNotThrow(() => assertDeveloperPublicEnablement(true, "production"));
});
