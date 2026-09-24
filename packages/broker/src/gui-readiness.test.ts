import assert from "node:assert/strict";
import test from "node:test";
import { assertGuiPublicEnablement, requiresAccessibilityPermission } from "./gui-readiness.js";

test("Accessibility readiness identifies only permission-dependent GUI tools", () => {
  assert.equal(requiresAccessibilityPermission("mac_app_focus"), true);
  assert.equal(requiresAccessibilityPermission("mac_ui_observe"), true);
  assert.equal(requiresAccessibilityPermission("mac_ui_action"), true);
  assert.equal(requiresAccessibilityPermission("mac_ui_type"), true);
  assert.equal(requiresAccessibilityPermission("mac_app_open"), false);
  assert.equal(requiresAccessibilityPermission("mac_app_list"), false);
});

test("GUI public exposure rejects unavailable and staging readiness", () => {
  assert.doesNotThrow(() => assertGuiPublicEnablement(false, "unavailable"));
  assert.throws(
    () => assertGuiPublicEnablement(true, "unavailable"),
    /production permission evidence/u
  );
  assert.throws(
    () => assertGuiPublicEnablement(true, "staging-only"),
    /production permission evidence/u
  );
  assert.doesNotThrow(() => assertGuiPublicEnablement(true, "production"));
});
