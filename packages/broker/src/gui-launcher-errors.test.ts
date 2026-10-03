import assert from "node:assert/strict";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { guiLauncherFailureError, throwGuiLauncherFailure } from "./gui-launcher-errors.js";

test("production launcher reserved exits identify the failed boundary", () => {
  for (const [exitCode, errorClass, prefix] of [
    [70, "PRECONDITION_FAILED", "GUI_HELPER_OWNER_UNAVAILABLE"],
    [71, "PRECONDITION_FAILED", "GUI_HELPER_UNAVAILABLE"],
    [72, "PRECONDITION_FAILED", "GUI_LAUNCHER_REQUEST_INVALID"],
    [73, "EXECUTION_FAILED", "GUI_LAUNCHER_IPC_SETUP_FAILED"],
    [74, "EXECUTION_FAILED", "GUI_LAUNCHER_TRANSPORT_FAILED"],
    [75, "EXECUTION_FAILED", "GUI_HELPER_CLEANUP_FAILED"],
    [76, "EXECUTION_FAILED", "GUI_LAUNCHER_OUTPUT_FAILED"]
  ] as const) {
    const error = guiLauncherFailureError({ resultClass: "EXECUTION_FAILED", exitCode });
    assert.ok(error instanceof BrokerError);
    assert.equal(error.errorClass, errorClass);
    assert.ok(error.message.startsWith(`${prefix}:`));
    assert.ok(error.message.length <= 180);
    assert.equal(error.retryable, exitCode === 73 || exitCode === 74);
  }
  assert.throws(() => throwGuiLauncherFailure({ resultClass: "EXECUTION_FAILED", exitCode: 71 }),
    (error: unknown) => error instanceof BrokerError && error.errorClass === "PRECONDITION_FAILED" &&
      /missing or failed identity validation/u.test(error.message) && !/Accessibility/iu.test(error.message));
});

test("launcher classification preserves supervisor outcomes and unrelated child statuses", () => {
  for (const resultClass of ["SUCCEEDED", "CANCELLED", "TIMEOUT", "OUTPUT_LIMIT", "UNKNOWN_OUTCOME"] as const) {
    assert.equal(guiLauncherFailureError({ resultClass, exitCode: 71 }), undefined);
  }
  for (const exitCode of [null, 0, 1, 69, 77]) {
    assert.equal(guiLauncherFailureError({ resultClass: "EXECUTION_FAILED", exitCode }), undefined);
  }
});
