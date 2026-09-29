import assert from "node:assert/strict";
import test from "node:test";
import { consentPage } from "./pages.js";

test("GUI consent describes screenshot and control access without contradicting the grant", () => {
  const gui = consentPage("csrf", "ChatGPT", "https://example.test/callback", true, true, true);
  assert.match(gui, /Observe Chrome or Safari windows and screenshots/u);
  assert.match(gui, /bounded mouse and keyboard control/u);
  assert.doesNotMatch(gui, /no GUI control is granted/iu);

  const writeOnly = consentPage("csrf", "ChatGPT", "https://example.test/callback", true, true);
  assert.match(writeOnly, /No unrestricted shell, root access, credential access, arbitrary scripts, or GUI control is granted/u);
});
