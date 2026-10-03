import assert from "node:assert/strict";
import test from "node:test";
import { consentPage, guiSessionPage } from "./pages.js";

test("GUI consent describes screenshot and control access without contradicting the grant", () => {
  const gui = consentPage("csrf", "ChatGPT", "https://example.test/callback", true, true, true);
  assert.match(gui, /Observe Chrome or Safari windows and screenshots/u);
  assert.match(gui, /bounded mouse and keyboard control/u);
  assert.doesNotMatch(gui, /no GUI control is granted/iu);

  const writeOnly = consentPage("csrf", "ChatGPT", "https://example.test/callback", true, true);
  assert.match(writeOnly, /No unrestricted shell, root access, credential access, arbitrary scripts, or GUI control is granted/u);
});

test("desktop consent and management describe explicit full-app delegation without widening browser consent", () => {
  const consent = consentPage("csrf", "ChatGPT", "https://example.test/callback", true, true, true, false, "", true);
  assert.match(consent, /Observe ordinary desktop applications and screenshots/u);
  assert.match(consent, /separate explicit owner authorization/u);
  assert.match(consent, /Existing browser access remains limited/u);
  const browser = { id: "gui-session:12345678-1234-1234-1234-123456789abc", appId: "bundle:com.google.Chrome",
    persistent: true, expiresAtMs: Number.MAX_SAFE_INTEGER, remainingOperations: Number.MAX_SAFE_INTEGER };
  const desktop = { ...browser, id: "gui-session:22345678-1234-1234-1234-123456789abc", appId: "desktop", desktop: true as const };
  const management = guiSessionPage("csrf", undefined, [browser, desktop]);
  assert.match(management, /Persistent desktop access active/u);
  assert.match(management, /ordinary desktop apps allowed by the current policy/u);
  assert.match(management, /bundle:com.google.Chrome/u);
  assert.match(management, /Revoke desktop access/u);
  assert.match(management, /Revoke browser access/u);
  assert.match(management, /can bring an authorized target app to the foreground/u);
  assert.doesNotMatch(management, /Keep the target browser in front/u);
  assert.equal((management.match(/name="grant_id"/gu) ?? []).length, 2);
});
