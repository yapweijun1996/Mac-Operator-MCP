import assert from "node:assert/strict";
import test from "node:test";
import { assertContentDoesNotContainSecrets, assertContentPathAllowed, redactBoundedText, redactLogText } from "./secret-policy.js";

test("fixed secret-zone policy denies credential and private-data paths", () => {
  const denied = [
    "/Users/test/project/.env",
    "/Users/test/project/.ENV.production",
    "/Users/test/.ssh/id_ed25519",
    "/Users/test/.config/gcloud/application_default_credentials.json",
    "/Users/test/.docker/config.json",
    "/Users/test/.docker/contexts/meta/abc/meta.json",
    "/Users/test/.config/gh/hosts.yml",
    "/Users/test/Library/Keychains/login.keychain-db",
    "/Users/test/Library/Application Support/Google/Chrome/Default/Login Data",
    "/Users/test/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data",
    "/Users/test/Library/Containers/com.apple.mail/Data/Library/Mail/V10/Envelope Index",
    "/Users/test/project/.git-credentials"
  ];
  for (const path of denied) {
    assert.throws(() => assertContentPathAllowed(path), /protected secret zone/u, path);
  }
  assert.doesNotThrow(() => assertContentPathAllowed("/Users/test/project/README.md"));
});

test("content policy denies representative private keys and access tokens", () => {
  const denied = [
    "-----BEGIN PRIVATE KEY-----\nnot-a-real-key",
    "aws=AKIA1234567890ABCDEF",
    "api_key=supersecretvalue",
    "token: xoxb-1234567890-abcdefghijklmnop",
    "Authorization: Bearer abcdefghijklmnop-secret",
    "Authorization: Basic YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4",
    "access_token=eyJheadersegment.payloadsegment.signaturesegment"
  ];
  for (const value of denied) {
    assert.throws(() => assertContentDoesNotContainSecrets(Buffer.from(value)), /protected secret signature/u);
  }
  assert.doesNotThrow(() => assertContentDoesNotContainSecrets(Buffer.from("ordinary documentation")));
});

test("log redaction removes secret-shaped values and bounds messages", () => {
  const redacted = redactLogText("token=supersecretvalue AKIA1234567890ABCDEF /Users/test/.ssh/id_ed25519");
  assert.equal(redacted.redacted, true);
  assert.equal(redacted.text.includes("supersecretvalue"), false);
  assert.equal(redacted.text.includes("AKIA1234567890ABCDEF"), false);
  assert.equal(redacted.text.includes("id_ed25519"), false);
  const protectedPath = redactLogText("open failed: /Users/test/Library/Application Support/Google/Chrome/Default/Login Data");
  assert.equal(protectedPath.redacted, true);
  assert.equal(protectedPath.text.includes("Login Data"), false);
  assert.equal(protectedPath.text.includes("Application Support"), false);
  const privateRootPath = redactLogText("path=/private/var/root/.docker/contexts/meta/abc/meta.json");
  assert.equal(privateRootPath.redacted, true);
  assert.equal(privateRootPath.text.includes("meta.json"), false);
  const bounded = redactLogText("x".repeat(20_000));
  assert.equal(bounded.redacted, true);
  assert.ok(bounded.text.length <= 8192);
});

test("bounded redaction never exceeds the requested UTF-8 byte budget", () => {
  for (const maxBytes of [1, 2, 3, 8, 16]) {
    const bounded = redactBoundedText("🙂".repeat(20), maxBytes);
    assert.ok(Buffer.byteLength(bounded.text, "utf8") <= maxBytes);
    assert.equal(bounded.truncated, true);
  }
});
