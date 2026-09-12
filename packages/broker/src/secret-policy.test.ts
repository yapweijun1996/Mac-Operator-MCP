import assert from "node:assert/strict";
import test from "node:test";
import { assertContentDoesNotContainSecrets, assertContentPathAllowed } from "./secret-policy.js";

test("fixed secret-zone policy denies credential and private-data paths", () => {
  const denied = [
    "/Users/test/project/.env",
    "/Users/test/project/.ENV.production",
    "/Users/test/.ssh/id_ed25519",
    "/Users/test/.config/gcloud/application_default_credentials.json",
    "/Users/test/.docker/config.json",
    "/Users/test/Library/Keychains/login.keychain-db",
    "/Users/test/Library/Application Support/Google/Chrome/Default/Login Data",
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
    "token: xoxb-1234567890-abcdefghijklmnop"
  ];
  for (const value of denied) {
    assert.throws(() => assertContentDoesNotContainSecrets(Buffer.from(value)), /protected secret signature/u);
  }
  assert.doesNotThrow(() => assertContentDoesNotContainSecrets(Buffer.from("ordinary documentation")));
});
