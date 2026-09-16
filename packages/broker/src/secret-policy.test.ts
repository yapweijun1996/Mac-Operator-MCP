import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { assertArgumentsDoNotContainSecrets, assertContentDoesNotContainSecrets, assertContentPathAllowed, assertEnvironmentValuesDoNotContainSecrets, redactBoundedText, redactLogText } from "./secret-policy.js";

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
    "/Users/test/project/.git-credentials",
    "/private/var/root/Library/Preferences/com.apple.loginwindow.plist",
    "/var/root/opaque-private-data"
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
    "aws_secret_access_key=QWERTYUIOPASDFGHJKLZXCVBNM1234567890",
    "oauth=ya29.aVeryLongSyntheticGoogleAccessTokenValue",
    "client_secret=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ntSecret",
    "api_key=supersecretvalue",
    "gitlab=glpat-aVeryLongSyntheticGitLabToken",
    "npm=npm_aVeryLongSyntheticNpmTokenValue",
    "pypi=pypi-aVeryLongSyntheticPyPiToken",
    "stripe=sk_live_aVeryLongSyntheticStripeToken",
    "openai=sk-aVeryLongSyntheticLegacyOpenAITokenValue",
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

test("argument policy denies credential options and token-shaped values", () => {
  const denied = [
    ["--token", "value"],
    ["--api-key=opaque-value"],
    ["--private_key", "/tmp/key"],
    ["Authorization: Bearer abcdefghijklmnop-secret"],
    ["Bearer", "split-secret-value"],
    ["--header", "Authorization:", "split-secret-value"],
    ["-H", "Cookie:", "session=split-secret-value"]
  ];
  for (const argumentsValue of denied) {
    assert.throws(() => assertArgumentsDoNotContainSecrets(argumentsValue), /protected secret/u, argumentsValue.join(" "));
  }
  assert.doesNotThrow(() => assertArgumentsDoNotContainSecrets(["--format", "json", "ordinary-file"]));
  assert.doesNotThrow(() => assertArgumentsDoNotContainSecrets(["-c", 'printf "${MOP_CONTROLLER_SECRET-unset}"']));
});

test("secret policy covers expanded token corpus and preserves safe arguments", () => {
  const corpus = [
    "ASIA1234567890ABCDEF",
    "github_pat_aVeryLongSyntheticGitHubFineGrainedToken",
    "cfp_aVeryLongSyntheticCloudflareToken",
    "cf_pat-aVeryLongSyntheticCloudflareToken",
    "heroku_api_key=aVeryLongSyntheticHerokuToken"
  ];
  for (const value of corpus) {
    assert.throws(() => assertContentDoesNotContainSecrets(Buffer.from(value)), /protected secret signature/u, value);
    const redacted = redactLogText(`value=${value}`);
    assert.equal(redacted.redacted, true, value);
    assert.equal(redacted.text.includes(value), false, value);
  }
  assert.doesNotThrow(() => assertArgumentsDoNotContainSecrets(["--format", "json", "ordinary-file"]));
  assert.doesNotThrow(() => assertArgumentsDoNotContainSecrets(["--secretary", "notes"]));
});

test("content policy detects conservative encoded credential representations", () => {
  const plain = "token=ghp_123456789012345678901234";
  const base64 = Buffer.from(plain, "utf8").toString("base64");
  assert.throws(() => assertContentDoesNotContainSecrets(Buffer.from(`payload:${base64}`, "utf8")), /protected secret signature/u);

  const utf16le = Buffer.from(plain, "utf16le");
  assert.throws(() => assertContentDoesNotContainSecrets(utf16le), /protected secret signature/u);

  const utf16be = Buffer.alloc(utf16le.byteLength);
  for (let index = 0; index < utf16le.byteLength; index += 2) {
    utf16be[index] = utf16le[index + 1]!;
    utf16be[index + 1] = utf16le[index]!;
  }
  assert.throws(() => assertContentDoesNotContainSecrets(utf16be), /protected secret signature/u);

  assert.doesNotThrow(() => assertContentDoesNotContainSecrets(Buffer.from("payload:VGhpcyBpcyBub3QgYSBjcmVkZW50aWFs", "utf8")));
  assert.throws(() => assertArgumentsDoNotContainSecrets([base64]), /protected secret/u);
  assert.throws(() => assertEnvironmentValuesDoNotContainSecrets({ PROFILE_DATA: base64 }), /protected secret/u);
});

test("content policy denies binary private-key formats but preserves public DER", () => {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateDer = privateKey.export({ format: "der", type: "pkcs8" });
  const encryptedPrivateDer = privateKey.export({ format: "der", type: "pkcs8", cipher: "aes-256-cbc", passphrase: "synthetic-passphrase" });
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  assert.throws(() => assertContentDoesNotContainSecrets(privateDer), /protected secret signature/u);
  assert.throws(() => assertContentDoesNotContainSecrets(encryptedPrivateDer), /protected secret signature/u);
  assert.doesNotThrow(() => assertContentDoesNotContainSecrets(publicDer));

  const encoded = privateDer.toString("base64");
  assert.throws(() => assertContentDoesNotContainSecrets(Buffer.from(`payload:${encoded}`, "utf8")), /protected secret signature/u);
  const redacted = redactLogText(`payload=${encoded}`);
  assert.equal(redacted.redacted, true);
  assert.equal(redacted.text.includes(encoded), false);

  assert.throws(() => assertContentDoesNotContainSecrets(Buffer.from("openssh-key-v1\0synthetic", "binary")), /protected secret signature/u);
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
  const privateRootGenericPath = redactLogText("path=/private/var/root/opaque-private-data");
  assert.equal(privateRootGenericPath.redacted, true);
  assert.equal(privateRootGenericPath.text.includes("opaque-private-data"), false);
  const bounded = redactLogText("x".repeat(20_000));
  assert.equal(bounded.redacted, true);
  assert.ok(bounded.text.length <= 8192);
});

test("log redaction removes encoded credential representations", () => {
  const encoded = Buffer.from("token=ghp_123456789012345678901234", "utf8").toString("base64");
  const redacted = redactLogText(`payload=${encoded}`);
  assert.equal(redacted.redacted, true);
  assert.equal(redacted.text.includes(encoded), false);
  assert.equal(redacted.text.includes("[REDACTED]"), true);
});

test("bounded redaction never exceeds the requested UTF-8 byte budget", () => {
  for (const maxBytes of [1, 2, 3, 8, 16]) {
    const bounded = redactBoundedText("🙂".repeat(20), maxBytes);
    assert.ok(Buffer.byteLength(bounded.text, "utf8") <= maxBytes);
    assert.equal(bounded.truncated, true);
  }
});
