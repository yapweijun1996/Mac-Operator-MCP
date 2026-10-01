import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import test from "node:test";
import { assertArgumentsDoNotContainSecrets, assertContentDoesNotContainSecrets, assertContentPathAllowed, assertEnvironmentValuesDoNotContainSecrets, redactBoundedText, redactLogText } from "./secret-policy.js";

test("fixed secret-zone policy denies credential and private-data paths", () => {
  const denied = [
    "/Users/test/project/.env",
    "/Users/test/project/.ENV.production",
    "/Users/test/.ssh/id_ed25519",
    "/Users/test/.codex/auth.json",
    "/Users/test/.claude/credentials.json",
    "/Users/test/.config/claude/session.json",
    "/Users/test/.config/opencode/auth.json",
    "/Users/test/.mozilla/firefox/profile/logins.json",
    "/Users/test/Library/Application Support/Firefox/profile/logins.json",
    "/Users/test/Library/Application Support/MacOperator/runtime/credentials.json",
    "/Users/test/.config/gcloud/application_default_credentials.json",
    "/Users/test/.docker/config.json",
    "/Users/test/.docker/contexts/meta/abc/meta.json",
    "/Users/test/.config/gh/hosts.yml",
    "/Users/test/Library/Keychains/login.keychain-db",
    "/Users/test/Library/Application Support/Google/Chrome/Default/Login Data",
    "/Users/test/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data",
    "/Users/test/Library/Containers/com.apple.mail/Data/Library/Mail/V10/Envelope Index",
    "/Users/test/project/.git-credentials",
    "/Users/test/project/apns-auth-key.p8",
    "/Users/test/project/team-signing.p12",
    "/Users/test/project/client-certificate.ppk",
    "/Users/test/project/enterprise.keystore",
    "/Users/test/.zsh_history",
    "/Users/test/.config/fish/fish_history",
    "/Users/test/.local/share/python_history",
    "/Users/test/bash_history",
    "/Users/test/Library/Application Support/com.apple.TCC/TCC.db",
    "/Library/Application Support/com.apple.TCC/TCC.db",
    "/private/var/db/TCC/TCC.db",
    "/private/var/db/dslocal/nodes/Default/users/test.plist",
    "/private/var/db/ConfigurationProfiles/Store/CloudConfigurationDetails.plist",
    "/private/var/db/keychains/system.keychain",
    "/private/var/db/lockdown/escrow_records.plist",
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
    "heroku_api_key=aVeryLongSyntheticHerokuToken",
    "rk_" + "live_aVeryLongSyntheticStripeRestrictedKey",
    "SG." + "aVeryLongSyntheticSendGridHeader.aVeryLongSyntheticSendGridPayload",
    "hf_aVeryLongSyntheticHuggingFaceTokenValue",
    "sntrys_aVeryLongSyntheticSentryToken",
    "vercel_aVeryLongSyntheticVercelToken",
    "sb_secret_aVeryLongSyntheticSupabaseToken"
  ];
  for (const value of corpus) {
    assert.throws(() => assertContentDoesNotContainSecrets(Buffer.from(value)), /protected secret signature/u, value);
    const redacted = redactLogText(`value=${value}`);
    assert.equal(redacted.redacted, true, value);
    assert.equal(redacted.text.includes(value), false, value);
  }
  assert.doesNotThrow(() => assertArgumentsDoNotContainSecrets(["--format", "json", "ordinary-file"]));
  assert.doesNotThrow(() => assertArgumentsDoNotContainSecrets(["--secretary", "notes"]));
  const opaqueHighEntropyValue = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0";
  assert.doesNotThrow(() => assertContentDoesNotContainSecrets(Buffer.from(opaqueHighEntropyValue)));
  const preserved = redactLogText(`value=${opaqueHighEntropyValue}`);
  assert.equal(preserved.redacted, false);
  assert.equal(preserved.text.includes(opaqueHighEntropyValue), true);
});

test("cloud signed URLs are denied and redacted without treating unrelated signatures as secrets", () => {
  const awsSignature = "a".repeat(64);
  const awsSessionToken = "IQoJb3JpZ2luX2VjSyntheticSessionToken%2FMoreBytes%3D";
  const azureSignature = "c3ludGhldGljLWF6dXJlLXNhcy1zaWduYXR1cmU%3D";
  const credentials = [
    `https://objects.example.test/file?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Signature=${awsSignature}`,
    `X-Amz-Security-Token=${awsSessionToken}`,
    `https://storage.example.test/blob?sv=2025-01-05&sp=rl&se=2030-01-01T00%3A00%3A00Z&sig=${azureSignature}`
  ];
  for (const value of credentials) {
    assert.throws(() => assertContentDoesNotContainSecrets(Buffer.from(value)), /protected secret signature/u);
    assert.throws(() => assertArgumentsDoNotContainSecrets([value]), /protected secret/u);
    assert.throws(() => assertEnvironmentValuesDoNotContainSecrets({ PROFILE_DATA: value }), /protected secret/u);
    const redacted = redactLogText(value);
    assert.equal(redacted.redacted, true);
    for (const secret of [awsSignature, awsSessionToken, azureSignature]) {
      assert.equal(redacted.text.includes(secret), false, value);
    }
  }

  const nearMisses = [
    `unrelated_digest=${awsSignature}`,
    "https://example.test/file?X-Amz-Signature=0123456789abcdef",
    "https://example.test/blob?sv=2025-01-05&sp=rl&sig=short",
    `https://example.test/file?sv=2025&sig=${"b".repeat(64)}`,
    `https://example.test/file?sig=${"b".repeat(64)}`
  ];
  for (const value of nearMisses) {
    assert.doesNotThrow(() => assertContentDoesNotContainSecrets(Buffer.from(value)), value);
    assert.equal(redactLogText(value).text.includes(value.slice(value.indexOf("=") + 1)), true, value);
  }
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
  const signingContainerPath = redactLogText("open failed: /tmp/team-signing.p12");
  assert.equal(signingContainerPath.redacted, true);
  assert.equal(signingContainerPath.text.includes("team-signing.p12"), false);
  const historyPath = redactLogText("open failed: /Users/test/.zsh_history");
  assert.equal(historyPath.redacted, true);
  assert.equal(historyPath.text.includes(".zsh_history"), false);
  const tccPath = redactLogText("open failed: /Users/test/Library/Application Support/com.apple.TCC/TCC.db");
  assert.equal(tccPath.redacted, true);
  assert.equal(tccPath.text.includes("com.apple.TCC"), false);
  const dslocalPath = redactLogText("open failed: /private/var/db/dslocal/nodes/Default/users/test.plist");
  assert.equal(dslocalPath.redacted, true);
  assert.equal(dslocalPath.text.includes("dslocal"), false);
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
