import assert from "node:assert/strict";
import test from "node:test";
import { redactBoundedText } from "./secret-policy.js";
import { TerminalOutputRedactor } from "./terminal-output-redactor.js";

test("terminal sanitizer recognizes credentials across every byte boundary", () => {
  const token = "ghp_" + "A".repeat(32);
  const samples = [token, "password = \"" + "s".repeat(20) + "\"", "Bearer\n" + "b".repeat(32),
    "aws_secret_access_key = " + "a".repeat(40), "X-Amz-Signature = " + "a".repeat(64),
    "X-Amz-Security-Token = " + "a".repeat(40), Buffer.from(token).toString("base64"),
    "https://example.test/blob?sv=2026-01-01&sig=" + "s".repeat(40) + "&sp=r&se=2026-12-01",
    "/Users/owner/Library/Application Support/Google/Chrome/Profile 1/Login Data",
    "/Users/owner/.azure/token", "/Users/owner/.azure/password", "/Users/owner/.azure/client_secret",
    "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "p".repeat(256) + "\n-----END OPENSSH PRIVATE KEY-----"];
  for (const sample of samples) {
    const value = `before % ${sample}\nafter % `;
    const expected = redactBoundedText(value, 65_536).text;
    const bytes = Buffer.from(value);
    for (let boundary = 0; boundary <= bytes.length; boundary++) {
      const redactor = new TerminalOutputRedactor();
      const output = redactor.push(bytes.subarray(0, boundary)) + redactor.push(bytes.subarray(boundary)) + redactor.finish();
      assert.equal(output, expected, `split at ${boundary} for ${samples.indexOf(sample)}`);
    }
    const redactor = new TerminalOutputRedactor();
    let output = "";
    for (const byte of bytes) output += redactor.push(Buffer.from([byte]));
    assert.equal(output + redactor.finish(), expected);
  }
});

test("terminal sanitizer streams ordinary prompts and flushes unfinished text at exit", () => {
  const redactor = new TerminalOutputRedactor();
  assert.equal(redactor.push(Buffer.from("ready % ")), "ready % ");
  assert.equal(redactor.push(Buffer.from("last-word")), "");
  assert.equal(redactor.finish(), "last-word");
});

test("terminal sanitizer streams dashed separators and public certificates without waiting for exit", () => {
  for (const value of ["-----\nready % ", "ordinary ----- separator\nready % ", "----- separator % ",
    "-----BEGIN CERTIFICATE-----\npublic-data\n-----END CERTIFICATE-----\nready % "]) {
    const redactor = new TerminalOutputRedactor();
    let output = "";
    for (const byte of Buffer.from(value)) output += redactor.push(Buffer.from([byte]));
    assert.equal(output, value);
    assert.equal(redactor.finish(), "");
  }
});

test("terminal sanitizer conceals unfinished and oversized private key bodies", () => {
  for (const header of ["-----BEGIN PRIVATE KEY-----\n", "-----BEGIN OPENSSH PRIVATE KEY-----\n", "-----BEGIN " + "A".repeat(70_000)]) {
    const redactor = new TerminalOutputRedactor();
    const body = "private-material".repeat(10_000);
    const output = redactor.push(Buffer.from(header)) + redactor.push(Buffer.from(body)) + redactor.finish();
    assert.match(output, /REDACTED/u);
    assert.ok(!output.includes("private-material"));
  }
});

test("terminal sanitizer bounds an unfinished record without exposing its continuation", () => {
  const redactor = new TerminalOutputRedactor();
  let output = redactor.push(Buffer.from("ghp_" + "A".repeat(70_000)));
  output += redactor.push(Buffer.from("A".repeat(70_000) + "\nafter % "));
  output += redactor.finish();
  assert.equal(output, "[REDACTED: oversized terminal record]\nafter % ");
});

test("terminal sanitizer distinguishes public and private PEM headers while discarding an oversized record", () => {
  for (const kind of ["CERTIFICATE", "PRIVATE KEY"]) {
    const redactor = new TerminalOutputRedactor();
    let output = redactor.push(Buffer.from("A".repeat(70_000)));
    const tail = `-----BEGIN ${kind}-----\nbody-data\n-----END ${kind}-----\nready % `;
    for (const byte of Buffer.from(tail)) output += redactor.push(Buffer.from([byte]));
    output += redactor.finish();
    assert.equal(output, kind === "CERTIFICATE"
      ? "[REDACTED: oversized terminal record]\nbody-data\n-----END CERTIFICATE-----\nready % "
      : "[REDACTED: oversized terminal record]\nready % ");
  }
});

test("terminal sanitizer retains split UTF-8 characters", () => {
  const redactor = new TerminalOutputRedactor();
  let output = "";
  for (const byte of Buffer.from("\u754c\ud83d\ude00\n")) output += redactor.push(Buffer.from([byte]));
  assert.equal(output + redactor.finish(), "\u754c\ud83d\ude00\n");
});
