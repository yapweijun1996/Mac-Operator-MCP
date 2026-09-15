import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalJson, canonicalJsonUtf8, CANONICAL_JSON_PROFILE, decodeUtf8Strict, parseJsonStrict, parseJsonUtf8Strict, sha256 } from "./index.js";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");

interface CanonicalJsonVector {
  name: string;
  value: unknown;
  canonical: string;
  sha256: string;
}

test("canonical JSON profile is explicit and stable across fixed wire vectors", async () => {
  const vectors = JSON.parse(await readFile(join(repositoryRoot, "schemas", "canonical-json-vectors.json"), "utf8")) as {
    profile: string;
    encoding: string;
    property_order: string;
    number_format: string;
    vectors: CanonicalJsonVector[];
  };
  assert.equal(vectors.profile, CANONICAL_JSON_PROFILE);
  assert.equal(vectors.encoding, "UTF-8");
  assert.equal(vectors.property_order, "UTF-16 code units");
  assert.equal(vectors.number_format, "ECMAScript JSON.stringify");
  assert.ok(Array.isArray(vectors.vectors));
  assert.ok(vectors.vectors.length >= 4);
  for (const vector of vectors.vectors) {
    const canonical = canonicalJson(vector.value);
    assert.equal(canonical, vector.canonical, vector.name);
    assert.equal(sha256(canonicalJsonUtf8(vector.value)), vector.sha256, vector.name);
    assert.deepEqual(new TextDecoder().decode(canonicalJsonUtf8(vector.value)), vector.canonical, vector.name);
  }
});

test("canonical JSON UTF-8 encoding preserves Unicode without normalization", () => {
  const value = { "\u00e9": "\u00e9", "e\u0301": "e\u0301", "\ud83d\ude00": "\ud83d\ude00" };
  const canonical = canonicalJson(value);
  assert.equal(canonical, '{"é":"é","é":"é","😀":"😀"}');
  assert.equal(new TextDecoder().decode(canonicalJsonUtf8(value)), canonical);
});

test("strict UTF-8 decoding rejects malformed protocol bytes", () => {
  assert.equal(decodeUtf8Strict(Buffer.from("é", "utf8")), "é");
  assert.throws(() => decodeUtf8Strict(Buffer.from([0xc3, 0x28])), /valid UTF-8/u);
});

test("strict JSON parsing rejects duplicate keys and unpaired surrogates", () => {
  assert.deepEqual(parseJsonUtf8Strict(Buffer.from('{"a":1,"nested":{"b":true}}')), { a: 1, nested: { b: true } });
  assert.throws(() => parseJsonUtf8Strict(Buffer.from('{"a":1,"a":2}')), /duplicate key/u);
  assert.throws(() => parseJsonUtf8Strict(Buffer.from('{"a":1,"\\u0061":2}')), /duplicate key/u);
  assert.throws(() => parseJsonUtf8Strict(Buffer.from('"\\ud800"')), /unpaired surrogate/u);
  assert.throws(() => parseJsonStrict('"\\udfff"'), /unpaired surrogate/u);
  assert.throws(() => canonicalJson("\ud800"), /JSON string contains an unpaired surrogate/u);
});

test("strict JSON parsing rejects numbers that cannot reproduce the canonical wire spelling", () => {
  assert.deepEqual(parseJsonStrict('{"small":1e-7,"fraction":1.2300,"large":1e21}'), {
    small: 1e-7,
    fraction: 1.23,
    large: 1e21
  });
  assert.throws(() => parseJsonStrict("9007199254740993"), /not representable/u);
  assert.throws(() => parseJsonStrict("0.100000000000000005"), /not representable/u);
  assert.throws(() => parseJsonStrict("1e400"), /not representable/u);
  assert.throws(() => parseJsonStrict("1e-324"), /not representable/u);
});

test("canonical JSON rejects unsafe plain decimal integers across runtimes", () => {
  assert.throws(() => parseJsonStrict("9007199254740992"), /safe integer/u);
  assert.equal(canonicalJson(9_007_199_254_740_992), "9007199254740992");
  assert.equal(parseJsonStrict("1e20"), 1e20);
  assert.throws(() => parseJsonStrict("100000000000000000000"), /safe integer/u);
  assert.equal(parseJsonStrict("1e21"), 1e21);
});
