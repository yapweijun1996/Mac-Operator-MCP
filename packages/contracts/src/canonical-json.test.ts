import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";
import { canonicalJson, canonicalJsonUtf8, CANONICAL_JSON_PROFILE, decodeUtf8Strict, sha256 } from "./index.js";

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
