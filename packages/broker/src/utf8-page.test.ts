import assert from "node:assert/strict";
import test from "node:test";
import { decodeUtf8Page } from "./utf8-page.js";

for (const character of ["é", "你", "😀"]) {
  for (let cut = 1; cut < Buffer.byteLength(character); cut++) {
    test(`UTF-8 page defers ${JSON.stringify(character)} after ${cut} bytes`, () => {
      const bytes = Buffer.from(`a${character}z`);
      assert.deepEqual(decodeUtf8Page(bytes.subarray(0, 1 + cut), true), { content: "a", bytesReturned: 1 });
      assert.deepEqual(decodeUtf8Page(bytes.subarray(1), false), { content: `${character}z`, bytesReturned: bytes.length - 1 });
      assert.throws(() => decodeUtf8Page(bytes.subarray(1, 1 + cut), true), /cannot fit/u);
      assert.throws(() => decodeUtf8Page(bytes.subarray(0, 1 + cut), false));
    });
  }
}
for (const bytes of [[0x80], [0xff], [0xe0, 0x80], [0xed, 0xa0], [0xf4, 0x90], [0xc0, 0xaf], [0xc2, 0x61]]) {
  test(`UTF-8 page rejects malformed bytes ${bytes.join(",")}`, () => {
    for (const more of [false, true]) assert.throws(() => decodeUtf8Page(Buffer.from(bytes), more));
  });
}
test("UTF-8 page counts BOM and handles empty EOF and exact character boundaries", () => {
  assert.deepEqual(decodeUtf8Page(Buffer.from("\ufeff你"), false), { content: "你", bytesReturned: 6 });
  assert.deepEqual(decodeUtf8Page(Buffer.alloc(0), false), { content: "", bytesReturned: 0 });
  assert.deepEqual(decodeUtf8Page(Buffer.from("你"), true), { content: "你", bytesReturned: 3 });
});
