import assert from "node:assert/strict";
import test from "node:test";
import { readProtectedFileAfterIdentity, type ProtectedFileMetadata } from "./protected-file.js";

const metadata: ProtectedFileMetadata = {
  dev: 1,
  ino: 2,
  uid: 3,
  gid: 4,
  mode: 0o600,
  size: 6,
  mtimeMs: 7,
  ctimeMs: 8
};

test("protected descriptor readback accepts unchanged metadata", async () => {
  const content = Buffer.from("policy");
  const result = await readProtectedFileAfterIdentity({
    readFile: async () => content,
    stat: async () => ({ ...metadata })
  }, metadata, 1_024, "Policy");
  assert.equal(result.toString(), "policy");
});

test("protected descriptor readback rejects in-place metadata changes and wipes bytes", async () => {
  const content = Buffer.from("secret");
  await assert.rejects(
    readProtectedFileAfterIdentity({
      readFile: async () => content,
      stat: async () => ({ ...metadata, ctimeMs: metadata.ctimeMs + 1 })
    }, metadata, 1_024, "Signing key"),
    /Signing key changed while reading/u
  );
  assert.deepEqual(content, Buffer.alloc(content.byteLength));
});

test("protected descriptor readback rejects a size limit even when metadata is stable", async () => {
  const content = Buffer.from("secret");
  await assert.rejects(
    readProtectedFileAfterIdentity({
      readFile: async () => content,
      stat: async () => ({ ...metadata })
    }, metadata, 5, "Signing key"),
    /Signing key changed while reading/u
  );
  assert.deepEqual(content, Buffer.alloc(content.byteLength));
});
