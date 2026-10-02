import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { AuthStore } from "./store.js";

const redirectUris = ["https://client.test/callback"];

async function privateDirectory(t: test.TestContext): Promise<string> {
  const directory = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-diag-")));
  t.after(() => rm(directory, { recursive: true, force: true }));
  return directory;
}

function insertRaw(directory: string, kind: string, id: string, payload: string): void {
  const db = new DatabaseSync(join(directory, "auth.sqlite"));
  try { db.prepare("INSERT INTO records VALUES(?,?,?)").run(kind, id, payload); } finally { db.close(); }
}

test("an unreadable record seals the store and names only the record kind and issue codes", async t => {
  const directory = await privateDirectory(t);
  const store = new AuthStore(directory, true);
  t.after(() => store.close());
  store.put("client", "good", { id: "good", name: "MCP client", redirectUris, expiresAt: Number.MAX_SAFE_INTEGER });
  insertRaw(directory, "client", "bad", JSON.stringify({ id: "bad", name: "secret-name", redirectUris, expiresAt: 1, extra: "secret-extra" }));
  assert.throws(() => store.get("client", "bad"), (error: Error) => {
    assert.match(error.message, /^Auth state unavailable: record kind=client invalid \(/u);
    assert.doesNotMatch(error.message, /secret|bad/u);
    return true;
  });
  assert.throws(() => store.get("client", "good"), /^Error: Auth state unavailable$/u);
});

test("a corrupt record at startup refuses to open and reports its kind", async t => {
  const directory = await privateDirectory(t);
  const first = new AuthStore(directory, true);
  first.close();
  insertRaw(directory, "grant", "bad", "not json");
  assert.throws(() => new AuthStore(directory), /record kind=grant invalid \(unparseable_json\)/u);
});
