import assert from "node:assert/strict";
import { mkdtemp, mkdir, readFile, readdir, rm, stat, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { buildToolCatalog } from "./build-tool-catalog.mjs";

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), "tool-catalog-"));
  await mkdir(join(root, "tool-contracts"));
  await writeFile(join(root, "tool-contracts/tool-contract.schema.json"), JSON.stringify({ properties: { capability_level: { enum: ["L0", "L1", "L2", "L3", "L4", "L5"] } } }));
  const contract = { tool_name: "mac_fixture", schema_version: "0.1", capability_level: "L0", required_scopes: ["mac.control.read"], purpose: "Public test capability" };
  const path = join(root, "tool-contracts/mac_fixture.json");
  await writeFile(path, JSON.stringify(contract));
  t.after(() => rm(root, { recursive: true, force: true }));
  return { root, path, contract, output: join(root, "artifacts/catalog.json") };
}

test("catalog build produces deterministic verified public metadata and a private atomic artifact", async t => {
  const f = await fixture(t);
  const first = await buildToolCatalog(f.root, f.output);
  assert.equal(first.tool_count, 1);
  assert.match(first.artifact_sha256, /^[a-f0-9]{64}$/u);
  assert.deepEqual(await buildToolCatalog(f.root, f.output), first);
  assert.equal((await stat(f.output)).mode & 0o777, 0o600);
  assert.deepEqual(await readdir(join(f.root, "artifacts")), ["catalog.json"]);
  const artifact = JSON.parse(await readFile(f.output, "utf8"));
  assert.equal(artifact.tools[0].name, "mac_fixture");
  assert.equal(artifact.source_sha256, first.source_sha256);
  await writeFile(f.path, JSON.stringify({ ...f.contract, purpose: "Changed public test capability" }));
  assert.notEqual((await buildToolCatalog(f.root, f.output)).source_sha256, first.source_sha256);
});

for (const [name, change] of [
  ["identity mismatch", { tool_name: "mac_other" }],
  ["unsupported version", { schema_version: "1.0" }],
  ["missing scopes", { required_scopes: [] }],
  ["duplicate scopes", { required_scopes: ["mac.control.read", "mac.control.read"] }],
  ["invalid scope", { required_scopes: ["arbitrary"] }],
  ["invalid level", { capability_level: "ROOT" }]
]) test(`catalog rejects ${name} without replacing an existing artifact`, async t => {
  const f = await fixture(t);
  await buildToolCatalog(f.root, f.output);
  const before = await readFile(f.output);
  await writeFile(f.path, JSON.stringify({ ...f.contract, ...change }));
  await assert.rejects(buildToolCatalog(f.root, f.output));
  assert.deepEqual(await readFile(f.output), before);
});

test("catalog rejects empty collections and symlink inputs", async t => {
  const f = await fixture(t);
  await rm(f.path);
  await assert.rejects(buildToolCatalog(f.root, f.output), /empty/u);
  const outside = join(f.root, "public.json");
  await writeFile(outside, JSON.stringify(f.contract));
  await symlink(outside, f.path);
  await assert.rejects(buildToolCatalog(f.root, f.output), /regular file/u);
});

test("catalog refuses symlink output and preserves its target", async t => {
  const f = await fixture(t);
  const target = join(f.root, "existing.json");
  await writeFile(target, "PUBLIC_EXISTING_CONTENT\n");
  await mkdir(join(f.root, "artifacts"));
  await symlink(target, f.output);
  await assert.rejects(buildToolCatalog(f.root, f.output), /destination/u);
  assert.equal(await readFile(target, "utf8"), "PUBLIC_EXISTING_CONTENT\n");
});
