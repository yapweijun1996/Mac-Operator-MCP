import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { mkdtemp, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { ownedDocumentCleanupAcknowledged } from "./gui-fixture-acknowledgment.mjs";

const exec = promisify(execFile);

test("OCR known-token geometry accepts adjacent words and rejects unrelated rows or gaps", { skip: process.platform !== "darwin" }, async () => {
  const directory = await mkdtemp(join(tmpdir(), "mba-marker-geometry-"));
  try {
    const header = fileURLToPath(new URL("./fixtures/gui-marker-geometry.h", import.meta.url));
    const source = join(directory, "geometry.c"), executable = join(directory, "geometry");
    await writeFile(source, `#include <assert.h>\n#include "${header}"\nint main(void) {
      MbaMarkerBox prefix={.1,.5,.15,.025}, word={.256,.502,.05,.02};
      assert(mbaMarkerTokensAdjacent(prefix,word));
      word.y=.6; assert(!mbaMarkerTokensAdjacent(prefix,word));
      word.y=.502; word.x=.31; assert(!mbaMarkerTokensAdjacent(prefix,word));
      word.x=.05; assert(!mbaMarkerTokensAdjacent(prefix,word));
      word.x=.12; assert(!mbaMarkerTokensAdjacent(prefix,word));
      word.x=.256; word.height=0; assert(!mbaMarkerTokensAdjacent(prefix,word));
      word.height=.02; word.x=NAN; assert(!mbaMarkerTokensAdjacent(prefix,word));
      word.x=.98; assert(!mbaMarkerTokensAdjacent(prefix,word));
      word.x=.27; assert(mbaMarkerTokensAdjacentWithAspect(prefix,word,.5));
      assert(!mbaMarkerTokensAdjacentWithAspect(prefix,word,2));
      assert(!mbaMarkerTokensAdjacentWithAspect(prefix,word,0));
      return 0;
    }\n`);
    await exec("/usr/bin/clang", [source, "-o", executable], { timeout: 10_000, maxBuffer: 4096 });
    await exec(executable, [], { timeout: 5000, maxBuffer: 4096 });
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test("TextEdit cleanup acknowledgment requires exact owned document identity and independent absence", () => {
  const expected = { probe_id: "owned-probe", app_id: "bundle:com.apple.TextEdit", document_title: "MBA-MCP Probe owned.rtf",
    document_path: "/private/tmp/owned/MBA-MCP Probe owned.rtf", window_id: "owned-window" };
  const valid = { ...expected, closed: true, independently_confirmed_absent: true };
  assert(ownedDocumentCleanupAcknowledged(valid, expected));
  for (const key of Object.keys(expected)) {
    assert.equal(ownedDocumentCleanupAcknowledged({ ...valid, [key]: "another-target" }, expected), false, key);
    const missing = { ...valid }; delete missing[key];
    assert.equal(ownedDocumentCleanupAcknowledged(missing, expected), false, `missing ${key}`);
  }
  for (const key of ["closed", "independently_confirmed_absent"]) {
    assert.equal(ownedDocumentCleanupAcknowledged({ ...valid, [key]: false }, expected), false, key);
    assert.equal(ownedDocumentCleanupAcknowledged({ ...valid, [key]: 1 }, expected), false, `${key} must be boolean`);
  }
  assert.equal(ownedDocumentCleanupAcknowledged(null, expected), false);
  assert.equal(ownedDocumentCleanupAcknowledged([], expected), false);
});

for (const mode of ["ordinary", "chrome_cua", "chrome_only"]) test(`real GUI reliability probe requires its explicit opt-in (${mode})`, async () => {
  const path = fileURLToPath(new URL("./probe-gui-observation-reliability.mjs", import.meta.url));
  const result = await exec(process.execPath, [path], { timeout: 5000, maxBuffer: 4096,
    env: { ...process.env, MOPS_REAL_GUI: "0", MOPS_REAL_GUI_CHROME: mode === "chrome_cua" ? "1" : "0",
      MOPS_REAL_GUI_CHROME_CUA: mode === "ordinary" ? "0" : "1", MOPS_REAL_GUI_ONLY_CHROME: mode === "chrome_only" ? "1" : "0", MOPS_REAL_GUI_APPLE_EVENTS: "0" } });
  const report = JSON.parse(result.stdout.trim());
  assert.equal(report.status, "skipped");
  assert.equal(report.failClosed, true);
  assert.equal(result.stderr, "");
});
