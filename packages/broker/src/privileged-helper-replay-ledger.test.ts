import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { chmod, lstat, mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { BrokerError } from "@mac-operator/contracts";
import { PrivilegedHelperReplayLedger } from "./privileged-helper-replay-ledger.js";

test("root-helper replay ledger is owner-only and survives guard recreation", async () => {
  const uid = process.geteuid?.();
  if (uid === undefined) throw new Error("POSIX effective user identity is unavailable");
  const root = await mkdtemp(join(tmpdir(), "mops-helper-replay-ledger-"));
  const canonicalRoot = await realpath(root);
  try {
    const ledgerPath = join(canonicalRoot, "state", "replay-ledger.sqlite");
    const moduleUrl = new URL("./privileged-helper-replay-ledger.js", import.meta.url).href;
    const recordCommand = `
      import { PrivilegedHelperReplayLedger } from ${JSON.stringify(moduleUrl)};
      new PrivilegedHelperReplayLedger(process.argv[1]).admit({
        requestId: "request:durable-helper-command-0001",
        nonce: "helper-nonce-durable-ledger-0001",
        timestampMs: 1700000000000,
        nonceExpiresAtMs: 1700000060000
      });
    `;
    const firstProcess = spawnSync(process.execPath, ["--input-type=module", "-e", recordCommand, canonicalRoot], { encoding: "utf8" });
    assert.equal(firstProcess.status, 0, firstProcess.stderr);

    const database = await lstat(ledgerPath);
    assert.equal(database.isFile(), true);
    assert.equal(database.uid, uid);
    assert.equal(database.nlink, 1);
    assert.equal(database.mode & 0o777, 0o600);

    const replayScript = `
      import { PrivilegedHelperReplayLedger } from ${JSON.stringify(moduleUrl)};
      try {
        new PrivilegedHelperReplayLedger(process.argv[1]).admit({
          requestId: process.argv[2], nonce: process.argv[3],
          timestampMs: 1700000000001, nonceExpiresAtMs: 1700000060000
        });
        process.exitCode = 2;
      } catch (error) {
        process.exitCode = error?.errorClass === "REPLAY_DENIED" ? 0 : 3;
      }
    `;
    for (const [requestId, nonce] of [
      ["request:durable-helper-command-0001", "helper-nonce-durable-ledger-0002"],
      ["request:durable-helper-command-0002", "helper-nonce-durable-ledger-0001"]
    ] as const) {
      const restartedProcess = spawnSync(process.execPath, ["--input-type=module", "-e", replayScript, canonicalRoot, requestId, nonce], { encoding: "utf8" });
      assert.equal(restartedProcess.status, 0, restartedProcess.stderr);
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("root-helper replay ledger fails closed when its state directory is not owner-only", async () => {
  const root = await mkdtemp(join(tmpdir(), "mops-helper-replay-ledger-mode-"));
  const canonicalRoot = await realpath(root);
  try {
    const ledger = new PrivilegedHelperReplayLedger(canonicalRoot);
    await chmod(join(canonicalRoot, "state"), 0o750);
    assert.throws(() => ledger.admit({
      requestId: "request:durable-helper-command-1001",
      nonce: "helper-nonce-durable-ledger-1001",
      timestampMs: 1_700_000_000_000,
      nonceExpiresAtMs: 1_700_000_060_000
    }), (error: unknown) => error instanceof BrokerError && error.errorClass === "AUDIT_UNAVAILABLE");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
