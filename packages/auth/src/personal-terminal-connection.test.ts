import assert from "node:assert/strict";
import { mkdir, mkdtemp, realpath, rm } from "node:fs/promises";
import { join } from "node:path";
import { tmpdir } from "node:os";
import test from "node:test";
import { BrokerServiceInstanceLock } from "@mac-operator/broker";
import { enablePersonalTerminalConnection } from "./personal-terminal-connection.js";

test("terminal connection opt-in refuses a live supervisor before reading or changing configuration", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mac-terminal-optin-")));
  const runtime = join(root, "personal/run");
  await mkdir(runtime, { recursive: true, mode: 0o700 });
  const lock = await BrokerServiceInstanceLock.acquire(join(runtime, "service.lock"));
  try {
    await assert.rejects(enablePersonalTerminalConnection(root, "/unused-package", "a".repeat(40)), /lock|instance|running|active/iu);
  } finally { await lock.close(); await rm(root, { recursive: true, force: true }); }
});
