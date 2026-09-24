import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, realpath, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import test from "node:test";
import {
  loadPersonalApprovalIssuerConfig,
  validatePersonalApprovalIssuerConfig
} from "./personal-approval-issuer.js";

test("personal approval issuer config is optional and disabled by default", async () => {
  const root = await mkdtemp(join(tmpdir(), "mop-pai-"));
  const dataRoot = join(root, "data");
  const runtimeRoot = join(root, "runtime");
  await mkdir(dataRoot, { mode: 0o700 });
  await mkdir(runtimeRoot, { mode: 0o700 });
  try {
    assert.equal(loadPersonalApprovalIssuerConfig(join(dataRoot, "approval-issuer.json"), resolve(dataRoot), resolve(runtimeRoot)), undefined);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("personal approval issuer config fixes the key and socket targets", async () => {
  const root = await mkdtemp(join(tmpdir(), "mop-pai-"));
  const canonicalRoot = await realpath(root);
  const dataRoot = resolve(join(canonicalRoot, "data"));
  const runtimeRoot = resolve(join(canonicalRoot, "runtime"));
  await mkdir(dataRoot, { mode: 0o700 });
  await mkdir(runtimeRoot, { mode: 0o700 });
  const configPath = join(dataRoot, "approval-issuer.json");
  try {
    const config = {
      schemaVersion: "0.1",
      enabled: false,
      keyConfigPath: join(dataRoot, "approval-keys.json"),
      socketPath: join(runtimeRoot, "approval.sock")
    } as const;
    await writeFile(configPath, `${JSON.stringify(config)}\n`, { mode: 0o600 });
    assert.deepEqual(loadPersonalApprovalIssuerConfig(configPath, dataRoot, runtimeRoot), config);
    await chmod(configPath, 0o644);
    assert.throws(() => loadPersonalApprovalIssuerConfig(configPath, dataRoot, runtimeRoot), /Protected auth file/u);
    assert.throws(() => validatePersonalApprovalIssuerConfig({ ...config, enabled: true, socketPath: join(runtimeRoot, "other.sock") }, configPath, dataRoot, runtimeRoot), /fixed/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
