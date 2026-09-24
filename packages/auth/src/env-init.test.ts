import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, realpath, writeFile, chmod, symlink, rm, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomBytes } from "node:crypto";
import { promisify } from "node:util";
import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { AuthStore } from "./store.js";
import { verifyPassword } from "./password.js";

const execute = promisify(execFile);
const cli = fileURLToPath(new URL("./cli.js", import.meta.url));

test("env initialization supports literal special characters, hides secrets, and never overwrites an owner", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-env-")));
  const secret = `${randomBytes(20).toString("hex")}#$()!`;
  try {
    const env = join(root, ".env"); const state = join(root, "auth");
    await writeFile(env, `MAC_OPERATOR_USERNAME=test-owner\nMAC_OPERATOR_PASSWORD='${secret}'\n`, { mode: 0o600 });
    const args = [cli, "init", "--dir", state, "--env-file", env, "--redirect-uri", "https://chatgpt.com/connector_platform_oauth_redirect"];
    const result = await execute(process.execPath, args);
    assert.ok(result.stdout.includes("Owner account provisioned"));
    assert.ok(!`${result.stdout}${result.stderr}`.includes(secret));
    assert.equal(process.env.MAC_OPERATOR_PASSWORD, undefined);
    const store = new AuthStore(state);
    try {
      const owner = store.get("account", "owner")!;
      assert.equal(owner.username, "test-owner");
      assert.ok(await verifyPassword(secret, owner.salt, owner.passwordHash));
      assert.ok(!(await readFile(join(state, "auth.sqlite"))).includes(Buffer.from(secret)));
      await assert.rejects(execute(process.execPath, args));
      assert.ok(await verifyPassword(secret, store.get("account", "owner")!.salt, store.get("account", "owner")!.passwordHash));
    } finally { store.close(); }
  } finally { await rm(root, { recursive: true, force: true }); }
});

test("env initialization rejects weak files, symlinks, missing passwords and conflicting inputs without printing values", async () => {
  const root = await realpath(await mkdtemp(join(tmpdir(), "mac-auth-env-invalid-")));
  const secret = randomBytes(20).toString("hex");
  try {
    const env = join(root, ".env"); const link = join(root, "linked.env");
    await writeFile(env, `MAC_OPERATOR_USERNAME=test-owner\nMAC_OPERATOR_PASSWORD='${secret}'\n`, { mode: 0o644 });
    const attempt = async (path: string, extra: string[] = []) => {
      try {
        await execute(process.execPath, [cli, "init", "--dir", join(root, "auth"), "--env-file", path,
          "--redirect-uri", "https://chatgpt.com/connector_platform_oauth_redirect", ...extra]);
        assert.fail("Unexpected initialization success");
      } catch (error) {
        const failure = error as { code?: number; stdout?: string; stderr?: string };
        assert.equal(failure.code, 1);
        assert.ok(!`${failure.stdout}${failure.stderr}`.includes(secret));
      }
    };
    await attempt(env);
    await chmod(env, 0o600); await symlink(env, link); await attempt(link);
    await attempt(env, ["--username", "ambiguous"]);
    await writeFile(env, "MAC_OPERATOR_USERNAME=test-owner\nMAC_OPERATOR_PASSWORD=''\n");
    await attempt(env);
  } finally { await rm(root, { recursive: true, force: true }); }
});
